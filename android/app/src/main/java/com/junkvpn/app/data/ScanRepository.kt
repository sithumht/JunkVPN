package com.junkvpn.app.data

import com.junkvpn.app.core.EndpointUi
import com.junkvpn.app.core.ScanSummary
import com.junkvpn.app.core.VerifyState
import com.junkvpn.app.core.VerifyUi
import com.junkvpn.app.core.WarpBridge
import com.junkvpn.app.core.parseScanResult
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject
import warpcore.Scan
import warpcore.ScanEvents

/** Everything the Scan screen renders, updated live from native callbacks. */
data class ScanUiState(
    val running: Boolean = false,
    val preset: String = "standard",
    val done: Long = 0,
    val total: Long = 0,
    val current: String = "",
    /** Reachable endpoints seen so far, handshake-confirmed first. */
    val live: List<EndpointUi> = emptyList(),
    /** Full result set of the last finished scan. */
    val results: List<EndpointUi> = emptyList(),
    val summary: ScanSummary? = null,
    val error: String? = null,
) {
    val progress: Float
        get() = if (total <= 0) 0f else (done.toFloat() / total).coerceIn(0f, 1f)
}

/**
 * Runs scans on an application-scoped coroutine scope (survives rotation),
 * translates gomobile callbacks into a single StateFlow, and persists every
 * finished run to [HistoryStore].
 *
 * Callbacks arrive on native worker threads, so live state is funnelled
 * through [lock] and emitted at a bounded rate.
 */
class ScanRepository(
    private val history: HistoryStore,
    private val settings: SettingsStore,
    private val account: AccountStore,
) {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val lock = Any()
    private var scan: Scan? = null

    // Guarded by lock.
    private var liveList: List<EndpointUi> = emptyList()
    private var lastEmitMs = 0L

    private val _state = MutableStateFlow(ScanUiState())
    val state: StateFlow<ScanUiState> = _state.asStateFlow()

    /** Verification lifecycle per endpoint key ("ip:port"). */
    private val _verify = MutableStateFlow<Map<String, VerifyState>>(emptyMap())
    val verify: StateFlow<Map<String, VerifyState>> = _verify.asStateFlow()

    fun start(preset: String, targets: List<String>) {
        // Claim the running flag synchronously so a double-tap can't start two scans.
        synchronized(lock) {
            if (_state.value.running) return
            _state.value = ScanUiState(running = true, preset = preset)
            liveList = emptyList()
            lastEmitMs = 0L
            _verify.value = emptyMap()
        }
        scope.launch { run(preset, targets) }
    }

    fun cancel() {
        synchronized(lock) { scan }?.cancel()
    }

    /**
     * Verifies [endpoint] with the registered account identity: the core
     * completes a full WireGuard handshake and only an endpoint that
     * recognizes the account's key answers with a valid authenticator.
     */
    fun verify(endpoint: String) {
        if (endpoint.isEmpty()) return
        synchronized(lock) {
            if (_verify.value[endpoint] != null) return
            _verify.value = _verify.value + (endpoint to VerifyState.Running)
        }
        scope.launch {
            val result = runCatching {
                WarpBridge.verify(endpoint, account.state.value.orEmpty())
            }.fold(
                onSuccess = { VerifyUi.parse(it) },
                onFailure = { e ->
                    VerifyUi(
                        ok = false,
                        code = "error",
                        rttMs = 0.0,
                        mac1 = false,
                        detail = e.message ?: e.toString(),
                    )
                },
            )
            _verify.update { it + (endpoint to VerifyState.Done(result)) }
        }
    }

    private suspend fun run(preset: String, targets: List<String>) {
        try {
            val cfgJson = JSONObject().apply {
                put("preset", preset)
                if (targets.isNotEmpty()) put("targets", JSONArray(targets))
                // Probe with the account identity so responders that only
                // answer registered keys respond to the scan.
                account.state.value?.takeIf { it.isNotBlank() }?.let { put("account", it) }
            }.toString()

            val session = WarpBridge.newScan(cfgJson, Events(this))
            synchronized(lock) { scan = session }
            val json = session.run()

            val (summary, results) = parseScanResult(json)
            history.add(summary, json)
            settings.saveBestEndpoint(summary.best)
            _state.update {
                it.copy(
                    running = false,
                    results = results,
                    summary = summary,
                    live = emptyList(),
                    current = "",
                )
            }
        } catch (t: Throwable) {
            _state.update {
                it.copy(running = false, error = t.message ?: t.toString())
            }
        } finally {
            synchronized(lock) { scan = null }
        }
    }

    // --- ScanEvents handlers (called from native threads) ---

    internal fun handleStart(total: Long) {
        _state.update { it.copy(done = 0, total = total) }
    }

    internal fun handleProgress(done: Long, total: Long, message: String) {
        _state.update { it.copy(done = done, total = total, current = message) }
    }

    internal fun handleResult(endpoint: String, wgMs: Double, tcpMs: Double, ok: Boolean) {
        if (!ok) return
        synchronized(lock) {
            val entry = EndpointUi.fromEvent(endpoint, wgMs, tcpMs, ok)
            val idx = liveList.indexOfFirst { it.endpoint == endpoint }
            liveList = if (idx >= 0) {
                liveList.toMutableList().apply { this[idx] = entry }
            } else {
                liveList + entry
            }.sortedWith(ranking)
            // Bound the emission rate: hundreds of results can land per second.
            val now = System.currentTimeMillis()
            if (now - lastEmitMs >= EMIT_INTERVAL_MS) {
                lastEmitMs = now
                _state.update { it.copy(live = liveList) }
            }
        }
    }

    internal fun handleFinish(best: String, reachable: Long, total: Long) {
        _state.update { it.copy(done = total, total = total) }
    }

    internal fun handleError(message: String) {
        _state.update { it.copy(error = message) }
    }

    private class Events(private val repo: ScanRepository) : ScanEvents {
        override fun onStart(total: Long) = repo.handleStart(total)
        override fun onProgress(done: Long, total: Long, message: String) =
            repo.handleProgress(done, total, message)
        override fun onResult(endpoint: String, wgMs: Double, tcpMs: Double, ok: Boolean) =
            repo.handleResult(endpoint, wgMs, tcpMs, ok)
        override fun onFinish(best: String, reachable: Long, total: Long) =
            repo.handleFinish(best, reachable, total)
        override fun onError(message: String) = repo.handleError(message)
    }

    private companion object {
        const val EMIT_INTERVAL_MS = 120L

        /** Handshake-confirmed endpoints rank above TCP-only ones, then by RTT. */
        val ranking = Comparator<EndpointUi> { a, b ->
            if (a.handshake != b.handshake) {
                if (a.handshake) -1 else 1
            } else {
                val av = a.latencyMs ?: Double.MAX_VALUE
                val bv = b.latencyMs ?: Double.MAX_VALUE
                av.compareTo(bv)
            }
        }
    }
}

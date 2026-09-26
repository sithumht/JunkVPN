package com.junkvpn.app.data

import android.content.Context
import com.junkvpn.app.core.ScanSummary
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/** A finished (or cancelled) scan kept for later review. */
data class HistoryEntry(
    val id: Long,
    val timestamp: Long,
    val preset: String,
    val best: String,
    val reachable: Int,
    val total: Int,
    val handshakes: Int,
    val durationMs: Long,
    val canceled: Boolean,
    /** Truncated ScanResult JSON (summary + top results). */
    val results: String,
)

/**
 * Local scan history, a single JSON file in the app's private storage.
 * All mutations are synchronous and guarded by [lock]; keep entries capped.
 */
class HistoryStore(context: Context) {

    private val file = File(context.filesDir, "scan_history.json")
    private val lock = Any()

    private val _entries = MutableStateFlow(read())
    val entries: StateFlow<List<HistoryEntry>> = _entries.asStateFlow()

    fun add(summary: ScanSummary, resultsJson: String) {
        synchronized(lock) {
            val entry = HistoryEntry(
                id = System.currentTimeMillis(),
                timestamp = System.currentTimeMillis(),
                preset = summary.preset,
                best = summary.best,
                reachable = summary.reachable,
                total = summary.total,
                handshakes = summary.handshakes,
                durationMs = summary.durationMs,
                canceled = summary.canceled,
                results = truncateResults(resultsJson, KEEP_RESULTS),
            )
            val next = (listOf(entry) + _entries.value).take(MAX_ENTRIES)
            write(next)
            _entries.value = next
        }
    }

    fun remove(id: Long) {
        synchronized(lock) {
            val next = _entries.value.filterNot { it.id == id }
            write(next)
            _entries.value = next
        }
    }

    fun clear() {
        synchronized(lock) {
            write(emptyList())
            _entries.value = emptyList()
        }
    }

    private fun read(): List<HistoryEntry> = runCatching {
        if (!file.exists()) return emptyList()
        val arr = JSONArray(file.readText())
        (0 until arr.length()).map { i ->
            val o = arr.getJSONObject(i)
            HistoryEntry(
                id = o.optLong("id"),
                timestamp = o.optLong("timestamp"),
                preset = o.optString("preset"),
                best = o.optString("best"),
                reachable = o.optInt("reachable"),
                total = o.optInt("total"),
                handshakes = o.optInt("handshakes"),
                durationMs = o.optLong("durationMs"),
                canceled = o.optBoolean("canceled"),
                results = o.optString("results"),
            )
        }
    }.getOrElse { emptyList() }

    private fun write(entries: List<HistoryEntry>) {
        runCatching {
            val arr = JSONArray()
            entries.forEach { e ->
                arr.put(
                    JSONObject().apply {
                        put("id", e.id)
                        put("timestamp", e.timestamp)
                        put("preset", e.preset)
                        put("best", e.best)
                        put("reachable", e.reachable)
                        put("total", e.total)
                        put("handshakes", e.handshakes)
                        put("durationMs", e.durationMs)
                        put("canceled", e.canceled)
                        put("results", e.results)
                    },
                )
            }
            file.writeText(arr.toString())
        }
    }

    private companion object {
        const val MAX_ENTRIES = 30
        const val KEEP_RESULTS = 20

        /** Keeps only the first [keep] results so history files stay small. */
        fun truncateResults(json: String, keep: Int): String = runCatching {
            val root = JSONObject(json)
            val all = root.optJSONArray("results") ?: JSONArray()
            val kept = JSONArray()
            for (i in 0 until minOf(keep, all.length())) kept.put(all.get(i))
            root.put("results", kept)
            root.toString()
        }.getOrDefault(json)
    }
}

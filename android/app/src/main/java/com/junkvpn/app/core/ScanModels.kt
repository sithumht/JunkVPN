package com.junkvpn.app.core

import org.json.JSONArray
import org.json.JSONObject

/**
 * One probed candidate, flattened for the UI.
 *
 * [wgMs] is only set when a real WireGuard handshake succeeded — the strongest
 * signal that an endpoint is usable. [tcpMs] is the fallback latency measured
 * with a TCP connect to the edge's web port.
 */
data class EndpointUi(
    val endpoint: String,
    val ip: String,
    val port: Int,
    val mode: String,
    val wgMs: Double?,
    val tcpMs: Double?,
    val jitterMs: Double,
    val lossPct: Double,
    val probes: Int,
    val ok: Boolean,
) {
    val latencyMs: Double? get() = wgMs ?: tcpMs
    val handshake: Boolean get() = wgMs != null

    companion object {
        /** Builds an entry from a live OnResult event (no jitter/loss yet). */
        fun fromEvent(endpoint: String, wgMs: Double, tcpMs: Double, ok: Boolean): EndpointUi {
            val host = endpoint.substringBefore(':')
            val port = endpoint.substringAfterLast(':').toIntOrNull() ?: 0
            val wg = wgMs.takeIf { it >= 0 }
            val tcp = tcpMs.takeIf { it >= 0 }
            return EndpointUi(
                endpoint = endpoint,
                ip = host,
                port = port,
                mode = if (wg != null) "wg" else "tcp",
                wgMs = wg,
                tcpMs = tcp,
                jitterMs = 0.0,
                lossPct = 0.0,
                probes = 1,
                ok = ok,
            )
        }
    }
}

/** Summary block of a finished scan, mirroring warpcore.ScanResult. */
data class ScanSummary(
    val preset: String,
    val startedAt: String,
    val durationMs: Long,
    val total: Int,
    val reachable: Int,
    val handshakes: Int,
    val best: String,
    val canceled: Boolean,
)

/** Parses the JSON produced by Scan.Run into UI models. */
fun parseScanResult(json: String): Pair<ScanSummary, List<EndpointUi>> {
    val root = JSONObject(json)
    val arr = root.optJSONArray("results") ?: JSONArray()
    val results = ArrayList<EndpointUi>(arr.length())
    for (i in 0 until arr.length()) {
        val o = arr.getJSONObject(i)
        results += EndpointUi(
            endpoint = o.optString("endpoint"),
            ip = o.optString("ip"),
            port = o.optInt("port"),
            mode = o.optString("mode"),
            wgMs = if (o.has("wgRttMs")) o.optDouble("wgRttMs") else null,
            tcpMs = if (o.has("tcpRttMs")) o.optDouble("tcpRttMs") else null,
            jitterMs = o.optDouble("jitterMs"),
            lossPct = o.optDouble("lossPct"),
            probes = o.optInt("probes"),
            ok = o.optBoolean("ok"),
        )
    }
    val summary = ScanSummary(
        preset = root.optString("preset"),
        startedAt = root.optString("startedAt"),
        durationMs = root.optLong("durationMs"),
        total = root.optInt("total"),
        reachable = root.optInt("reachable"),
        handshakes = root.optInt("handshakes"),
        best = root.optString("best"),
        canceled = root.optBoolean("canceled"),
    )
    return summary to results
}

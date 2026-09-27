package com.junkvpn.app.core

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import warpcore.RegisterEvents
import warpcore.Scan
import warpcore.ScanEvents
import warpcore.Warpcore

/**
 * Thin suspend wrapper around the gomobile-generated [Warpcore] bindings.
 *
 * Every call blocks inside JNI (network, crypto, file-less CPU work), so all
 * of them are dispatched to [Dispatchers.IO]. Scan sessions are exposed
 * directly because they have their own run/cancel lifecycle.
 */
object WarpBridge {

    suspend fun version(): String = call { Warpcore.version() }

    suspend fun presetConfig(name: String): String = call { Warpcore.presetConfig(name) }

    /**
     * Registers a fresh WARP account. [events] receives progress steps while
     * the route chain runs (direct → proxy → WARP tunnel fallback); it is
     * called from native worker threads.
     */
    suspend fun registerAccount(optsJson: String = "{}", events: RegisterEvents): String =
        call { Warpcore.registerAccount(optsJson, events) }

    suspend fun buildConfig(kind: String, accountJson: String, optsJson: String = ""): String =
        call { Warpcore.buildConfig(kind, accountJson, optsJson) }

    /**
     * Sends real WireGuard handshakes to [endpoint] using the account's
     * registered keys and returns the VerifyResult JSON. A valid response
     * proves the endpoint recognizes this account's identity.
     */
    suspend fun verify(endpoint: String, accountJson: String, timeoutMs: Long = 2000, attempts: Long = 2): String =
        call { Warpcore.verifyEndpoint(endpoint, accountJson, timeoutMs, attempts) }

    fun newScan(cfgJson: String, events: ScanEvents): Scan = Warpcore.newScan(cfgJson, events)

    private suspend fun <T> call(block: () -> T): T = withContext(Dispatchers.IO) { block() }
}

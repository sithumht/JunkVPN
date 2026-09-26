package com.junkvpn.app.core

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
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

    suspend fun registerAccount(optsJson: String = "{}"): String =
        call { Warpcore.registerAccount(optsJson) }

    suspend fun buildConfig(kind: String, accountJson: String, optsJson: String = ""): String =
        call { Warpcore.buildConfig(kind, accountJson, optsJson) }

    fun newScan(cfgJson: String, events: ScanEvents): Scan = Warpcore.newScan(cfgJson, events)

    private suspend fun <T> call(block: () -> T): T = withContext(Dispatchers.IO) { block() }
}

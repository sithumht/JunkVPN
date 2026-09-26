package com.junkvpn.app.data

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Holds the registered WARP account (identity + peer config) as JSON, at
 * rest encrypted through [KeystoreCrypto]. Emits null when no account exists.
 */
class AccountStore(context: Context) {

    private val prefs = context.getSharedPreferences("junkvpn_account", Context.MODE_PRIVATE)

    private val _state = MutableStateFlow(load())
    val state: StateFlow<String?> = _state.asStateFlow()

    private fun load(): String? {
        val stored = prefs.getString(KEY, null) ?: return null
        return runCatching { KeystoreCrypto.decrypt(stored) }.getOrNull()
    }

    fun save(json: String) {
        // Fail loudly instead of silently falling back to plaintext storage.
        val encrypted = KeystoreCrypto.encrypt(json)
        prefs.edit().putString(KEY, encrypted).apply()
        _state.value = json
    }

    fun clear() {
        prefs.edit().remove(KEY).apply()
        _state.value = null
    }

    private companion object {
        const val KEY = "account_enc"
    }
}

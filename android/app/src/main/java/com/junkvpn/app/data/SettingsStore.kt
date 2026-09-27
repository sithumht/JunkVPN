package com.junkvpn.app.data

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

enum class ThemeMode { SYSTEM, LIGHT, DARK }

/**
 * Small preferences: theme, default scan preset, the last known best
 * endpoint (used as the default target when exporting configs) and the
 * optional proxy used for WARP registration on blocked networks.
 */
class SettingsStore(context: Context) {

    private val prefs = context.getSharedPreferences("junkvpn_settings", Context.MODE_PRIVATE)

    private val _themeMode = MutableStateFlow(
        runCatching { ThemeMode.valueOf(prefs.getString(KEY_THEME, ThemeMode.SYSTEM.name)!!) }
            .getOrDefault(ThemeMode.SYSTEM),
    )
    val themeMode: StateFlow<ThemeMode> = _themeMode.asStateFlow()

    private val _defaultPreset = MutableStateFlow(prefs.getString(KEY_PRESET, "standard") ?: "standard")
    val defaultPreset: StateFlow<String> = _defaultPreset.asStateFlow()

    private val _bestEndpoint = MutableStateFlow(prefs.getString(KEY_BEST, "") ?: "")
    val bestEndpoint: StateFlow<String> = _bestEndpoint.asStateFlow()

    private val _registrationProxy = MutableStateFlow(prefs.getString(KEY_PROXY, "") ?: "")
    val registrationProxy: StateFlow<String> = _registrationProxy.asStateFlow()

    fun setThemeMode(mode: ThemeMode) {
        prefs.edit().putString(KEY_THEME, mode.name).apply()
        _themeMode.value = mode
    }

    fun setDefaultPreset(preset: String) {
        prefs.edit().putString(KEY_PRESET, preset).apply()
        _defaultPreset.value = preset
    }

    fun setRegistrationProxy(proxy: String) {
        prefs.edit().putString(KEY_PROXY, proxy).apply()
        _registrationProxy.value = proxy
    }

    fun saveBestEndpoint(endpoint: String) {
        if (endpoint.isBlank()) return
        prefs.edit().putString(KEY_BEST, endpoint).apply()
        _bestEndpoint.value = endpoint
    }

    private companion object {
        const val KEY_THEME = "theme_mode"
        const val KEY_PRESET = "default_preset"
        const val KEY_BEST = "best_endpoint"
        const val KEY_PROXY = "registration_proxy"
    }
}

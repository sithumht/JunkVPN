package com.junkvpn.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import com.junkvpn.app.data.ThemeMode
import com.junkvpn.app.ui.App
import com.junkvpn.app.ui.theme.JunkVPNTheme

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        val container = (application as JunkVPN).container

        setContent {
            val mode by container.settings.themeMode.collectAsState()
            val darkTheme = when (mode) {
                ThemeMode.SYSTEM -> isSystemInDarkTheme()
                ThemeMode.DARK -> true
                ThemeMode.LIGHT -> false
            }
            JunkVPNTheme(darkTheme = darkTheme) {
                App(container = container)
            }
        }
    }
}

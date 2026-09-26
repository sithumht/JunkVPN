package com.junkvpn.app.ui

import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.junkvpn.app.Container
import com.junkvpn.app.ui.screens.AccountScreen
import com.junkvpn.app.ui.screens.HistoryScreen
import com.junkvpn.app.ui.screens.ScanScreen
import com.junkvpn.app.ui.screens.SettingsScreen
import kotlinx.coroutines.launch

private data class Tab(val route: String, val label: String, val icon: ImageVector)

private val tabs = listOf(
    Tab("scan", "Scan", Icons.Filled.Speed),
    Tab("history", "History", Icons.Filled.History),
    Tab("account", "Account", Icons.Filled.VpnKey),
    Tab("settings", "Settings", Icons.Filled.Tune),
)

@Composable
fun App(container: Container) {
    val navController = rememberNavController()
    val snackbarHostState = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    val toast: (String) -> Unit = { message ->
        scope.launch { snackbarHostState.showSnackbar(message) }
    }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) },
        bottomBar = {
            NavigationBar {
                val backStack by navController.currentBackStackEntryAsState()
                val selectedRoute = backStack?.destination?.route
                tabs.forEach { tab ->
                    NavigationBarItem(
                        selected = selectedRoute == tab.route,
                        onClick = {
                            navController.navigate(tab.route) {
                                popUpTo(navController.graph.startDestinationId) {
                                    saveState = true
                                }
                                launchSingleTop = true
                                restoreState = true
                            }
                        },
                        icon = { Icon(tab.icon, contentDescription = tab.label) },
                        label = { Text(tab.label) },
                    )
                }
            }
        },
    ) { padding ->
        NavHost(
            navController = navController,
            startDestination = "scan",
            modifier = Modifier.padding(padding),
        ) {
            composable("scan") { ScanScreen(container, toast) }
            composable("history") { HistoryScreen(container, toast) }
            composable("account") { AccountScreen(container, toast) }
            composable("settings") { SettingsScreen(container, toast) }
        }
    }
}

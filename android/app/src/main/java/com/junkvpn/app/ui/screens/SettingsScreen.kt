package com.junkvpn.app.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.junkvpn.app.BuildConfig
import com.junkvpn.app.Container
import com.junkvpn.app.core.WarpBridge
import com.junkvpn.app.data.ThemeMode
import com.junkvpn.app.ui.components.DetailRow

private val ThemeMode.label: String
    get() = when (this) {
        ThemeMode.SYSTEM -> "System"
        ThemeMode.LIGHT -> "Light"
        ThemeMode.DARK -> "Dark"
    }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(container: Container, toast: (String) -> Unit) {
    val themeMode by container.settings.themeMode.collectAsState()
    val defaultPreset by container.settings.defaultPreset.collectAsState()
    val registrationProxy by container.settings.registrationProxy.collectAsState()
    val registrationRoute by container.settings.registrationRoute.collectAsState()
    val historyEntries by container.history.entries.collectAsState()
    var confirmClear by remember { mutableStateOf(false) }
    var coreVersion by remember { mutableStateOf("…") }

    val proxyLooksValid = registrationProxy.isBlank() ||
        registrationProxy.startsWith("socks5://") ||
        registrationProxy.startsWith("http://") ||
        registrationProxy.startsWith("https://")

    LaunchedEffect(Unit) {
        coreVersion = runCatching { WarpBridge.version() }.getOrDefault("?")
    }

    Column(Modifier.fillMaxSize()) {
        TopAppBar(title = { Text("Settings") })

        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 4.dp, bottom = 28.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item(key = "appearance") {
                SectionCard(title = "Appearance") {
                    Text(
                        text = "Theme",
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    SingleChoiceSegmentedButtonRow(
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        ThemeMode.entries.forEachIndexed { index, mode ->
                            SegmentedButton(
                                selected = themeMode == mode,
                                onClick = { container.settings.setThemeMode(mode) },
                                shape = SegmentedButtonDefaults.itemShape(
                                    index = index,
                                    count = ThemeMode.entries.size,
                                ),
                            ) {
                                Text(mode.label)
                            }
                        }
                    }
                }
            }

            item(key = "scan") {
                SectionCard(title = "Scanning") {
                    Text(
                        text = "Default preset",
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        listOf("quick" to "Quick", "standard" to "Standard", "deep" to "Deep")
                            .forEach { (id, label) ->
                                FilterChip(
                                    selected = defaultPreset == id,
                                    onClick = { container.settings.setDefaultPreset(id) },
                                    label = { Text(label) },
                                )
                            }
                    }
                    Text(
                        text = "Used when the Scan screen opens. A scan sends UDP " +
                            "WireGuard probes to Cloudflare WARP ranges, with a TCP " +
                            "connect fallback when UDP is filtered.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            item(key = "registration") {
                SectionCard(title = "Registration") {
                    Text(
                        text = "Route",
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    SingleChoiceSegmentedButtonRow(
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        listOf(
                            "auto" to "Auto",
                            "direct" to "Direct",
                            "tunnel" to "Tunnel",
                        ).forEachIndexed { index, (id, label) ->
                            SegmentedButton(
                                selected = registrationRoute == id,
                                onClick = { container.settings.setRegistrationRoute(id) },
                                shape = SegmentedButtonDefaults.itemShape(
                                    index = index,
                                    count = 3,
                                ),
                            ) {
                                Text(label)
                            }
                        }
                    }
                    Text(
                        text = "Auto tries the WARP API directly and, when the " +
                            "network blocks it, falls back to registering through a " +
                            "WARP tunnel. Tunnel forces that tunnel route (useful on " +
                            "always-blocked networks); Direct never tunnels.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    OutlinedTextField(
                        value = registrationProxy,
                        onValueChange = { container.settings.setRegistrationProxy(it.trim()) },
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text("Proxy") },
                        placeholder = { Text("socks5://127.0.0.1:1080") },
                        singleLine = true,
                        isError = !proxyLooksValid,
                        supportingText = {
                            Text(
                                text = if (proxyLooksValid) {
                                    "Optional — routes only the WARP register request " +
                                        "instead of the tunnel. Empty = direct or tunnel."
                                } else {
                                    "Use socks5://host:port or http://host:port"
                                },
                            )
                        },
                    )
                    Text(
                        text = "For networks that block api.cloudflareclient.com. " +
                            "Local ports exposed by other VPN apps work too. A set " +
                            "proxy replaces the tunnel fallback. Scanning never uses " +
                            "it — probes always connect directly.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            item(key = "data") {
                SectionCard(title = "Data") {
                    Text(
                        text = "Scan history",
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(
                        text = "${historyEntries.size} scan${if (historyEntries.size == 1) "" else "s"} stored locally",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    TextButton(
                        onClick = { confirmClear = true },
                        enabled = historyEntries.isNotEmpty(),
                    ) {
                        Text("Clear history")
                    }
                }
            }

            item(key = "about") {
                SectionCard(title = "About") {
                    DetailRow("App version", BuildConfig.VERSION_NAME)
                    DetailRow("Core version", coreVersion)
                    DetailRow("Package", BuildConfig.APPLICATION_ID)
                    Text(
                        text = "JunkVPN is an independent, open-source tool. It is " +
                            "not affiliated with, endorsed by, or connected to " +
                            "Cloudflare, Inc. Registration uses the public WARP API " +
                            "and scanning probes public Cloudflare anycast ranges.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }

    if (confirmClear) {
        AlertDialog(
            onDismissRequest = { confirmClear = false },
            title = { Text("Clear history?") },
            text = { Text("All saved scans are removed from this device.") },
            confirmButton = {
                TextButton(onClick = {
                    container.history.clear()
                    confirmClear = false
                    toast("History cleared")
                }) { Text("Clear") }
            },
            dismissButton = {
                TextButton(onClick = { confirmClear = false }) { Text("Cancel") }
            },
        )
    }
}

@Composable
private fun SectionCard(title: String, content: @Composable ColumnScope.() -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.primary,
            )
            content()
        }
    }
}

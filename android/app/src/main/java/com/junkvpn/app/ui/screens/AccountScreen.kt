package com.junkvpn.app.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.junkvpn.app.Container
import com.junkvpn.app.core.WarpBridge
import com.junkvpn.app.ui.components.DetailRow
import com.junkvpn.app.ui.copyToClipboard
import com.junkvpn.app.ui.shareText
import kotlinx.coroutines.launch
import org.json.JSONObject
import warpcore.RegisterEvents

private data class ConfigPreview(val title: String, val body: String)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AccountScreen(container: Container, toast: (String) -> Unit) {
    val accountJson by container.account.state.collectAsState()
    val bestEndpoint by container.settings.bestEndpoint.collectAsState()
    val scanState by container.scan.state.collectAsState()
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var regStep by remember { mutableStateOf<String?>(null) }
    var preview by remember { mutableStateOf<ConfigPreview?>(null) }
    var confirmDelete by remember { mutableStateOf(false) }
    var confirmReplace by remember { mutableStateOf(false) }

    val account = remember(accountJson) {
        accountJson?.let { runCatching { JSONObject(it) }.getOrNull() }
    }

    fun register(replacing: Boolean) {
        busy = true
        error = null
        regStep = null
        scope.launch {
            val proxy = container.settings.registrationProxy.value
            val route = container.settings.registrationRoute.value
            // Progress steps arrive on a native worker thread; hop back to
            // the main dispatcher before touching Compose state.
            val events = object : RegisterEvents {
                override fun onStep(step: String) {
                    scope.launch { regStep = step }
                }
            }
            val outcome = runCatching {
                val opts = JSONObject().apply {
                    if (proxy.isNotBlank()) put("proxy", proxy)
                    put("route", route)
                }
                val json = WarpBridge.registerAccount(opts.toString(), events)
                container.account.save(json)
            }
            busy = false
            val lastStep = regStep
            regStep = null
            outcome
                .onSuccess {
                    toast(if (replacing) "New account created" else "WARP account created")
                }
                .onFailure { err ->
                    val detail = (err.message ?: err.toString()) +
                        if (lastStep != null) "\n\nLast step: $lastStep" else ""
                    error = withNetworkHint(detail, proxy)
                }
        }
    }

    fun export(kind: String, title: String) {
        val json = accountJson ?: return
        scope.launch {
            val outcome = runCatching {
                val chosen = scanState.summary?.best?.takeIf { it.isNotBlank() }
                    ?: bestEndpoint
                val opts = JSONObject().apply {
                    if (chosen.isNotBlank()) put("endpoint", chosen)
                }.toString()
                WarpBridge.buildConfig(kind, json, opts)
            }
            outcome
                .onSuccess { body -> preview = ConfigPreview(title, body) }
                .onFailure { toast(it.message ?: "Config export failed") }
        }
    }

    Column(Modifier.fillMaxSize()) {
        TopAppBar(
            title = {
                Column {
                    Text("Account")
                    Text(
                        text = if (account == null) "No WARP identity yet"
                        else "WARP device registered",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            },
        )

        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 4.dp, bottom = 28.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            if (account == null) {
                item(key = "intro") {
                    Card(
                        shape = MaterialTheme.shapes.large,
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.primaryContainer,
                        ),
                    ) {
                        Column(
                            modifier = Modifier.padding(20.dp),
                            verticalArrangement = Arrangement.spacedBy(10.dp),
                        ) {
                            Text(
                                text = "Create a WARP account",
                                style = MaterialTheme.typography.titleLarge,
                                color = MaterialTheme.colorScheme.onPrimaryContainer,
                            )
                            Text(
                                text = "Registering generates a WireGuard key pair on " +
                                    "this device and asks Cloudflare WARP for a device " +
                                    "identity. Only the public key leaves the phone; the " +
                                    "private key stays here, encrypted with the Android " +
                                    "Keystore.",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.85f),
                            )
                            Button(
                                onClick = { register(replacing = false) },
                                enabled = !busy,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(54.dp),
                                shape = CircleShape,
                            ) {
                                if (busy) {
                                    CircularProgressIndicator(
                                        modifier = Modifier.size(20.dp),
                                        strokeWidth = 2.dp,
                                    )
                                    Spacer(Modifier.width(10.dp))
                                    Text("Registering…")
                                } else {
                                    Text("Create account")
                                }
                            }
                            if (busy && regStep != null) {
                                Text(
                                    text = regStep!!,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.75f),
                                )
                            }
                        }
                    }
                }
                error?.let { message ->
                    item(key = "error") {
                        ErrorCard(message)
                    }
                }
            } else {
                val acc = account
                item(key = "device") {
                    Card(
                        shape = MaterialTheme.shapes.large,
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.surfaceVariant,
                        ),
                    ) {
                        Column(
                            modifier = Modifier.padding(16.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp),
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Text("Device", style = MaterialTheme.typography.labelLarge)
                                TextButton(onClick = {
                                    copyToClipboard(context, "Device ID", acc.optString("deviceId"))
                                    toast("Device ID copied")
                                }) {
                                    Icon(
                                        Icons.Filled.ContentCopy,
                                        contentDescription = null,
                                        modifier = Modifier.size(16.dp),
                                    )
                                    Spacer(Modifier.width(6.dp))
                                    Text("Copy ID")
                                }
                            }
                            DetailRow("Device ID", acc.optString("deviceId").ifEmpty { "—" })
                            DetailRow("IPv4", acc.optString("addressV4").ifEmpty { "—" })
                            DetailRow("IPv6", acc.optString("addressV6").ifEmpty { "—" })
                            DetailRow("License", acc.optString("license").ifEmpty { "—" })
                            DetailRow(
                                label = "Peer endpoint",
                                value = acc.optString("peerEndpoint").ifEmpty { "from scan results" },
                            )
                            DetailRow("Created", acc.optString("createdAt").ifEmpty { "—" })
                            if (bestEndpoint.isNotBlank()) {
                                DetailRow("Export target", bestEndpoint)
                            }
                        }
                    }
                }

                item(key = "export") {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(
                            text = "Export tunnel config",
                            style = MaterialTheme.typography.titleMedium,
                        )
                        FilledTonalButton(
                            onClick = { export("wireguard", "WireGuard config") },
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(52.dp),
                            shape = CircleShape,
                        ) { Text("WireGuard .conf") }
                        OutlinedButton(
                            onClick = { export("amnezia", "AmneziaWG config") },
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(52.dp),
                            shape = CircleShape,
                        ) { Text("AmneziaWG config") }
                        Text(
                            text = if (bestEndpoint.isBlank())
                                "Run a scan first to pick the endpoint used in the config."
                            else "Config targets your best endpoint: $bestEndpoint",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }

                error?.let { message ->
                    item(key = "error") { ErrorCard(message) }
                }

                if (busy && regStep != null) {
                    item(key = "progress") {
                        Text(
                            text = regStep!!,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }

                item(key = "manage") {
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(
                            onClick = { confirmReplace = true },
                            enabled = !busy,
                            modifier = Modifier.weight(1f),
                            shape = CircleShape,
                        ) {
                            Icon(Icons.Filled.Refresh, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(6.dp))
                            Text("Replace")
                        }
                        OutlinedButton(
                            onClick = { confirmDelete = true },
                            enabled = !busy,
                            modifier = Modifier.weight(1f),
                            shape = CircleShape,
                        ) {
                            Icon(Icons.Filled.Delete, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(6.dp))
                            Text("Delete")
                        }
                    }
                }
            }
        }
    }

    preview?.let { config ->
        AlertDialog(
            onDismissRequest = { preview = null },
            title = { Text(config.title) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.End,
                    ) {
                        TextButton(onClick = {
                            shareText(context, "Share config", config.body)?.let(toast)
                        }) {
                            Icon(
                                Icons.Filled.Share,
                                contentDescription = null,
                                modifier = Modifier.size(16.dp),
                            )
                            Spacer(Modifier.width(6.dp))
                            Text("Share")
                        }
                    }
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                    Text(
                        text = config.body,
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(max = 320.dp)
                            .verticalScroll(rememberScrollState()),
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    copyToClipboard(context, config.title, config.body)
                    toast("Config copied")
                }) { Text("Copy") }
            },
            dismissButton = {
                TextButton(onClick = { preview = null }) { Text("Close") }
            },
        )
    }

    if (confirmReplace) {
        AlertDialog(
            onDismissRequest = { confirmReplace = false },
            title = { Text("Replace account?" ) },
            text = {
                Text("A fresh device identity is registered and the current one is " +
                    "erased from this device. Exported configs from the old identity " +
                    "stop matching.")
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmReplace = false
                    register(replacing = true)
                }) { Text("Replace") }
            },
            dismissButton = {
                TextButton(onClick = { confirmReplace = false }) { Text("Cancel") }
            },
        )
    }

    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text("Delete account?") },
            text = {
                Text("The device identity and its private key are erased from this " +
                    "device. Previously exported configs are not revoked, but they " +
                    "cannot be regenerated here anymore.")
            },
            confirmButton = {
                TextButton(onClick = {
                    container.account.clear()
                    confirmDelete = false
                    toast("Account deleted")
                }) { Text("Delete") }
            },
            dismissButton = {
                TextButton(onClick = { confirmDelete = false }) { Text("Cancel") }
            },
        )
    }
}

@Composable
private fun ErrorCard(message: String) {
    Card(
        shape = MaterialTheme.shapes.medium,
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.errorContainer,
        ),
    ) {
        Text(
            text = message,
            modifier = Modifier.padding(16.dp),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onErrorContainer,
        )
    }
}

/**
 * Adds actionable guidance to a registration failure. A refused configured
 * proxy points at the proxy setting; refused/timeout errors otherwise look
 * like a network blocking the WARP API (the common carrier/DPI case), so
 * users know the account itself is not the problem. When the tunnel
 * fallback already ran and failed, the advice reflects that instead of
 * suggesting it.
 */
private fun withNetworkHint(message: String, proxy: String): String {
    val proxyHost = proxy.substringAfter("://", "").substringBeforeLast(":").trim('/')
    if (proxy.isNotBlank() && proxyHost.isNotEmpty() && message.contains(proxyHost)) {
        return message + "\n\nThe proxy at $proxyHost refused the " +
            "connection — check Settings → Registration, or start the " +
            "VPN/proxy app that provides it."
    }
    val looksBlocked = listOf(
        "connection refused",
        "timed out",
        "timeout",
        "no such host",
        "network is unreachable",
        "host is unreachable",
        "all addresses failed",
        "completed a handshake",
    ).any { message.contains(it, ignoreCase = true) }
    if (!looksBlocked) return message
    val tunnelTried = message.contains("via WARP tunnel") ||
        message.contains("completed a handshake", ignoreCase = true)
    return if (tunnelTried) {
        message + "\n\nThis network appears to block the WARP " +
            "registration API, and the built-in WARP tunnel fallback " +
            "failed here too. Try a proxy in Settings → Registration, " +
            "or register once on another network (Wi-Fi or hotspot) — " +
            "the account keeps working here afterwards."
    } else {
        message + "\n\nThis network appears to block the WARP " +
            "registration API. Set the Registration route to Auto or " +
            "Tunnel in Settings so the WARP tunnel fallback can run, " +
            "set a proxy there, or register once on another network " +
            "(Wi-Fi or hotspot) — the account keeps working here " +
            "afterwards."
    }
}

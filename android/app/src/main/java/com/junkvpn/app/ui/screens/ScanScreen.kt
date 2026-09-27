package com.junkvpn.app.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material.icons.outlined.VerifiedUser
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.junkvpn.app.Container
import com.junkvpn.app.core.EndpointUi
import com.junkvpn.app.ui.components.EndpointCard
import com.junkvpn.app.ui.components.ModeBadge
import com.junkvpn.app.ui.copyToClipboard

private data class PresetOption(val id: String, val label: String, val detail: String)

private val presetOptions = listOf(
    PresetOption("quick", "Quick", "64 targets · 1 probe · 1.0s"),
    PresetOption("standard", "Standard", "256 targets · 2 probes · 1.5s"),
    PresetOption("deep", "Deep", "1024 targets · 3 probes · 2.0s"),
    PresetOption("custom", "Custom", "your targets · 2 probes · 1.5s"),
)

/** Splits the free-form target field into individual host/IP entries. */
private fun parseTargets(raw: String): List<String> =
    raw.split(',', '\n', ' ', '\t')
        .map { it.trim() }
        .filter { it.isNotEmpty() }

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun ScanScreen(container: Container, toast: (String) -> Unit) {
    val state by container.scan.state.collectAsState()
    val verifyStates by container.scan.verify.collectAsState()
    val defaultPreset by container.settings.defaultPreset.collectAsState()
    var preset by rememberSaveable { mutableStateOf(defaultPreset) }
    var customTargets by rememberSaveable { mutableStateOf("") }
    val context = LocalContext.current

    val running = state.running
    val finished = !running && state.summary != null
    val display: List<EndpointUi> = if (running) state.live
    else state.results.filter { it.ok }
    val unreachable = if (finished) state.results.count { !it.ok } else 0

    /** Starts a scan honouring the Custom preset's target rules. */
    val startScan: () -> Unit = {
        if (!running) {
            val targets = if (preset == "custom") parseTargets(customTargets) else emptyList()
            if (preset == "custom" && targets.isEmpty()) {
                toast("Add at least one target, e.g. 162.159.192.1:2408")
            } else {
                container.scan.start(preset, targets)
            }
        }
    }

    Column(Modifier.fillMaxSize()) {
        TopAppBar(
            title = {
                Column {
                    Text("Endpoint scanner")
                    Text(
                        text = "WireGuard handshake, TCP fallback",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            },
            actions = {
                if (running) {
                    IconButton(onClick = { container.scan.cancel() }) {
                        Icon(Icons.Filled.Stop, contentDescription = "Stop scan")
                    }
                }
            },
        )

        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 4.dp, bottom = 28.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item(key = "presets") {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(
                        text = "Preset",
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        presetOptions.forEach { option ->
                            FilterChip(
                                selected = preset == option.id,
                                onClick = { preset = option.id },
                                label = { Text(option.label) },
                            )
                        }
                    }
                    Text(
                        text = when (preset) {
                            "custom" -> {
                                val n = parseTargets(customTargets).size
                                if (n == 0) "your targets · required"
                                else "$n target${if (n == 1) "" else "s"} · 2 probes · 1.5s"
                            }
                            else -> {
                                val base = presetOptions.firstOrNull { it.id == preset }?.detail.orEmpty()
                                if (customTargets.isNotBlank()) "$base · custom targets ignored" else base
                            }
                        },
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            // The targets box belongs to the Custom preset only; hidden
            // text is kept and reused when Custom is selected again.
            if (preset == "custom") {
                item(key = "targets") {
                    val targets = parseTargets(customTargets)
                    val customMissing = targets.isEmpty()
                    OutlinedTextField(
                        value = customTargets,
                        onValueChange = { customTargets = it },
                        modifier = Modifier.fillMaxWidth(),
                        shape = MaterialTheme.shapes.medium,
                        label = { Text("Custom targets") },
                        placeholder = { Text("162.159.192.1:2408, 1.1.1.1") },
                        isError = customMissing,
                        supportingText = {
                            Text(
                                text = if (customMissing) {
                                    "Add at least one target for the Custom preset"
                                } else {
                                    "${targets.size} target${if (targets.size == 1) "" else "s"}" +
                                        " · scanned instead of the WARP ranges"
                                },
                                color = if (customMissing) MaterialTheme.colorScheme.error
                                else MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        },
                        minLines = 1,
                        maxLines = 3,
                    )
                }
            }

            item(key = "action") {
                Button(
                    onClick = {
                        if (running) {
                            container.scan.cancel()
                        } else {
                            startScan()
                        }
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(58.dp),
                    shape = CircleShape,
                    colors = if (running) {
                        ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
                    } else {
                        ButtonDefaults.buttonColors()
                    },
                ) {
                    Icon(
                        imageVector = if (running) Icons.Filled.Stop else Icons.Filled.PlayArrow,
                        contentDescription = null,
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(
                        text = if (running) "Stop scan" else "Start scan",
                        style = MaterialTheme.typography.titleMedium,
                    )
                }
            }

            if (running) {
                item(key = "progress") {
                    Card(
                        shape = MaterialTheme.shapes.large,
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.surfaceVariant,
                        ),
                    ) {
                        Column(
                            modifier = Modifier.padding(16.dp),
                            verticalArrangement = Arrangement.spacedBy(10.dp),
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                            ) {
                                Text("Scanning…", style = MaterialTheme.typography.titleMedium)
                                Text(
                                    text = "${state.done}/${state.total}",
                                    style = MaterialTheme.typography.labelLarge,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                            LinearProgressIndicator(
                                progress = { state.progress },
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(10.dp)
                                    .clip(CircleShape),
                            )
                            if (state.current.isNotEmpty()) {
                                Text(
                                    text = state.current,
                                    style = MaterialTheme.typography.labelSmall,
                                    fontFamily = FontFamily.Monospace,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    maxLines = 1,
                                )
                            }
                        }
                    }
                }
            }

            state.error?.let { message ->
                item(key = "error") {
                    Card(
                        shape = MaterialTheme.shapes.medium,
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.errorContainer,
                        ),
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(
                                text = message,
                                modifier = Modifier.weight(1f),
                                color = MaterialTheme.colorScheme.onErrorContainer,
                                style = MaterialTheme.typography.bodyMedium,
                            )
                            TextButton(onClick = { startScan() }) {
                                Text("Retry")
                            }
                        }
                    }
                }
            }

            if (finished) {
                item(key = "summary") {
                    state.summary?.let { summary ->
                        ScanSummaryCard(
                            state = state,
                            context = context,
                            toast = toast,
                            verifyState = verifyStates[summary.best],
                            onVerify = { container.scan.verify(summary.best) },
                        )
                    }
                }
            }

            if (display.isEmpty()) {
                if (!running) {
                    item(key = "empty") {
                        Card(
                            shape = MaterialTheme.shapes.large,
                            colors = CardDefaults.cardColors(
                                containerColor = MaterialTheme.colorScheme.surfaceVariant,
                            ),
                        ) {
                            Column(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(24.dp),
                                horizontalAlignment = Alignment.CenterHorizontally,
                                verticalArrangement = Arrangement.spacedBy(8.dp),
                            ) {
                                Text(
                                    text = "No results yet",
                                    style = MaterialTheme.typography.titleLarge,
                                )
                                Text(
                                    text = "Run a scan to find which Cloudflare WARP " +
                                        "endpoints answer from your network. Handshake-" +
                                        "confirmed hosts rank first.",
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                    }
                }
            } else {
                item(key = "list-title") {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Text(
                            text = "Reachable endpoints",
                            style = MaterialTheme.typography.titleMedium,
                        )
                        if (unreachable > 0) {
                            Text(
                                text = "$unreachable unreachable",
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
                itemsIndexed(display, key = { _, item -> item.endpoint }) { index, item ->
                    EndpointCard(
                        rank = index + 1,
                        item = item,
                        highlighted = index == 0,
                        onCopy = {
                            copyToClipboard(context, "Endpoint", item.endpoint)
                            toast("Copied ${item.endpoint}")
                        },
                        verifyState = verifyStates[item.endpoint],
                        onVerify = { container.scan.verify(item.endpoint) },
                    )
                }
            }
        }
    }
}

@Composable
private fun ScanSummaryCard(
    state: com.junkvpn.app.data.ScanUiState,
    context: android.content.Context,
    toast: (String) -> Unit,
    verifyState: com.junkvpn.app.core.VerifyState?,
    onVerify: () -> Unit,
) {
    val summary = state.summary ?: return
    Card(
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text(
                text = if (summary.canceled) "Scan stopped" else "Scan complete",
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.7f),
            )
            if (summary.best.isEmpty()) {
                Text(
                    text = "No reachable endpoint found",
                    style = MaterialTheme.typography.titleLarge,
                    color = MaterialTheme.colorScheme.onPrimaryContainer,
                )
            } else {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(
                        text = summary.best,
                        style = MaterialTheme.typography.titleLarge,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                        modifier = Modifier.weight(1f, fill = false),
                    )
                    ModeBadge(mode = state.results.firstOrNull { it.endpoint == summary.best }?.mode ?: "tcp")
                }
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    TextButton(onClick = {
                        copyToClipboard(context, "Best endpoint", summary.best)
                        toast("Copied ${summary.best}")
                    }) {
                        Icon(Icons.Filled.ContentCopy, contentDescription = null)
                        Spacer(Modifier.width(6.dp))
                        Text("Copy")
                    }
                    val verifying = verifyState is com.junkvpn.app.core.VerifyState.Running
                    TextButton(onClick = onVerify, enabled = !verifying) {
                        Icon(Icons.Outlined.VerifiedUser, contentDescription = null)
                        Spacer(Modifier.width(6.dp))
                        Text(if (verifying) "Verifying…" else "Verify identity")
                    }
                }
                (verifyState as? com.junkvpn.app.core.VerifyState.Done)?.let { done ->
                    Text(
                        text = done.result.message(),
                        style = MaterialTheme.typography.labelMedium,
                        color = if (done.result.ok) MaterialTheme.colorScheme.tertiary
                        else MaterialTheme.colorScheme.error,
                    )
                }
            }
            Text(
                text = "${summary.reachable}/${summary.total} reachable · " +
                    "${summary.handshakes} handshakes · " +
                    "${summary.durationMs / 1000.0}s · ${summary.preset}",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.8f),
            )
            if (summary.handshakes == 0 && summary.best.isNotEmpty()) {
                Text(
                    text = "UDP is filtered on this network — latency comes from a TCP connect to port 443.",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.6f),
                )
            }
        }
    }
}

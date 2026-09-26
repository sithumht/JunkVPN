package com.junkvpn.app.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

/*
 * JunkVPN palette: electric violet for actions, mint for telemetry
 * (latencies, confirmed handshakes) and coral for warnings.
 */

private val LightColors = lightColorScheme(
    primary = Color(0xFF4B32C3),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFE7DEFF),
    onPrimaryContainer = Color(0xFF17122E),
    secondary = Color(0xFF00695B),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFA9F2DC),
    onSecondaryContainer = Color(0xFF00201A),
    tertiary = Color(0xFF9C4146),
    onTertiary = Color(0xFFFFFFFF),
    tertiaryContainer = Color(0xFFFFDAD9),
    onTertiaryContainer = Color(0xFF41000A),
    background = Color(0xFFF7F5FF),
    onBackground = Color(0xFF1B1B21),
    surface = Color(0xFFF7F5FF),
    onSurface = Color(0xFF1B1B21),
    surfaceVariant = Color(0xFFE5E1F2),
    onSurfaceVariant = Color(0xFF474656),
    outline = Color(0xFF78768A),
    outlineVariant = Color(0xFFC8C4DA),
    error = Color(0xFFBA1A1A),
    onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFFFDAD6),
    onErrorContainer = Color(0xFF410002),
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFFC9B8FF),
    onPrimary = Color(0xFF251A4A),
    primaryContainer = Color(0xFF3D2FA8),
    onPrimaryContainer = Color(0xFFE7DEFF),
    secondary = Color(0xFF8CD6BE),
    onSecondary = Color(0xFF00382D),
    secondaryContainer = Color(0xFF005143),
    onSecondaryContainer = Color(0xFFA9F2DC),
    tertiary = Color(0xFFFFB3AB),
    onTertiary = Color(0xFF690007),
    tertiaryContainer = Color(0xFF7E2A2E),
    onTertiaryContainer = Color(0xFFFFDAD9),
    background = Color(0xFF121218),
    onBackground = Color(0xFFE5E1EA),
    surface = Color(0xFF121218),
    onSurface = Color(0xFFE5E1EA),
    surfaceVariant = Color(0xFF464653),
    onSurfaceVariant = Color(0xFFC8C4D4),
    outline = Color(0xFF92909F),
    outlineVariant = Color(0xFF484653),
    error = Color(0xFFFFB4AB),
    onError = Color(0xFF690005),
    errorContainer = Color(0xFF93000A),
    onErrorContainer = Color(0xFFFFDAD6),
)

/** Generous, pill-heavy shapes — the "expressive" part of the design. */
private val AppShapes = Shapes(
    extraSmall = RoundedCornerShape(8.dp),
    small = RoundedCornerShape(14.dp),
    medium = RoundedCornerShape(20.dp),
    large = RoundedCornerShape(28.dp),
    extraLarge = RoundedCornerShape(36.dp),
)

private val AppTypography = Typography().let { base ->
    base.copy(
        displaySmall = base.displaySmall.copy(fontWeight = FontWeight.Bold),
        headlineMedium = base.headlineMedium.copy(fontWeight = FontWeight.Bold),
        headlineSmall = base.headlineSmall.copy(fontWeight = FontWeight.Bold),
        titleLarge = base.titleLarge.copy(fontWeight = FontWeight.SemiBold),
        titleMedium = base.titleMedium.copy(fontWeight = FontWeight.SemiBold),
        labelLarge = base.labelLarge.copy(fontWeight = FontWeight.Medium),
    )
}

@Composable
fun JunkVPNTheme(
    darkTheme: Boolean,
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = if (darkTheme) DarkColors else LightColors,
        typography = AppTypography,
        shapes = AppShapes,
        content = content,
    )
}

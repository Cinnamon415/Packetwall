package io.github.cinnamon415.packetwall.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily

// Graphite / Material 3 baseline blue, as in docs/concepts/prototype.html
private val Light = lightColorScheme(
    primary = Color(0xFF415F91), onPrimary = Color.White,
    primaryContainer = Color(0xFFD6E3FF), onPrimaryContainer = Color(0xFF001B3E),
    secondaryContainer = Color(0xFFDAE2F9), onSecondaryContainer = Color(0xFF131C2B),
    background = Color(0xFFF9F9FF), onBackground = Color(0xFF191C20),
    surface = Color(0xFFF9F9FF), onSurface = Color(0xFF191C20),
    surfaceVariant = Color(0xFFE2E3EC), onSurfaceVariant = Color(0xFF44474E),
    surfaceContainerLowest = Color.White, surfaceContainerLow = Color(0xFFF1F2F9),
    surfaceContainer = Color(0xFFEAEBF3), surfaceContainerHigh = Color(0xFFE2E3EC),
    surfaceContainerHighest = Color(0xFFD7D9E3),
    outline = Color(0xFF74777F), outlineVariant = Color(0xFFC4C6D0),
    error = Color(0xFFBA1A1A), onError = Color.White,
    errorContainer = Color(0xFFFFDAD6), onErrorContainer = Color(0xFF410002)
)

private val Dark = darkColorScheme(
    primary = Color(0xFFAAC7FF), onPrimary = Color(0xFF0A305F),
    primaryContainer = Color(0xFF284777), onPrimaryContainer = Color(0xFFD6E3FF),
    secondaryContainer = Color(0xFF3E4759), onSecondaryContainer = Color(0xFFDAE2F9),
    background = Color(0xFF111318), onBackground = Color(0xFFE2E2E9),
    surface = Color(0xFF111318), onSurface = Color(0xFFE2E2E9),
    surfaceVariant = Color(0xFF33363E), onSurfaceVariant = Color(0xFFC4C6D0),
    surfaceContainerLowest = Color(0xFF0C0E13), surfaceContainerLow = Color(0xFF191C21),
    surfaceContainer = Color(0xFF1F2228), surfaceContainerHigh = Color(0xFF282B32),
    surfaceContainerHighest = Color(0xFF33363E),
    outline = Color(0xFF8E9099), outlineVariant = Color(0xFF44474E),
    error = Color(0xFFFFB4AB), onError = Color(0xFF690005),
    errorContainer = Color(0xFF93000A), onErrorContainer = Color(0xFFFFDAD6)
)

/** Semantic colors that Material 3 has no slot for. */
@Immutable
data class ExtraColors(
    val ok: Color,
    val up: Color,
    val down: Color,
    /** Paused state: an amber container. */
    val warnContainer: Color,
    val onWarnContainer: Color,
    val warn: Color
)

private val LightExtra = ExtraColors(
    ok = Color(0xFF2E6B3A),
    up = Color(0xFF7A5300),
    down = Color(0xFF415F91),
    warnContainer = Color(0xFFFFDFA6),
    onWarnContainer = Color(0xFF261900),
    warn = Color(0xFF7A5300)
)
private val DarkExtra = ExtraColors(
    ok = Color(0xFF8BD89A),
    up = Color(0xFFF1C27D),
    down = Color(0xFFAAC7FF),
    warnContainer = Color(0xFF5C4000),
    onWarnContainer = Color(0xFFFFDFA6),
    warn = Color(0xFFF1C27D)
)

val LocalExtraColors = staticCompositionLocalOf { LightExtra }
val Mono = FontFamily.Monospace

@Composable
fun PacketwallTheme(dark: Boolean = isSystemInDarkTheme(), content: @Composable () -> Unit) {
    CompositionLocalProvider(LocalExtraColors provides if (dark) DarkExtra else LightExtra) {
        MaterialTheme(colorScheme = if (dark) Dark else Light, content = content)
    }
}

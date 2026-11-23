package io.github.cinnamon415.packetwall.ui

import android.content.Context
import android.util.LruCache
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.graphics.drawable.toBitmap
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.engine.AppInfo
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

private val iconCache = LruCache<String, ImageBitmap>(256)

private fun iconKey(pkg: String, px: Int) = "$pkg@$px"

private fun loadIcon(ctx: Context, pkg: String, px: Int): ImageBitmap? {
    iconCache.get(iconKey(pkg, px))?.let { return it }
    return try {
        val d = ctx.packageManager.getApplicationIcon(pkg)
        d.toBitmap(px, px).asImageBitmap().also { iconCache.put(iconKey(pkg, px), it) }
    } catch (e: Exception) {
        null
    }
}

/**
 * Round app icon (as in PCAPdroid); falls back to a letter avatar for system uids. The image is
 * tagged "icon:<package>" with the package it was loaded for (tests check rows show their own app).
 */
@Composable
fun AppIcon(app: AppInfo, size: Dp = 40.dp) {
    val ctx = LocalContext.current
    val px = with(LocalDensity.current) { size.roundToPx() }
    val pkg = app.packageName
    // keyed by the package: a row reused for another app (lists reorder as traffic comes in) must not
    // keep the previous app's icon
    var icon by remember(pkg, px) { mutableStateOf(iconCache.get(iconKey(pkg, px))) }
    if (icon == null) {
        LaunchedEffect(pkg, px) { icon = withContext(Dispatchers.IO) { loadIcon(ctx, pkg, px) } }
    }
    val bmp = icon
    if (bmp != null) {
        Image(bmp, contentDescription = null, modifier = Modifier.size(size).clip(CircleShape).testTag("icon:$pkg"))
    } else {
        Box(
            Modifier.size(size).clip(CircleShape).background(MaterialTheme.colorScheme.surfaceContainerHighest),
            contentAlignment = Alignment.Center
        ) {
            Text(
                app.name.take(1).uppercase(),
                fontWeight = FontWeight.Bold,
                fontSize = (size.value * 0.4f).sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

/** Unit names from the resources, so they follow the app's language. Loaded by [PacketwallApp]. */
object Units {
    var b = "B"
    var kb = "KB"
    var mb = "MB"
    var gb = "GB"
    var h = "h"
    var m = "min"
    var s = "s"

    fun load(ctx: Context) {
        b = ctx.getString(R.string.unit_b)
        kb = ctx.getString(R.string.unit_kb)
        mb = ctx.getString(R.string.unit_mb)
        gb = ctx.getString(R.string.unit_gb)
        h = ctx.getString(R.string.unit_h)
        m = ctx.getString(R.string.unit_min)
        s = ctx.getString(R.string.unit_s)
    }
}

fun formatBytes(b: Long): String = when {
    b >= 1L shl 30 -> String.format(Locale.getDefault(), "%.1f %s", b / 1073741824.0, Units.gb)
    b >= 1L shl 20 -> String.format(Locale.getDefault(), "%.1f %s", b / 1048576.0, Units.mb)
    b >= 1L shl 10 -> "${b / 1024} ${Units.kb}"
    else -> "$b ${Units.b}"
}

private val timeFmt = DateTimeFormatter.ofPattern("HH:mm:ss")

/** Local wall-clock time of [ms] (thread-safe). */
fun formatTime(ms: Long): String = timeFmt.format(Instant.ofEpochMilli(ms).atZone(ZoneId.systemDefault()))

private val dayTimeFmt = DateTimeFormatter.ofPattern("dd.MM HH:mm")

/** Time of day for today, date and time for earlier days (the log can keep up to 30 days). */
private val dayFmt = DateTimeFormatter.ofPattern("dd.MM.yyyy")

/** [today] for today's [ms], else its date. */
fun formatDay(ms: Long, today: String, now: Long = System.currentTimeMillis()): String {
    val zone = ZoneId.systemDefault()
    val t = Instant.ofEpochMilli(ms).atZone(zone)
    return if (t.toLocalDate() == Instant.ofEpochMilli(now).atZone(zone).toLocalDate()) today else dayFmt.format(t)
}

fun formatWhen(ms: Long, now: Long = System.currentTimeMillis()): String {
    val zone = ZoneId.systemDefault()
    val t = Instant.ofEpochMilli(ms).atZone(zone)
    return if (t.toLocalDate() == Instant.ofEpochMilli(now).atZone(zone).toLocalDate()) timeFmt.format(t) else dayTimeFmt.format(t)
}

fun formatDuration(ms: Long): String {
    val s = ms / 1000
    return when {
        s >= 3600 -> "${s / 3600} ${Units.h} ${s % 3600 / 60} ${Units.m}"
        s >= 60 -> "${s / 60} ${Units.m} ${s % 60} ${Units.s}"
        else -> "$s ${Units.s}"
    }
}

/** A small accent label above a group of fields in a dialog. */
@Composable
fun FieldLabel(text: String) {
    Text(text, style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
}

/** The single-line "Name" text field used by the set/profile/group dialogs. */
@Composable
fun NameField(value: String, onChange: (String) -> Unit) {
    OutlinedTextField(value, onChange, Modifier.fillMaxWidth(), singleLine = true, label = { Text(stringResource(R.string.name)) })
}

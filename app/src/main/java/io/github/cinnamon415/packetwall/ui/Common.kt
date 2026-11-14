package io.github.cinnamon415.packetwall.ui

import android.content.Context
import android.util.LruCache
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.graphics.drawable.toBitmap
import io.github.cinnamon415.packetwall.engine.AppInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private val iconCache = LruCache<String, ImageBitmap>(256)

private fun loadIcon(ctx: Context, pkg: String, px: Int): ImageBitmap? {
    iconCache.get(pkg)?.let { return it }
    return try {
        val d = ctx.packageManager.getApplicationIcon(pkg)
        d.toBitmap(px, px).asImageBitmap().also { iconCache.put(pkg, it) }
    } catch (e: Exception) {
        null
    }
}

/** Round app icon (as in PCAPdroid); falls back to a letter avatar for system uids. */
@Composable
fun AppIcon(app: AppInfo, size: Dp = 40.dp) {
    val ctx = LocalContext.current
    val px = with(androidx.compose.ui.platform.LocalDensity.current) { size.roundToPx() }
    val icon by produceState(iconCache.get(app.packageName), app.packageName) {
        if (value == null) value = withContext(Dispatchers.IO) { loadIcon(ctx, app.packageName, px) }
    }
    val bmp = icon
    if (bmp != null) {
        Image(bmp, contentDescription = null, modifier = Modifier.size(size).clip(CircleShape))
    } else {
        Box(Modifier.size(size).clip(CircleShape).background(MaterialTheme.colorScheme.surfaceContainerHighest),
            contentAlignment = Alignment.Center) {
            Text(app.name.take(1).uppercase(), fontWeight = FontWeight.Bold,
                fontSize = (size.value * 0.4f).sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

fun formatBytes(b: Long): String = when {
    b >= 1L shl 30 -> String.format(Locale.getDefault(), "%.1f ГБ", b / 1073741824.0)
    b >= 1L shl 20 -> String.format(Locale.getDefault(), "%.1f МБ", b / 1048576.0)
    b >= 1L shl 10 -> "${b / 1024} КБ"
    else -> "$b Б"
}

private val timeFmt = SimpleDateFormat("HH:mm:ss", Locale.getDefault())
fun formatTime(ms: Long): String = timeFmt.format(Date(ms))

fun formatDuration(ms: Long): String {
    val s = ms / 1000
    return if (s >= 3600) "${s / 3600} ч ${s % 3600 / 60} мин" else if (s >= 60) "${s / 60} мин ${s % 60} с" else "$s с"
}

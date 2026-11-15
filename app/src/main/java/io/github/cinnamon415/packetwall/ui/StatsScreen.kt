package io.github.cinnamon415.packetwall.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.background
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.github.cinnamon415.packetwall.PacketwallApp
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.ui.theme.LocalExtraColors
import io.github.cinnamon415.packetwall.engine.ConnectionsRegister
import kotlin.math.max

@Composable
fun StatsScreen(app: PacketwallApp, openDrawer: () -> Unit) {
    val conns by app.connections.conns.collectAsState()
    val stats by app.connections.stats.collectAsState()
    val history by app.connections.history.collectAsState()
    val up = LocalExtraColors.current.up
    val down = LocalExtraColors.current.down

    val byApp = remember(conns) {
        conns.groupBy { it.uid }.map { (_, l) -> Triple(l.first().app, l.sumOf { it.sentBytes }, l.sumOf { it.rcvdBytes }) }
            .sortedByDescending { it.second + it.third }.take(8)
    }
    val byHost = remember(conns) {
        conns.filter { !it.host.isNullOrEmpty() && it.l7proto != "DNS" }.groupBy { it.host!! }
            .map { (h, l) -> Triple(h, l.size, l.sumOf { it.bytes }) }.sortedByDescending { it.third }.take(8)
    }
    val byProto = remember(conns) { conns.groupingBy { it.protoLabel }.eachCount().entries.sortedByDescending { it.value }.take(8) }
    val trackersByApp = remember(conns) {
        conns.filter { app.trackers.trackingOf(it.host) != null }.groupBy { it.uid }
            .map { (_, l) -> Triple(l.first().app, l.size, l.mapNotNull { app.trackers.trackingOf(it.host)?.name }.distinct()) }
            .sortedByDescending { it.second }.take(8)
    }
    val blockedByApp = remember(conns) {
        conns.filter { it.blocked && it.fwRule != 0 }.groupBy { it.uid }.map { (_, l) -> l.first().app to l.size }
            .sortedByDescending { it.second }.take(8)
    }

    ScreenScaffold(title = stringResource(R.string.nav_stats), onMenu = openDrawer) {
        Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 12.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            RoundedGroup {
                Row(Modifier.padding(12.dp)) {
                    StatCell(Modifier.weight(1f), "↑ " + stringResource(R.string.sent), formatBytes(stats.bytesSent), up)
                    StatCell(Modifier.weight(1f), "↓ " + stringResource(R.string.received), formatBytes(stats.bytesRcvd), down)
                    StatCell(Modifier.weight(1f), stringResource(R.string.tile_requests), "${stats.totalConns}", MaterialTheme.colorScheme.onSurface)
                    StatCell(Modifier.weight(1f), "DNS", "${stats.dnsQueries}", MaterialTheme.colorScheme.onSurface)
                }
            }
            SectionHeader(stringResource(R.string.speed), null, null)
            RoundedGroup { SpeedChart(history, up, down) }

            if (byApp.isNotEmpty()) {
                SectionHeader(stringResource(R.string.top_apps), null, null)
                RoundedGroup {
                    val maxB = max(1L, byApp.maxOf { it.second + it.third })
                    byApp.forEachIndexed { i, (a, s, r) ->
                        if (i > 0) HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
                        Row(Modifier.fillMaxWidth().padding(horizontal = 10.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                            AppIcon(a, 28.dp)
                            Spacer(Modifier.width(10.dp))
                            Column(Modifier.weight(1f)) {
                                Row {
                                    Text(a.name, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
                                    Text("↑ ${formatBytes(s)}  ↓ ${formatBytes(r)}", style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                                }
                                Spacer(Modifier.height(5.dp))
                                SplitBar((s.toFloat() / maxB), (r.toFloat() / maxB), up, down)
                            }
                        }
                    }
                }
            }
            if (byHost.isNotEmpty()) {
                SectionHeader(stringResource(R.string.top_hosts), null, null)
                RoundedGroup {
                    byHost.forEachIndexed { i, (h, n, b) ->
                        if (i > 0) HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
                        Row(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp)) {
                            Text(h, fontFamily = FontFamily.Monospace, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f),
                                style = MaterialTheme.typography.bodyMedium)
                            Text("$n · ${formatBytes(b)}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                }
            }
            if (byProto.isNotEmpty()) {
                SectionHeader(stringResource(R.string.protocols), null, null)
                RoundedGroup {
                    byProto.forEachIndexed { i, (p, n) ->
                        if (i > 0) HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
                        Row(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp)) {
                            Text(p, modifier = Modifier.weight(1f))
                            Text("$n", color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                }
            }
            if (trackersByApp.isNotEmpty()) {
                SectionHeader(stringResource(R.string.trackers_by_app), null, null)
                RoundedGroup {
                    trackersByApp.forEachIndexed { i, (a, n, names) ->
                        if (i > 0) HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
                        Row(Modifier.fillMaxWidth().padding(horizontal = 10.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                            AppIcon(a, 28.dp)
                            Spacer(Modifier.width(10.dp))
                            Column(Modifier.weight(1f)) {
                                Text(a.name, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                Text(names.take(4).joinToString(", "), style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            }
                            Text("$n", color = MaterialTheme.colorScheme.tertiary)
                        }
                    }
                }
            }
            if (blockedByApp.isNotEmpty()) {
                SectionHeader(stringResource(R.string.blocked_by_app), null, null)
                RoundedGroup {
                    blockedByApp.forEachIndexed { i, (a, n) ->
                        if (i > 0) HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
                        Row(Modifier.fillMaxWidth().padding(horizontal = 10.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                            AppIcon(a, 28.dp)
                            Spacer(Modifier.width(10.dp))
                            Text(a.name, modifier = Modifier.weight(1f))
                            Text("$n", color = MaterialTheme.colorScheme.error)
                        }
                    }
                }
            }
            Spacer(Modifier.height(16.dp))
        }
    }
}

@Composable
private fun StatCell(modifier: Modifier, label: String, value: String, color: Color) {
    Column(modifier) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1)
        Text(value, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold, color = color, maxLines = 1)
    }
}

@Composable
private fun SplitBar(a: Float, b: Float, ca: Color, cb: Color) {
    val track = MaterialTheme.colorScheme.surfaceContainerHighest
    Canvas(Modifier.fillMaxWidth().height(4.dp)) {
        drawRect(track)
        drawRect(ca, Offset.Zero, Size(size.width * a, size.height))
        drawRect(cb, Offset(size.width * a, 0f), Size(size.width * b, size.height))
    }
}

/** Bytes/s over the last minutes, up and down. */
@Composable
private fun SpeedChart(h: List<ConnectionsRegister.Sample>, up: Color, down: Color) {
    val grid = MaterialTheme.colorScheme.outlineVariant
    val rates = remember(h) {
        h.zipWithNext { a, b ->
            val dt = max(1L, b.t - a.t) / 1000f
            Triple(b.t, max(0L, b.sent - a.sent) / dt, max(0L, b.rcvd - a.rcvd) / dt)
        }
    }
    val peak = rates.maxOfOrNull { max(it.second, it.third) } ?: 0f
    val cur = rates.lastOrNull()
    Column(Modifier.padding(12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Dot(up); Text(" ↑ ${formatBytes((cur?.second ?: 0f).toLong())}/s   ", style = MaterialTheme.typography.bodySmall)
            Dot(down); Text(" ↓ ${formatBytes((cur?.third ?: 0f).toLong())}/s", style = MaterialTheme.typography.bodySmall)
            Spacer(Modifier.weight(1f))
            Text("max ${formatBytes(peak.toLong())}/s", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Spacer(Modifier.height(8.dp))
        Canvas(Modifier.fillMaxWidth().height(120.dp)) {
            for (i in 0..3) { val y = size.height * i / 3; drawLine(grid, Offset(0f, y), Offset(size.width, y), 1f) }
            if (rates.size < 2 || peak <= 0f) return@Canvas
            val t0 = rates.first().first; val span = max(1L, rates.last().first - t0).toFloat()
            fun path(sel: (Triple<Long, Float, Float>) -> Float) = Path().apply {
                rates.forEachIndexed { i, r ->
                    val x = (r.first - t0) / span * size.width
                    val y = size.height - sel(r) / peak * size.height
                    if (i == 0) moveTo(x, y) else lineTo(x, y)
                }
            }
            drawPath(path { it.third }, down, style = Stroke(2.dp.toPx()))
            drawPath(path { it.second }, up, style = Stroke(2.dp.toPx()))
        }
    }
}

@Composable
private fun Dot(c: Color) {
    androidx.compose.foundation.layout.Box(Modifier.size(8.dp).clip(CircleShape).background(c))
}

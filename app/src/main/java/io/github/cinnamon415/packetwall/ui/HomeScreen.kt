package io.github.cinnamon415.packetwall.ui

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.github.cinnamon415.packetwall.PacketwallApp
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.engine.CaptureState
import io.github.cinnamon415.packetwall.ui.theme.LocalExtraColors
import kotlinx.coroutines.delay

@Composable
fun HomeScreen(
    app: PacketwallApp,
    state: CaptureState,
    onToggle: (Boolean) -> Unit,
    openDrawer: () -> Unit,
    onOpenLogs: () -> Unit,
    onOpenStats: () -> Unit,
    onOpenConn: (Int) -> Unit,
) {
    val conns by app.connections.conns.collectAsState()
    val stats by app.connections.stats.collectAsState()
    val on = state is CaptureState.Running
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(on) { while (on) { now = System.currentTimeMillis(); delay(1000) } }

    ScreenScaffold(
        title = "Packetwall",
        onMenu = openDrawer,
        actions = {
            IconButton(onClick = onOpenStats) { Icon(painterResource(R.drawable.ic_chart), stringResource(R.string.nav_stats)) }
            IconButton(onClick = onOpenLogs) { Icon(painterResource(R.drawable.ic_logs), stringResource(R.string.nav_logs)) }
        },
    ) {
        Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 12.dp, vertical = 4.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)) {

            // Status card
            Surface(shape = RoundedCornerShape(16.dp), color = MaterialTheme.colorScheme.surfaceContainerLow) {
                Row(Modifier.fillMaxWidth().padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                    val bg by animateColorAsState(if (on) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.surfaceContainerHigh, label = "pw")
                    val fg by animateColorAsState(if (on) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurfaceVariant, label = "pwf")
                    val radius by animateDpAsState(if (on) 20.dp else 30.dp, label = "pwr")
                    Box(Modifier.size(60.dp).clip(RoundedCornerShape(radius)).background(bg).clickable { onToggle(!on) },
                        contentAlignment = Alignment.Center) {
                        Icon(painterResource(R.drawable.ic_power), stringResource(if (on) R.string.turn_off else R.string.turn_on),
                            tint = fg, modifier = Modifier.size(28.dp))
                    }
                    Spacer(Modifier.width(14.dp))
                    Column(Modifier.weight(1f)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(Modifier.size(8.dp).clip(CircleShape).background(if (on) LocalExtraColors.current.ok else MaterialTheme.colorScheme.outline))
                            Spacer(Modifier.width(6.dp))
                            Text(stringResource(if (on) R.string.status_on else R.string.status_off),
                                style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                        }
                        if (state is CaptureState.Running)
                            Text(formatDuration(now - state.since), style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant)
                        val strictDns by io.github.cinnamon415.packetwall.engine.CaptureService.privateDnsStrict.collectAsState()
                        if (on && strictDns)
                            Text(stringResource(R.string.private_dns_strict), style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.error)
                        val fwState by app.firewall.state.collectAsState()
                        Text(listOfNotNull("VPN", fwState.profile?.name).joinToString(" · "), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }

            // Tiles 2x2
            // only decisions of the rules (not the internal Private DNS drops)
            val blocked = conns.count { it.blocked && it.fwRule != 0 }
            val alpha = if (on) 1f else 0.5f
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Tile(Modifier.weight(1f), R.drawable.ic_logs, stringResource(R.string.tile_requests), "${stats.totalConns}", alpha, onClick = onOpenLogs)
                Tile(Modifier.weight(1f), R.drawable.ic_block, stringResource(R.string.tile_blocked), "$blocked", alpha,
                    color = MaterialTheme.colorScheme.error, onClick = onOpenLogs)
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Tile(Modifier.weight(1f), R.drawable.ic_import, stringResource(R.string.tile_received), formatBytes(stats.bytesRcvd), alpha, onClick = onOpenStats)
                Tile(Modifier.weight(1f), R.drawable.ic_wall, stringResource(R.string.tile_active), "${stats.activeConns}", alpha, onClick = onOpenLogs)
            }

            // Recent blocks (max 5)
            SectionHeader(stringResource(R.string.recent_blocks), stringResource(R.string.all), onOpenLogs)
            val recent = conns.filter { it.blocked && it.fwRule != 0 }.take(5)
            Surface(shape = RoundedCornerShape(16.dp), color = MaterialTheme.colorScheme.surfaceContainerLow) {
                if (recent.isEmpty()) {
                    Text(stringResource(R.string.no_blocks), color = MaterialTheme.colorScheme.onSurfaceVariant,
                        style = MaterialTheme.typography.bodyMedium, modifier = Modifier.fillMaxWidth().padding(16.dp))
                } else Column {
                    recent.forEachIndexed { i, c ->
                        if (i > 0) HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
                        Row(Modifier.fillMaxWidth().clickable { onOpenConn(c.id) }.padding(horizontal = 10.dp, vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically) {
                            AppIcon(c.app, 28.dp)
                            Spacer(Modifier.width(10.dp))
                            Column(Modifier.weight(1f)) {
                                Text(c.title, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyMedium,
                                    maxLines = 1, overflow = TextOverflow.Ellipsis)
                                Text("${c.app.name} · ${formatTime(c.firstSeen)}", style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                        }
                    }
                }
            }

            // Top apps by traffic
            val top = conns.groupBy { it.uid }.map { (_, l) -> l.first().app to l.sumOf { it.bytes } }
                .sortedByDescending { it.second }.take(5)
            if (top.isNotEmpty()) {
                SectionHeader(stringResource(R.string.nav_stats), null, null)
                val max = top.first().second.coerceAtLeast(1)
                Surface(shape = RoundedCornerShape(16.dp), color = MaterialTheme.colorScheme.surfaceContainerLow) {
                    Column {
                        top.forEachIndexed { i, (a, b) ->
                            if (i > 0) HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
                            Row(Modifier.fillMaxWidth().padding(horizontal = 10.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                                AppIcon(a, 28.dp)
                                Spacer(Modifier.width(10.dp))
                                Column(Modifier.weight(1f)) {
                                    Row {
                                        Text(a.name, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold,
                                            modifier = Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis)
                                        Text(formatBytes(b), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                    }
                                    Spacer(Modifier.height(5.dp))
                                    LinearProgressIndicator(progress = { b.toFloat() / max }, modifier = Modifier.fillMaxWidth().height(4.dp),
                                        drawStopIndicator = {}, gapSize = 0.dp)
                                }
                            }
                        }
                    }
                }
            }
            Spacer(Modifier.height(16.dp))
        }
    }
}

@Composable
private fun Tile(modifier: Modifier, icon: Int, label: String, value: String, alpha: Float, color: Color? = null, onClick: () -> Unit) {
    Surface(modifier = modifier, shape = RoundedCornerShape(16.dp), color = MaterialTheme.colorScheme.surfaceContainerLow, onClick = onClick) {
        Column(Modifier.padding(horizontal = 12.dp, vertical = 10.dp)) {
            Icon(painterResource(icon), null, tint = (color ?: MaterialTheme.colorScheme.primary).copy(alpha = alpha), modifier = Modifier.size(18.dp))
            Spacer(Modifier.height(4.dp))
            Text(label.uppercase(), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = alpha))
            Text(value, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold,
                color = (color ?: MaterialTheme.colorScheme.onSurface).copy(alpha = alpha))
        }
    }
}

@Composable
fun SectionHeader(title: String, action: String?, onAction: (() -> Unit)?) {
    Row(Modifier.fillMaxWidth().padding(start = 4.dp, top = 4.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.weight(1f))
        if (action != null && onAction != null) TextButton(onClick = onAction) { Text(action) }
    }
}

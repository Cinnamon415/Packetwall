package io.github.cinnamon415.packetwall.ui

import android.widget.Toast
import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.cinnamon415.packetwall.PacketwallApp
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.engine.CaptureService
import io.github.cinnamon415.packetwall.engine.CaptureState
import io.github.cinnamon415.packetwall.engine.CaptureStatus
import io.github.cinnamon415.packetwall.engine.Conn
import io.github.cinnamon415.packetwall.ui.theme.LocalExtraColors
import java.net.URI
import kotlinx.coroutines.delay

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun HomeScreen(
    app: PacketwallApp,
    state: CaptureState,
    onToggle: (Boolean) -> Unit,
    openDrawer: () -> Unit,
    onOpenLogs: (LogsLink.Request) -> Unit,
    onOpenStats: () -> Unit,
    onOpenConn: (Int) -> Unit,
    onOpenSets: () -> Unit = {}
) {
    val summary by appViewModel(app) { a, _ -> DashboardViewModel(a) }.summary.collectAsStateWithLifecycle()
    val stats by app.connections.stats.collectAsState()
    val fw by app.firewall.state.collectAsState()
    var quick by remember { mutableStateOf<Conn?>(null) }
    val ctx = LocalContext.current
    quick?.let { c ->
        QuickRuleSheet(c, app, fw, onDismiss = { quick = null }) { msg ->
            quick = null
            Toast.makeText(ctx, msg, Toast.LENGTH_SHORT).show()
        }
    }
    val on = state is CaptureState.Running
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(on) {
        while (on) {
            now = System.currentTimeMillis()
            delay(1000)
        }
    }

    ScreenScaffold(
        title = "Packetwall",
        onMenu = openDrawer,
        actions = {
            IconButton(onClick = onOpenStats) { Icon(painterResource(R.drawable.ic_chart), stringResource(R.string.nav_stats)) }
            IconButton(onClick = { onOpenLogs(LogsLink.Request(StatusFilter.ALL, "")) }) {
                Icon(painterResource(R.drawable.ic_logs), stringResource(R.string.nav_logs))
            }
        }
    ) {
        Column(
            Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 12.dp, vertical = 4.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            StatusBanner(app, state, now, onToggle, onOpenSets)

            // Tiles 2x2
            val blocked = summary.blockedCount
            val alpha = if (on) 1f else 0.5f
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Tile(
                    Modifier.weight(1f),
                    R.drawable.ic_logs,
                    stringResource(R.string.tile_requests),
                    "${summary.total}",
                    alpha,
                    onClick = { onOpenLogs(LogsLink.Request(StatusFilter.ALL, "")) }
                )
                Tile(
                    Modifier.weight(1f),
                    R.drawable.ic_block,
                    stringResource(R.string.tile_blocked),
                    "$blocked",
                    alpha,
                    color = MaterialTheme.colorScheme.error,
                    onClick = { onOpenLogs(LogsLink.Request(StatusFilter.BLOCKED, "")) }
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Tile(
                    Modifier.weight(1f),
                    R.drawable.ic_import,
                    stringResource(R.string.tile_received),
                    formatBytes(stats.bytesRcvd),
                    alpha,
                    onClick = onOpenStats
                )
                Tile(
                    Modifier.weight(1f),
                    R.drawable.ic_wall,
                    stringResource(R.string.tile_active),
                    "${summary.active}",
                    alpha,
                    onClick = { onOpenLogs(LogsLink.Request(StatusFilter.ALL, "active")) }
                )
            }

            // Speed ↑↓ (spec: home shows the speed graph)
            if (on) {
                val history by app.connections.history.collectAsState()
                Surface(shape = RoundedCornerShape(16.dp), color = MaterialTheme.colorScheme.surfaceContainerLow) {
                    SpeedChart(history, LocalExtraColors.current.up, LocalExtraColors.current.down, height = 64.dp)
                }
            }

            // Recent blocks (max 5)
            SectionHeader(stringResource(R.string.recent_blocks), stringResource(R.string.all)) {
                onOpenLogs(LogsLink.Request(StatusFilter.BLOCKED, ""))
            }
            val recent = summary.recentBlocked.take(5)
            Surface(shape = RoundedCornerShape(16.dp), color = MaterialTheme.colorScheme.surfaceContainerLow) {
                if (recent.isEmpty()) {
                    Text(
                        stringResource(R.string.no_blocks),
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.fillMaxWidth().padding(16.dp)
                    )
                } else {
                    Column {
                        recent.forEachIndexed { i, c ->
                            if (i > 0) HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
                            Row(
                                Modifier.fillMaxWidth().combinedClickable(onLongClick = { quick = c }) {
                                    LogsLink.ids = recent.map { it.id }
                                    onOpenConn(c.id)
                                }.padding(start = 10.dp, top = 2.dp, bottom = 2.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                AppIcon(c.app, 28.dp)
                                Spacer(Modifier.width(10.dp))
                                Column(Modifier.weight(1f)) {
                                    Text(
                                        c.title,
                                        fontFamily = FontFamily.Monospace,
                                        style = MaterialTheme.typography.bodyMedium,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                    Text(
                                        "${c.app.name} · ${formatWhen(c.firstSeen)}",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                                // quick allow (spec: recent blocks with a quick allow)
                                TextButton({ quick = c }) { Text(stringResource(R.string.action_allow)) }
                            }
                        }
                    }
                }
            }

            // Top apps by traffic
            val top = summary.byApp.take(5).map { it.app to it.total }
            if (top.isNotEmpty()) {
                SectionHeader(stringResource(R.string.nav_stats), null, null)
                val max = top.first().second.coerceAtLeast(1)
                Surface(shape = RoundedCornerShape(16.dp), color = MaterialTheme.colorScheme.surfaceContainerLow) {
                    Column {
                        top.forEachIndexed { i, (a, b) ->
                            if (i > 0) HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
                            Row(
                                Modifier.fillMaxWidth().padding(horizontal = 10.dp, vertical = 8.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                AppIcon(a, 28.dp)
                                Spacer(Modifier.width(10.dp))
                                Column(Modifier.weight(1f)) {
                                    Row {
                                        Text(
                                            a.name,
                                            style = MaterialTheme.typography.bodyMedium,
                                            fontWeight = FontWeight.SemiBold,
                                            modifier = Modifier.weight(1f),
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                        Text(
                                            formatBytes(b),
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    }
                                    Spacer(Modifier.height(5.dp))
                                    LinearProgressIndicator(
                                        progress = {
                                            b.toFloat() / max
                                        },
                                        modifier = Modifier.fillMaxWidth().height(4.dp),
                                        drawStopIndicator = {},
                                        gapSize = 0.dp
                                    )
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
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(16.dp),
        color = MaterialTheme.colorScheme.surfaceContainerLow,
        onClick = onClick
    ) {
        Column(Modifier.padding(horizontal = 12.dp, vertical = 10.dp)) {
            Icon(
                painterResource(icon),
                null,
                tint = (color ?: MaterialTheme.colorScheme.primary).copy(alpha = alpha),
                modifier = Modifier.size(18.dp)
            )
            Spacer(Modifier.height(4.dp))
            Text(
                label.uppercase(),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = alpha)
            )
            Text(
                value,
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                color = (color ?: MaterialTheme.colorScheme.onSurface).copy(alpha = alpha)
            )
        }
    }
}

@Composable
fun SectionHeader(title: String, action: String?, onAction: (() -> Unit)?) {
    Row(Modifier.fillMaxWidth().padding(start = 4.dp, top = 4.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(
            title,
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(1f)
        )
        if (action != null && onAction != null) TextButton(onClick = onAction) { Text(action) }
    }
}

/**
 * Protection state with a three-way switch: running, paused (rules keep filtering, nothing is
 * recorded) and off.
 */
@Composable
private fun StatusBanner(app: PacketwallApp, state: CaptureState, now: Long, onToggle: (Boolean) -> Unit, onOpenSets: () -> Unit) {
    val ctx = LocalContext.current
    val on = state is CaptureState.Running
    val pausedSince by CaptureStatus.pausedSince.collectAsState()
    val paused = on && pausedSince != null
    val extra = LocalExtraColors.current
    val bg by animateColorAsState(
        when {
            paused -> extra.warnContainer
            on -> MaterialTheme.colorScheme.primaryContainer
            else -> MaterialTheme.colorScheme.surfaceContainerLow
        },
        label = "banner"
    )
    val fg = when {
        paused -> extra.onWarnContainer
        on -> MaterialTheme.colorScheme.onPrimaryContainer
        else -> MaterialTheme.colorScheme.onSurface
    }
    Surface(shape = RoundedCornerShape(16.dp), color = bg, contentColor = fg) {
        Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    painterResource(if (paused) R.drawable.ic_pause else R.drawable.ic_wall),
                    null,
                    modifier = Modifier.size(28.dp),
                    tint = if (on) fg else MaterialTheme.colorScheme.outline
                )
                Spacer(Modifier.width(12.dp))
                // tapping the status (with the profile in it) switches profiles
                var profiles by remember { mutableStateOf(false) }
                ProfileMenu(app, profiles, { profiles = false }, onOpenSets)
                Column(Modifier.weight(1f).clip(RoundedCornerShape(8.dp)).clickable { profiles = true }) {
                    Text(
                        stringResource(
                            when {
                                paused -> R.string.status_paused
                                on -> R.string.status_on
                                else -> R.string.status_off
                            }
                        ),
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    val fwState by app.firewall.state.collectAsState()
                    val doh by CaptureStatus.dohActive.collectAsState()
                    val line = when {
                        paused -> listOf(stringResource(R.string.paused_hint), formatDuration(now - pausedSince!!))
                        on -> listOfNotNull(
                            formatDuration(now - (state as CaptureState.Running).since),
                            "VPN",
                            fwState.profile?.name,
                            doh?.let { "DoH " + (URI(it).host ?: "") }
                        )
                        else -> listOfNotNull("VPN", fwState.profile?.name)
                    }
                    Text(line.joinToString(" · "), style = MaterialTheme.typography.bodySmall)
                    val strictDns by CaptureStatus.privateDnsStrict.collectAsState()
                    if (on && strictDns) {
                        Text(
                            stringResource(R.string.private_dns_strict),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error
                        )
                    }
                }
            }
            val modes = listOf(R.string.mode_running, R.string.mode_paused, R.string.mode_off)
            val current = when {
                paused -> 1
                on -> 0
                else -> 2
            }
            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                modes.forEachIndexed { i, label ->
                    SegmentedButton(
                        selected = current == i,
                        onClick = {
                            when (i) {
                                0 -> if (!on) onToggle(true) else CaptureService.setPaused(ctx, false)
                                1 -> if (on) CaptureService.setPaused(ctx, true)
                                else -> if (on) onToggle(false)
                            }
                        },
                        enabled = i != 1 || on,
                        shape = SegmentedButtonDefaults.itemShape(i, modes.size),
                        colors = if (paused && i == 1) {
                            SegmentedButtonDefaults.colors(
                                activeContainerColor = extra.warn,
                                activeContentColor = MaterialTheme.colorScheme.surface
                            )
                        } else {
                            SegmentedButtonDefaults.colors()
                        },
                        icon = {}
                    ) { Text(stringResource(label), maxLines = 1) }
                }
            }
        }
    }
}

package io.github.cinnamon415.packetwall.ui

import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import io.github.cinnamon415.packetwall.PacketwallApp
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.analysis.Trackers
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConnectionScreen(
    app: PacketwallApp,
    source: CaptureSource,
    id: Int,
    initialTab: Int,
    onNeighbor: (Int, Int) -> Unit,
    onBack: () -> Unit,
    onOpenApp: (String) -> Unit,
    onOpenPacket: (Long) -> Unit
) {
    val conns by source.conns.collectAsState()
    val idx = conns.indexOfFirst { it.id == id }
    val c = conns.getOrNull(idx)
    var tab by rememberSaveable { mutableIntStateOf(initialTab) }
    val fw by app.firewall.state.collectAsState()
    var quick by remember { mutableStateOf(false) }
    val ctx = LocalContext.current
    ScreenScaffold(
        title = c?.title ?: "#$id",
        subtitle = c?.let { "#${it.id} · ${it.app.name} · ${it.protoLabel}" },
        monoTitle = true,
        onBack = onBack,
        actions = {
            // neighbours in the log order (newest first): ‹ newer, › older
            IconButton(onClick = { conns.getOrNull(idx - 1)?.let { onNeighbor(it.id, tab) } }, enabled = idx > 0) {
                Text("‹", style = MaterialTheme.typography.headlineSmall)
            }
            IconButton(
                onClick = { conns.getOrNull(idx + 1)?.let { onNeighbor(it.id, tab) } },
                enabled = idx >= 0 && idx < conns.lastIndex
            ) {
                Text("›", style = MaterialTheme.typography.headlineSmall)
            }
            if (c != null) {
                val export = rememberFileExport("application/octet-stream")
                IconButton(onClick = {
                    export.launch("conn-${c.id}-${c.title.take(40)}.pcapng") { out ->
                        source.packets.writePcapng(out, source.packets.packetsOf(c))
                    }
                }) {
                    Icon(painterResource(R.drawable.ic_save), stringResource(R.string.export_pcapng))
                }
            }
        }
    ) {
        val tabs = listOf(R.string.conn_overview, R.string.conn_packets, R.string.conn_data, R.string.tab_http)
        PrimaryTabRow(selectedTabIndex = tab) {
            tabs.forEachIndexed { i, s -> Tab(tab == i, { tab = i }, text = { Text(stringResource(s)) }) }
        }
        if (c == null) {
            Box(Modifier.fillMaxSize().padding(24.dp), contentAlignment = Alignment.Center) {
                Text(stringResource(R.string.conn_gone), color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            return@ScreenScaffold
        }
        when (tab) {
            1 -> {
                PacketsTab(source, c, onOpenPacket)
                return@ScreenScaffold
            }
            2 -> {
                DataTab(source, c)
                return@ScreenScaffold
            }
            3 -> {
                HttpTab(source, c)
                return@ScreenScaffold
            }
        }
        val decision = decisionText(c.fwRule, c.blocked, fw, app, c)
        val rows = listOfNotNull(
            decision?.let { R.string.kv_rule to it },
            R.string.kv_protocol to "${c.protoLabel} · ${c.l4} · IPv${c.ipver}",
            R.string.kv_status to stringResource(
                when {
                    c.blocked -> R.string.st_blocked
                    c.active -> R.string.st_active
                    else -> R.string.st_closed
                }
            ),
            R.string.kv_app to "${c.app.name} (uid ${c.uid})",
            R.string.kv_package to c.app.packageName,
            R.string.kv_source to "${c.srcIp}:${c.srcPort}",
            R.string.kv_destination to "${c.dstIp}:${c.dstPort}" + if (c.country.isNotEmpty()) " · ${c.country}" else "",
            R.string.kv_host to (c.host ?: "—"),
            app.trackers.of(c.host)?.let { t -> R.string.kv_tracker to "${t.name} · ${stringResource(categoryLabel(t.category))}" },
            R.string.kv_asn to (remember(c.dstIp) { app.geo.asn(c.dstIp) }?.let { (n, org) -> "AS$n $org" } ?: "—"),
            // the route only matters when an upstream proxy is configured
            if (app.settings.current.upstream || c.proxied) {
                R.string.kv_route to stringResource(if (c.proxied) R.string.route_upstream else R.string.route_direct)
            } else {
                null
            },
            R.string.kv_traffic to "↑ ${formatBytes(c.sentBytes)} · ↓ ${formatBytes(c.rcvdBytes)}",
            R.string.kv_packets to "${c.sentPkts} ↑ · ${c.rcvdPkts} ↓",
            R.string.kv_first_seen to formatTime(c.firstSeen),
            R.string.kv_last_seen to formatTime(c.lastSeen)
        )
        Column(Modifier.verticalScroll(rememberScrollState())) {
            Row(Modifier.padding(horizontal = 12.dp, vertical = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = { quick = true }) { Text(stringResource(R.string.rule_add)) }
                OutlinedButton(onClick = { onOpenApp(c.app.packageName) }) { Text(stringResource(R.string.app_rules)) }
            }
            rows.forEach { (k, v) ->
                Row(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp)) {
                    Text(stringResource(k), color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.width(130.dp))
                    val mono = k == R.string.kv_host || k == R.string.kv_destination || k == R.string.kv_source
                    Text(v, fontFamily = if (mono) FontFamily.Monospace else null)
                }
                HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
            }
        }
        if (quick) {
            QuickRuleSheet(c, app, fw, onDismiss = { quick = false }) { msg ->
                quick = false
                Toast.makeText(ctx, msg, Toast.LENGTH_SHORT).show()
            }
        }
    }
}

fun categoryLabel(c: Trackers.Category) = when (c) {
    Trackers.Category.ADVERTISING -> R.string.cat_ads
    Trackers.Category.ANALYTICS -> R.string.cat_analytics
    Trackers.Category.TELEMETRY -> R.string.cat_telemetry
    Trackers.Category.SOCIAL -> R.string.cat_social
    Trackers.Category.OTHER -> R.string.cat_other
}

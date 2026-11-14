package io.github.cinnamon415.packetwall.ui

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import io.github.cinnamon415.packetwall.PacketwallApp
import io.github.cinnamon415.packetwall.R

@Composable
fun ConnectionScreen(app: PacketwallApp, id: Int, onBack: () -> Unit) {
    val conns by app.connections.conns.collectAsState()
    val c = conns.firstOrNull { it.id == id }
    var tab by rememberSaveable { mutableIntStateOf(0) }
    ScreenScaffold(title = c?.title ?: "#$id", subtitle = c?.let { "#${it.id} · ${it.app.name} · ${it.protoLabel}" },
        monoTitle = true, onBack = onBack) {
        val tabs = listOf(R.string.conn_overview, R.string.conn_packets, R.string.conn_data, R.string.tab_http)
        PrimaryTabRow(selectedTabIndex = tab) {
            tabs.forEachIndexed { i, s -> Tab(tab == i, { tab = i }, text = { Text(stringResource(s)) }) }
        }
        if (c == null || tab != 0) {
            Box(Modifier.fillMaxSize().padding(24.dp), contentAlignment = Alignment.Center) {
                Text(stringResource(R.string.coming_in, "M2"), color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            return@ScreenScaffold
        }
        val rows = listOf(
            R.string.kv_protocol to "${c.protoLabel} · ${c.l4} · IPv${c.ipver}",
            R.string.kv_status to stringResource(when { c.blocked -> R.string.st_blocked; c.active -> R.string.st_active; else -> R.string.st_closed }),
            R.string.kv_app to "${c.app.name} (uid ${c.uid})",
            R.string.kv_package to c.app.packageName,
            R.string.kv_source to "${c.srcIp}:${c.srcPort}",
            R.string.kv_destination to "${c.dstIp}:${c.dstPort}",
            R.string.kv_host to (c.host ?: "—"),
            R.string.kv_traffic to "↑ ${formatBytes(c.sentBytes)} · ↓ ${formatBytes(c.rcvdBytes)}",
            R.string.kv_packets to "${c.sentPkts} ↑ · ${c.rcvdPkts} ↓",
            R.string.kv_first_seen to formatTime(c.firstSeen),
            R.string.kv_last_seen to formatTime(c.lastSeen),
        )
        Column(Modifier.verticalScroll(rememberScrollState())) {
            rows.forEach { (k, v) ->
                Row(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp)) {
                    Text(stringResource(k), color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.width(130.dp))
                    Text(v, fontFamily = if (k == R.string.kv_host || k == R.string.kv_destination || k == R.string.kv_source) FontFamily.Monospace else null)
                }
                HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
            }
        }
    }
}

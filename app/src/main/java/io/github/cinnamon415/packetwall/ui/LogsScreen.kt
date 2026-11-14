package io.github.cinnamon415.packetwall.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.github.cinnamon415.packetwall.PacketwallApp
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.engine.CaptureState
import io.github.cinnamon415.packetwall.engine.Conn
import io.github.cinnamon415.packetwall.ui.theme.LocalExtraColors

@Composable
fun LogsScreen(app: PacketwallApp, state: CaptureState, openDrawer: () -> Unit, onOpenConn: (Int) -> Unit) {
    val conns by app.connections.conns.collectAsState()
    var filter by rememberSaveable { mutableStateOf("") }
    var status by rememberSaveable { mutableStateOf(0) } // 0 all, 1 blocked, 2 allowed
    var compact by rememberSaveable { mutableStateOf(false) }
    val q = filter.trim().lowercase()
    val list = conns.filter { c ->
        (status == 0 || (status == 1) == c.blocked) &&
            (q.isEmpty() || c.app.name.lowercase().contains(q) || c.title.lowercase().contains(q) || c.dstIp.contains(q))
    }
    ScreenScaffold(title = stringResource(R.string.nav_logs), subtitle = "${conns.size}", onMenu = openDrawer) {
        Column(Modifier.padding(horizontal = 12.dp)) {
            OutlinedTextField(filter, { filter = it }, Modifier.fillMaxWidth(), singleLine = true,
                leadingIcon = { Icon(painterResource(R.drawable.ic_filter), null) },
                placeholder = { Text(stringResource(R.string.logs_filter_hint), fontFamily = FontFamily.Monospace) })
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                listOf(R.string.chip_all, R.string.chip_blocked, R.string.chip_allowed).forEachIndexed { i, s ->
                    FilterChip(status == i, { status = i }, { Text(stringResource(s)) })
                }
                FilterChip(compact, { compact = !compact }, { Icon(painterResource(R.drawable.ic_density), null) })
            }
        }
        HorizontalDivider()
        if (list.isEmpty()) {
            Box(Modifier.fillMaxSize().padding(24.dp), contentAlignment = Alignment.Center) {
                Text(stringResource(if (state is CaptureState.Running) R.string.empty_logs else R.string.empty_logs_off),
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        } else LazyColumn {
            items(list, key = { it.id }) { c ->
                ConnRow(c, compact) { onOpenConn(c.id) }
                HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
            }
        }
    }
}

@Composable
private fun ConnRow(c: Conn, compact: Boolean, onClick: () -> Unit) {
    val muted = MaterialTheme.colorScheme.onSurfaceVariant
    val time = formatTime(c.firstSeen)
    val proto = "${c.protoLabel}, ${c.dstPort}"
    Row(Modifier.fillMaxWidth().clickable(onClick = onClick).padding(horizontal = 10.dp, vertical = if (compact) 5.dp else 7.dp),
        verticalAlignment = Alignment.CenterVertically) {
        AppIcon(c.app, if (compact) 32.dp else 40.dp)
        Spacer(Modifier.width(12.dp))
        if (compact) {
            Column(Modifier.weight(1f)) {
                Row { // app — time (red when blocked)
                    Text(c.app.name, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
                    Text(time, style = MaterialTheme.typography.bodySmall,
                        color = when { c.blocked -> MaterialTheme.colorScheme.error; c.active -> LocalExtraColors.current.ok; else -> muted })
                }
                Row {
                    Text("$proto · ${c.title}", style = MaterialTheme.typography.bodySmall, color = muted,
                        maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
                    Text(formatBytes(c.bytes), style = MaterialTheme.typography.bodySmall)
                }
            }
        } else {
            Column(Modifier.weight(1f)) {
                Text(c.app.name, fontWeight = FontWeight.SemiBold, color = muted, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(proto, style = MaterialTheme.typography.bodySmall, color = muted)
                Text(c.title, style = MaterialTheme.typography.bodySmall, color = muted, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            Column(horizontalAlignment = Alignment.End) {
                Text(stringResource(when { c.blocked -> R.string.st_blocked; c.active -> R.string.st_active; else -> R.string.st_closed }),
                    style = MaterialTheme.typography.bodySmall,
                    color = when { c.blocked -> MaterialTheme.colorScheme.error; c.active -> LocalExtraColors.current.ok; else -> muted })
                Text(time, style = MaterialTheme.typography.bodySmall, color = muted)
                Text(formatBytes(c.bytes), style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}

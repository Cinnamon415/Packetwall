package io.github.cinnamon415.packetwall.ui

import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import io.github.cinnamon415.packetwall.PacketwallApp
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.engine.AppInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** One line of the proxy app list. */
sealed interface ProxyPickRow {
    data class Header(val vpnClients: Boolean) : ProxyPickRow

    data class App(val app: AppInfo) : ProxyPickRow
}

/**
 * Rows of the proxy app list. Real apps only (uid ≥ 10000), never Packetwall itself. Without a
 * search, VPN clients (apps with a VpnService: v2rayNG, FlClash…) come first under their own
 * header, then all other apps; a search gives one flat list. System apps are hidden unless
 * [system] is on, except the [selected] one. Pure, tested.
 */
fun proxyPickRows(
    all: List<AppInfo>,
    vpnPackages: Set<String>,
    query: String,
    system: Boolean,
    selected: String,
    self: String
): List<ProxyPickRow> {
    val n = query.trim().lowercase()
    val shown = all.filter {
        it.uid >= 10000 && !it.packageName.startsWith(self) &&
            (system || !it.isSystem || it.packageName == selected) &&
            (n.isEmpty() || it.name.lowercase().contains(n) || it.packageName.lowercase().contains(n))
    }.sortedBy { it.name.lowercase() }
    if (n.isNotEmpty()) return shown.map { ProxyPickRow.App(it) }
    val (vpn, rest) = shown.partition { it.packageName in vpnPackages }
    return buildList {
        if (vpn.isNotEmpty()) {
            add(ProxyPickRow.Header(true))
            vpn.forEach { add(ProxyPickRow.App(it)) }
            if (rest.isNotEmpty()) add(ProxyPickRow.Header(false))
        }
        rest.forEach { add(ProxyPickRow.App(it)) }
    }
}

/** Packages that declare a VPN service: the proxy clients the user most likely means. */
fun vpnClientPackages(ctx: Context): Set<String> = try {
    ctx.packageManager.queryIntentServices(Intent(VpnService.SERVICE_INTERFACE), 0)
        .mapNotNull { it.serviceInfo?.packageName }
        .toSet()
} catch (e: Exception) {
    emptySet()
}

/** Full-screen single choice of the upstream proxy app: search, system apps off by default. */
@Composable
fun ProxyAppPicker(app: PacketwallApp, selected: String, onDismiss: () -> Unit, onPick: (String) -> Unit) {
    val data by produceState<Pair<List<AppInfo>, Set<String>>?>(null) {
        value = withContext(Dispatchers.IO) { app.apps.installed() to vpnClientPackages(app) }
    }
    var q by rememberSaveable { mutableStateOf("") }
    var system by rememberSaveable { mutableStateOf(false) }
    val selectedName = data?.first?.firstOrNull { it.packageName == selected }?.name ?: selected
    Dialog(onDismiss, DialogProperties(usePlatformDefaultWidth = false)) {
        Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.surface) {
            Column(Modifier.fillMaxSize()) {
                Row(Modifier.fillMaxWidth().padding(4.dp), verticalAlignment = Alignment.CenterVertically) {
                    IconButton(onDismiss) { Icon(Icons.Filled.Close, stringResource(R.string.cancel)) }
                    Column(Modifier.weight(1f)) {
                        Text(
                            stringResource(R.string.upstream_app_pick),
                            style = MaterialTheme.typography.titleLarge,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Text(
                            if (selected.isEmpty()) stringResource(R.string.upstream_app_none) else selectedName,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }
                SearchField(q, { q = it })
                Row(Modifier.padding(horizontal = 12.dp), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    FilterChip(system, { system = !system }, { Text(stringResource(R.string.system_apps)) })
                }
                val d = data
                if (d == null) {
                    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { Text(stringResource(R.string.loading)) }
                    return@Column
                }
                val rows = proxyPickRows(d.first, d.second, q, system, selected, app.packageName.substringBefore(".debug"))
                // a new filter starts from the top
                val listState = rememberLazyListState()
                LaunchedEffect(system, q.trim()) { listState.scrollToItem(0) }
                LazyColumn(state = listState, contentPadding = PaddingValues(bottom = 16.dp)) {
                    if (q.isBlank()) {
                        item(key = "none") { PickRow(selected.isEmpty(), { onPick("") }) { Text(stringResource(R.string.upstream_app_none)) } }
                    }
                    if (rows.isEmpty()) item(key = "empty") { EmptyHint(stringResource(R.string.nothing_found)) }
                    items(rows, key = { r ->
                        when (r) {
                            is ProxyPickRow.Header -> "h${r.vpnClients}"
                            is ProxyPickRow.App -> r.app.packageName
                        }
                    }) { r ->
                        when (r) {
                            is ProxyPickRow.Header -> Text(
                                stringResource(if (r.vpnClients) R.string.upstream_app_vpn_clients else R.string.upstream_app_others),
                                style = MaterialTheme.typography.labelLarge,
                                color = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.padding(start = 20.dp, end = 20.dp, top = 16.dp, bottom = 4.dp)
                            )
                            is ProxyPickRow.App -> PickRow(r.app.packageName == selected, { onPick(r.app.packageName) }) {
                                AppIcon(r.app, 36.dp)
                                Spacer(Modifier.width(12.dp))
                                Column(Modifier.weight(1f)) {
                                    Text(r.app.name, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                    Text(
                                        r.app.packageName,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun PickRow(on: Boolean, onClick: () -> Unit, content: @Composable () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clickable(onClick = onClick).padding(horizontal = 8.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        RadioButton(on, null, Modifier.size(48.dp))
        Spacer(Modifier.width(4.dp))
        Row(Modifier.weight(1f), verticalAlignment = Alignment.CenterVertically) { content() }
    }
}

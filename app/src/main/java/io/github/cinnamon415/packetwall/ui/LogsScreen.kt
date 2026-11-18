package io.github.cinnamon415.packetwall.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.widget.Toast
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.PrimaryScrollableTabRow
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
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
import io.github.cinnamon415.packetwall.Settings
import io.github.cinnamon415.packetwall.analysis.Dissector
import io.github.cinnamon415.packetwall.analysis.PcapServer
import io.github.cinnamon415.packetwall.engine.CaptureState
import io.github.cinnamon415.packetwall.engine.Conn
import io.github.cinnamon415.packetwall.ui.theme.LocalExtraColors
import java.io.File
import java.io.Writer
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LogsScreen(app: PacketwallApp, state: CaptureState, openDrawer: () -> Unit, onOpenConn: (Int) -> Unit, onOpenFiles: () -> Unit) {
    val vm = appViewModel(app) { a, saved -> LogsViewModel(a.connections.conns, saved) }
    val fw by app.firewall.state.collectAsState()
    val shownState by vm.shown.collectAsStateWithLifecycle()
    val shown = shownState.list
    val check by vm.filterCheck.collectAsStateWithLifecycle()
    val status by vm.status.collectAsState()
    val tab by vm.tab.collectAsState()
    val compact by vm.compact.collectAsState()
    var quick by remember { mutableStateOf<Conn?>(null) }
    val ctx = LocalContext.current

    val scope = rememberCoroutineScope()
    var menu by remember { mutableStateOf(false) }
    val csvExport = rememberFileExport("text/csv")
    val pcapExport = rememberFileExport("application/octet-stream")
    val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
    ScreenScaffold(
        title = stringResource(
            R.string.nav_logs
        ),
        subtitle = "${shown.size} / ${shownState.total}",
        onMenu = openDrawer,
        actions = {
            IconButton(onClick = { menu = true }) { Icon(Icons.Filled.MoreVert, null) }
            DropdownMenu(menu, { menu = false }) {
                DropdownMenuItem({ Text(stringResource(R.string.export_csv)) }, {
                    menu = false
                    csvExport.launch("packetwall-log-$stamp.csv") { out -> out.bufferedWriter().use { w -> writeCsv(w, shown, app) } }
                })
                DropdownMenuItem({ Text(stringResource(R.string.export_pcapng_filtered)) }, {
                    menu = false
                    pcapExport.launch("packetwall-filtered-$stamp.pcapng") { out ->
                        app.packets.writePcapng(out, shown.flatMap { app.packets.packetsOf(it) }.sortedBy { it.seq })
                    }
                })
            }
        }
    ) {
        Column(Modifier.padding(horizontal = 12.dp)) {
            OutlinedTextField(
                vm.filter, vm::updateFilter, Modifier.fillMaxWidth(), singleLine = true,
                leadingIcon = { Icon(painterResource(R.drawable.ic_filter), null) },
                textStyle = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace),
                isError = !check.valid,
                supportingText = check.error?.let { e -> { Text(parseErrorText(e)) } },
                placeholder = { Text(stringResource(R.string.logs_filter_hint), fontFamily = FontFamily.Monospace) }
            )
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                val chips = listOf(R.string.chip_all, R.string.chip_blocked, R.string.chip_allowed)
                StatusFilter.entries.zip(chips).forEach { (f, label) ->
                    FilterChip(status == f, { vm.setStatus(f) }, { Text(stringResource(label)) })
                }
                FilterChip(compact, vm::toggleCompact, { Icon(painterResource(R.drawable.ic_density), null) })
            }
        }
        PrimaryScrollableTabRow(selectedTabIndex = tab.ordinal, edgePadding = 0.dp) {
            val labels = listOf(R.string.tab_conns, R.string.tab_dns, R.string.tab_http, R.string.tab_captures)
            LogTab.entries.zip(labels).forEach { (t, label) ->
                Tab(tab == t, { vm.setTab(t) }, text = { Text(stringResource(label), maxLines = 1) })
            }
        }
        if (tab == LogTab.CAPTURES) {
            CapturesTab(app, onOpenFiles)
            return@ScreenScaffold
        }
        if (shown.isEmpty()) {
            Box(Modifier.fillMaxSize().padding(24.dp), contentAlignment = Alignment.Center) {
                Text(
                    stringResource(if (state is CaptureState.Running) R.string.empty_logs else R.string.empty_logs_off),
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        } else {
            LazyColumn {
                items(shown, key = { it.id }) { c ->
                    when (tab) {
                        LogTab.DNS -> DnsRow(app, c, onLongClick = { quick = c }) { onOpenConn(c.id) }
                        LogTab.HTTP -> HttpRow(c, onLongClick = { quick = c }) { onOpenConn(c.id) }
                        else -> ConnRow(c, compact, c.tracker, onLongClick = { quick = c }) { onOpenConn(c.id) }
                    }
                    HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
                }
            }
        }
    }
    quick?.let { c ->
        QuickRuleSheet(c, app, fw, onDismiss = { quick = null }) { msg ->
            quick = null
            Toast.makeText(ctx, msg, Toast.LENGTH_SHORT).show()
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
internal fun ConnRow(c: Conn, compact: Boolean, tracker: String?, onLongClick: () -> Unit, onClick: () -> Unit) {
    val muted = MaterialTheme.colorScheme.onSurfaceVariant
    val error = MaterialTheme.colorScheme.error
    val time = formatTime(c.firstSeen)
    val proto = "${c.protoLabel}, ${c.dstPort}"
    Row(
        Modifier.fillMaxWidth()
            // compact view: blocked rows get a red stripe on the left (spec)
            .drawBehind {
                if (compact &&
                    c.blocked
                ) {
                    drawLine(error, Offset(1.5.dp.toPx(), 0f), Offset(1.5.dp.toPx(), size.height), 3.dp.toPx())
                }
            }
            .combinedClickable(onLongClick = onLongClick, onClick = onClick)
            .padding(horizontal = 10.dp, vertical = if (compact) 5.dp else 7.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        AppIcon(c.app, if (compact) 32.dp else 40.dp)
        Spacer(Modifier.width(12.dp))
        if (compact) {
            Column(Modifier.weight(1f)) {
                Row {
                    // app — time (red when blocked)
                    Text(
                        c.app.name,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f)
                    )
                    Text(
                        time,
                        style = MaterialTheme.typography.bodySmall,
                        color = when {
                            c.blocked -> error
                            c.active -> LocalExtraColors.current.ok
                            else -> muted
                        }
                    )
                }
                Row {
                    Text(
                        "$proto · ${c.title}" + (
                            tracker?.let {
                                " · ⚑ $it"
                            } ?: ""
                            ),
                        style = MaterialTheme.typography.bodySmall,
                        color = muted,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f)
                    )
                    Text(formatBytes(c.bytes), style = MaterialTheme.typography.bodySmall)
                }
            }
        } else {
            Column(Modifier.weight(1f)) {
                Text(c.app.name, fontWeight = FontWeight.SemiBold, color = muted, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(proto, style = MaterialTheme.typography.bodySmall, color = muted)
                Text(c.title, style = MaterialTheme.typography.bodySmall, color = muted, maxLines = 1, overflow = TextOverflow.Ellipsis)
                if (tracker != null) {
                    Text(
                        "⚑ $tracker",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.tertiary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
            Column(horizontalAlignment = Alignment.End) {
                Text(
                    stringResource(
                        when {
                            c.blocked -> R.string.st_blocked
                            c.active -> R.string.st_active
                            else -> R.string.st_closed
                        }
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = when {
                        c.blocked -> error
                        c.active -> LocalExtraColors.current.ok
                        else -> muted
                    }
                )
                Text(time, style = MaterialTheme.typography.bodySmall, color = muted)
                Text(formatBytes(c.bytes), style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun HttpRow(c: Conn, onLongClick: () -> Unit, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().combinedClickable(
            onLongClick = onLongClick,
            onClick = onClick
        ).padding(horizontal = 10.dp, vertical = 7.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        AppIcon(c.app, 32.dp)
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(c.host ?: c.dstIp, fontFamily = FontFamily.Monospace, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(
                c.url ?: "/",
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
        Column(horizontalAlignment = Alignment.End) {
            Text(
                formatTime(c.firstSeen),
                style = MaterialTheme.typography.bodySmall,
                color = if (c.blocked) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(formatBytes(c.bytes), style = MaterialTheme.typography.bodySmall)
        }
    }
}

// ------------------------------------------------------------------ Captures

fun capturesDir(app: PacketwallApp) = File(app.filesDir, "captures").apply { mkdirs() }

@Composable
private fun CapturesTab(app: PacketwallApp, onOpenFiles: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val info by app.packets.info.collectAsState()
    val settings by app.settings.values.collectAsState()
    var files by remember { mutableStateOf(capturesDir(app).listFiles()?.sortedByDescending { it.lastModified() } ?: emptyList()) }
    val saveMsg = stringResource(R.string.capture_saved)
    fun refresh() {
        files = capturesDir(app).listFiles()?.sortedByDescending { it.lastModified() } ?: emptyList()
    }
    var deleting by remember { mutableStateOf<File?>(null) }
    deleting?.let { f ->
        ConfirmDialog(stringResource(R.string.confirm_delete_file, f.name), { deleting = null }) {
            f.delete()
            deleting = null
            refresh()
        }
    }

    val export = rememberFileExport("application/octet-stream")
    val stamp = { SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date()) }

    LazyColumn(contentPadding = PaddingValues(12.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        item {
            RoundedGroup {
                Column(Modifier.padding(12.dp)) {
                    Text(stringResource(R.string.buffer_title), style = MaterialTheme.typography.titleSmall)
                    Text(
                        if (!settings.capturePackets) {
                            stringResource(R.string.capture_off)
                        } else {
                            stringResource(R.string.buffer_line, info.packets, formatBytes(info.bytes), settings.bufferMb, info.dropped)
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(Modifier.height(8.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(enabled = info.packets > 0, onClick = {
                            scope.launch {
                                withContext(Dispatchers.IO) {
                                    File(capturesDir(app), "packetwall-${stamp()}.pcapng").outputStream().use {
                                        app.packets.writePcapng(it)
                                    }
                                }
                                refresh()
                                Toast.makeText(ctx, saveMsg, Toast.LENGTH_SHORT).show()
                            }
                        }) { Text(stringResource(R.string.save_capture)) }
                        OutlinedButton(enabled = info.packets > 0, onClick = {
                            export.launch("packetwall-${stamp()}.pcapng") { app.packets.writePcapng(it) }
                        }) {
                            Text(stringResource(R.string.export))
                        }
                    }
                }
            }
        }
        item { StreamCard(app, settings) }
        item { RecordCard(app, settings) { refresh() } }
        item {
            // saved and recorded files are opened, exported and deleted in "File analysis"
            OutlinedButton(onClick = onOpenFiles, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.files_go, files.size))
            }
        }
    }
}

@Composable
private fun StreamCard(app: PacketwallApp, s: Settings.Values) {
    val st by app.pcapServer.state.collectAsState()
    var howTo by rememberSaveable { mutableStateOf(false) }
    RoundedGroup {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(stringResource(R.string.stream_title), style = MaterialTheme.typography.titleSmall)
                    Text(
                        when {
                            st.error != null -> problemText(st.error!!)
                            st.running && st.lan -> stringResource(R.string.stream_lan_running, st.address, st.port, st.clients)
                            st.running -> stringResource(R.string.stream_usb_running, st.clients)
                            else -> stringResource(R.string.stream_off)
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = if (st.error != null) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Switch(s.stream, { v -> app.settings.update { it.copy(stream = v) } })
            }
            if (s.stream) {
                Row(
                    Modifier.fillMaxWidth().clickable { app.settings.update { it.copy(streamLan = !it.streamLan) } },
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Checkbox(s.streamLan, null, Modifier.padding(end = 8.dp))
                    Text(stringResource(R.string.stream_lan), style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f))
                }
                if (s.streamLan) {
                    Text(
                        stringResource(R.string.stream_lan_warn),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }
                FilledTonalButton(onClick = { howTo = true }) { Text(stringResource(R.string.stream_how)) }
            }
        }
    }
    if (howTo) StreamHowToSheet(app, s, st) { howTo = false }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun StreamHowToSheet(app: PacketwallApp, s: Settings.Values, st: PcapServer.State, onDismiss: () -> Unit) {
    var tab by rememberSaveable { mutableIntStateOf(if (s.streamLan) 1 else 0) }
    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(Modifier.padding(horizontal = 16.dp).padding(bottom = 24.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(R.string.stream_sheet_title), style = MaterialTheme.typography.titleLarge)
            PrimaryTabRow(selectedTabIndex = tab) {
                Tab(tab == 0, { tab = 0 }, text = { Text(stringResource(R.string.stream_tab_usb)) })
                Tab(tab == 1, { tab = 1 }, text = { Text(stringResource(R.string.stream_tab_wifi)) })
            }
            val wireshark = "wireshark -k -i -"
            val wiresharkWin = "\"C:\\Program Files\\Wireshark\\Wireshark.exe\" -k -i -"
            if (tab == 0) {
                val local = 57012
                Step("1.", stringResource(R.string.stream_usb_step1))
                Step("2.", stringResource(R.string.stream_usb_step2))
                CopyCode("adb forward tcp:$local localabstract:${app.packageName}.pcap")
                Step("3.", stringResource(R.string.stream_step_open))
                CopyCode("curl -sN http://127.0.0.1:$local/ | $wireshark")
                Text(stringResource(R.string.stream_step_open_win), style = MaterialTheme.typography.bodySmall)
                CopyCode("curl -sN http://127.0.0.1:$local/ | $wiresharkWin")
                Step("4.", stringResource(R.string.stream_step_done))
                Text(
                    stringResource(R.string.stream_usb_only_adb),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else if (!s.streamLan) {
                Text(stringResource(R.string.stream_wifi_off), style = MaterialTheme.typography.bodyMedium)
            } else {
                val url = "http://${st.address.ifEmpty { "<IP>" }}:${s.streamPort}/${s.streamToken}"
                Step("1.", stringResource(R.string.stream_wifi_step1))
                Step("2.", stringResource(R.string.stream_step_open))
                CopyCode("curl -sN $url | $wireshark")
                Text(stringResource(R.string.stream_step_open_win), style = MaterialTheme.typography.bodySmall)
                CopyCode("curl -sN $url | $wiresharkWin")
                Step("3.", stringResource(R.string.stream_step_done))
                Text(
                    stringResource(R.string.stream_wifi_token),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                OutlinedButton(onClick = { app.settings.update { it.copy(streamToken = PcapServer.newToken()) } }) {
                    Text(stringResource(R.string.stream_new_token))
                }
            }
        }
    }
}

@Composable
private fun Step(n: String, text: String) {
    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(n, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.primary)
        Text(text, style = MaterialTheme.typography.bodyMedium)
    }
}

/** A command in a monospace box with a copy button. */
@Composable
fun CopyCode(text: String) {
    val ctx = LocalContext.current
    val copied = stringResource(R.string.copied)
    Surface(shape = RoundedCornerShape(8.dp), color = MaterialTheme.colorScheme.surfaceContainerHighest) {
        Row(Modifier.padding(start = 10.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(
                text,
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.weight(1f).padding(vertical = 8.dp)
            )
            IconButton(onClick = {
                ctx.getSystemService(ClipboardManager::class.java)?.setPrimaryClip(ClipData.newPlainText("command", text))
                Toast.makeText(ctx, copied, Toast.LENGTH_SHORT).show()
            }) { Icon(painterResource(R.drawable.ic_copy), stringResource(R.string.copy)) }
        }
    }
}

@Composable
private fun RecordCard(app: PacketwallApp, s: Settings.Values, onChanged: () -> Unit) {
    val st by app.recorder.state.collectAsState()
    LaunchedEffect(st.file) { onChanged() }
    // settings live in Settings → Analysis; here only what the recorder is doing
    RoundedGroup {
        Column(Modifier.padding(12.dp)) {
            Text(stringResource(R.string.record_title), style = MaterialTheme.typography.titleSmall)
            Text(
                when {
                    !s.record || !s.capturePackets -> stringResource(R.string.record_off)
                    st.running && st.file != null -> "${st.file} · ${formatBytes(st.bytes)}"
                    else -> stringResource(R.string.record_waiting, s.recordMb, s.recordKeep)
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

/** CSV of the shown connections (the current filter), RFC 4180 quoting. */
fun writeCsv(w: Writer, list: List<Conn>, app: PacketwallApp) {
    fun q(v: Any?): String {
        val t = v?.toString() ?: return ""
        return if (t.any { it == ',' || it == '"' || it == '\n' }) "\"" + t.replace("\"", "\"\"") + "\"" else t
    }
    w.write(
        "id,first_seen,last_seen,app,package,uid,l4,l7,src_ip,src_port,dst_ip,dst_port,host,url,country," +
            "sent_bytes,rcvd_bytes,sent_pkts,rcvd_pkts,status,blocked,rule,route,tracker\n"
    )
    val iso = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX", Locale.US)
    for (c in list) {
        val status = when {
            c.blocked -> "blocked"
            c.active -> "active"
            else -> "closed"
        }
        w.write(
            listOf(
                c.id, iso.format(Date(c.firstSeen)), iso.format(Date(c.lastSeen)), c.app.name, c.app.packageName, c.uid, c.l4, c.l7proto,
                c.srcIp, c.srcPort, c.dstIp, c.dstPort, c.host, c.url, c.country, c.sentBytes, c.rcvdBytes, c.sentPkts, c.rcvdPkts, status,
                c.blocked,
                if (c.fwRule !=
                    0
                ) {
                    c.fwRule
                } else {
                    null
                },
                if (c.proxied) "upstream" else "direct", c.tracker
            )
                .joinToString(",") { q(it) }
        )
        w.write("\n")
    }
}

/** DNS tab row: the query and, when its packets are still in the buffer, the answer. */
@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun DnsRow(app: PacketwallApp, c: Conn, onLongClick: () -> Unit, onClick: () -> Unit) {
    val answer by produceState<String?>(null, c.id, c.lastSeen) {
        value = withContext(Dispatchers.Default) {
            app.packets.packetsOf(c).asReversed().firstOrNull { !it.tx }?.let {
                Dissector.summary(it.block, it.dataOff, it.capLen).info.substringAfter("→ ", "")
            }?.takeIf { it.isNotEmpty() }
        }
    }
    Row(
        Modifier.fillMaxWidth().combinedClickable(
            onLongClick = onLongClick,
            onClick = onClick
        ).padding(horizontal = 10.dp, vertical = 7.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        AppIcon(c.app, 32.dp)
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(c.host ?: "?", fontFamily = FontFamily.Monospace, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(
                when {
                    c.blocked -> stringResource(R.string.dns_blocked_answer)
                    answer != null -> "→ $answer"
                    else -> c.app.name
                },
                style = MaterialTheme.typography.bodySmall,
                fontFamily = if (answer != null && !c.blocked) FontFamily.Monospace else null,
                color = if (c.blocked) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
        Text(
            formatTime(c.firstSeen),
            style = MaterialTheme.typography.bodySmall,
            color = if (c.blocked) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

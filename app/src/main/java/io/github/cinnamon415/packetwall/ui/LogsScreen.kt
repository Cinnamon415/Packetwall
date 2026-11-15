package io.github.cinnamon415.packetwall.ui

import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.PrimaryScrollableTabRow
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
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
import io.github.cinnamon415.packetwall.PacketwallApp
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.analysis.ConnFilter
import io.github.cinnamon415.packetwall.engine.CaptureState
import io.github.cinnamon415.packetwall.engine.Conn
import io.github.cinnamon415.packetwall.ui.theme.LocalExtraColors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.text.DateFormat
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LogsScreen(app: PacketwallApp, state: CaptureState, openDrawer: () -> Unit, onOpenConn: (Int) -> Unit) {
    val conns by app.connections.conns.collectAsState()
    val fw by app.firewall.state.collectAsState()
    var filter by rememberSaveable { mutableStateOf("") }
    var status by rememberSaveable { mutableIntStateOf(0) } // 0 all, 1 blocked, 2 allowed
    var compact by rememberSaveable { mutableStateOf(false) }
    var tab by rememberSaveable { mutableIntStateOf(0) }
    var quick by remember { mutableStateOf<Conn?>(null) }
    val ctx = LocalContext.current

    val compiled = remember(filter) { runCatching { ConnFilter.compile(filter) } }
    val pred = compiled.getOrNull() ?: { true }
    val list = conns.filter { c -> (status == 0 || (status == 1) == c.blocked) && pred(c) }
    val shown = when (tab) {
        1 -> list.filter { it.l7proto == "DNS" }
        2 -> list.filter { !it.url.isNullOrEmpty() }
        else -> list
    }

    ScreenScaffold(title = stringResource(R.string.nav_logs), subtitle = "${conns.size}", onMenu = openDrawer) {
        Column(Modifier.padding(horizontal = 12.dp)) {
            OutlinedTextField(filter, { filter = it }, Modifier.fillMaxWidth(), singleLine = true,
                leadingIcon = { Icon(painterResource(R.drawable.ic_filter), null) },
                textStyle = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace),
                isError = compiled.isFailure,
                supportingText = (compiled.exceptionOrNull() as? ConnFilter.ParseError)?.let { e -> { Text(e.message ?: "") } },
                placeholder = { Text(stringResource(R.string.logs_filter_hint), fontFamily = FontFamily.Monospace) })
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                listOf(R.string.chip_all, R.string.chip_blocked, R.string.chip_allowed).forEachIndexed { i, s ->
                    FilterChip(status == i, { status = i }, { Text(stringResource(s)) })
                }
                FilterChip(compact, { compact = !compact }, { Icon(painterResource(R.drawable.ic_density), null) })
            }
        }
        PrimaryScrollableTabRow(selectedTabIndex = tab, edgePadding = 0.dp) {
            listOf(R.string.tab_conns, R.string.tab_dns, R.string.tab_http, R.string.tab_captures).forEachIndexed { i, s ->
                Tab(tab == i, { tab = i }, text = { Text(stringResource(s), maxLines = 1) })
            }
        }
        if (tab == 3) { CapturesTab(app); return@ScreenScaffold }
        if (shown.isEmpty()) {
            Box(Modifier.fillMaxSize().padding(24.dp), contentAlignment = Alignment.Center) {
                Text(stringResource(if (state is CaptureState.Running) R.string.empty_logs else R.string.empty_logs_off),
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        } else LazyColumn {
            items(shown, key = { it.id }) { c ->
                when (tab) {
                    2 -> HttpRow(c, onLongClick = { quick = c }) { onOpenConn(c.id) }
                    else -> ConnRow(c, compact, onLongClick = { quick = c }) { onOpenConn(c.id) }
                }
                HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
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
private fun ConnRow(c: Conn, compact: Boolean, onLongClick: () -> Unit, onClick: () -> Unit) {
    val muted = MaterialTheme.colorScheme.onSurfaceVariant
    val error = MaterialTheme.colorScheme.error
    val time = formatTime(c.firstSeen)
    val proto = "${c.protoLabel}, ${c.dstPort}"
    Row(Modifier.fillMaxWidth()
        // compact view: blocked rows get a red stripe on the left (spec)
        .drawBehind { if (compact && c.blocked) drawLine(error, Offset(1.5.dp.toPx(), 0f), Offset(1.5.dp.toPx(), size.height), 3.dp.toPx()) }
        .combinedClickable(onLongClick = onLongClick, onClick = onClick)
        .padding(horizontal = 10.dp, vertical = if (compact) 5.dp else 7.dp),
        verticalAlignment = Alignment.CenterVertically) {
        AppIcon(c.app, if (compact) 32.dp else 40.dp)
        Spacer(Modifier.width(12.dp))
        if (compact) {
            Column(Modifier.weight(1f)) {
                Row { // app — time (red when blocked)
                    Text(c.app.name, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
                    Text(time, style = MaterialTheme.typography.bodySmall,
                        color = when { c.blocked -> error; c.active -> LocalExtraColors.current.ok; else -> muted })
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
                    color = when { c.blocked -> error; c.active -> LocalExtraColors.current.ok; else -> muted })
                Text(time, style = MaterialTheme.typography.bodySmall, color = muted)
                Text(formatBytes(c.bytes), style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun HttpRow(c: Conn, onLongClick: () -> Unit, onClick: () -> Unit) {
    Row(Modifier.fillMaxWidth().combinedClickable(onLongClick = onLongClick, onClick = onClick).padding(horizontal = 10.dp, vertical = 7.dp),
        verticalAlignment = Alignment.CenterVertically) {
        AppIcon(c.app, 32.dp)
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(c.host ?: c.dstIp, fontFamily = FontFamily.Monospace, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(c.url ?: "/", style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
        Column(horizontalAlignment = Alignment.End) {
            Text(formatTime(c.firstSeen), style = MaterialTheme.typography.bodySmall,
                color = if (c.blocked) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant)
            Text(formatBytes(c.bytes), style = MaterialTheme.typography.bodySmall)
        }
    }
}

// ------------------------------------------------------------------ Captures

fun capturesDir(app: PacketwallApp) = File(app.filesDir, "captures").apply { mkdirs() }

@Composable
private fun CapturesTab(app: PacketwallApp) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val info by app.packets.info.collectAsState()
    val settings by app.settings.values.collectAsState()
    var files by remember { mutableStateOf(capturesDir(app).listFiles()?.sortedByDescending { it.lastModified() } ?: emptyList()) }
    var exporting by remember { mutableStateOf<File?>(null) }
    val doneMsg = stringResource(R.string.exported)
    val saveMsg = stringResource(R.string.capture_saved)
    fun refresh() { files = capturesDir(app).listFiles()?.sortedByDescending { it.lastModified() } ?: emptyList() }

    val exportBuffer = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        if (uri != null) scope.launch {
            runCatching { withContext(Dispatchers.IO) { ctx.contentResolver.openOutputStream(uri, "wt")!!.use { app.packets.writePcapng(it) } } }
            Toast.makeText(ctx, doneMsg, Toast.LENGTH_SHORT).show()
        }
    }
    val exportFile = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val f = exporting
        if (uri != null && f != null) scope.launch {
            runCatching { withContext(Dispatchers.IO) { ctx.contentResolver.openOutputStream(uri, "wt")!!.use { o -> f.inputStream().use { it.copyTo(o) } } } }
            Toast.makeText(ctx, doneMsg, Toast.LENGTH_SHORT).show()
        }
    }
    val stamp = { SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date()) }

    LazyColumn(contentPadding = PaddingValues(12.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        item {
            RoundedGroup {
                Column(Modifier.padding(12.dp)) {
                    Text(stringResource(R.string.buffer_title), style = MaterialTheme.typography.titleSmall)
                    Text(if (!settings.capturePackets) stringResource(R.string.capture_off)
                        else stringResource(R.string.buffer_line, info.packets, formatBytes(info.bytes), settings.bufferMb, info.dropped),
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Spacer(Modifier.height(8.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(enabled = info.packets > 0, onClick = {
                            scope.launch {
                                withContext(Dispatchers.IO) {
                                    File(capturesDir(app), "packetwall-${stamp()}.pcapng").outputStream().use { app.packets.writePcapng(it) }
                                }
                                refresh()
                                Toast.makeText(ctx, saveMsg, Toast.LENGTH_SHORT).show()
                            }
                        }) { Text(stringResource(R.string.save_capture)) }
                        OutlinedButton(enabled = info.packets > 0, onClick = { exportBuffer.launch("packetwall-${stamp()}.pcapng") }) {
                            Text(stringResource(R.string.export))
                        }
                    }
                }
            }
        }
        if (files.isEmpty()) item { EmptyHint(stringResource(R.string.no_captures)) }
        else item {
            RoundedGroup {
                files.forEachIndexed { i, f ->
                    if (i > 0) HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
                    Row(Modifier.fillMaxWidth().clickable { exporting = f; exportFile.launch(f.name) }.padding(start = 12.dp, end = 4.dp, top = 6.dp, bottom = 6.dp),
                        verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(f.name, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            Text("${formatBytes(f.length())} · ${DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(Date(f.lastModified()))}",
                                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        IconButton({ f.delete(); refresh() }) { Icon(painterResource(R.drawable.ic_delete), stringResource(R.string.delete)) }
                    }
                }
            }
        }
        item {
            Text(stringResource(R.string.captures_hint), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

package io.github.cinnamon415.packetwall.ui

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Surface
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.github.cinnamon415.packetwall.PacketwallApp
import io.github.cinnamon415.packetwall.Problem
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.analysis.CaptureFile
import io.github.cinnamon415.packetwall.analysis.ConnFilter
import io.github.cinnamon415.packetwall.analysis.Dissector
import io.github.cinnamon415.packetwall.analysis.ParserService
import java.io.File
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json

/** A file opened before, for the "Recent" list (the URI keeps a persistable read grant). */
@Serializable
data class RecentFile(val uri: String, val name: String, val opened: Long, val packets: Int)

private object Recents {
    private const val MAX = 10
    private val serializer = ListSerializer(RecentFile.serializer())
    private fun prefs(ctx: Context) = ctx.getSharedPreferences("files", Context.MODE_PRIVATE)

    fun load(ctx: Context): List<RecentFile> =
        runCatching { Json.decodeFromString(serializer, prefs(ctx).getString("recent", null) ?: "[]") }.getOrDefault(emptyList())

    fun add(ctx: Context, f: RecentFile) {
        val list = (listOf(f) + load(ctx).filter { it.uri != f.uri }).take(MAX)
        prefs(ctx).edit().putString("recent", Json.encodeToString(serializer, list)).apply()
    }
}

private fun fileName(ctx: Context, uri: Uri): String = displayName(ctx, uri) ?: uri.lastPathSegment?.substringAfterLast('/') ?: "capture"

/**
 * Opens a capture into [OpenedFile]: the parser process reads it into a directory in the cache
 * (packets on disk), then the connection table is loaded here. Returns the number of packets.
 */
private suspend fun openCapture(app: PacketwallApp, name: String, uri: String?, path: String?): Int {
    val root = File(app.cacheDir, "captures-open").apply { mkdirs() }
    val dir = File(root, "f${System.currentTimeMillis()}")
    try {
        val n = ParserService.parse(app, uri, path, dir)
        val r = withContext(Dispatchers.IO) { CaptureFile.load(dir) { uid -> app.apps.get(uid) } }
        val old = OpenedFile.current
        OpenedFile.current = FileSource(name, r.conns, r.packets, r.skipped, r.truncated, dir)
        old?.packets?.close()
        // earlier files are no longer shown: free their space
        withContext(Dispatchers.IO) { root.listFiles()?.filter { it != dir }?.forEach { it.deleteRecursively() } }
        return n
    } catch (e: Throwable) {
        withContext(NonCancellable + Dispatchers.IO) { dir.deleteRecursively() }
        throw e
    }
}

/** "File analysis": open a pcap/pcapng, the recent ones, and Packetwall's own recordings. */
@Composable
fun FilesScreen(app: PacketwallApp, openDrawer: () -> Unit, onOpened: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var problem by remember { mutableStateOf<Problem?>(null) }
    var recents by remember { mutableStateOf(Recents.load(ctx)) }
    var recordings by remember { mutableStateOf(capturesDir(app).listFiles()?.sortedByDescending { it.lastModified() } ?: emptyList()) }
    var deleting by remember { mutableStateOf<File?>(null) }
    val export = rememberFileExport("application/octet-stream")

    fun open(name: String, uri: String?, path: String? = null) {
        busy = true
        problem = null
        scope.launch {
            try {
                val n = openCapture(app, name, uri, path)
                if (uri != null) {
                    Recents.add(ctx, RecentFile(uri, name, System.currentTimeMillis(), n))
                    recents = Recents.load(ctx)
                }
                onOpened()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                problem = Problem.of(e)
            }
            busy = false
        }
    }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            runCatching { ctx.contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION) }
            open(fileName(ctx, uri), uri.toString())
        }
    }

    deleting?.let { f ->
        ConfirmDialog(stringResource(R.string.confirm_delete_file, f.name), { deleting = null }) {
            f.delete()
            deleting = null
            recordings = capturesDir(app).listFiles()?.sortedByDescending { it.lastModified() } ?: emptyList()
        }
    }

    ScreenScaffold(title = stringResource(R.string.nav_files), onMenu = openDrawer) {
        LazyColumn(contentPadding = PaddingValues(12.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            item {
                Surface(shape = RoundedCornerShape(16.dp), color = MaterialTheme.colorScheme.primaryContainer) {
                    Column(
                        Modifier.fillMaxWidth().padding(16.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        Text(stringResource(R.string.files_open), style = MaterialTheme.typography.titleMedium)
                        Text(stringResource(R.string.files_open_hint), style = MaterialTheme.typography.bodySmall)
                        if (busy) {
                            CircularProgressIndicator(Modifier.padding(top = 6.dp))
                        } else {
                            Button(onClick = { picker.launch(arrayOf("*/*")) }, modifier = Modifier.padding(top = 4.dp)) {
                                Icon(painterResource(R.drawable.ic_file), null)
                                Text(stringResource(R.string.files_choose), modifier = Modifier.padding(start = 8.dp))
                            }
                        }
                        problem?.let {
                            Text(problemText(it), color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }
            if (recents.isNotEmpty()) {
                item { ListSubheader(stringResource(R.string.files_recent)) }
                item {
                    RoundedGroup {
                        recents.forEachIndexed { i, f ->
                            if (i > 0) HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
                            FileRow(f.name, stringResource(R.string.files_recent_line, formatDate(f.opened), f.packets), enabled = !busy) {
                                open(f.name, f.uri)
                            }
                        }
                    }
                }
            }
            item { ListSubheader(stringResource(R.string.files_recordings)) }
            if (recordings.isEmpty()) {
                item { EmptyHint(stringResource(R.string.no_captures)) }
            } else {
                item {
                    RoundedGroup {
                        recordings.forEachIndexed { i, f ->
                            if (i > 0) HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
                            FileRow(f.name, "${formatBytes(f.length())} · ${formatDate(f.lastModified())}", enabled = !busy, trailing = {
                                IconButton({ export.launch(f.name) { out -> f.inputStream().use { it.copyTo(out) } } }) {
                                    Icon(painterResource(R.drawable.ic_save), stringResource(R.string.export))
                                }
                                IconButton({
                                    deleting = f
                                }) { Icon(painterResource(R.drawable.ic_delete), stringResource(R.string.delete)) }
                            }) { open(f.name, null, f.path) }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun FileRow(name: String, line: String, enabled: Boolean, trailing: @Composable () -> Unit = { Chevron() }, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clickable(
            enabled = enabled,
            onClick = onClick
        ).padding(start = 12.dp, end = 4.dp, top = 6.dp, bottom = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(painterResource(R.drawable.ic_file), null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
        Column(Modifier.weight(1f).padding(start = 10.dp)) {
            Text(
                name,
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.bodyMedium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Text(line, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        trailing()
    }
}

/** An opened capture file: its connections (with the log filter) and all its packets. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FileViewScreen(onBack: () -> Unit, onOpenConn: (Int) -> Unit, onOpenPacket: (Int, Long) -> Unit) {
    val f = OpenedFile.current
    if (f == null) {
        // the process was restarted: the file is not in memory any more
        LaunchedEffect(Unit) { onBack() }
        return
    }
    var tab by rememberSaveable { mutableIntStateOf(0) }
    var filter by rememberSaveable { mutableStateOf("") }
    val conns by f.conns.collectAsState()
    val info by f.packets.info.collectAsState()
    val compiled = remember(filter) { runCatching { ConnFilter.compile(filter) } }
    val shown = remember(conns, compiled) { compiled.getOrNull()?.let { p -> conns.filter(p) } ?: conns }
    ScreenScaffold(
        title = f.name,
        subtitle = stringResource(R.string.file_summary, info.packets, conns.size),
        monoTitle = true,
        onBack = onBack
    ) {
        PrimaryTabRow(selectedTabIndex = tab) {
            Tab(tab == 0, { tab = 0 }, text = { Text(stringResource(R.string.tab_conns)) })
            Tab(tab == 1, { tab = 1 }, text = { Text(stringResource(R.string.conn_packets)) })
        }
        if (tab == 0) {
            OutlinedTextField(
                filter,
                { filter = it },
                Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 6.dp),
                singleLine = true,
                isError = compiled.isFailure,
                textStyle = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace),
                placeholder = { Text(stringResource(R.string.logs_filter_hint), fontFamily = FontFamily.Monospace) },
                supportingText = (compiled.exceptionOrNull() as? ConnFilter.ParseError)?.let { e -> { Text(parseErrorText(e)) } },
                trailingIcon = { FilterHelpButton { filter = it } }
            )
            if (f.truncated) {
                Text(
                    stringResource(R.string.file_truncated, info.packets),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.padding(horizontal = 16.dp)
                )
            }
            if (f.skipped > 0) {
                Text(
                    stringResource(R.string.file_skipped, f.skipped),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 16.dp)
                )
            }
            LazyColumn {
                items(shown, key = { it.id }) { c ->
                    ConnRow(c, false, c.tracker, onLongClick = {}) {
                        LogsLink.ids = shown.map { it.id }
                        onOpenConn(c.id)
                    }
                    HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
                }
            }
        } else {
            // every packet of the file, read from disk only for the rows on screen
            val t0 = remember(f) { f.packets.info.value.firstTs }
            LazyColumn {
                items(f.packets.count(), key = { it }) { i ->
                    val row by produceState<PktRow?>(null, i) {
                        value = withContext(Dispatchers.IO) {
                            f.packets.packetAt(i)?.let { p ->
                                PktRow(
                                    p,
                                    Dissector.summary(p.block, p.dataOff, p.capLen),
                                    null,
                                    null,
                                    p.ts - t0
                                )
                            }
                        }
                    }
                    val r = row
                    if (r == null) {
                        Box(Modifier.fillMaxWidth().height(48.dp))
                    } else {
                        PacketRow(r) { onOpenPacket(f.packets.flowOf(i), r.p.seq) }
                    }
                    HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
                }
            }
        }
    }
}

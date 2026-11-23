package io.github.cinnamon415.packetwall.ui

import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectDragGesturesAfterLongPress
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.FilledTonalIconButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.CustomAccessibilityAction
import androidx.compose.ui.semantics.customActions
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import androidx.compose.ui.zIndex
import io.github.cinnamon415.packetwall.Limits
import io.github.cinnamon415.packetwall.PacketwallApp
import io.github.cinnamon415.packetwall.Problem
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.fw.Action
import io.github.cinnamon415.packetwall.fw.Catalog
import io.github.cinnamon415.packetwall.fw.ExportFile
import io.github.cinnamon415.packetwall.fw.FirewallStore
import io.github.cinnamon415.packetwall.fw.ForeignImport
import io.github.cinnamon415.packetwall.fw.FwState
import io.github.cinnamon415.packetwall.fw.RethinkReader
import io.github.cinnamon415.packetwall.fw.RuleSet
import io.github.cinnamon415.packetwall.fw.SetKind
import io.github.cinnamon415.packetwall.readCapped
import java.text.DateFormat
import java.util.Date
import kotlin.math.roundToInt
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

internal fun formatDate(ms: Long): String =
    if (ms == 0L) "—" else DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(Date(ms))

// ------------------------------------------------------------------ Blocklists

/** Lists: the connected ones on top, the catalog below (by category), add by URL or from a file. */
@Composable
fun BlocklistsScreen(app: PacketwallApp, openDrawer: () -> Unit, onOpenList: (Int) -> Unit) {
    val st by app.firewall.state.collectAsState()
    val updating by app.firewall.updating.collectAsState()
    var adding by remember { mutableStateOf(false) }
    var importUri by remember { mutableStateOf<Uri?>(null) }
    var category by rememberSaveable { mutableStateOf<Catalog.Category?>(null) }
    val openFile = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { importUri = it }

    val lists = st.blocklists
    val total = lists.filter { st.isEnabled(it.id) }.sumOf { it.entries }
    val have = lists.mapNotNull { it.url }.toSet()

    ScreenScaffold(
        title = stringResource(R.string.nav_blocklists),
        subtitle = stringResource(
            R.string.lists_enabled,
            lists.count {
                st.isEnabled(it.id)
            },
            total
        ),
        onMenu = openDrawer,
        actions = {
            IconButton(onClick = { app.firewall.updateAll() }, enabled = updating.isEmpty() && lists.any { it.url != null }) {
                Icon(Icons.Filled.Refresh, stringResource(R.string.update_all))
            }
        }
    ) {
        Box(Modifier.fillMaxSize()) {
            Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 12.dp)) {
                ListSubheader(stringResource(R.string.lists_connected))
                if (lists.isEmpty()) {
                    EmptyHint(stringResource(R.string.no_blocklists))
                } else {
                    RoundedGroup {
                        lists.forEachIndexed { i, s ->
                            if (i > 0) HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
                            Row(
                                Modifier.fillMaxWidth()
                                    .clickable { onOpenList(s.id) }
                                    .padding(start = 14.dp, end = 8.dp, top = 8.dp, bottom = 8.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(Modifier.weight(1f)) {
                                    Text(s.name, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                    val line = when {
                                        s.id in updating -> stringResource(R.string.updating)
                                        s.error != null -> problemText(Problem.decode(s.error))
                                        else -> listOfNotNull(
                                            stringResource(R.string.entries_count, s.entries),
                                            if (s.action == Action.ALLOW) stringResource(R.string.action_allow) else null,
                                            if (s.edited) stringResource(R.string.list_edits_n, s.disabled.size + s.added.size) else null,
                                            if (s.url == null) stringResource(R.string.from_file) else formatDate(s.updated)
                                        ).joinToString(" · ")
                                    }
                                    Text(
                                        line,
                                        style = MaterialTheme.typography.bodySmall,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                        color = if (s.error != null &&
                                            s.id !in updating
                                        ) {
                                            MaterialTheme.colorScheme.error
                                        } else {
                                            MaterialTheme.colorScheme.onSurfaceVariant
                                        }
                                    )
                                }
                                if (s.id in updating) {
                                    CircularProgressIndicator(Modifier.size(20.dp).padding(end = 4.dp), strokeWidth = 2.dp)
                                }
                                Switch(st.isEnabled(s.id), { app.firewall.setEnabled(s.id, it) })
                            }
                        }
                    }
                }

                ListSubheader(stringResource(R.string.catalog))
                Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    FilterChip(category == null, { category = null }, { Text(stringResource(R.string.all)) })
                    Catalog.Category.entries.forEach { c ->
                        FilterChip(category == c, { category = if (category == c) null else c }, { Text(stringResource(c.label)) })
                    }
                }
                val available = Catalog.entries.filter { (category == null || it.category == category) && it.url !in have }
                if (available.isEmpty()) {
                    EmptyHint(stringResource(R.string.catalog_all_added))
                } else {
                    RoundedGroup(Modifier.padding(top = 6.dp)) {
                        available.forEachIndexed { i, e ->
                            if (i > 0) HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
                            Row(
                                Modifier.fillMaxWidth().padding(start = 14.dp, end = 4.dp, top = 6.dp, bottom = 6.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(Modifier.weight(1f)) {
                                    Text(e.name, fontWeight = FontWeight.SemiBold)
                                    Text(
                                        stringResource(e.note),
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                                FilledTonalIconButton({ app.firewall.addBlocklist(e.name, e.url) }) {
                                    Icon(Icons.Filled.Add, stringResource(R.string.add_list_named, e.name))
                                }
                            }
                        }
                    }
                }
                Spacer(Modifier.height(96.dp))
            }
            ExtendedFloatingActionButton(
                onClick = { adding = true },
                icon = { Icon(Icons.Filled.Add, null) },
                text = { Text(stringResource(R.string.list_add_url_file)) },
                modifier = Modifier.align(Alignment.BottomEnd).padding(16.dp)
            )
        }
    }
    if (adding) {
        AddListDialog(
            existing = st.blocklists.mapNotNull { it.url?.trim() }.toSet(),
            onDismiss = { adding = false },
            onFile = {
                adding = false
                openFile.launch(arrayOf("*/*"))
            }
        ) { name, url ->
            adding = false
            app.firewall.addBlocklist(name.ifBlank { Uri.parse(url).host ?: url }, url.trim())
        }
    }
    importUri?.let { uri -> ImportListDialog(app, uri) { importUri = null } }
}

@Composable
private fun AddListDialog(existing: Set<String>, onDismiss: () -> Unit, onFile: () -> Unit, onUrl: (String, String) -> Unit) {
    var name by remember { mutableStateOf("") }
    var url by remember { mutableStateOf("") }
    val dup = url.trim() in existing
    val urlOk = url.trim().let { it.startsWith("https://") || it.startsWith("http://") } && !dup
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.list_add_url_file)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                FieldLabel(stringResource(R.string.custom_url))
                OutlinedTextField(
                    url,
                    { url = it },
                    Modifier.fillMaxWidth(),
                    singleLine = true,
                    isError = url.isNotBlank() && !urlOk,
                    supportingText = if (dup) ({ Text(stringResource(R.string.list_already_added)) }) else null,
                    placeholder = { Text("https://…", fontFamily = FontFamily.Monospace) }
                )
                NameField(name) { name = it }
                HorizontalDivider(Modifier.padding(vertical = 4.dp))
                FieldLabel(stringResource(R.string.list_from_file_label))
                OutlinedButton(onClick = onFile, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.import_file)) }
                Text(
                    stringResource(R.string.import_file_hint),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        },
        confirmButton = { TextButton({ onUrl(name, url) }, enabled = urlOk) { Text(stringResource(R.string.add)) } },
        dismissButton = { TextButton(onDismiss) { Text(stringResource(R.string.cancel)) } }
    )
}

@Composable
internal fun BlocklistDetails(app: PacketwallApp, s: RuleSet, onDismiss: () -> Unit) {
    var name by remember { mutableStateOf(s.name) }
    var action by remember { mutableStateOf(s.action) }
    var reject by remember { mutableStateOf(s.reject) }
    var confirmDelete by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(s.name) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                NameField(name) { name = it }
                if (s.url != null) {
                    Text(
                        s.url,
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Text(
                    stringResource(R.string.list_stats, s.entries, s.skipped, formatDate(s.updated)),
                    style = MaterialTheme.typography.bodySmall
                )
                SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                    listOf(Action.BLOCK to R.string.action_block, Action.ALLOW to R.string.action_allow).forEachIndexed { i, (a, l) ->
                        SegmentedButton(action == a, { action = a }, SegmentedButtonDefaults.itemShape(i, 2)) { Text(stringResource(l)) }
                    }
                }
                if (action == Action.BLOCK) CheckRow(reject, stringResource(R.string.reject_label), Help.REJECT) { reject = it }
                Row {
                    if (s.url != null) TextButton({ app.firewall.updateList(s.id) }) { Text(stringResource(R.string.update_now)) }
                    TextButton({ confirmDelete = true }) { Text(stringResource(R.string.delete), color = MaterialTheme.colorScheme.error) }
                }
            }
        },
        confirmButton = {
            TextButton({
                app.firewall.updateSet(s.copy(name = name.trim().ifEmpty { s.name }, action = action, reject = reject))
                onDismiss()
            }) {
                Text(stringResource(R.string.save))
            }
        },
        dismissButton = { TextButton(onDismiss) { Text(stringResource(R.string.cancel)) } }
    )
    if (confirmDelete) {
        ConfirmDialog(stringResource(R.string.delete_set_q, s.name), { confirmDelete = false }) {
            app.firewall.deleteSet(s.id)
            onDismiss()
        }
    }
}

/**
 * File import with a format picker (auto-detected): the file is converted into Packetwall rules / list
 * entries with a report of what could not be converted (spec 3), then lands in new sets.
 */
@Composable
private fun ImportListDialog(app: PacketwallApp, uri: Uri, onDismiss: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var bytes by remember { mutableStateOf<ByteArray?>(null) }
    var format by remember { mutableStateOf(ForeignImport.Format.AUTO) }
    var detected by remember { mutableStateOf<ForeignImport.Format?>(null) }
    var plan by remember { mutableStateOf<ForeignImport.Plan?>(null) }
    var error by remember { mutableStateOf<Problem?>(null) }
    val defaultName = stringResource(R.string.import_default_name)
    var name by remember { mutableStateOf(uri.lastPathSegment?.substringAfterLast('/')?.substringBeforeLast('.') ?: defaultName) }
    var action by remember { mutableStateOf(Action.BLOCK) }
    var done by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(uri) {
        // the provider's file name, not the document id of the path ("msf:1234")
        withContext(Dispatchers.IO) { displayName(ctx, uri) }?.substringBeforeLast('.')?.takeIf { it.isNotBlank() }?.let { name = it }
        try {
            bytes = withContext(Dispatchers.IO) { ctx.contentResolver.openInputStream(uri)!!.readCapped(Limits.IMPORT_BYTES, "import") }
            detected = withContext(Dispatchers.Default) { ForeignImport.detect(bytes!!) }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            error = Problem.of(e) // OutOfMemoryError included: a crash here would also stop the VPN
        }
    }
    val effective = if (format == ForeignImport.Format.AUTO) detected else format
    if (effective == ForeignImport.Format.PACKETWALL) {
        ImportJsonDialog(app, uri, onDismiss)
        return
    }
    LaunchedEffect(bytes, effective) {
        val b = bytes ?: return@LaunchedEffect
        val f = effective ?: return@LaunchedEffect
        plan = null
        error = null
        try {
            plan = withContext(Dispatchers.IO) {
                val installed = app.apps.installed().filter { it.uid >= 0 }.map { ForeignImport.App(it.packageName, it.uid, it.isSystem) }
                when (f) {
                    ForeignImport.Format.PCAPDROID -> ForeignImport.pcapdroid(String(b, Charsets.UTF_8))
                    ForeignImport.Format.NETGUARD -> ForeignImport.netguard(String(b, Charsets.UTF_8), installed)
                    ForeignImport.Format.AFWALL -> ForeignImport.afwall(String(b, Charsets.UTF_8), installed)
                    ForeignImport.Format.SINGBOX -> ForeignImport.singbox(b)
                    ForeignImport.Format.RETHINK -> ForeignImport.rethink(RethinkReader.read(b.inputStream(), ctx.cacheDir), installed)
                    else -> ForeignImport.list(String(b, Charsets.UTF_8).lineSequence())
                }
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            error = Problem.of(e) // OutOfMemoryError included: a crash here would also stop the VPN
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.import_file)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (done != null) {
                    Text(done!!)
                    return@Column
                }
                FieldLabel(stringResource(R.string.import_format))
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    ForeignImport.Format.entries.forEach { f ->
                        FilterChip(format == f, { format = f }, {
                            val auto = f == ForeignImport.Format.AUTO
                            Text(if (auto) stringResource(R.string.import_auto, detected?.label ?: "…") else f.label)
                        })
                    }
                }
                val p = plan
                when {
                    error != null -> Text(problemText(error!!), color = MaterialTheme.colorScheme.error)
                    p == null -> CircularProgressIndicator()
                    else -> {
                        Text(stringResource(R.string.import_plan, p.rules.size, p.entries.size + p.important.size, p.skipped))
                        p.notes.forEach { Text("• ${noteText(it)}", style = MaterialTheme.typography.bodySmall) }
                        if (p.samples.isNotEmpty()) {
                            Text(stringResource(R.string.skipped_examples), style = MaterialTheme.typography.labelMedium)
                            Text(
                                p.samples.take(8).joinToString("\n"),
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = FontFamily.Monospace,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        NameField(name) { name = it }
                        if (p.entries.isNotEmpty() || p.important.isNotEmpty()) {
                            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                                val choices = listOf(Action.BLOCK to R.string.action_block, Action.ALLOW to R.string.action_allow)
                                choices.forEachIndexed { i, (a, l) ->
                                    SegmentedButton(action == a, { action = a }, SegmentedButtonDefaults.itemShape(i, 2)) {
                                        Text(stringResource(l))
                                    }
                                }
                            }
                        }
                        Text(
                            stringResource(R.string.import_lowest),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        },
        confirmButton = {
            if (done != null) {
                TextButton(onDismiss) { Text(stringResource(R.string.ok)) }
            } else {
                val okMsg = stringResource(R.string.import_done_sets)
                TextButton(enabled = plan?.empty == false && name.isNotBlank(), onClick = {
                    scope.launch(Dispatchers.Main) {
                        val ids = withContext(Dispatchers.IO) { app.firewall.applyImport(name.trim(), plan!!, action) }
                        done = String.format(okMsg, ids.size)
                    }
                }) { Text(stringResource(R.string.import_action)) }
            }
        },
        dismissButton = { if (done == null) TextButton(onDismiss) { Text(stringResource(R.string.cancel)) } }
    )
}

@Composable
fun ConfirmDialog(text: String, onDismiss: () -> Unit, onOk: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        text = { Text(text) },
        confirmButton = {
            TextButton({
                onOk()
                onDismiss()
            }) { Text(stringResource(R.string.delete), color = MaterialTheme.colorScheme.error) }
        },
        dismissButton = { TextButton(onDismiss) { Text(stringResource(R.string.cancel)) } }
    )
}

// ------------------------------------------------------------------ Sets & profiles

@Composable
fun SetsScreen(app: PacketwallApp, openDrawer: () -> Unit) {
    val undo = LocalUndo.current
    val profileDeletedMsg = stringResource(R.string.undo_profile_deleted)
    val st by app.firewall.state.collectAsState()
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var menu by remember { mutableStateOf(false) }
    var newSet by remember { mutableStateOf(false) }
    var newProfile by remember { mutableStateOf(false) }
    var editSet by remember { mutableStateOf<RuleSet?>(null) }
    var profileMenu by remember { mutableStateOf<Int?>(null) }
    var renameProfile by remember { mutableStateOf<Int?>(null) }
    var importJsonUri by remember { mutableStateOf<Uri?>(null) }

    val export = rememberFileExport("application/json")
    val openJson = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { importJsonUri = it }

    ScreenScaffold(title = stringResource(R.string.nav_sets), onMenu = openDrawer, actions = {
        IconButton(onClick = { menu = true }) { Icon(Icons.Filled.MoreVert, stringResource(R.string.more)) }
        DropdownMenu(menu, { menu = false }) {
            DropdownMenuItem({ Text(stringResource(R.string.export_json)) }, {
                menu = false
                export.launchText("packetwall-rules.json") { app.firewall.exportJson() }
            })
            DropdownMenuItem({ Text(stringResource(R.string.import_json)) }, {
                menu = false
                openJson.launch(arrayOf("application/json", "text/*", "*/*"))
            })
        }
    }) {
        Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 12.dp)) {
            ListSubheader(stringResource(R.string.profiles), Help.PROFILES)
            RoundedGroup {
                st.profiles.forEachIndexed { i, p ->
                    if (i > 0) HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
                    Box {
                        Row(
                            Modifier.fillMaxWidth().clickable { app.firewall.activateProfile(p.id) }.padding(end = 4.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            RadioButton(st.activeProfile == p.id, { app.firewall.activateProfile(p.id) })
                            Column(Modifier.weight(1f)) {
                                Text(p.name)
                                Text(
                                    stringResource(R.string.profile_summary, p.sets.count { it.enabled }, p.sets.size),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                            IconButton({ profileMenu = p.id }) { Icon(Icons.Filled.MoreVert, stringResource(R.string.more)) }
                        }
                        DropdownMenu(profileMenu == p.id, { profileMenu = null }) {
                            DropdownMenuItem({ Text(stringResource(R.string.rename)) }, {
                                profileMenu = null
                                renameProfile = p.id
                            })
                            DropdownMenuItem({ Text(stringResource(R.string.export)) }, {
                                profileMenu = null
                                export.launchText("packetwall-profile-${safeFileName(p.name)}.json") { app.firewall.exportProfile(p.id) }
                            })
                            DropdownMenuItem(
                                { Text(stringResource(R.string.delete)) },
                                {
                                    profileMenu = null
                                    val prev = app.firewall.state.value
                                    app.firewall.deleteProfile(p.id)
                                    undo?.offer(profileDeletedMsg.format(p.name)) { app.firewall.restore(prev) }
                                },
                                enabled = st.profiles.size > 1
                            )
                        }
                    }
                }
            }
            TextButton(onClick = { newProfile = true }) {
                Icon(Icons.Filled.Add, null)
                Spacer(Modifier.width(6.dp))
                Text(stringResource(R.string.profile_new))
            }

            ListSubheader(stringResource(R.string.sets_order), Help.SET_PRIORITY)
            ReorderableSets(app, st) { editSet = it }
            TextButton(onClick = { newSet = true }) {
                Icon(Icons.Filled.Add, null)
                Spacer(Modifier.width(6.dp))
                Text(stringResource(R.string.set_new))
            }
            Text(
                stringResource(R.string.sets_hint),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(start = 4.dp, bottom = 6.dp)
            )
            Spacer(Modifier.height(24.dp))
        }
    }

    if (newSet) {
        NameDialog(stringResource(R.string.set_new), "", { newSet = false }) {
            newSet = false
            app.firewall.addSet(it)
        }
    }
    if (newProfile) {
        NameDialog(stringResource(R.string.profile_new), "", { newProfile = false }) {
            newProfile = false
            app.firewall.addProfile(it)
        }
    }
    renameProfile?.let { id ->
        NameDialog(stringResource(R.string.rename), st.profiles.firstOrNull { it.id == id }?.name ?: "", { renameProfile = null }) {
            renameProfile = null
            app.firewall.renameProfile(id, it)
        }
    }
    editSet?.let { s -> SetDialog(app, s, st) { editSet = null } }
    importJsonUri?.let { uri -> ImportJsonDialog(app, uri) { importJsonUri = null } }
}

/** Long press a row and drag to change the priority; the first set wins. */
@Composable
private fun ReorderableSets(app: PacketwallApp, st: FwState, onEdit: (RuleSet) -> Unit) {
    val rowPx = with(LocalDensity.current) { 60.dp.toPx() }
    var dragIndex by remember { mutableIntStateOf(-1) }
    var dragOffset by remember { mutableFloatStateOf(0f) }
    val sets = st.orderedSets
    val ruleCounts = remember(st.rules) { st.rules.groupingBy { it.setId }.eachCount() }
    val divider = MaterialTheme.colorScheme.surfaceContainerHigh
    val currentSets by rememberUpdatedState(sets)

    RoundedGroup {
        // the gesture lives on the (non-moving) container, rows only get an offset
        Column(
            Modifier.pointerInput(Unit) {
                detectDragGesturesAfterLongPress(
                    onDragStart = { pos ->
                        dragIndex = (pos.y / rowPx).toInt().coerceIn(0, currentSets.size - 1)
                        dragOffset = 0f
                    },
                    onDragEnd = {
                        dragIndex = -1
                        dragOffset = 0f
                    },
                    onDragCancel = {
                        dragIndex = -1
                        dragOffset = 0f
                    }
                ) { change, amount ->
                    change.consume()
                    val cur = dragIndex
                    if (cur < 0) return@detectDragGesturesAfterLongPress
                    dragOffset += amount.y
                    val target = (cur + (dragOffset / rowPx).roundToInt()).coerceIn(0, currentSets.size - 1)
                    if (target != cur) {
                        app.firewall.moveSet(cur, target)
                        dragOffset -= (target - cur) * rowPx
                        dragIndex = target
                    }
                }
            }
        ) {
            val moveUp = stringResource(R.string.move_up)
            val moveDown = stringResource(R.string.move_down)
            sets.forEachIndexed { i, s ->
                val dragging = i == dragIndex
                val elevation by animateDpAsState(if (dragging) 8.dp else 0.dp, label = "drag")
                Row(
                    Modifier.fillMaxWidth().height(60.dp)
                        .zIndex(if (dragging) 1f else 0f)
                        .offset { IntOffset(0, if (dragging) dragOffset.roundToInt() else 0) }
                        .shadow(elevation)
                        .background(if (dragging) MaterialTheme.colorScheme.surfaceContainerHighest else Color.Transparent)
                        .drawBehind { if (i > 0 && !dragging) drawLine(divider, Offset(0f, 0f), Offset(size.width, 0f), 1.dp.toPx()) }
                        .clickable { onEdit(s) }
                        .semantics {
                            // TalkBack and switch access cannot drag: move with actions instead
                            customActions = listOfNotNull(
                                if (i > 0) CustomAccessibilityAction(moveUp) { app.firewall.moveSet(i, i - 1).let { true } } else null,
                                if (i <
                                    sets.lastIndex
                                ) {
                                    CustomAccessibilityAction(moveDown) { app.firewall.moveSet(i, i + 1).let { true } }
                                } else {
                                    null
                                }
                            )
                        }
                        .padding(start = 4.dp, end = 8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(Modifier.size(40.dp), contentAlignment = Alignment.Center) {
                        Icon(painterResource(R.drawable.ic_drag), stringResource(R.string.drag), tint = MaterialTheme.colorScheme.outline)
                    }
                    Text(
                        "${i + 1}",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.outline,
                        modifier = Modifier.width(22.dp)
                    )
                    Column(Modifier.weight(1f)) {
                        Text(s.name, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text(
                            if (s.kind == SetKind.BLOCKLIST) {
                                stringResource(R.string.set_blocklist_line, s.entries)
                            } else {
                                (ruleCounts[s.id] ?: 0).let { n -> pluralStringResource(R.plurals.rules_n, n, n) }
                            },
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Switch(st.isEnabled(s.id), { app.firewall.setEnabled(s.id, it) })
                }
            }
        }
    }
}

@Composable
private fun SetDialog(app: PacketwallApp, s: RuleSet, st: FwState, onDismiss: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var name by remember { mutableStateOf(s.name) }
    var confirm by remember { mutableStateOf(false) }
    val export = rememberFileExport("*/*")
    val safe = safeFileName(s.name)
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(s.name) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                NameField(name) { name = it }
                FieldLabel(stringResource(R.string.export))
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    TextButton({
                        export.launchText("$safe.json") { app.firewall.exportJson(s.id) }
                    }) { Text("JSON") }
                    TextButton({
                        export.launchText("$safe.hosts") { app.firewall.exportPlain(s.id, hosts = true) }
                    }) { Text("hosts") }
                    TextButton({
                        export.launchText("$safe.txt") { app.firewall.exportPlain(s.id, hosts = false) }
                    }) { Text(stringResource(R.string.domains)) }
                }
                if (s.id != FwState.DEFAULT_SET) {
                    TextButton({ confirm = true }) { Text(stringResource(R.string.delete_set), color = MaterialTheme.colorScheme.error) }
                }
            }
        },
        confirmButton = {
            TextButton({
                if (name.isNotBlank()) app.firewall.renameSet(s.id, name)
                onDismiss()
            }) { Text(stringResource(R.string.save)) }
        },
        dismissButton = { TextButton(onDismiss) { Text(stringResource(R.string.cancel)) } }
    )
    if (confirm) {
        val n = st.rules.count { it.setId == s.id }
        val q = if (s.kind ==
            SetKind.BLOCKLIST
        ) {
            stringResource(R.string.delete_set_q, s.name)
        } else {
            stringResource(R.string.delete_set_rules_q, s.name, n)
        }
        ConfirmDialog(q, { confirm = false }) {
            app.firewall.deleteSet(s.id)
            onDismiss()
        }
    }
}

@Composable
private fun ImportJsonDialog(app: PacketwallApp, uri: Uri, onDismiss: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var file by remember { mutableStateOf<Pair<String, ExportFile>?>(null) }
    var problem by remember { mutableStateOf<Problem?>(null) }
    var replace by remember { mutableStateOf(false) }
    var confirmReplace by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<String?>(null) }
    var replaced by remember { mutableStateOf(false) }
    val fmt = stringResource(R.string.import_json_done)
    val restoredMsg = stringResource(R.string.import_restored)

    LaunchedEffect(uri) {
        try {
            file = withContext(Dispatchers.IO) {
                val text = ctx.contentResolver.openInputStream(uri)!!.readCapped(Limits.IMPORT_BYTES, "import").toString(Charsets.UTF_8)
                text to FirewallStore.json.decodeFromString(ExportFile.serializer(), text)
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            problem = Problem.of(e)
        }
    }
    val full = file?.second?.state?.profiles?.isNotEmpty() == true

    fun run() {
        val text = file?.first ?: return
        busy = true
        scope.launch(Dispatchers.Main) {
            try {
                val sum = withContext(Dispatchers.IO) { app.firewall.importJson(text, replace) }
                replaced = replace
                result = String.format(fmt, sum.sets, sum.rules, sum.groups, sum.profiles)
            } catch (e: Exception) {
                problem = Problem.of(e)
            }
            busy = false
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.import_json)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                val f = file?.second
                when {
                    problem != null -> Text(problemText(problem!!), color = MaterialTheme.colorScheme.error)
                    result != null -> Text(result!!)
                    f == null || busy -> CircularProgressIndicator()
                    confirmReplace -> Text(stringResource(R.string.import_replace_confirm))
                    else -> {
                        Text(
                            stringResource(
                                R.string.import_file_has,
                                f.state.sets.size,
                                f.state.rules.size,
                                f.state.groups.size,
                                f.state.profiles.size
                            ),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        // subscriptions are downloaded right after the import (and daily): show where from
                        val urls = f.state.sets.mapNotNull { it.url }.distinct()
                        if (urls.isNotEmpty()) {
                            Text(
                                stringResource(R.string.import_will_download) + "\n" + urls.joinToString("\n"),
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = FontFamily.Monospace
                            )
                        }
                        Row(Modifier.fillMaxWidth().clickable { replace = false }, verticalAlignment = Alignment.CenterVertically) {
                            RadioButton(!replace, { replace = false })
                            Text(stringResource(R.string.import_merge))
                        }
                        Row(
                            Modifier.fillMaxWidth().clickable(enabled = full) { replace = true },
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            RadioButton(replace, { replace = true }, enabled = full)
                            Column {
                                Text(
                                    stringResource(R.string.import_replace),
                                    color = if (full) Color.Unspecified else MaterialTheme.colorScheme.outline
                                )
                                if (!full) {
                                    Text(
                                        stringResource(R.string.import_replace_full_only),
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            when {
                result != null && replaced -> Row {
                    TextButton({
                        scope.launch(Dispatchers.Main) {
                            val ok = withContext(Dispatchers.IO) { app.firewall.restoreReplaceBackup() }
                            if (ok) Toast.makeText(ctx, restoredMsg, Toast.LENGTH_SHORT).show()
                            onDismiss()
                        }
                    }) { Text(stringResource(R.string.import_restore)) }
                    TextButton(onDismiss) { Text(stringResource(R.string.ok)) }
                }
                result != null || problem != null -> TextButton(onDismiss) { Text(stringResource(R.string.ok)) }
                confirmReplace -> TextButton({ run() }, enabled = !busy) {
                    Text(stringResource(R.string.import_replace_action), color = MaterialTheme.colorScheme.error)
                }
                else -> TextButton({ if (replace) confirmReplace = true else run() }, enabled = file != null && !busy) {
                    Text(stringResource(R.string.import_action))
                }
            }
        },
        dismissButton = { if (result == null && problem == null) TextButton(onDismiss) { Text(stringResource(R.string.cancel)) } }
    )
}

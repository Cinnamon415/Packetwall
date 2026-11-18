package io.github.cinnamon415.packetwall.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Badge
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.github.cinnamon415.packetwall.PacketwallApp
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.fw.ListParser
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** How a normalized list entry reads: "!" = allow, "=" = this name only, else + subdomains. */
@Composable
private fun EntryText(
    entry: String,
    line: String? = null,
    badge: String? = null,
    lead: @Composable () -> Unit = {},
    trail: @Composable () -> Unit = {}
) {
    val allow = entry.startsWith("!")
    val body = entry.removePrefix("!")
    val exact = body.startsWith("=")
    val name = body.removePrefix("=")
    Row(Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 2.dp), verticalAlignment = Alignment.CenterVertically) {
        lead()
        Column(Modifier.weight(1f).padding(start = 4.dp)) {
            Text(name, fontFamily = FontFamily.Monospace, maxLines = 1, overflow = TextOverflow.Ellipsis)
            val desc = listOfNotNull(
                if (allow) stringResource(R.string.entry_allow) else null,
                stringResource(if (exact) R.string.entry_exact else R.string.entry_subdomains),
                line
            ).joinToString(" · ")
            Text(desc, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        badge?.let {
            Badge(containerColor = MaterialTheme.colorScheme.errorContainer, contentColor = MaterialTheme.colorScheme.onErrorContainer) {
                Text(it)
            }
        }
        trail()
    }
}

/** One list: its entries with search, and the user's edits that survive updates. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ListScreen(app: PacketwallApp, id: Int, onBack: () -> Unit) {
    val st by app.firewall.state.collectAsState()
    val set = st.set(id)
    if (set == null) {
        LaunchedEffect(Unit) { onBack() }
        return
    }
    var tab by rememberSaveable { mutableIntStateOf(0) }
    var query by rememberSaveable { mutableStateOf("") }
    var settings by remember { mutableStateOf(false) }
    var adding by remember { mutableStateOf(false) }
    var confirmReset by remember { mutableStateOf(false) }
    // the downloaded entries (reloaded when the list is updated)
    val entries by produceState<List<String>?>(null, set.updated, set.entries) {
        value = withContext(Dispatchers.IO) { app.firewall.readList(id) }
    }
    val disabled = set.disabled.toHashSet()
    val edits = set.disabled.size + set.added.size

    ScreenScaffold(
        title = set.name,
        subtitle = stringResource(R.string.list_stats, set.entries, set.skipped, formatDate(set.updated)),
        onBack = onBack,
        actions = { IconButton({ settings = true }) { Icon(Icons.Filled.Settings, stringResource(R.string.list_settings)) } }
    ) {
        PrimaryTabRow(selectedTabIndex = tab) {
            Tab(tab == 0, { tab = 0 }, text = { Text(stringResource(R.string.list_entries)) })
            Tab(tab == 1, { tab = 1 }, text = { Text(stringResource(R.string.list_my_edits, edits)) })
        }
        Box(Modifier.fillMaxSize()) {
            if (tab == 0) {
                Column {
                    SearchField(query) { query = it }
                    val all = entries
                    if (all == null) {
                        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
                    } else {
                        val needle = query.trim().lowercase()
                        val found =
                            remember(all, needle) {
                                if (needle.isEmpty()) {
                                    all.take(SHOWN)
                                } else {
                                    all.asSequence().filter {
                                        it.contains(needle)
                                    }.take(SHOWN).toList()
                                }
                            }
                        if (found.size == SHOWN) {
                            Text(
                                stringResource(R.string.list_shown_first, SHOWN),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.padding(horizontal = 16.dp)
                            )
                        }
                        LazyColumn(contentPadding = PaddingValues(bottom = 96.dp)) {
                            items(found, key = { it }) { e ->
                                val off = e in disabled
                                EntryText(
                                    e,
                                    line = if (off) stringResource(R.string.entry_off) else null,
                                    lead = { Checkbox(!off, { on -> app.firewall.setEntryDisabled(id, e, !on) }) }
                                )
                                HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
                            }
                        }
                    }
                }
            } else {
                val inList = remember(entries) { entries?.toHashSet() ?: emptySet() }
                LazyColumn(contentPadding = PaddingValues(12.dp, 8.dp, 12.dp, 96.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    item {
                        Text(
                            stringResource(R.string.list_edits_hint),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    if (set.disabled.isNotEmpty()) {
                        item { ListSubheader(stringResource(R.string.list_switched_off)) }
                        item {
                            RoundedGroup {
                                set.disabled.forEachIndexed { i, e ->
                                    if (i > 0) HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
                                    EntryText(
                                        e,
                                        badge = if (entries != null && e !in inList) stringResource(R.string.edit_outdated) else null,
                                        trail = {
                                            TextButton({
                                                app.firewall.setEntryDisabled(id, e, false)
                                            }) { Text(stringResource(R.string.edit_restore)) }
                                        }
                                    )
                                }
                            }
                        }
                    }
                    if (set.added.isNotEmpty()) {
                        item { ListSubheader(stringResource(R.string.list_added)) }
                        item {
                            RoundedGroup {
                                set.added.forEachIndexed { i, e ->
                                    if (i > 0) HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
                                    EntryText(e, trail = {
                                        IconButton({
                                            app.firewall.removeAdded(id, e)
                                        }) { Icon(Icons.Filled.Close, stringResource(R.string.delete)) }
                                    })
                                }
                            }
                        }
                    }
                    if (edits == 0) {
                        item { EmptyHint(stringResource(R.string.list_no_edits)) }
                    } else {
                        item {
                            OutlinedButton({ confirmReset = true }) { Text(stringResource(R.string.list_reset_edits)) }
                        }
                    }
                }
            }
            ExtendedFloatingActionButton(
                onClick = { adding = true },
                icon = { Icon(Icons.Filled.Add, null) },
                text = { Text(stringResource(R.string.list_add_entry)) },
                modifier = Modifier.align(Alignment.BottomEnd).padding(16.dp)
            )
        }
    }
    if (settings) BlocklistDetails(app, set) { settings = false }
    if (confirmReset) {
        ConfirmDialog(stringResource(R.string.list_reset_q, edits), { confirmReset = false }) {
            confirmReset = false
            app.firewall.resetEdits(id)
        }
    }
    if (adding) {
        AddEntryDialog({ adding = false }) { normalized ->
            adding = false
            app.firewall.addEntries(id, normalized)
        }
    }
}

/** A domain, an IP/CIDR, or any list syntax (||x^, @@, hosts lines), normalized like a downloaded list. */
@Composable
private fun AddEntryDialog(onDismiss: () -> Unit, onAdd: (List<String>) -> Unit) {
    var text by remember { mutableStateOf("") }
    val parsed = remember(text) { if (text.isBlank()) emptyList() else ListParser.parse(text.lineSequence()).entries }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.list_add_entry)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                OutlinedTextField(
                    text,
                    { text = it },
                    Modifier.fillMaxWidth(),
                    textStyle = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace),
                    placeholder = { Text("tracker.example.com", fontFamily = FontFamily.Monospace) },
                    isError = text.isNotBlank() && parsed.isEmpty(),
                    minLines = 2
                )
                Text(
                    stringResource(R.string.list_add_entry_hint),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        },
        confirmButton = { TextButton({ onAdd(parsed) }, enabled = parsed.isNotEmpty()) { Text(stringResource(R.string.add)) } },
        dismissButton = { TextButton(onDismiss) { Text(stringResource(R.string.cancel)) } }
    )
}

private const val SHOWN = 300

package io.github.cinnamon415.packetwall.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Badge
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
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
import io.github.cinnamon415.packetwall.engine.AppInfo
import io.github.cinnamon415.packetwall.fw.Action
import io.github.cinnamon415.packetwall.fw.AppGroup
import io.github.cinnamon415.packetwall.fw.FwState
import io.github.cinnamon415.packetwall.fw.Rule
import io.github.cinnamon415.packetwall.fw.Target
import io.github.cinnamon415.packetwall.fw.TargetKind
import io.github.cinnamon415.packetwall.fw.Who
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@Composable
private fun SearchField(q: String, onChange: (String) -> Unit) {
    OutlinedTextField(q, onChange, Modifier.fillMaxWidth().padding(horizontal = 12.dp), singleLine = true,
        leadingIcon = { Icon(Icons.Filled.Search, null) }, placeholder = { Text(stringResource(R.string.search)) })
}

// ------------------------------------------------------------------ Apps

@Composable
fun AppsScreen(app: PacketwallApp, openDrawer: () -> Unit, onOpenApp: (String) -> Unit, onOpenGroup: (Int) -> Unit) {
    val st by app.firewall.state.collectAsState()
    val all by produceState<List<AppInfo>?>(null) { value = withContext(Dispatchers.IO) { app.apps.installed() } }
    var q by rememberSaveable { mutableStateOf("") }
    var showSystem by rememberSaveable { mutableStateOf(false) }
    var onlyWithRules by rememberSaveable { mutableStateOf(false) }
    var setFilter by rememberSaveable { mutableStateOf<Int?>(null) }
    var menu by remember { mutableStateOf(false) }
    var newGroup by remember { mutableStateOf(false) }
    var sort by rememberSaveable { mutableStateOf(0) } // 0 rules, 1 name, 2 traffic
    val conns by app.connections.conns.collectAsState()
    val traffic = remember(conns) { conns.groupBy { it.app.packageName }.mapValues { (_, l) -> l.sumOf { it.bytes } } }

    val counts = remember(st, setFilter) {
        st.rules.filter { setFilter == null || it.setId == setFilter }
            .mapNotNull { (it.who as? Who.App)?.pkg }.groupingBy { it }.eachCount()
    }
    val groupCounts = remember(st, setFilter) {
        st.rules.filter { setFilter == null || it.setId == setFilter }
            .mapNotNull { (it.who as? Who.Group)?.id }.groupingBy { it }.eachCount()
    }
    val needle = q.trim().lowercase()
    val list = (all ?: emptyList()).filter { a ->
        (showSystem || !a.isSystem || counts.containsKey(a.packageName)) &&
            (!onlyWithRules || counts.containsKey(a.packageName)) &&
            (needle.isEmpty() || a.name.lowercase().contains(needle) || a.packageName.contains(needle))
    }.sortedWith(when (sort) {
        1 -> compareBy { it.name.lowercase() }
        2 -> compareByDescending<AppInfo> { traffic[it.packageName] ?: 0L }.thenBy { it.name.lowercase() }
        else -> compareByDescending<AppInfo> { counts[it.packageName] ?: 0 }.thenBy { it.name.lowercase() }
    })

    ScreenScaffold(title = stringResource(R.string.nav_apps), subtitle = all?.let { "${list.size}" }, onMenu = openDrawer, actions = {
        IconButton(onClick = { menu = true }) { Icon(Icons.Filled.MoreVert, null) }
        DropdownMenu(menu, { menu = false }) {
            DropdownMenuItem({ Text(stringResource(R.string.show_system)) }, { showSystem = !showSystem },
                trailingIcon = { Checkbox(showSystem, null) })
            DropdownMenuItem({ Text(stringResource(R.string.only_with_rules)) }, { onlyWithRules = !onlyWithRules },
                trailingIcon = { Checkbox(onlyWithRules, null) })
            HorizontalDivider()
            listOf(R.string.sort_rules, R.string.sort_name, R.string.sort_traffic).forEachIndexed { i, s ->
                DropdownMenuItem({ Text(stringResource(s)) }, { sort = i; menu = false }, trailingIcon = { if (sort == i) Text("✓") })
            }
            HorizontalDivider()
            DropdownMenuItem({ Text(stringResource(R.string.group_new)) }, { menu = false; newGroup = true })
        }
    }) {
        SearchField(q) { q = it }
        Spacer(Modifier.height(6.dp))
        SetChips(st, setFilter, { setFilter = it })
        HorizontalDivider(Modifier.padding(top = 6.dp))
        if (all == null) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { Text(stringResource(R.string.loading)) }
            return@ScreenScaffold
        }
        LazyColumn(contentPadding = PaddingValues(bottom = 24.dp)) {
            if (st.groups.isNotEmpty() && needle.isEmpty()) {
                item { ListSubheader(stringResource(R.string.groups)) }
                items(st.groups, key = { "g${it.id}" }) { g ->
                    Row(Modifier.fillMaxWidth().clickable { onOpenGroup(g.id) }.padding(horizontal = 12.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically) {
                        Surface(Modifier.size(40.dp), shape = RoundedCornerShape(12.dp), color = MaterialTheme.colorScheme.secondaryContainer) {
                            Box(contentAlignment = Alignment.Center) { Icon(painterResource(R.drawable.ic_apps), null) }
                        }
                        Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f)) {
                            Text(g.name, fontWeight = FontWeight.SemiBold)
                            Text(stringResource(R.string.group_members, g.packages.size), style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        groupCounts[g.id]?.let { Badge(containerColor = MaterialTheme.colorScheme.secondaryContainer, contentColor = MaterialTheme.colorScheme.onSecondaryContainer) { Text("$it") } }
                        Chevron()
                    }
                }
                item { ListSubheader(stringResource(R.string.nav_apps)) }
            }
            items(list, key = { it.packageName }) { a ->
                Row(Modifier.fillMaxWidth().clickable { onOpenApp(a.packageName) }.padding(horizontal = 12.dp, vertical = 7.dp),
                    verticalAlignment = Alignment.CenterVertically) {
                    AppIcon(a, 40.dp)
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        Text(a.name, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text(listOfNotNull(a.packageName, traffic[a.packageName]?.takeIf { it > 0 }?.let { formatBytes(it) }).joinToString(" · "),
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                    counts[a.packageName]?.let { Badge(containerColor = MaterialTheme.colorScheme.secondaryContainer, contentColor = MaterialTheme.colorScheme.onSecondaryContainer) { Text("$it") } }
                    Chevron()
                }
            }
        }
    }
    if (newGroup) NameDialog(stringResource(R.string.group_new), "", onDismiss = { newGroup = false }) { name ->
        newGroup = false
        onOpenGroup(app.firewall.saveGroup(AppGroup(0, name)))
    }
}

@Composable
fun Chevron() {
    Text("›", color = MaterialTheme.colorScheme.outline, style = MaterialTheme.typography.titleLarge,
        modifier = Modifier.padding(start = 8.dp))
}

@Composable
fun ListSubheader(text: String) {
    Text(text, style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(start = 16.dp, top = 12.dp, bottom = 4.dp))
}

// ------------------------------------------------------------------ App / group rules

/** Rules of one app (or app group) in every set. */
@Composable
fun WhoRulesScreen(app: PacketwallApp, who: Who, onBack: () -> Unit) {
    val st by app.firewall.state.collectAsState()
    val info = (who as? Who.App)?.let { remember(it.pkg) { app.apps.byPackage(it.pkg) } }
    val group = (who as? Who.Group)?.let { st.group(it.id) }
    var editing by remember { mutableStateOf<Rule?>(null) }
    var menu by remember { mutableStateOf(false) }
    var rename by remember { mutableStateOf(false) }
    var members by remember { mutableStateOf(false) }

    if (who is Who.Group && group == null) { LaunchedEffect(Unit) { onBack() }; return }

    val rules = st.rules.filter { it.who == who }
        .sortedWith(compareBy<Rule> { r -> st.order.indexOfFirst { it.id == r.setId } }.thenBy { it.target.kind }.thenBy { it.target.value })
    val title = info?.name ?: group?.name ?: (who as? Who.App)?.pkg ?: ""
    val subtitle = info?.let { "${it.packageName} · uid ${it.uid}" } ?: group?.let { stringResource(R.string.group_members, it.packages.size) }

    ScreenScaffold(title = title, subtitle = subtitle, onBack = onBack, actions = {
        if (group != null) {
            IconButton(onClick = { menu = true }) { Icon(Icons.Filled.MoreVert, null) }
            DropdownMenu(menu, { menu = false }) {
                DropdownMenuItem({ Text(stringResource(R.string.group_members_edit)) }, { menu = false; members = true })
                DropdownMenuItem({ Text(stringResource(R.string.rename)) }, { menu = false; rename = true })
                DropdownMenuItem({ Text(stringResource(R.string.delete), color = MaterialTheme.colorScheme.error) },
                    { menu = false; app.firewall.deleteGroup(group.id) })
            }
        }
    }) {
        Box(Modifier.fillMaxSize()) {
            Column(Modifier.padding(horizontal = 12.dp)) {
                if (info == null && who is Who.App) EmptyHint(stringResource(R.string.app_not_installed))
                if (rules.isEmpty()) EmptyHint(stringResource(R.string.no_rules_app))
                else {
                    Spacer(Modifier.height(4.dp))
                    RulesList(rules, st, withSet = true, withWho = false, app = app) { editing = it }
                }
            }
            ExtendedFloatingActionButton(onClick = {
                editing = Rule(0, FwState.DEFAULT_SET, who, Target(TargetKind.ALL), Action.BLOCK)
            }, icon = { Icon(Icons.Filled.Add, null) }, text = { Text(stringResource(R.string.rule_add)) },
                modifier = Modifier.align(Alignment.BottomEnd).padding(16.dp))
        }
    }
    editing?.let { r ->
        RuleEditorDialog(r, st, onSave = { app.firewall.saveRule(it); editing = null },
            onDelete = if (r.id != 0) {{ app.firewall.deleteRule(r.id); editing = null }} else null,
            onDismiss = { editing = null })
    }
    if (rename && group != null) NameDialog(stringResource(R.string.rename), group.name, { rename = false }) {
        rename = false; app.firewall.saveGroup(group.copy(name = it))
    }
    if (members && group != null) GroupMembersDialog(app, group, { members = false }) {
        members = false; app.firewall.saveGroup(group.copy(packages = it))
    }
}

@Composable
private fun GroupMembersDialog(app: PacketwallApp, g: AppGroup, onDismiss: () -> Unit, onSave: (List<String>) -> Unit) {
    val all by produceState<List<AppInfo>>(emptyList()) {
        value = withContext(Dispatchers.IO) { app.apps.installed().sortedBy { it.name.lowercase() } }
    }
    var sel by remember { mutableStateOf(g.packages.toSet()) }
    var q by remember { mutableStateOf("") }
    AlertDialog(onDismissRequest = onDismiss, title = { Text(g.name) },
        text = {
            Column {
                OutlinedTextField(q, { q = it }, Modifier.fillMaxWidth(), singleLine = true,
                    leadingIcon = { Icon(Icons.Filled.Search, null) })
                LazyColumn(Modifier.height(380.dp)) {
                    val n = q.trim().lowercase()
                    items(all.filter { n.isEmpty() || it.name.lowercase().contains(n) || it.packageName.contains(n) }, key = { it.packageName }) { a ->
                        Row(Modifier.fillMaxWidth().clickable { sel = if (a.packageName in sel) sel - a.packageName else sel + a.packageName },
                            verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(a.packageName in sel, null)
                            AppIcon(a, 28.dp)
                            Spacer(Modifier.width(8.dp))
                            Text(a.name, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        }
                    }
                }
            }
        },
        confirmButton = { TextButton({ onSave(sel.toList().sorted()) }) { Text(stringResource(R.string.save)) } },
        dismissButton = { TextButton(onDismiss) { Text(stringResource(R.string.cancel)) } })
}

@Composable
fun NameDialog(title: String, initial: String, onDismiss: () -> Unit, onOk: (String) -> Unit) {
    var v by remember { mutableStateOf(initial) }
    AlertDialog(onDismissRequest = onDismiss, title = { Text(title) },
        text = { OutlinedTextField(v, { v = it }, singleLine = true, label = { Text(stringResource(R.string.name)) }) },
        confirmButton = { TextButton({ onOk(v.trim()) }, enabled = v.isNotBlank()) { Text(stringResource(R.string.ok)) } },
        dismissButton = { TextButton(onDismiss) { Text(stringResource(R.string.cancel)) } })
}

// ------------------------------------------------------------------ Global rules

@Composable
fun GlobalScreen(app: PacketwallApp, openDrawer: () -> Unit) {
    val st by app.firewall.state.collectAsState()
    var q by rememberSaveable { mutableStateOf("") }
    var setFilter by rememberSaveable { mutableStateOf<Int?>(null) }
    var kind by rememberSaveable { mutableStateOf<TargetKind?>(null) }
    var portsOnly by rememberSaveable { mutableStateOf(false) }
    var editing by remember { mutableStateOf<Rule?>(null) }
    var sortNew by rememberSaveable { mutableStateOf(false) }
    var menu by remember { mutableStateOf(false) }

    val needle = q.trim().lowercase()
    val rules = st.rules.filter { r ->
        r.who == Who.Global && (setFilter == null || r.setId == setFilter) &&
            (kind == null || r.target.kind == kind) && (!portsOnly || r.port != 0 || r.proto != io.github.cinnamon415.packetwall.fw.Proto.ANY) &&
            (needle.isEmpty() || r.target.value.contains(needle))
    }.let { l -> if (sortNew) l.sortedByDescending { it.created } else l.sortedWith(compareBy({ it.target.kind }, { it.target.value })) }

    ScreenScaffold(title = stringResource(R.string.nav_global), subtitle = "${rules.size}", onMenu = openDrawer, actions = {
        IconButton(onClick = { menu = true }) { Icon(Icons.Filled.MoreVert, null) }
        DropdownMenu(menu, { menu = false }) {
            DropdownMenuItem({ Text(stringResource(R.string.sort_name)) }, { sortNew = false; menu = false },
                trailingIcon = { if (!sortNew) Text("✓") })
            DropdownMenuItem({ Text(stringResource(R.string.sort_new)) }, { sortNew = true; menu = false },
                trailingIcon = { if (sortNew) Text("✓") })
        }
    }) {
        Box(Modifier.fillMaxSize()) {
            Column {
                SearchField(q) { q = it }
                Spacer(Modifier.height(6.dp))
                SetChips(st, setFilter, { setFilter = it })
                Row(Modifier.horizontalScroll(rememberScrollState()).padding(horizontal = 12.dp), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    listOf(TargetKind.DOMAIN to R.string.kind_hosts, TargetKind.IP to R.string.kind_ip,
                        TargetKind.ASN to R.string.kind_asn, TargetKind.COUNTRY to R.string.kind_countries, TargetKind.ALL to R.string.target_all).forEach { (k, s) ->
                        FilterChip(kind == k, { kind = if (kind == k) null else k }, { Text(stringResource(s)) })
                    }
                    FilterChip(portsOnly, { portsOnly = !portsOnly }, { Text(stringResource(R.string.kind_ports)) })
                }
                LazyColumn(contentPadding = PaddingValues(start = 12.dp, end = 12.dp, top = 4.dp, bottom = 88.dp)) {
                    if (rules.isEmpty()) item { EmptyHint(stringResource(R.string.no_rules_global)) }
                    else item { RulesList(rules, st, withSet = setFilter == null, withWho = false, app = app) { editing = it } }
                }
            }
            ExtendedFloatingActionButton(onClick = {
                editing = Rule(0, setFilter ?: FwState.DEFAULT_SET, Who.Global, Target(TargetKind.DOMAIN, "", true), Action.BLOCK)
            }, icon = { Icon(Icons.Filled.Add, null) }, text = { Text(stringResource(R.string.rule_add)) },
                modifier = Modifier.align(Alignment.BottomEnd).padding(16.dp))
        }
    }
    editing?.let { r ->
        RuleEditorDialog(r, st, onSave = { app.firewall.saveRule(it); editing = null },
            onDelete = if (r.id != 0) {{ app.firewall.deleteRule(r.id); editing = null }} else null,
            onDismiss = { editing = null })
    }
}


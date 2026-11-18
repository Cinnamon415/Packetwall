package io.github.cinnamon415.packetwall.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Badge
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Surface
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
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.cinnamon415.packetwall.PacketwallApp
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.engine.AppInfo
import io.github.cinnamon415.packetwall.fw.Action
import io.github.cinnamon415.packetwall.fw.AppGroup
import io.github.cinnamon415.packetwall.fw.FwState
import io.github.cinnamon415.packetwall.fw.Proto
import io.github.cinnamon415.packetwall.fw.Rule
import io.github.cinnamon415.packetwall.fw.Target
import io.github.cinnamon415.packetwall.fw.TargetKind
import io.github.cinnamon415.packetwall.fw.Who
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@Composable
internal fun SearchField(q: String, onChange: (String) -> Unit) {
    OutlinedTextField(
        q,
        onChange,
        Modifier.fillMaxWidth().padding(horizontal = 12.dp),
        singleLine = true,
        leadingIcon = { Icon(Icons.Filled.Search, null) },
        placeholder = { Text(stringResource(R.string.search)) }
    )
}

// ------------------------------------------------------------------ Apps

/** Global rules matching the screen's filters; newest first or by kind and value. Pure. */
fun globalRules(all: List<Rule>, search: String, setId: Int?, kind: TargetKind?, portsOnly: Boolean, newestFirst: Boolean): List<Rule> {
    val needle = search.trim().lowercase()
    val shown = all.filter { r ->
        r.who == Who.Global &&
            (setId == null || r.setId == setId) &&
            (kind == null || r.target.kind == kind) &&
            (!portsOnly || r.port != 0 || r.proto != Proto.ANY) &&
            (needle.isEmpty() || r.target.value.contains(needle))
    }
    return if (newestFirst) {
        shown.sortedByDescending {
            it.created
        }
    } else {
        shown.sortedWith(compareBy({ it.target.kind }, { it.target.value }))
    }
}

@Composable
fun AppsScreen(app: PacketwallApp, openDrawer: () -> Unit, onOpenApp: (String) -> Unit, onOpenGroup: (Int) -> Unit) {
    val st by app.firewall.state.collectAsState()
    val vm = appViewModel(app) { a, saved -> AppsViewModel(a, saved) }
    val q by vm.query.collectAsStateWithLifecycle()
    val view by vm.list.collectAsStateWithLifecycle()
    val list = view.apps ?: emptyList()
    val counts = view.ruleCounts
    val groupCounts = view.groupRuleCounts
    val traffic = view.traffic
    var menu by remember { mutableStateOf(false) }
    var newGroup by remember { mutableStateOf(false) }

    ScreenScaffold(title = stringResource(R.string.nav_apps), subtitle = view.apps?.let { "${it.size}" }, onMenu = openDrawer, actions = {
        IconButton(onClick = { menu = true }) { Icon(Icons.Filled.MoreVert, stringResource(R.string.more)) }
        DropdownMenu(menu, { menu = false }) {
            DropdownMenuItem(
                { Text(stringResource(R.string.show_system)) },
                { vm.setQuery { it.copy(showSystem = !it.showSystem) } },
                trailingIcon = { Checkbox(q.showSystem, null) }
            )
            DropdownMenuItem(
                { Text(stringResource(R.string.only_with_rules)) },
                { vm.setQuery { it.copy(onlyWithRules = !it.onlyWithRules) } },
                trailingIcon = { Checkbox(q.onlyWithRules, null) }
            )
            HorizontalDivider()
            val sorts = listOf(R.string.sort_rules, R.string.sort_name, R.string.sort_traffic)
            AppSort.entries.zip(sorts).forEach { (sort, label) ->
                DropdownMenuItem({ Text(stringResource(label)) }, {
                    vm.setQuery { it.copy(sort = sort) }
                    menu = false
                }, trailingIcon = { if (q.sort == sort) Text("✓") })
            }
        }
    }) {
        SearchField(vm.search, vm::updateSearch)
        Spacer(Modifier.height(6.dp))
        SetChips(st, q.setId, { id -> vm.setQuery { it.copy(setId = id) } })
        HorizontalDivider(Modifier.padding(top = 6.dp))
        if (view.apps == null) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { Text(stringResource(R.string.loading)) }
            return@ScreenScaffold
        }
        LazyColumn(contentPadding = PaddingValues(bottom = 24.dp)) {
            if (vm.search.isBlank()) {
                item { ListSubheader(stringResource(R.string.groups)) }
                items(st.groups, key = { "g${it.id}" }) { g ->
                    Row(
                        Modifier.fillMaxWidth().clickable { onOpenGroup(g.id) }.padding(horizontal = 12.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Surface(
                            Modifier.size(40.dp),
                            shape = RoundedCornerShape(12.dp),
                            color = MaterialTheme.colorScheme.secondaryContainer
                        ) {
                            Box(contentAlignment = Alignment.Center) { Icon(painterResource(R.drawable.ic_apps), null) }
                        }
                        Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f)) {
                            Text(g.name, fontWeight = FontWeight.SemiBold)
                            Text(
                                stringResource(R.string.group_members, g.packages.size),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        groupCounts[g.id]?.let {
                            Badge(
                                containerColor = MaterialTheme.colorScheme.secondaryContainer,
                                contentColor = MaterialTheme.colorScheme.onSecondaryContainer
                            ) {
                                Text("$it")
                            }
                        }
                        Chevron()
                    }
                }
                item {
                    TextButton(onClick = { newGroup = true }, modifier = Modifier.padding(horizontal = 4.dp)) {
                        Icon(Icons.Filled.Add, null)
                        Spacer(Modifier.width(6.dp))
                        Text(stringResource(R.string.group_new))
                    }
                }
                item { ListSubheader(stringResource(R.string.nav_apps)) }
            }
            items(list, key = { it.packageName }) { a ->
                Row(
                    Modifier.fillMaxWidth().clickable { onOpenApp(a.packageName) }.padding(horizontal = 12.dp, vertical = 7.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    AppIcon(a, 40.dp)
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        Text(a.name, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text(
                            listOfNotNull(
                                a.packageName,
                                traffic[a.packageName]?.takeIf {
                                    it > 0
                                }?.let { formatBytes(it) }
                            ).joinToString(" · "),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                    counts[a.packageName]?.let {
                        Badge(
                            containerColor = MaterialTheme.colorScheme.secondaryContainer,
                            contentColor = MaterialTheme.colorScheme.onSecondaryContainer
                        ) {
                            Text("$it")
                        }
                    }
                    Chevron()
                }
            }
        }
    }
    if (newGroup) {
        NameDialog(stringResource(R.string.group_new), "", onDismiss = { newGroup = false }) { name ->
            newGroup = false
            onOpenGroup(app.firewall.saveGroup(AppGroup(0, name)))
        }
    }
}

@Composable
fun Chevron() {
    // decoration: the row itself is the button
    Text(
        "›",
        color = MaterialTheme.colorScheme.outline,
        style = MaterialTheme.typography.titleLarge,
        modifier = Modifier.padding(start = 8.dp).clearAndSetSemantics {}
    )
}

@Composable
fun ListSubheader(text: String, help: Help? = null) {
    if (help == null) {
        Text(
            text,
            style = MaterialTheme.typography.labelLarge,
            color = MaterialTheme.colorScheme.primary,
            modifier = Modifier.padding(start = 16.dp, top = 12.dp, bottom = 4.dp)
        )
    } else {
        TitleWithInfo(text, help, Modifier.padding(start = 16.dp, top = 4.dp)) {
            Text(it, style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
        }
    }
}

// ------------------------------------------------------------------ App / group rules

/** Rules of one app (or app group) in every set. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WhoRulesScreen(app: PacketwallApp, who: Who, onBack: () -> Unit, onOpenGroup: (Int) -> Unit = {}, initialTab: Int = 0) {
    val undo = LocalUndo.current
    val ruleDeletedMsg = stringResource(R.string.undo_rule_deleted)
    val groupDeletedMsg = stringResource(R.string.undo_group_deleted)
    val st by app.firewall.state.collectAsState()
    val info = (who as? Who.App)?.let { remember(it.pkg) { app.apps.byPackage(it.pkg) } }
    val group = (who as? Who.Group)?.let { st.group(it.id) }
    var editing by remember { mutableStateOf<Rule?>(null) }
    var menu by remember { mutableStateOf(false) }
    var rename by remember { mutableStateOf(false) }
    var picker by rememberSaveable { mutableStateOf(false) }
    // a group opens on its members: that is what a new group needs first
    var tab by rememberSaveable { mutableIntStateOf(initialTab) }
    var selection by remember { mutableStateOf(setOf<Int>()) }

    if (who is Who.Group && group == null) {
        LaunchedEffect(Unit) { onBack() }
        return
    }

    val rules = st.rules.filter { it.who == who }
        .sortedWith(
            compareBy<Rule> { r ->
                st.order.indexOfFirst { it.id == r.setId }
            }.thenBy { it.target.kind }.thenBy { it.target.value }
        )
    val title = info?.name ?: group?.name ?: (who as? Who.App)?.pkg ?: ""
    val subtitle = info?.let { "${it.packageName} · uid ${it.uid}" }
        ?: group?.let {
            stringResource(R.string.group_label) + " · " +
                pluralStringResource(R.plurals.apps_n, it.packages.size, it.packages.size)
        }
    val showRules = group == null || tab == 1

    BackHandler(selection.isNotEmpty()) { selection = emptySet() }
    ScreenScaffold(
        title = if (selection.isEmpty()) title else stringResource(R.string.selected_n, selection.size),
        subtitle = subtitle,
        onBack = onBack,
        actions = {
            if (selection.isNotEmpty()) {
                SelectionActions(app, st, selection) { selection = emptySet() }
                return@ScreenScaffold
            }
            if (group != null) {
                IconButton(onClick = { rename = true }) { Icon(Icons.Filled.Edit, stringResource(R.string.rename)) }
                IconButton(onClick = { menu = true }) { Icon(Icons.Filled.MoreVert, stringResource(R.string.more)) }
                DropdownMenu(menu, { menu = false }) {
                    DropdownMenuItem(
                        { Text(stringResource(R.string.group_delete), color = MaterialTheme.colorScheme.error) },
                        {
                            menu = false
                            val prev = app.firewall.state.value
                            app.firewall.deleteGroup(group.id)
                            undo?.offer(groupDeletedMsg.format(group.name)) { app.firewall.restore(prev) }
                        }
                    )
                }
            }
        }
    ) {
        Box(Modifier.fillMaxSize()) {
            Column {
                if (group != null) {
                    PrimaryTabRow(selectedTabIndex = tab) {
                        Tab(tab == 0, { tab = 0 }, text = { Text(stringResource(R.string.group_tab_members, group.packages.size)) })
                        Tab(tab == 1, { tab = 1 }, text = { Text(stringResource(R.string.group_tab_rules, rules.size)) })
                    }
                }
                if (group != null && tab == 0) {
                    GroupMembers(app, group, onAdd = { picker = true })
                } else {
                    Column(Modifier.padding(horizontal = 12.dp)) {
                        if (info == null && who is Who.App) EmptyHint(stringResource(R.string.app_not_installed))
                        if (who is Who.App) {
                            val groups = st.groups.filter { who.pkg in it.packages }
                            if (groups.isNotEmpty()) {
                                Row(
                                    Modifier.horizontalScroll(rememberScrollState()).padding(top = 6.dp),
                                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        stringResource(R.string.app_in_groups),
                                        style = MaterialTheme.typography.labelMedium,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                    groups.forEach { g -> AssistChip({ onOpenGroup(g.id) }, { Text(g.name) }) }
                                }
                            }
                        }
                        if (rules.isEmpty()) {
                            EmptyHint(stringResource(if (group != null) R.string.no_rules_group else R.string.no_rules_app))
                        } else {
                            Spacer(Modifier.height(4.dp))
                            RulesList(
                                rules,
                                st,
                                withSet = true,
                                withWho = false,
                                app = app,
                                selection = selection,
                                onLongClick = { r -> selection = selection + r.id }
                            ) { r ->
                                if (selection.isNotEmpty()) {
                                    selection = if (r.id in selection) selection - r.id else selection + r.id
                                } else {
                                    editing = r
                                }
                            }
                        }
                    }
                }
            }
            if (showRules) {
                ExtendedFloatingActionButton(
                    onClick = {
                        editing = Rule(0, FwState.DEFAULT_SET, who, Target(TargetKind.ALL), Action.BLOCK)
                    },
                    icon = { Icon(Icons.Filled.Add, null) },
                    text = { Text(stringResource(R.string.rule_add)) },
                    modifier = Modifier.align(Alignment.BottomEnd).padding(16.dp)
                )
            }
        }
    }
    editing?.let { r ->
        RuleEditorDialog(
            r,
            st,
            onSave = {
                app.firewall.saveRule(it)
                editing = null
            },
            onDelete = if (r.id != 0) {
                {
                    val prev = app.firewall.state.value
                    app.firewall.deleteRule(r.id)
                    editing = null
                    undo?.offer(ruleDeletedMsg) { app.firewall.restore(prev) }
                }
            } else {
                null
            },
            onDismiss = { editing = null }
        )
    }
    if (rename && group != null) {
        NameDialog(stringResource(R.string.rename), group.name, { rename = false }) {
            rename = false
            app.firewall.saveGroup(group.copy(name = it))
        }
    }
    if (picker && group != null) {
        AppPickerDialog(app, group, { picker = false }) { added ->
            picker = false
            // re-read: the group may have changed while the picker was open
            val g = app.firewall.state.value.group(group.id) ?: return@AppPickerDialog
            app.firewall.saveGroup(g.copy(packages = (g.packages + added).distinct().sorted()))
        }
    }
}

/** Members of a group, each with ✕; "Add apps" opens the full-screen picker. */
@Composable
private fun GroupMembers(app: PacketwallApp, g: AppGroup, onAdd: () -> Unit) {
    val undo = LocalUndo.current
    val removedMsg = stringResource(R.string.undo_member_removed)
    val members = remember(g.packages) {
        g.packages.map { pkg -> pkg to app.apps.byPackage(pkg) }.sortedBy { (pkg, a) -> (a?.name ?: pkg).lowercase() }
    }
    LazyColumn(contentPadding = PaddingValues(bottom = 24.dp)) {
        item {
            FilledTonalButton(onClick = onAdd, modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp)) {
                Icon(Icons.Filled.Add, null)
                Spacer(Modifier.width(6.dp))
                Text(stringResource(R.string.group_add_apps))
            }
        }
        if (members.isEmpty()) item { EmptyHint(stringResource(R.string.group_empty)) }
        items(members, key = { it.first }) { (pkg, a) ->
            Row(
                Modifier.fillMaxWidth().padding(start = 12.dp, end = 4.dp, top = 6.dp, bottom = 6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                if (a != null) {
                    AppIcon(a, 40.dp)
                } else {
                    Box(Modifier.size(40.dp))
                }
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Text(a?.name ?: pkg, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text(
                        if (a == null) stringResource(R.string.app_not_installed_short, pkg) else pkg,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
                IconButton({
                    val prev = app.firewall.state.value
                    val cur = prev.group(g.id) ?: return@IconButton
                    app.firewall.saveGroup(cur.copy(packages = cur.packages - pkg))
                    undo?.offer(removedMsg.format(a?.name ?: pkg)) { app.firewall.restore(prev) }
                }) { Icon(Icons.Filled.Close, stringResource(R.string.group_remove_member, a?.name ?: pkg)) }
            }
        }
    }
}

/** Full-screen choice of apps to add to [g]; current members are not listed. */
@Composable
private fun AppPickerDialog(app: PacketwallApp, g: AppGroup, onDismiss: () -> Unit, onAdd: (List<String>) -> Unit) {
    val all by produceState<List<AppInfo>?>(null) {
        value = withContext(Dispatchers.IO) { app.apps.installed().sortedBy { it.name.lowercase() } }
    }
    var sel by rememberSaveable { mutableStateOf(listOf<String>()) }
    var q by rememberSaveable { mutableStateOf("") }
    var system by rememberSaveable { mutableStateOf(false) }
    Dialog(onDismiss, DialogProperties(usePlatformDefaultWidth = false)) {
        Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.surface) {
            Box(Modifier.fillMaxSize()) {
                Column(Modifier.fillMaxSize()) {
                    Row(Modifier.fillMaxWidth().padding(4.dp), verticalAlignment = Alignment.CenterVertically) {
                        IconButton(onDismiss) { Icon(Icons.Filled.Close, stringResource(R.string.cancel)) }
                        Column(Modifier.weight(1f)) {
                            Text(
                                stringResource(R.string.group_add_to, g.name),
                                style = MaterialTheme.typography.titleLarge,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                            Text(
                                stringResource(R.string.selected_n, sel.size),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                    SearchField(q, { q = it })
                    Row(Modifier.padding(horizontal = 12.dp), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        FilterChip(system, { system = !system }, { Text(stringResource(R.string.system_apps)) })
                    }
                    val n = q.trim().lowercase()
                    val shown = all?.filter {
                        it.packageName !in g.packages &&
                            (system || !it.isSystem || it.packageName in sel) &&
                            (n.isEmpty() || it.name.lowercase().contains(n) || it.packageName.contains(n))
                    }
                    when {
                        shown == null -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                            Text(stringResource(R.string.loading))
                        }
                        shown.isEmpty() -> EmptyHint(stringResource(R.string.nothing_found))
                        else -> {
                            // a new filter starts from the top, not from wherever the old first row moved to
                            val listState = rememberLazyListState()
                            LaunchedEffect(system, n) { listState.scrollToItem(0) }
                            LazyColumn(state = listState, contentPadding = PaddingValues(bottom = 88.dp)) {
                                items(shown, key = { it.packageName }) { a ->
                                    val on = a.packageName in sel
                                    Row(
                                        Modifier.fillMaxWidth().clickable { sel = if (on) sel - a.packageName else sel + a.packageName }
                                            .padding(horizontal = 8.dp, vertical = 4.dp),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Checkbox(on, null)
                                        Spacer(Modifier.width(4.dp))
                                        AppIcon(a, 36.dp)
                                        Spacer(Modifier.width(12.dp))
                                        Column(Modifier.weight(1f)) {
                                            Text(a.name, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                            Text(
                                                a.packageName,
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
                if (sel.isNotEmpty()) {
                    ExtendedFloatingActionButton(
                        onClick = { onAdd(sel) },
                        icon = { Icon(Icons.Filled.Check, null) },
                        text = { Text(stringResource(R.string.group_add_n, sel.size)) },
                        modifier = Modifier.align(Alignment.BottomEnd).padding(16.dp)
                    )
                }
            }
        }
    }
}

@Composable
fun NameDialog(title: String, initial: String, onDismiss: () -> Unit, onOk: (String) -> Unit) {
    var v by remember { mutableStateOf(initial) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = { OutlinedTextField(v, { v = it }, singleLine = true, label = { Text(stringResource(R.string.name)) }) },
        confirmButton = { TextButton({ onOk(v.trim()) }, enabled = v.isNotBlank()) { Text(stringResource(R.string.ok)) } },
        dismissButton = { TextButton(onDismiss) { Text(stringResource(R.string.cancel)) } }
    )
}

// ------------------------------------------------------------------ Global rules

@Composable
fun GlobalScreen(app: PacketwallApp, openDrawer: () -> Unit) {
    val undo = LocalUndo.current
    val ruleDeletedMsg = stringResource(R.string.undo_rule_deleted)
    val groupDeletedMsg = stringResource(R.string.undo_group_deleted)
    val st by app.firewall.state.collectAsState()
    var q by rememberSaveable { mutableStateOf("") }
    var setFilter by rememberSaveable { mutableStateOf<Int?>(null) }
    var kind by rememberSaveable { mutableStateOf<TargetKind?>(null) }
    var portsOnly by rememberSaveable { mutableStateOf(false) }
    var editing by remember { mutableStateOf<Rule?>(null) }
    var sortNew by rememberSaveable { mutableStateOf(false) }
    var menu by remember { mutableStateOf(false) }
    var selection by remember { mutableStateOf(setOf<Int>()) }

    val rules = remember(st.rules, q, setFilter, kind, portsOnly, sortNew) {
        globalRules(st.rules, q, setFilter, kind, portsOnly, sortNew)
    }

    BackHandler(selection.isNotEmpty()) { selection = emptySet() }
    ScreenScaffold(
        title = if (selection.isEmpty()) stringResource(R.string.nav_global) else stringResource(R.string.selected_n, selection.size),
        subtitle = "${rules.size}",
        onMenu = openDrawer,
        actions = {
            if (selection.isNotEmpty()) {
                SelectionActions(app, st, selection) { selection = emptySet() }
                return@ScreenScaffold
            }
            IconButton(onClick = { menu = true }) { Icon(Icons.Filled.MoreVert, stringResource(R.string.more)) }
            DropdownMenu(menu, { menu = false }) {
                DropdownMenuItem(
                    { Text(stringResource(R.string.sort_name)) },
                    {
                        sortNew = false
                        menu = false
                    },
                    trailingIcon = { if (!sortNew) Text("✓") }
                )
                DropdownMenuItem(
                    { Text(stringResource(R.string.sort_new)) },
                    {
                        sortNew = true
                        menu = false
                    },
                    trailingIcon = { if (sortNew) Text("✓") }
                )
            }
        }
    ) {
        Box(Modifier.fillMaxSize()) {
            Column {
                SearchField(q) { q = it }
                Spacer(Modifier.height(6.dp))
                SetChips(st, setFilter, { setFilter = it })
                Row(
                    Modifier.horizontalScroll(rememberScrollState()).padding(horizontal = 12.dp),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    listOf(
                        TargetKind.DOMAIN to R.string.kind_hosts,
                        TargetKind.IP to R.string.kind_ip,
                        TargetKind.ASN to R.string.kind_asn,
                        TargetKind.COUNTRY to R.string.kind_countries,
                        TargetKind.ALL to R.string.kind_all_traffic
                    ).forEach { (k, s) ->
                        FilterChip(kind == k, { kind = if (kind == k) null else k }, { Text(stringResource(s)) })
                    }
                    FilterChip(portsOnly, { portsOnly = !portsOnly }, { Text(stringResource(R.string.kind_ports)) })
                }
                LazyColumn(contentPadding = PaddingValues(start = 12.dp, end = 12.dp, top = 4.dp, bottom = 88.dp)) {
                    if (rules.isEmpty()) {
                        item { EmptyHint(stringResource(R.string.no_rules_global)) }
                    } else {
                        item {
                            RulesList(
                                rules,
                                st,
                                withSet = setFilter == null,
                                withWho = false,
                                app = app,
                                selection = selection,
                                onLongClick = { r -> selection = selection + r.id }
                            ) { r ->
                                if (selection.isNotEmpty()) {
                                    selection = if (r.id in
                                        selection
                                    ) {
                                        selection - r.id
                                    } else {
                                        selection + r.id
                                    }
                                } else {
                                    editing = r
                                }
                            }
                        }
                    }
                }
            }
            ExtendedFloatingActionButton(
                onClick = {
                    editing = Rule(0, setFilter ?: FwState.DEFAULT_SET, Who.Global, Target(TargetKind.DOMAIN, "", true), Action.BLOCK)
                },
                icon = { Icon(Icons.Filled.Add, null) },
                text = { Text(stringResource(R.string.rule_add)) },
                modifier = Modifier.align(Alignment.BottomEnd).padding(16.dp)
            )
        }
    }
    editing?.let { r ->
        RuleEditorDialog(
            r,
            st,
            onSave = {
                app.firewall.saveRule(it)
                editing = null
            },
            onDelete = if (r.id != 0) {
                {
                    val prev = app.firewall.state.value
                    app.firewall.deleteRule(r.id)
                    editing = null
                    undo?.offer(ruleDeletedMsg) { app.firewall.restore(prev) }
                }
            } else {
                null
            },
            onDismiss = { editing = null }
        )
    }
}

/** Top bar actions for selected rules: move to a set, export, delete. */
@Composable
private fun RowScope.SelectionActions(app: PacketwallApp, st: FwState, selection: Set<Int>, onDone: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var moveMenu by remember { mutableStateOf(false) }
    val export = rememberFileExport("application/json") { ok -> if (ok) onDone() }
    Box {
        TextButton({ moveMenu = true }) { Text(stringResource(R.string.move_to_set)) }
        DropdownMenu(moveMenu, { moveMenu = false }) {
            st.userSets.forEach { s ->
                DropdownMenuItem({ Text(s.name) }, {
                    moveMenu = false
                    app.firewall.moveRules(selection, s.id)
                    onDone()
                })
            }
        }
    }
    IconButton({
        export.launchText("packetwall-rules-${selection.size}.json") { app.firewall.exportRules(selection) }
    }) { Icon(painterResource(R.drawable.ic_save), stringResource(R.string.export)) }
    val undo = LocalUndo.current
    val deletedMsg = stringResource(R.string.undo_rules_deleted, selection.size)
    IconButton({
        val prev = app.firewall.state.value
        app.firewall.deleteRules(selection)
        onDone()
        undo?.offer(deletedMsg) { app.firewall.restore(prev) }
    }) { Icon(painterResource(R.drawable.ic_delete), stringResource(R.string.delete)) }
}

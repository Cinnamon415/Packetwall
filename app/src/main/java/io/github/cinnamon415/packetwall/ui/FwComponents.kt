package io.github.cinnamon415.packetwall.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MenuAnchorType
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.github.cinnamon415.packetwall.PacketwallApp
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.engine.Conn
import io.github.cinnamon415.packetwall.fw.Action
import io.github.cinnamon415.packetwall.fw.FwState
import io.github.cinnamon415.packetwall.fw.ListParser
import io.github.cinnamon415.packetwall.fw.Proto
import io.github.cinnamon415.packetwall.fw.Rule
import io.github.cinnamon415.packetwall.fw.SetKind
import io.github.cinnamon415.packetwall.fw.Target
import io.github.cinnamon415.packetwall.fw.TargetKind
import io.github.cinnamon415.packetwall.fw.Who
import io.github.cinnamon415.packetwall.ui.theme.LocalExtraColors

// ------------------------------------------------------------------ text helpers

@Composable
fun ruleTitle(r: Rule): String = when (r.target.kind) {
    TargetKind.ALL -> stringResource(R.string.target_all)
    TargetKind.COUNTRY -> stringResource(R.string.target_country_fmt, r.target.value.uppercase())
    else -> r.target.value
}

/** Second line: only real properties (spec: no hints, no hit counters). */
@Composable
fun ruleProps(r: Rule, st: FwState, withSet: Boolean, withWho: Boolean, app: PacketwallApp? = null): String {
    val parts = ArrayList<String>()
    if (withWho) parts.add(whoLabel(r.who, st, app))
    if (r.target.kind == TargetKind.DOMAIN && r.target.subdomains) parts.add(stringResource(R.string.prop_subdomains))
    if (r.proto != Proto.ANY || r.port != 0) {
        val p = if (r.proto == Proto.ANY) "*" else r.proto.name.lowercase()
        parts.add(if (r.port != 0) "$p/${r.port}" else p)
    }
    if (r.action == Action.BLOCK && r.reject) parts.add("reject")
    if (withSet) st.set(r.setId)?.let { parts.add(it.name) }
    return parts.joinToString(" · ")
}

@Composable
fun whoLabel(who: Who, st: FwState, app: PacketwallApp?): String = when (who) {
    Who.Global -> stringResource(R.string.who_global)
    is Who.App -> app?.apps?.byPackage(who.pkg)?.name ?: who.pkg
    is Who.Group -> st.group(who.id)?.name ?: "#${who.id}"
}

/** "Why": the rule (or blocklist) that decided a connection. */
@Composable
fun decisionText(ref: Int, blocked: Boolean, st: FwState, app: PacketwallApp): String? {
    if (ref == 0) return null
    val verb = stringResource(if (blocked) R.string.decision_blocked else R.string.decision_allowed)
    if (ref < 0) {
        val set = st.set(-ref) ?: return verb
        return "$verb · ${stringResource(R.string.decision_list, set.name)}"
    }
    val r = st.rule(ref) ?: return "$verb · #$ref"
    val set = st.set(r.setId)?.name ?: ""
    return "$verb · ${ruleTitle(r)} · ${whoLabel(r.who, st, app)} · $set"
}

// ------------------------------------------------------------------ rule list

@Composable
fun RoundedGroup(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    Surface(modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp), color = MaterialTheme.colorScheme.surfaceContainerLow) {
        Column(content = content)
    }
}

@Composable
fun ActionDot(action: Action) {
    val c = if (action == Action.BLOCK) MaterialTheme.colorScheme.error else LocalExtraColors.current.ok
    Box(Modifier.size(28.dp).clip(CircleShape).background(c.copy(alpha = 0.14f)), contentAlignment = Alignment.Center) {
        Icon(painterResource(if (action == Action.BLOCK) R.drawable.ic_block else R.drawable.ic_check), null,
            tint = c, modifier = Modifier.size(16.dp))
    }
}

@Composable
fun RuleRow(r: Rule, props: String, onClick: () -> Unit) {
    Row(Modifier.fillMaxWidth().clickable(onClick = onClick).padding(horizontal = 12.dp, vertical = 9.dp),
        verticalAlignment = Alignment.CenterVertically) {
        ActionDot(r.action)
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(ruleTitle(r), fontFamily = if (r.target.kind == TargetKind.ALL) null else FontFamily.Monospace,
                style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
            if (props.isNotEmpty())
                Text(props, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
    }
}

@Composable
fun RulesList(rules: List<Rule>, st: FwState, withSet: Boolean, withWho: Boolean, app: PacketwallApp, onClick: (Rule) -> Unit) {
    RoundedGroup {
        rules.forEachIndexed { i, r ->
            if (i > 0) HorizontalDivider(Modifier.padding(start = 52.dp), color = MaterialTheme.colorScheme.surfaceContainerHigh)
            RuleRow(r, ruleProps(r, st, withSet, withWho, app)) { onClick(r) }
        }
    }
}

/** Set filter chips ("folders" on top of rule screens). null = all sets. */
@Composable
fun SetChips(st: FwState, selected: Int?, onSelect: (Int?) -> Unit, includeBlocklists: Boolean = false) {
    Row(Modifier.horizontalScroll(rememberScrollState()).padding(horizontal = 12.dp),
        horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        FilterChip(selected == null, { onSelect(null) }, { Text(stringResource(R.string.all_sets)) })
        st.orderedSets.filter { includeBlocklists || it.kind == SetKind.USER }.forEach { s ->
            FilterChip(selected == s.id, { onSelect(s.id) }, {
                Text(s.name, color = if (st.isEnabled(s.id)) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.outline)
            })
        }
    }
}

@Composable
fun EmptyHint(text: String) {
    Text(text, color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodyMedium,
        modifier = Modifier.fillMaxWidth().padding(24.dp))
}

// ------------------------------------------------------------------ rule editor

fun validTarget(t: Target): Boolean = when (t.kind) {
    TargetKind.ALL -> true
    TargetKind.DOMAIN -> ListParser.isDomain(t.value.trim().lowercase())
    TargetKind.IP -> ListParser.isIp(t.value.trim().lowercase())
    TargetKind.COUNTRY -> t.value.trim().length == 2 && t.value.trim().all { it.isLetter() }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RuleEditorDialog(initial: Rule, st: FwState, onSave: (Rule) -> Unit, onDelete: (() -> Unit)?, onDismiss: () -> Unit) {
    var action by remember { mutableStateOf(initial.action) }
    var kind by remember { mutableStateOf(initial.target.kind) }
    var value by remember { mutableStateOf(initial.target.value) }
    var subs by remember { mutableStateOf(if (initial.id == 0 && initial.target.kind != TargetKind.DOMAIN) true else initial.target.subdomains) }
    var proto by remember { mutableStateOf(initial.proto) }
    var port by remember { mutableStateOf(if (initial.port == 0) "" else initial.port.toString()) }
    var reject by remember { mutableStateOf(initial.reject) }
    var setId by remember { mutableStateOf(initial.setId) }

    val target = Target(kind, value.trim().lowercase(), subs)
    val portNum = port.toIntOrNull()
    val portOk = port.isEmpty() || (portNum != null && portNum in 1..65535)
    val ok = validTarget(target) && portOk && st.set(setId) != null

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(if (initial.id == 0) R.string.rule_new else R.string.rule_edit)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                    listOf(Action.BLOCK to R.string.action_block, Action.ALLOW to R.string.action_allow).forEachIndexed { i, (a, s) ->
                        SegmentedButton(action == a, { action = a }, SegmentedButtonDefaults.itemShape(i, 2)) { Text(stringResource(s)) }
                    }
                }
                Text(whoLabel(initial.who, st, null).let { stringResource(R.string.rule_for, it) },
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)

                val kinds = listOf(TargetKind.ALL to R.string.target_all, TargetKind.DOMAIN to R.string.target_domain,
                    TargetKind.IP to R.string.target_ip, TargetKind.COUNTRY to R.string.target_country)
                Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    kinds.forEach { (k, s) -> FilterChip(kind == k, { kind = k }, { Text(stringResource(s)) }) }
                }
                if (kind != TargetKind.ALL) {
                    OutlinedTextField(value, { value = it }, Modifier.fillMaxWidth(), singleLine = true,
                        isError = value.isNotBlank() && !validTarget(target),
                        textStyle = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace),
                        placeholder = { Text(when (kind) { TargetKind.DOMAIN -> "ads.example.com"; TargetKind.IP -> "203.0.113.0/24"; else -> "US" },
                            fontFamily = FontFamily.Monospace) },
                        supportingText = if (kind == TargetKind.DOMAIN) {{ Text(stringResource(R.string.domain_mask_help)) }}
                            else if (kind == TargetKind.COUNTRY) {{ Text(stringResource(R.string.country_help)) }} else null)
                }
                if (kind == TargetKind.DOMAIN)
                    CheckRow(subs, stringResource(R.string.prop_subdomains)) { subs = it }

                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    SingleChoiceSegmentedButtonRow(Modifier.weight(1f)) {
                        Proto.entries.forEachIndexed { i, p ->
                            SegmentedButton(proto == p, { proto = p }, SegmentedButtonDefaults.itemShape(i, Proto.entries.size)) {
                                Text(if (p == Proto.ANY) "*" else p.name, maxLines = 1)
                            }
                        }
                    }
                    OutlinedTextField(port, { port = it.filter(Char::isDigit).take(5) }, Modifier.width(96.dp), singleLine = true,
                        isError = !portOk, label = { Text(stringResource(R.string.port)) },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number))
                }
                if (action == Action.BLOCK)
                    CheckRow(reject, stringResource(R.string.reject_label)) { reject = it }

                SetDropdown(st, setId) { setId = it }
            }
        },
        confirmButton = {
            Button(enabled = ok, onClick = {
                onSave(initial.copy(action = action, target = target.copy(subdomains = kind == TargetKind.DOMAIN && subs),
                    proto = proto, port = portNum ?: 0, reject = action == Action.BLOCK && reject, setId = setId))
            }) { Text(stringResource(R.string.save)) }
        },
        dismissButton = {
            Row {
                if (onDelete != null)
                    TextButton(onClick = onDelete) { Text(stringResource(R.string.delete), color = MaterialTheme.colorScheme.error) }
                TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
            }
        },
    )
}

@Composable
fun CheckRow(checked: Boolean, label: String, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth().clip(RoundedCornerShape(8.dp)).clickable { onChange(!checked) },
        verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked, onChange)
        Text(label)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SetDropdown(st: FwState, setId: Int, onSelect: (Int) -> Unit) {
    var open by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(open, { open = it }) {
        OutlinedTextField(st.set(setId)?.name ?: "", {}, readOnly = true, singleLine = true,
            label = { Text(stringResource(R.string.rule_set)) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(open) },
            modifier = Modifier.fillMaxWidth().menuAnchor(MenuAnchorType.PrimaryNotEditable))
        ExposedDropdownMenu(open, { open = false }) {
            st.userSets.forEach { s ->
                DropdownMenuItem({ Text(s.name) }, { onSelect(s.id); open = false })
            }
        }
    }
}

// ------------------------------------------------------------------ quick rule from a connection

/**
 * Long press on a connection: block or allow its host / domain / IP for the app or globally.
 * The rule goes to the default set unless another one is picked.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun QuickRuleSheet(c: Conn, app: PacketwallApp, st: FwState, onDismiss: () -> Unit, onDone: (String) -> Unit) {
    val sheet = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    var action by rememberSaveable { mutableStateOf(if (c.blocked) Action.ALLOW else Action.BLOCK) }
    var forApp by rememberSaveable { mutableStateOf(c.uid >= 0) }
    var setId by rememberSaveable { mutableStateOf(FwState.DEFAULT_SET) }

    val host = c.host?.takeIf { it.isNotEmpty() && ListParser.isDomain(it.lowercase()) }?.lowercase()
    val options = buildList {
        if (host != null) {
            add(Target(TargetKind.DOMAIN, host, false))
            val base = ListParser.baseDomain(host)
            add(Target(TargetKind.DOMAIN, base, true))
        }
        add(Target(TargetKind.IP, c.dstIp))
        if (forApp) add(Target(TargetKind.ALL))
    }
    var choice by rememberSaveable(options.size) { mutableStateOf(if (host != null) 1 else 0) }
    val sel = options.getOrElse(choice) { options.first() }
    val doneMsg = stringResource(R.string.rule_added)

    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = sheet) {
        Column(Modifier.padding(horizontal = 16.dp).padding(bottom = 24.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                AppIcon(c.app, 32.dp)
                Spacer(Modifier.width(10.dp))
                Column {
                    Text(c.app.name, style = MaterialTheme.typography.titleMedium)
                    Text("${c.protoLabel} · ${c.title}", style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
            }
            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                listOf(Action.BLOCK to R.string.action_block, Action.ALLOW to R.string.action_allow).forEachIndexed { i, (a, s) ->
                    SegmentedButton(action == a, { action = a }, SegmentedButtonDefaults.itemShape(i, 2)) { Text(stringResource(s)) }
                }
            }
            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                SegmentedButton(forApp, { forApp = true }, SegmentedButtonDefaults.itemShape(0, 2), enabled = c.uid >= 0) {
                    Text(stringResource(R.string.for_app), maxLines = 1)
                }
                SegmentedButton(!forApp, { forApp = false; if (sel.kind == TargetKind.ALL) choice = 0 }, SegmentedButtonDefaults.itemShape(1, 2)) {
                    Text(stringResource(R.string.who_global), maxLines = 1)
                }
            }
            Column {
                options.forEachIndexed { i, t ->
                    Row(Modifier.fillMaxWidth().clip(RoundedCornerShape(8.dp)).clickable { choice = i },
                        verticalAlignment = Alignment.CenterVertically) {
                        RadioButton(choice == i, { choice = i })
                        Column {
                            Text(if (t.kind == TargetKind.ALL) stringResource(R.string.target_all_traffic) else t.value,
                                fontFamily = if (t.kind == TargetKind.ALL) null else FontFamily.Monospace)
                            val hint = when {
                                t.kind == TargetKind.DOMAIN && t.subdomains -> stringResource(R.string.prop_subdomains)
                                t.kind == TargetKind.DOMAIN -> stringResource(R.string.exact_host)
                                t.kind == TargetKind.IP -> "IP"
                                else -> null
                            }
                            if (hint != null) Text(hint, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                }
            }
            SetDropdown(st, setId) { setId = it }
            Spacer(Modifier.height(4.dp))
            Button(modifier = Modifier.fillMaxWidth(), onClick = {
                val who = if (forApp) Who.App(c.app.packageName) else Who.Global
                app.firewall.addRule(Rule(0, setId, who, sel, action))
                onDone(doneMsg)
            }) { Text(stringResource(if (action == Action.BLOCK) R.string.action_block else R.string.action_allow)) }
        }
    }
}

package io.github.cinnamon415.packetwall.ui

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
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
import androidx.compose.material3.FilledTonalButton
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
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.github.cinnamon415.packetwall.PacketwallApp
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.analysis.GeoIp
import io.github.cinnamon415.packetwall.engine.CaptureStatus
import io.github.cinnamon415.packetwall.engine.Conn
import io.github.cinnamon415.packetwall.engine.VpnSetup
import io.github.cinnamon415.packetwall.fw.Action
import io.github.cinnamon415.packetwall.fw.FwState
import io.github.cinnamon415.packetwall.fw.ListParser
import io.github.cinnamon415.packetwall.fw.Proto
import io.github.cinnamon415.packetwall.fw.Route
import io.github.cinnamon415.packetwall.fw.Rule
import io.github.cinnamon415.packetwall.fw.RuleScore
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
    TargetKind.ASN -> "AS" + (ListParser.asnNumber(r.target.value) ?: r.target.value)
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
    if (r.action == Action.ALLOW && r.route != Route.DEFAULT) {
        parts.add("→ " + stringResource(if (r.route == Route.UPSTREAM) R.string.route_upstream else R.string.route_direct))
    }
    if (withSet) st.set(r.setId)?.let { parts.add(it.name) }
    return parts.joinToString(" · ")
}

@Composable
fun whoLabel(who: Who, st: FwState, app: PacketwallApp?): String = when (who) {
    Who.Global -> stringResource(R.string.who_global)
    is Who.App -> app?.apps?.byPackage(who.pkg)?.name ?: who.pkg
    is Who.Group -> st.group(who.id)?.name ?: "#${who.id}"
}

/**
 * Why a connection was blocked when no rule did it. The engine blocks on its own in a few cases
 * (see capture_vpn.c); they are told apart by what the connection looks like.
 */
fun internalBlockReason(c: Conn, app: PacketwallApp): Int {
    val s = app.settings.values.value
    val udp = c.ipproto == 17
    return when {
        c.dstPort == 853 || (c.l7proto == "TLS" && c.host != null && DNS_HOSTS.any { c.host.endsWith(it) }) -> R.string.reason_private_dns
        s.upstream && s.upOnDown == 0 && CaptureStatus.upstreamUp.value == false -> R.string.reason_kill_switch
        // the engine blocks UDP for the upstream before it looks at DNS; only its own DNS server is let through
        s.upstream && udp && s.upUdp == 1 && c.dstIp != VpnSetup.DNS4 -> R.string.reason_upstream_udp
        c.dstPort == 53 || c.l7proto == "DNS" -> R.string.reason_dns
        s.upstream && s.upOnDown == 0 -> R.string.reason_kill_switch
        c.l7proto == "QUIC" -> R.string.reason_quic
        else -> R.string.reason_internal
    }
}

private val DNS_HOSTS = listOf(
    "dns.google", "cloudflare-dns.com", "one.one.one.one", "1dot1dot1dot1.cloudflare-dns.com", "quad9.net", "adguard-dns.com",
    "dns.adguard.com", "nextdns.io", "mullvad.net", "controld.com", "opendns.com"
)

/** "Why": the rule (or blocklist) that decided a connection. */
@Composable
fun decisionText(ref: Int, blocked: Boolean, st: FwState, app: PacketwallApp, c: Conn? = null): String? {
    if (ref ==
        0
    ) {
        return if (blocked &&
            c != null
        ) {
            stringResource(R.string.decision_blocked) + " · " + stringResource(internalBlockReason(c, app))
        } else {
            null
        }
    }
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

/** Why a rule has no effect now: its set is off, or the GeoIP database it needs is missing. */
fun ruleInactive(r: Rule, st: FwState, geo: GeoIp.Info): Int? = when {
    !st.isEnabled(r.setId) -> R.string.rule_set_off
    r.target.kind == TargetKind.COUNTRY && !geo.country.loaded -> R.string.rule_no_geo
    r.target.kind == TargetKind.ASN && !geo.asn.loaded -> R.string.rule_no_asn
    else -> null
}

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
        Icon(
            painterResource(if (action == Action.BLOCK) R.drawable.ic_block else R.drawable.ic_check),
            stringResource(if (action == Action.BLOCK) R.string.action_block else R.string.action_allow),
            tint = c,
            modifier = Modifier.size(16.dp)
        )
    }
}

@Composable
@OptIn(ExperimentalFoundationApi::class)
fun RuleRow(
    r: Rule,
    props: String,
    selected: Boolean = false,
    onLongClick: (() -> Unit)? = null,
    dim: Boolean = false,
    onClick: () -> Unit
) {
    Row(
        Modifier.fillMaxWidth()
            .background(if (selected) MaterialTheme.colorScheme.secondaryContainer else Color.Transparent)
            .combinedClickable(onLongClick = onLongClick, onClick = onClick).padding(horizontal = 12.dp, vertical = 9.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        ActionDot(r.action)
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(
                ruleTitle(r),
                color = if (dim) MaterialTheme.colorScheme.outline else Color.Unspecified,
                fontFamily = if (r.target.kind == TargetKind.ALL) null else FontFamily.Monospace,
                style = MaterialTheme.typography.bodyLarge,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            if (props.isNotEmpty()) {
                Text(
                    props,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
    }
}

@Composable
fun RulesList(
    rules: List<Rule>,
    st: FwState,
    withSet: Boolean,
    withWho: Boolean,
    app: PacketwallApp,
    selection: Set<Int> = emptySet(),
    onLongClick: ((Rule) -> Unit)? = null,
    onClick: (Rule) -> Unit
) {
    val geo by app.geo.info.collectAsState()
    RoundedGroup {
        rules.forEachIndexed { i, r ->
            if (i > 0) HorizontalDivider(Modifier.padding(start = 52.dp), color = MaterialTheme.colorScheme.surfaceContainerHigh)
            val inactive = ruleInactive(r, st, geo)
            val props = listOfNotNull(
                ruleProps(r, st, withSet, withWho, app).takeIf {
                    it.isNotEmpty()
                },
                inactive?.let { stringResource(it) }
            )
                .joinToString(" · ")
            RuleRow(r, props, r.id in selection, onLongClick?.let { { it(r) } }, dim = inactive != null) { onClick(r) }
        }
    }
}

/** Set filter chips ("folders" on top of rule screens). null = all sets. */
@Composable
fun SetChips(st: FwState, selected: Int?, onSelect: (Int?) -> Unit, includeBlocklists: Boolean = false) {
    Row(
        Modifier.horizontalScroll(rememberScrollState()).padding(horizontal = 12.dp),
        horizontalArrangement = Arrangement.spacedBy(6.dp)
    ) {
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
    Text(
        text,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        style = MaterialTheme.typography.bodyMedium,
        modifier = Modifier.fillMaxWidth().padding(24.dp)
    )
}

// ------------------------------------------------------------------ rule editor

fun validTarget(t: Target): Boolean = when (t.kind) {
    TargetKind.ALL -> true
    TargetKind.DOMAIN -> ListParser.isDomain(t.value.trim().lowercase())
    TargetKind.IP -> ListParser.isIp(t.value.trim().lowercase())
    TargetKind.COUNTRY -> t.value.trim().length == 2 && t.value.trim().all { it in 'a'..'z' || it in 'A'..'Z' }
    TargetKind.ASN -> ListParser.isAsn(t.value)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RuleEditorDialog(initial: Rule, st: FwState, onSave: (Rule) -> Unit, onDelete: (() -> Unit)?, onDismiss: () -> Unit) {
    var action by remember { mutableStateOf(initial.action) }
    var kind by remember { mutableStateOf(initial.target.kind) }
    var value by remember { mutableStateOf(initial.target.value) }
    var subs by remember {
        mutableStateOf(
            if (initial.id == 0 &&
                initial.target.kind != TargetKind.DOMAIN
            ) {
                true
            } else {
                initial.target.subdomains
            }
        )
    }
    var proto by remember { mutableStateOf(initial.proto) }
    var port by remember { mutableStateOf(if (initial.port == 0) "" else initial.port.toString()) }
    var reject by remember { mutableStateOf(initial.reject) }
    var setId by remember { mutableStateOf(initial.setId) }
    var route by remember { mutableStateOf(initial.route) }

    val target = Target(kind, value.trim().lowercase(), subs)
    val portNum = port.toIntOrNull()
    val portOk = port.isEmpty() || (portNum != null && portNum in 1..65535)
    val ok = validTarget(target) && portOk && st.set(setId) != null
    val cutsAll = initial.who == Who.Global && kind == TargetKind.ALL && action == Action.BLOCK && port.isEmpty() && proto == Proto.ANY

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
                val app = LocalContext.current.applicationContext as? PacketwallApp
                Text(
                    whoLabel(initial.who, st, app).let { stringResource(R.string.rule_for, it) },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                if (cutsAll) {
                    Text(
                        stringResource(R.string.warn_global_block_all),
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall
                    )
                }

                val kinds = listOf(
                    TargetKind.ALL to R.string.target_all,
                    TargetKind.DOMAIN to R.string.target_domain,
                    TargetKind.IP to R.string.target_ip,
                    TargetKind.ASN to R.string.kind_asn,
                    TargetKind.COUNTRY to R.string.target_country
                )
                Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    kinds.forEach { (k, s) -> FilterChip(kind == k, { kind = k }, { Text(stringResource(s)) }) }
                }
                if (kind != TargetKind.ALL) {
                    OutlinedTextField(
                        value,
                        { value = it },
                        Modifier.fillMaxWidth(),
                        singleLine = true,
                        isError = value.isNotBlank() && !validTarget(target),
                        textStyle = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace),
                        placeholder = {
                            Text(
                                when (kind) {
                                    TargetKind.DOMAIN -> "ads.example.com"
                                    TargetKind.IP -> "203.0.113.0/24"
                                    TargetKind.ASN -> "AS13335"
                                    else -> "US"
                                },
                                fontFamily = FontFamily.Monospace
                            )
                        },
                        supportingText = if (kind == TargetKind.DOMAIN) {
                            { Text(stringResource(R.string.domain_mask_help)) }
                        } else if (kind == TargetKind.COUNTRY) {
                            { Text(stringResource(R.string.country_help)) }
                        } else if (kind == TargetKind.ASN) {
                            { Text(stringResource(R.string.asn_help)) }
                        } else {
                            null
                        }
                    )
                }
                if (kind == TargetKind.DOMAIN) {
                    CheckRow(subs, stringResource(R.string.prop_subdomains)) { subs = it }
                }

                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    SingleChoiceSegmentedButtonRow(Modifier.weight(1f)) {
                        Proto.entries.forEachIndexed { i, p ->
                            SegmentedButton(proto == p, { proto = p }, SegmentedButtonDefaults.itemShape(i, Proto.entries.size)) {
                                Text(if (p == Proto.ANY) "*" else p.name, maxLines = 1)
                            }
                        }
                    }
                    OutlinedTextField(
                        port,
                        { port = it.filter(Char::isDigit).take(5) },
                        Modifier.width(96.dp),
                        singleLine = true,
                        isError = !portOk,
                        label = { Text(stringResource(R.string.port)) },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number)
                    )
                }
                if (action == Action.BLOCK) {
                    CheckRow(reject, stringResource(R.string.reject_label), Help.REJECT) { reject = it }
                }
                if (action == Action.ALLOW) {
                    Text(stringResource(R.string.kv_route), style = MaterialTheme.typography.labelMedium)
                    Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        listOf(
                            Route.DEFAULT to R.string.route_default,
                            Route.DIRECT to R.string.route_direct,
                            Route.UPSTREAM to R.string.route_upstream
                        ).forEach { (rt, s) ->
                            FilterChip(route == rt, { route = rt }, { Text(stringResource(s)) })
                        }
                    }
                }

                SetDropdown(st, setId) { setId = it }
            }
        },
        confirmButton = {
            Button(enabled = ok, onClick = {
                onSave(
                    initial.copy(
                        action = action,
                        target = target.copy(subdomains = kind == TargetKind.DOMAIN && subs),
                        proto = proto,
                        port = portNum ?: 0,
                        reject = action == Action.BLOCK && reject,
                        setId = setId,
                        route = if (action == Action.ALLOW) route else Route.DEFAULT
                    )
                )
            }) { Text(stringResource(R.string.save)) }
        },
        dismissButton = {
            Row {
                if (onDelete != null) {
                    TextButton(onClick = onDelete) { Text(stringResource(R.string.delete), color = MaterialTheme.colorScheme.error) }
                }
                TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
            }
        }
    )
}

@Composable
fun CheckRow(checked: Boolean, label: String, help: Help? = null, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Row(
            Modifier.weight(1f).clip(RoundedCornerShape(8.dp)).clickable { onChange(!checked) },
            verticalAlignment = Alignment.CenterVertically
        ) {
            Checkbox(checked, onChange)
            Text(label)
        }
        if (help != null) InfoButton(help)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SetDropdown(st: FwState, setId: Int, onSelect: (Int) -> Unit) {
    var open by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(open, { open = it }) {
        OutlinedTextField(
            st.set(setId)?.name ?: "",
            {},
            readOnly = true,
            singleLine = true,
            label = { Text(stringResource(R.string.rule_set)) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(open) },
            modifier = Modifier.fillMaxWidth().menuAnchor(MenuAnchorType.PrimaryNotEditable)
        )
        ExposedDropdownMenu(open, { open = false }) {
            st.userSets.forEach { s ->
                DropdownMenuItem({ Text(s.name) }, {
                    onSelect(s.id)
                    open = false
                })
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
    // The rule (or blocklist) that decided this connection. An exception must live in the same set or a
    // higher one (spec 2.5): we pre-select it and warn when a lower set is chosen.
    val decidingRule = if (c.fwRule > 0) st.rule(c.fwRule) else null
    val decidingSet: Int? = when {
        c.fwRule > 0 -> decidingRule?.setId
        c.fwRule < 0 -> -c.fwRule
        else -> null
    }
    val pos = { id: Int -> st.order.indexOfFirst { it.id == id } }
    val suggested = decidingSet?.let { ds ->
        if (st.set(ds)?.kind == SetKind.USER) {
            ds
        } else {
            st.order.take(maxOf(0, pos(ds))).lastOrNull { st.set(it.id)?.kind == SetKind.USER }?.id
        }
    } ?: FwState.DEFAULT_SET
    var setId by rememberSaveable { mutableStateOf(if (c.blocked) suggested else FwState.DEFAULT_SET) }

    val host = c.host?.takeIf { it.isNotEmpty() && ListParser.isDomain(it.lowercase()) }?.lowercase()
    val options = buildList {
        if (host != null) {
            add(Target(TargetKind.DOMAIN, host, false))
            val base = ListParser.baseDomain(host)
            add(Target(TargetKind.DOMAIN, base, true))
        }
        add(Target(TargetKind.IP, c.dstIp))
        RuleScore.subnet(c.dstIp)?.let { add(Target(TargetKind.IP, it)) }
        if (forApp) add(Target(TargetKind.ALL))
    }
    // unblocking: start from the deciding rule's own target (an exact host stays exact), else the base domain
    val initialChoice = decidingRule?.target?.let { t -> options.indexOfFirst { it == t } }?.takeIf { it >= 0 }
        ?: if (host != null) 1 else 0
    // kept across "for this app" / "globally"; only "all traffic of the app" (app rules only) falls back to the domain
    var choice by rememberSaveable { mutableStateOf(initialChoice) }
    val sel = options.getOrElse(choice) { options.first() }
    val doneMsg = stringResource(R.string.rule_added)

    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = sheet) {
        Column(Modifier.padding(horizontal = 16.dp).padding(bottom = 24.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                AppIcon(c.app, 32.dp)
                Spacer(Modifier.width(10.dp))
                Column {
                    Text(c.app.name, style = MaterialTheme.typography.titleMedium)
                    Text(
                        "${c.protoLabel} · ${c.title}",
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
            if (c.blocked && decidingRule != null && decidingRule.action == Action.BLOCK) {
                // the simplest way to unblock: remove the rule that blocks it
                val undo = LocalUndo.current
                val deletedMsg = stringResource(R.string.undo_rule_deleted)
                Surface(shape = RoundedCornerShape(12.dp), color = MaterialTheme.colorScheme.surfaceContainerHigh) {
                    Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text(
                            stringResource(R.string.blocked_by_rule, ruleTitle(decidingRule), whoLabel(decidingRule.who, st, app)) +
                                " · " + (st.set(decidingRule.setId)?.name ?: ""),
                            style = MaterialTheme.typography.bodyMedium
                        )
                        FilledTonalButton({
                            val prev = app.firewall.state.value
                            app.firewall.deleteRule(decidingRule.id)
                            onDismiss()
                            undo?.offer(deletedMsg) { app.firewall.restore(prev) }
                        }) { Text(stringResource(R.string.delete_blocking_rule)) }
                    }
                }
                Text(stringResource(R.string.or_add_exception), style = MaterialTheme.typography.labelLarge)
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
                SegmentedButton(!forApp, {
                    forApp = false
                    if (sel.kind == TargetKind.ALL) choice = if (host != null) 1 else 0
                }, SegmentedButtonDefaults.itemShape(1, 2)) {
                    Text(stringResource(R.string.who_global), maxLines = 1)
                }
            }
            Column {
                options.forEachIndexed { i, t ->
                    Row(
                        Modifier.fillMaxWidth().clip(RoundedCornerShape(8.dp)).clickable { choice = i },
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        RadioButton(choice == i, { choice = i })
                        Column {
                            Text(
                                if (t.kind == TargetKind.ALL) stringResource(R.string.target_all_traffic) else t.value,
                                fontFamily = if (t.kind == TargetKind.ALL) null else FontFamily.Monospace
                            )
                            val hint = when {
                                t.kind == TargetKind.DOMAIN && t.subdomains -> stringResource(R.string.prop_subdomains)
                                t.kind == TargetKind.DOMAIN -> stringResource(R.string.exact_host)
                                t.kind == TargetKind.IP && '/' in t.value -> stringResource(R.string.target_subnet)
                                t.kind == TargetKind.IP -> "IP"
                                else -> null
                            }
                            if (hint !=
                                null
                            ) {
                                Text(
                                    hint,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }
            }
            SetDropdown(st, setId) { setId = it }
            val who = if (forApp) Who.App(c.app.packageName) else Who.Global
            if (action == Action.ALLOW && decidingSet != null && c.blocked) {
                val candidate = Rule(0, setId, who, sel, Action.ALLOW)
                val warn = when {
                    RuleScore.allowWins(st, candidate, decidingRule, decidingSet) -> null
                    pos(setId) > pos(decidingSet) -> stringResource(R.string.exception_lower_set, st.set(decidingSet)?.name ?: "")
                    decidingRule != null && RuleScore.whoLevel(who) < RuleScore.whoLevel(decidingRule.who) ->
                        stringResource(R.string.exception_global_vs_app)
                    decidingRule != null -> stringResource(R.string.exception_broader, ruleTitle(decidingRule))
                    else -> null
                }
                if (warn != null) Text(warn, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
            }
            Spacer(Modifier.height(4.dp))
            Button(modifier = Modifier.fillMaxWidth(), onClick = {
                app.firewall.addRule(Rule(0, setId, who, sel, action))
                onDone(doneMsg)
            }) { Text(stringResource(if (action == Action.BLOCK) R.string.action_block else R.string.action_allow)) }
        }
    }
}

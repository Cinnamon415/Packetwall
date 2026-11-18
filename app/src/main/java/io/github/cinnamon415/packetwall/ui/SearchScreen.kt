package io.github.cinnamon415.packetwall.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.github.cinnamon415.packetwall.PacketwallApp
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.engine.AppInfo
import io.github.cinnamon415.packetwall.engine.Conn
import io.github.cinnamon415.packetwall.fw.FwSearch
import io.github.cinnamon415.packetwall.fw.TargetKind
import io.github.cinnamon415.packetwall.fw.Who
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

private enum class Kind(val label: Int) {
    ALL(R.string.search_all),
    RULES(R.string.search_rules),
    LISTS(R.string.search_lists),
    APPS(R.string.search_apps),
    CONNS(R.string.search_conns)
}

/** Where to go from a search result. */
class SearchNav(val who: (Who) -> Unit, val list: (id: Int, query: String) -> Unit, val app: (String) -> Unit, val conn: (Int) -> Unit)

/** One field for rules (with where they live), list entries, apps and connections. */
@Composable
fun SearchScreen(app: PacketwallApp, openDrawer: () -> Unit, go: SearchNav) {
    val st by app.firewall.state.collectAsState()
    var q by rememberSaveable { mutableStateOf("") }
    var kind by rememberSaveable { mutableStateOf(Kind.ALL) }
    val n = FwSearch.needle(q)

    val installed by produceState<List<AppInfo>>(emptyList()) {
        value = withContext(Dispatchers.IO) { app.apps.installed().sortedBy { it.name.lowercase() } }
    }
    val groupName = st.groups.associate { it.id to it.name }
    val rules = remember(st, n) {
        FwSearch.rules(st, n) { w ->
            when (w) {
                is Who.App -> app.apps.byPackage(w.pkg)?.name ?: w.pkg
                is Who.Group -> groupName[w.id] ?: ""
                Who.Global -> ""
            }
        }
    }
    // lists can hold hundreds of thousands of entries: read them off the main thread, after typing stops
    val lists by produceState<List<FwSearch.ListHit>>(emptyList(), n, st.blocklists) {
        if (n.length < 2) {
            value = emptyList()
            return@produceState
        }
        delay(250)
        value = withContext(Dispatchers.IO) {
            st.blocklists.mapNotNull { s ->
                val f = app.firewall.listFile(s.id)
                val off = s.disabled.toHashSet()
                val (count, ex) = if (f.exists()) {
                    f.bufferedReader().useLines { lines -> FwSearch.listEntries(lines.filter { it !in off } + s.added.asSequence(), n) }
                } else {
                    FwSearch.listEntries(s.added.asSequence(), n)
                }
                if (count > 0) FwSearch.ListHit(s.id, s.name, count, ex) else null
            }
        }
    }
    val apps = remember(installed, n) {
        if (n.isEmpty()) emptyList() else installed.filter { it.name.lowercase().contains(n) || it.packageName.contains(n) }
    }
    val conns = remember(n) {
        if (n.isEmpty()) {
            emptyList()
        } else {
            app.connections.conns.value.asSequence().filter { c ->
                c.host?.lowercase()?.contains(n) == true ||
                    c.dstIp.contains(n) ||
                    c.app.name.lowercase().contains(n) ||
                    c.app.packageName.contains(n)
            }.sortedByDescending { it.lastSeen }.take(CONNS_SHOWN).toList()
        }
    }
    val counts = mapOf(
        Kind.RULES to rules.size,
        Kind.LISTS to lists.size,
        Kind.APPS to apps.size,
        Kind.CONNS to conns.size
    )

    ScreenScaffold(title = stringResource(R.string.nav_search), onMenu = openDrawer) {
        SearchField(q) { q = it }
        Row(
            Modifier.horizontalScroll(rememberScrollState()).padding(horizontal = 12.dp, vertical = 6.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Kind.entries.forEach { k ->
                val c = if (k == Kind.ALL) counts.values.sum() else counts[k] ?: 0
                FilterChip(kind == k, { kind = k }, { Text(stringResource(k.label) + if (n.isNotEmpty()) " $c" else "") })
            }
        }
        HorizontalDivider()
        if (n.isEmpty()) {
            EmptyHint(stringResource(R.string.search_hint))
            return@ScreenScaffold
        }
        val show = { k: Kind -> kind == Kind.ALL || kind == k }
        LazyColumn(contentPadding = PaddingValues(bottom = 24.dp)) {
            if (show(Kind.APPS)) {
                items(apps, key = { "a" + it.packageName }) { a ->
                    val ruleCount = st.rules.count { (it.who as? Who.App)?.pkg == a.packageName }
                    ResultRow(
                        icon = { AppIcon(a, 36.dp) },
                        title = a.name,
                        sub = listOfNotNull(
                            a.packageName,
                            ruleCount.takeIf { it > 0 }?.let { pluralStringResource(R.plurals.rules_n, it, it) }
                        ).joinToString(" · ")
                    ) { go.app(a.packageName) }
                }
            }
            if (show(Kind.RULES)) {
                items(rules, key = { "r" + it.rule.id }) { h ->
                    val r = h.rule
                    val where = listOf(
                        whoLabel(r.who, st, app),
                        stringResource(R.string.search_in_set, h.setName),
                        when {
                            !h.setOn && h.profiles.isEmpty() -> stringResource(R.string.search_set_off)
                            h.profiles.isEmpty() -> stringResource(R.string.search_no_profile)
                            else -> pluralStringResource(R.plurals.search_profiles, h.profiles.size, h.profiles.joinToString(", ")) +
                                if (!h.setOn) " · " + stringResource(R.string.search_off_now) else ""
                        }
                    ).joinToString(" · ")
                    val extra = ruleProps(r, st, withSet = false, withWho = false)
                    ResultRow(
                        icon = { ActionDot(r.action) },
                        title = ruleTitle(r) + if (extra.isNotEmpty()) " · $extra" else "",
                        mono = r.target.kind != TargetKind.ALL,
                        sub = where,
                        dim = !h.setOn
                    ) { go.who(r.who) }
                }
            }
            if (show(Kind.LISTS)) {
                items(lists, key = { "l" + it.setId }) { h ->
                    ResultRow(
                        icon = {
                            Box(
                                Modifier.size(36.dp).clip(CircleShape).background(MaterialTheme.colorScheme.secondaryContainer),
                                contentAlignment = Alignment.Center
                            ) { Icon(painterResource(R.drawable.ic_filter), null, Modifier.size(20.dp)) }
                        },
                        title = h.name,
                        sub = pluralStringResource(R.plurals.search_entries, h.count, h.count, h.examples.joinToString(", ")),
                        dim = !st.isEnabled(h.setId)
                    ) {
                        // the list screen searches by text: a host found through its parent domain opens on that entry
                        go.list(h.setId, if (h.examples.any { it.contains(n) }) n else h.examples.first())
                    }
                }
            }
            if (show(Kind.CONNS)) {
                items(conns, key = { "c" + it.id }) { c -> ConnResult(c) { go.conn(c.id) } }
            }
            if (counts.values.sum() == 0 || (kind != Kind.ALL && counts[kind] == 0)) {
                item { EmptyHint(stringResource(R.string.nothing_found)) }
            }
        }
    }
}

private const val CONNS_SHOWN = 100

@Composable
private fun ConnResult(c: Conn, onClick: () -> Unit) {
    ResultRow(
        icon = { AppIcon(c.app, 36.dp) },
        title = c.host ?: c.dstIp,
        mono = true,
        sub = listOf(
            c.app.name,
            formatWhen(c.lastSeen),
            stringResource(if (c.blocked) R.string.search_blocked else R.string.search_allowed)
        ).joinToString(" · ")
    ) { onClick() }
}

@Composable
private fun ResultRow(
    icon: @Composable () -> Unit,
    title: String,
    sub: String,
    mono: Boolean = false,
    dim: Boolean = false,
    onClick: () -> Unit
) {
    val color = if (dim) MaterialTheme.colorScheme.outline else MaterialTheme.colorScheme.onSurface
    Row(
        Modifier.fillMaxWidth().clickable(onClick = onClick).padding(horizontal = 12.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        icon()
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(
                title,
                color = color,
                fontWeight = if (mono) null else FontWeight.SemiBold,
                fontFamily = if (mono) FontFamily.Monospace else null,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Spacer(Modifier.height(1.dp))
            Text(
                sub,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis
            )
        }
        Chevron()
    }
}

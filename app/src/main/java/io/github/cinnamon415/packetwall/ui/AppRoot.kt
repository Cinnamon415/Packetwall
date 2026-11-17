package io.github.cinnamon415.packetwall.ui

import androidx.activity.compose.BackHandler
import androidx.annotation.DrawableRes
import androidx.annotation.StringRes
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.DrawerValue
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalDrawerSheet
import androidx.compose.material3.ModalNavigationDrawer
import androidx.compose.material3.NavigationDrawerItem
import androidx.compose.material3.NavigationDrawerItemDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.rememberDrawerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveableStateHolder
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import io.github.cinnamon415.packetwall.BuildConfig
import io.github.cinnamon415.packetwall.PacketwallApp
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.engine.CaptureService
import io.github.cinnamon415.packetwall.engine.CaptureState
import io.github.cinnamon415.packetwall.fw.Who
import kotlinx.coroutines.launch

private data class DrawerEntry(val dest: Dest, @StringRes val label: Int, @DrawableRes val icon: Int)

@Composable
fun AppRoot(app: PacketwallApp, onToggleProtection: (Boolean) -> Unit) {
    val nav = rememberNavigator()
    // keeps tab selections etc. of screens below the top of the stack
    val saveable = rememberSaveableStateHolder()
    val drawer = rememberDrawerState(DrawerValue.Closed)
    val scope = rememberCoroutineScope()
    val state by CaptureService.state.collectAsState()
    val openDrawer: () -> Unit = { scope.launch { drawer.open() } }

    BackHandler(enabled = drawer.isOpen || nav.stack.size > 1) {
        if (drawer.isOpen) scope.launch { drawer.close() } else nav.pop()
    }

    ModalNavigationDrawer(
        drawerState = drawer,
        gesturesEnabled = nav.stack.size <= 2,
        drawerContent = {
            DrawerContent(nav.current, state) { d ->
                scope.launch { drawer.close() }
                if (nav.current != d) nav.root(d)
            }
        }
    ) {
        AnimatedContent(
            targetState = nav.stack.toList(),
            transitionSpec = {
                val forward = targetState.size >= initialState.size
                if (targetState.size == initialState.size) {
                    fadeIn(tween(180)) togetherWith fadeOut(tween(120))
                } else if (forward) {
                    (slideInHorizontally(tween(260)) { it / 4 } + fadeIn(tween(260))) togetherWith fadeOut(tween(200))
                } else {
                    fadeIn(tween(220)) togetherWith (slideOutHorizontally(tween(220)) { it / 4 } + fadeOut(tween(220)))
                }
            },
            label = "nav"
        ) { stack ->
            val d0 = stack.last()
            saveable.SaveableStateProvider("${stack.size}:$d0") {
                when (val d = d0) {
                    Dest.Home -> HomeScreen(
                        app,
                        state,
                        onToggleProtection,
                        openDrawer,
                        onOpenLogs = { nav.root(Dest.Logs) },
                        onOpenStats = { nav.root(Dest.Stats) },
                        onOpenConn = { nav.push(Dest.Connection(it)) }
                    )
                    Dest.Logs -> LogsScreen(app, state, openDrawer, onOpenConn = { nav.push(Dest.Connection(it)) })
                    is Dest.Connection -> ConnectionScreen(
                        app,
                        d.id,
                        d.tab,
                        onNeighbor = { id, tab -> nav.replace(Dest.Connection(id, tab)) },
                        onBack = { nav.pop() },
                        onOpenApp = { nav.push(Dest.AppRules(it)) },
                        onOpenPacket = { nav.push(Dest.Packet(d.id, it)) }
                    )
                    is Dest.Packet -> PacketScreen(app, d.connId, d.seq, onBack = { nav.pop() })
                    Dest.Stats -> StatsScreen(app, openDrawer)
                    Dest.Apps -> AppsScreen(
                        app,
                        openDrawer,
                        onOpenApp = { nav.push(Dest.AppRules(it)) },
                        onOpenGroup = { nav.push(Dest.GroupRules(it)) }
                    )
                    is Dest.AppRules -> WhoRulesScreen(app, Who.App(d.pkg), onBack = { nav.pop() })
                    is Dest.GroupRules -> WhoRulesScreen(app, Who.Group(d.id), onBack = { nav.pop() })
                    Dest.Global -> GlobalScreen(app, openDrawer)
                    Dest.Blocklists -> BlocklistsScreen(app, openDrawer)
                    Dest.Sets -> SetsScreen(app, openDrawer)
                    Dest.Settings -> SettingsScreen(app, openDrawer)
                    Dest.About -> AboutScreen(openDrawer)
                }
            }
        }
    }
}

@Composable
private fun DrawerContent(current: Dest, state: CaptureState, onSelect: (Dest) -> Unit) {
    val main = listOf(
        DrawerEntry(Dest.Home, R.string.nav_home, R.drawable.ic_wall),
        DrawerEntry(Dest.Logs, R.string.nav_logs, R.drawable.ic_logs),
        DrawerEntry(Dest.Stats, R.string.nav_stats, R.drawable.ic_chart)
    )
    val fw = listOf(
        DrawerEntry(Dest.Apps, R.string.nav_apps, R.drawable.ic_apps),
        DrawerEntry(Dest.Global, R.string.nav_global, R.drawable.ic_rules),
        DrawerEntry(Dest.Blocklists, R.string.nav_blocklists, R.drawable.ic_filter),
        DrawerEntry(Dest.Sets, R.string.nav_sets, R.drawable.ic_layers)
    )
    val other = listOf(
        DrawerEntry(Dest.Settings, R.string.nav_settings, R.drawable.ic_density),
        DrawerEntry(Dest.About, R.string.nav_about, R.drawable.ic_globe)
    )
    ModalDrawerSheet {
        Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 12.dp)) {
            Spacer(Modifier.height(16.dp))
            Text(
                "Packetwall",
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.padding(horizontal = 16.dp)
            )
            Text(
                stringResource(if (state is CaptureState.Running) R.string.status_on else R.string.status_off),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(start = 16.dp, top = 2.dp, bottom = 12.dp)
            )
            HorizontalDivider()
            Spacer(Modifier.height(8.dp))
            main.forEach { DrawerItem(it, current, onSelect) }
            HorizontalDivider(Modifier.padding(vertical = 8.dp))
            Text(
                stringResource(R.string.nav_group_firewall),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.padding(start = 16.dp, bottom = 4.dp)
            )
            fw.forEach { DrawerItem(it, current, onSelect) }
            HorizontalDivider(Modifier.padding(vertical = 8.dp))
            other.forEach { DrawerItem(it, current, onSelect) }
            Spacer(Modifier.height(16.dp))
        }
    }
}

@Composable
private fun DrawerItem(e: DrawerEntry, current: Dest, onSelect: (Dest) -> Unit) {
    NavigationDrawerItem(
        label = { Text(stringResource(e.label)) },
        icon = { Icon(painterResource(e.icon), contentDescription = null) },
        selected = current == e.dest,
        onClick = { onSelect(e.dest) },
        colors = NavigationDrawerItemDefaults.colors()
    )
}

@Composable
fun AboutScreen(openDrawer: () -> Unit) {
    ScreenScaffold(title = stringResource(R.string.nav_about), onMenu = openDrawer) {
        Box(Modifier.fillMaxSize().padding(16.dp)) {
            Column {
                Text(
                    "Packetwall ${BuildConfig.VERSION_NAME}",
                    style = MaterialTheme.typography.titleMedium
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    "GPL-3.0-or-later. Native engine adapted from PCAPdroid (Emanuele Faranda), " +
                        "zdtun and nDPI (LGPL-3.0), zstd, libpcap, OkHttp (Apache-2.0). " +
                        "IP Geolocation by DB-IP (db-ip.com), CC BY 4.0. Tracker data: AdGuard companiesdb, CC BY-SA 4.0.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

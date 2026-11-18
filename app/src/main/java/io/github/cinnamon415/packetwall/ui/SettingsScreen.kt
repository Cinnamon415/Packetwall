package io.github.cinnamon415.packetwall.ui

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
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
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import io.github.cinnamon415.packetwall.PacketwallApp
import io.github.cinnamon415.packetwall.Problem
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.Settings
import io.github.cinnamon415.packetwall.engine.AppInfo
import io.github.cinnamon415.packetwall.engine.CaptureStatus
import io.github.cinnamon415.packetwall.engine.DnsProxy
import io.github.cinnamon415.packetwall.engine.UdpAssociation
import io.github.cinnamon415.packetwall.fw.TargetKind
import io.github.cinnamon415.packetwall.system.Schedules
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.text.DateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.Credentials
import okhttp3.OkHttpClient
import okhttp3.Request

@Composable
fun SettingsScreen(app: PacketwallApp, openDrawer: () -> Unit) {
    var shorterLog by remember { mutableStateOf<Int?>(null) }
    val s by app.settings.values.collectAsState()
    ScreenScaffold(title = stringResource(R.string.nav_settings), onMenu = openDrawer) {
        Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 12.dp)) {
            ListSubheader(stringResource(R.string.settings_appearance))
            RoundedGroup {
                Column(Modifier.padding(horizontal = 14.dp, vertical = 10.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(stringResource(R.string.theme))
                    val options = listOf(R.string.theme_system, R.string.theme_light, R.string.theme_dark)
                    SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                        options.forEachIndexed { i, label ->
                            SegmentedButton(s.theme == i, {
                                app.settings.update { it.copy(theme = i) }
                            }, SegmentedButtonDefaults.itemShape(i, options.size)) {
                                Text(stringResource(label), maxLines = 1)
                            }
                        }
                    }
                }
            }
            ListSubheader(stringResource(R.string.settings_analysis))
            RoundedGroup {
                Row(
                    Modifier.fillMaxWidth().clickable { app.settings.update { it.copy(capturePackets = !it.capturePackets) } }
                        .padding(horizontal = 14.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(Modifier.weight(1f)) {
                        Text(stringResource(R.string.capture_packets))
                        Text(
                            stringResource(R.string.capture_packets_hint),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Switch(s.capturePackets, { v -> app.settings.update { it.copy(capturePackets = v) } })
                }
                HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
                ChoiceRow(stringResource(R.string.buffer_size), Settings.BUFFER_SIZES, s.bufferMb, {
                    "$it ${Units.mb}"
                }, Help.BUFFER) { v ->
                    app.settings.update { it.copy(bufferMb = v) }
                }
                HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
                ChoiceRow(
                    stringResource(R.string.snaplen),
                    Settings.SNAPLENS,
                    s.snaplen,
                    { if (it == 0) stringResource(R.string.snaplen_full) else "$it ${Units.b}" },
                    Help.SNAPLEN
                ) { v -> app.settings.update { it.copy(snaplen = v) } }
                HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
                // writing needs the packets: without "keep packets" the engine does not hand them over
                SwitchRow(
                    stringResource(R.string.record_to_disk),
                    stringResource(if (s.capturePackets) R.string.record_to_disk_hint else R.string.record_needs_packets),
                    s.record && s.capturePackets,
                    enabled = s.capturePackets,
                    help = Help.RECORD
                ) { v -> app.settings.update { it.copy(record = v) } }
                if (s.record && s.capturePackets) {
                    ChoiceRow(stringResource(R.string.record_size), listOf(8, 32, 128, 512), s.recordMb, { "$it ${Units.mb}" }) { v ->
                        app.settings.update { it.copy(recordMb = v) }
                    }
                    ChoiceRow(
                        stringResource(R.string.record_age),
                        listOf(10, 60, 360, 1440),
                        s.recordMinutes,
                        { if (it < 60) "$it ${Units.m}" else "${it / 60} ${Units.h}" }
                    ) { v -> app.settings.update { it.copy(recordMinutes = v) } }
                    ChoiceRow(stringResource(R.string.record_keep), listOf(2, 5, 10, 24), s.recordKeep, { "$it" }) { v ->
                        app.settings.update { it.copy(recordKeep = v) }
                    }
                }
            }
            Text(
                stringResource(R.string.settings_apply_hint),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(start = 4.dp, top = 6.dp)
            )
            ListSubheader(stringResource(R.string.settings_network))
            RoundedGroup {
                SwitchRow(
                    stringResource(R.string.lan_bypass),
                    stringResource(R.string.lan_bypass_hint),
                    s.lanBypass,
                    help = Help.LAN_BYPASS
                ) { v ->
                    app.settings.update { it.copy(lanBypass = v) }
                }
            }
            ListSubheader(stringResource(R.string.upstream))
            UpstreamSettings(app, s)
            ListSubheader("DNS", Help.DNS)
            DnsSettings(app, s)
            Text(
                stringResource(R.string.settings_apply_hint),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(start = 4.dp, top = 6.dp)
            )
            ListSubheader("GeoIP")
            GeoSettings(app)
            ListSubheader(stringResource(R.string.trackers))
            TrackersSettings(app)
            ListSubheader(stringResource(R.string.settings_schedules))
            SchedulesSettings(app, s)
            ListSubheader(stringResource(R.string.settings_storage))
            RoundedGroup {
                ChoiceRow(
                    stringResource(R.string.log_keep),
                    Settings.LOG_DAYS,
                    s.logDays,
                    { if (it == 0) stringResource(R.string.storage_session) else pluralStringResource(R.plurals.days, it, it) },
                    Help.LOG_STORAGE
                ) { v ->
                    // a shorter retention deletes older entries right away: ask first
                    if (v in 1 until s.logDays) shorterLog = v else app.settings.update { it.copy(logDays = v) }
                }
                shorterLog?.let { v ->
                    ConfirmDialog(stringResource(R.string.confirm_log_shorter, pluralStringResource(R.plurals.days, v, v)), {
                        shorterLog =
                            null
                    }) {
                        app.settings.update { it.copy(logDays = v) }
                        shorterLog = null
                    }
                }
                Column(Modifier.padding(start = 14.dp, end = 14.dp, bottom = 10.dp)) {
                    Text(
                        stringResource(if (s.logDays == 0) R.string.storage_session_hint else R.string.storage_db_hint),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    if (s.logDays > 0) {
                        Row(
                            Modifier.fillMaxWidth().clickable { app.settings.update { it.copy(logBlockedOnly = !it.logBlockedOnly) } },
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Checkbox(s.logBlockedOnly, { v -> app.settings.update { it.copy(logBlockedOnly = v) } })
                            Text(stringResource(R.string.log_blocked_only))
                        }
                        val scope = rememberCoroutineScope()
                        var confirmClear by remember { mutableStateOf(false) }
                        TextButton({ confirmClear = true }) { Text(stringResource(R.string.log_clear)) }
                        if (confirmClear) {
                            ConfirmDialog(stringResource(R.string.confirm_log_clear), { confirmClear = false }) {
                                confirmClear = false
                                scope.launch(Dispatchers.IO) {
                                    app.logDb.clear()
                                    app.connections.configureLog(app.logDb, s.logDays)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun <T> ChoiceRow(
    title: String,
    options: List<T>,
    value: T,
    label: @Composable (T) -> String,
    help: Help? = null,
    onPick: (T) -> Unit
) {
    Column(Modifier.padding(horizontal = 14.dp, vertical = if (help != null) 4.dp else 10.dp)) {
        TitleWithInfo(title, help)
        Row(Modifier.horizontalScroll(rememberScrollState()).padding(top = 4.dp), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            options.forEach { o -> FilterChip(o == value, { onPick(o) }, { Text(label(o)) }) }
        }
    }
}

@Composable
private fun DnsSettings(app: PacketwallApp, s: Settings.Values) {
    val stats by DnsProxy.stats.collectAsState()
    val active by CaptureStatus.dohActive.collectAsState()
    var custom by rememberSaveable {
        mutableStateOf(if (DnsProxy.PRESETS.any { it.url == s.dohUrl }) "" else s.dohUrl)
    }
    RoundedGroup {
        listOf(0 to R.string.dns_system, 1 to R.string.dns_doh).forEach { (mode, label) ->
            Row(
                Modifier.fillMaxWidth().clickable { app.settings.update { it.copy(dnsMode = mode) } }.padding(end = 14.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                RadioButton(s.dnsMode == mode, { app.settings.update { it.copy(dnsMode = mode) } })
                Column {
                    Text(stringResource(label))
                    Text(
                        stringResource(if (mode == 0) R.string.dns_system_hint else R.string.dns_doh_hint),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
        if (s.dnsMode == 1) {
            HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
            Column(Modifier.padding(horizontal = 14.dp, vertical = 10.dp)) {
                Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    DnsProxy.PRESETS.forEach { p ->
                        FilterChip(s.dohUrl == p.url, {
                            custom = ""
                            app.settings.update { it.copy(dohUrl = p.url) }
                        }, { Text(p.name) })
                    }
                }
                val ok = custom.isBlank() || custom.trim().startsWith("https://")
                OutlinedTextField(
                    custom,
                    { v ->
                        custom = v
                        if (v.trim().startsWith("https://")) app.settings.update { it.copy(dohUrl = v.trim()) }
                    },
                    Modifier.fillMaxWidth().padding(top = 6.dp),
                    singleLine = true,
                    isError = !ok,
                    label = { Text(stringResource(R.string.doh_custom)) },
                    placeholder = { Text("https://dns.example/dns-query") }
                )
                Text(
                    s.dohUrl,
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 4.dp)
                )
                if (active != null) {
                    Text(
                        stringResource(R.string.doh_stats, stats.queries, stats.failures, stats.avgMs) +
                            (stats.lastError?.let { " · " + problemText(it) } ?: ""),
                        style = MaterialTheme.typography.bodySmall,
                        color = if (stats.failures > 0) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }
}

@Composable
private fun UpstreamSettings(app: PacketwallApp, s: Settings.Values) {
    val ctx = LocalContext.current
    val up by CaptureStatus.upstreamUp.collectAsState()
    val scope = rememberCoroutineScope()
    var test by remember { mutableStateOf<String?>(null) }
    var pickApp by remember { mutableStateOf(false) }
    val appName = remember(s.upApp) { if (s.upApp.isEmpty()) null else app.apps.byPackage(s.upApp)?.name ?: s.upApp }
    RoundedGroup {
        Row(
            Modifier.fillMaxWidth().clickable { app.settings.update { it.copy(upstream = !it.upstream) } }
                .padding(horizontal = 14.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f)) {
                TitleWithInfo(stringResource(R.string.upstream_socks), Help.UPSTREAM)
                val relay by CaptureStatus.udpRelayUp.collectAsState()
                Text(
                    when (up) {
                        true -> stringResource(R.string.upstream_up) + if (relay) " · UDP ✓" else ""
                        false -> stringResource(R.string.upstream_down)
                        else -> stringResource(R.string.upstream_hint)
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = if (up == false) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Switch(s.upstream, { v -> app.settings.update { it.copy(upstream = v) } })
        }
        if (s.upstream) {
            HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
            Column(Modifier.padding(horizontal = 14.dp, vertical = 10.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    SettingChip(app, s.upAll, stringResource(R.string.upstream_all)) { it.copy(upAll = true) }
                    SettingChip(app, !s.upAll, stringResource(R.string.upstream_rules_only)) { it.copy(upAll = false) }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    SettingChip(app, s.upType == 0, "SOCKS5") { it.copy(upType = 0) }
                    SettingChip(app, s.upType == 1, "HTTP CONNECT") { it.copy(upType = 1, upUdp = if (it.upUdp == 2) 1 else it.upUdp) }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        s.upHost,
                        { v -> app.settings.update { it.copy(upHost = v.trim()) } },
                        Modifier.weight(1f),
                        singleLine = true,
                        label = { Text(stringResource(R.string.host)) }
                    )
                    OutlinedTextField(
                        s.upPort.toString(),
                        { v ->
                            v.filter(Char::isDigit).take(5).toIntOrNull()?.let { p ->
                                app.settings.update { it.copy(upPort = p) }
                            }
                        },
                        Modifier.width(100.dp),
                        singleLine = true,
                        label = { Text(stringResource(R.string.port)) },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number)
                    )
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        s.upUser,
                        { v -> app.settings.update { it.copy(upUser = v) } },
                        Modifier.weight(1f),
                        singleLine = true,
                        label = { Text(stringResource(R.string.username)) }
                    )
                    OutlinedTextField(
                        s.upPass,
                        { v -> app.settings.update { it.copy(upPass = v) } },
                        Modifier.weight(1f),
                        singleLine = true,
                        label = { Text(stringResource(R.string.password)) },
                        visualTransformation = PasswordVisualTransformation()
                    )
                }
                Row(Modifier.fillMaxWidth().clickable { pickApp = true }.padding(vertical = 6.dp)) {
                    Column(Modifier.weight(1f)) {
                        Text(stringResource(R.string.upstream_app))
                        Text(
                            appName ?: stringResource(R.string.upstream_app_none),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Chevron()
                }
                TitleWithInfo(stringResource(R.string.upstream_udp), Help.UDP) { Text(it, style = MaterialTheme.typography.labelLarge) }
                Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    SettingChip(app, s.upUdp == 1, stringResource(R.string.upstream_udp_block)) { it.copy(upUdp = 1) }
                    if (s.upType == 0) SettingChip(app, s.upUdp == 2, stringResource(R.string.upstream_udp_proxy)) { it.copy(upUdp = 2) }
                    SettingChip(app, s.upUdp == 0, stringResource(R.string.upstream_udp_direct)) { it.copy(upUdp = 0) }
                }
                TitleWithInfo(stringResource(R.string.upstream_on_down), Help.KILL_SWITCH) {
                    Text(it, style = MaterialTheme.typography.labelLarge)
                }
                Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    SettingChip(app, s.upOnDown == 0, stringResource(R.string.kill_switch)) { it.copy(upOnDown = 0) }
                    SettingChip(app, s.upOnDown == 1, stringResource(R.string.go_direct)) { it.copy(upOnDown = 1) }
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    OutlinedButton(onClick = {
                        test = "…"
                        scope.launch { test = upstreamTest(s, ctx) }
                    }) { Text(stringResource(R.string.check)) }
                    test?.let { Text(it, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(start = 10.dp)) }
                }
                Text(
                    stringResource(R.string.upstream_notes),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
    if (pickApp) {
        AppPickerDialog(app, onDismiss = { pickApp = false }) { pkg ->
            pickApp = false
            app.settings.update { it.copy(upApp = pkg) }
        }
    }
}

/** TCP connect time to the proxy, the external IP seen through it, and for SOCKS5 a DNS query over UDP ASSOCIATE. */
private suspend fun upstreamTest(s: Settings.Values, ctx: Context): String = withContext(Dispatchers.IO) {
    try {
        val addr = InetSocketAddress(InetAddress.getByName(s.upHost), s.upPort)
        val t0 = System.nanoTime()
        Socket().use { it.connect(addr, 3000) }
        val ms = (System.nanoTime() - t0) / 1_000_000
        val ip = if (s.upType == 0 && s.upUser.isNotEmpty()) {
            null
        } else {
            try {
                OkHttpClient.Builder()
                    .proxy(Proxy(if (s.upType == 1) Proxy.Type.HTTP else Proxy.Type.SOCKS, addr))
                    .apply {
                        if (s.upType == 1 && s.upUser.isNotEmpty()) {
                            proxyAuthenticator { _, r ->
                                r.request.newBuilder().header("Proxy-Authorization", Credentials.basic(s.upUser, s.upPass)).build()
                            }
                        }
                    }
                    .callTimeout(8, TimeUnit.SECONDS).build()
                    .newCall(Request.Builder().url("https://api.ipify.org").build()).execute().use { it.body?.string()?.trim() }
            } catch (e: Exception) {
                "? (${Problem.of(e).message(ctx)})"
            }
        }
        val udp = if (s.upType == 1) "UDP —" else udpTest(s)
        "TCP $ms ms" + (ip?.let { " · IP $it" } ?: "") + " · $udp"
    } catch (e: Exception) {
        "✕ ${Problem.of(e).message(ctx)}"
    }
}

/** DNS query for example.com to 1.1.1.1 through a fresh UDP ASSOCIATE. */
private fun udpTest(s: Settings.Values): String {
    val a = UdpAssociation(s.upHost, s.upPort, s.upUser, s.upPass)
    if (!a.open()) return "UDP ✕"
    return try {
        DatagramSocket().use { ds ->
            ds.soTimeout = 3000
            val q = byteArrayOf(0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7) + "example".toByteArray() + byteArrayOf(3) +
                "com".toByteArray() + byteArrayOf(0, 0, 1, 0, 1)
            val hdr = byteArrayOf(0, 0, 0, 1, 1, 1, 1, 1, 0, 53)
            val out = hdr + q
            val t0 = System.nanoTime()
            ds.send(DatagramPacket(out, out.size, InetAddress.getByName(a.relayIp), a.relayPort))
            val buf = ByteArray(1500)
            val p = DatagramPacket(buf, buf.size)
            ds.receive(p)
            val ok = p.length > 12 && buf[10] == 0x12.toByte() && buf[11] == 0x34.toByte()
            if (ok) "UDP ${(System.nanoTime() - t0) / 1_000_000} ms" else "UDP ?"
        }
    } catch (e: Exception) {
        "UDP ✕"
    } finally {
        a.close()
    }
}

@Composable
private fun AppPickerDialog(app: PacketwallApp, onDismiss: () -> Unit, onPick: (String) -> Unit) {
    val all by produceState<List<AppInfo>>(emptyList()) {
        value = withContext(Dispatchers.IO) {
            app.apps.installed().filter { it.uid >= 10000 }.sortedBy { it.name.lowercase() }
        }
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.upstream_app)) },
        text = {
            LazyColumn(Modifier.height(400.dp)) {
                item {
                    Row(Modifier.fillMaxWidth().clickable { onPick("") }.padding(vertical = 10.dp)) {
                        Text(stringResource(R.string.upstream_app_none))
                    }
                }
                items(all.size) { i ->
                    val a = all[i]
                    Row(
                        Modifier.fillMaxWidth().clickable { onPick(a.packageName) }.padding(vertical = 6.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        AppIcon(a, 28.dp)
                        Column(Modifier.padding(start = 10.dp)) {
                            Text(a.name)
                            Text(
                                a.packageName,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }
        },
        confirmButton = { TextButton(onDismiss) { Text(stringResource(R.string.cancel)) } }
    )
}

@Composable
private fun SchedulesSettings(app: PacketwallApp, s: Settings.Values) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val pickDir = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocumentTree()
    ) { uri ->
        if (uri != null) {
            ctx.contentResolver.takePersistableUriPermission(
                uri,
                Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            )
            app.settings.update { it.copy(backupUri = uri.toString()) }
        }
    }
    val okMsg = stringResource(R.string.backup_done)
    val failMsg = stringResource(R.string.backup_failed)
    RoundedGroup {
        SwitchRow(stringResource(R.string.lists_auto), stringResource(R.string.lists_auto_hint), s.listsAutoUpdate) { v ->
            app.settings.update { it.copy(listsAutoUpdate = v) }
        }
        if (s.listsAutoUpdate) {
            HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
            SwitchRow(stringResource(R.string.lists_wifi), null, s.listsWifiOnly) { v ->
                app.settings.update { it.copy(listsWifiOnly = v) }
            }
        }
        HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
        Column(Modifier.padding(horizontal = 14.dp, vertical = 10.dp)) {
            Text(stringResource(R.string.backup_auto))
            val folder = s.backupUri.takeIf { it.isNotEmpty() }?.let { Uri.parse(it).lastPathSegment?.substringAfterLast(':') }
            Text(
                if (folder == null) {
                    stringResource(R.string.backup_off)
                } else {
                    stringResource(
                        R.string.backup_folder,
                        folder,
                        if (s.lastBackup == 0L) {
                            "—"
                        } else {
                            DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(Date(s.lastBackup))
                        }
                    )
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(top = 6.dp)) {
                OutlinedButton({ pickDir.launch(null) }) { Text(stringResource(R.string.backup_choose)) }
                if (s.backupUri.isNotEmpty()) {
                    OutlinedButton({
                        scope.launch {
                            val ok = withContext(Dispatchers.IO) {
                                Schedules.backupNow(ctx)
                            }
                            Toast.makeText(ctx, if (ok) okMsg else failMsg, Toast.LENGTH_SHORT).show()
                        }
                    }) { Text(stringResource(R.string.backup_now)) }
                    TextButton({ app.settings.update { it.copy(backupUri = "") } }) { Text(stringResource(R.string.turn_off)) }
                }
            }
        }
    }
}

private fun mb(v: Float) = String.format(Locale.US, "%.1f", v)

/** A filter chip that applies one settings change. */
@Composable
private fun SettingChip(app: PacketwallApp, selected: Boolean, label: String, change: (Settings.Values) -> Settings.Values) =
    FilterChip(selected, { app.settings.update(change) }, { Text(label) })

@Composable
private fun SwitchRow(
    title: String,
    hint: String?,
    value: Boolean,
    enabled: Boolean = true,
    help: Help? = null,
    onChange: (Boolean) -> Unit
) {
    Row(
        Modifier.fillMaxWidth().clickable(enabled = enabled) { onChange(!value) }.padding(horizontal = 14.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(Modifier.weight(1f)) {
            TitleWithInfo(title, help) { Text(it, color = if (enabled) Color.Unspecified else MaterialTheme.colorScheme.outline) }
            if (hint != null) Text(hint, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Switch(value, onChange, enabled = enabled)
    }
}

@Composable
private fun GeoSettings(app: PacketwallApp) {
    var confirmGeo by remember { mutableStateOf(false) }
    if (confirmGeo) {
        val fw by app.firewall.state.collectAsState()
        val affected = fw.rules.count { it.target.kind == TargetKind.COUNTRY || it.target.kind == TargetKind.ASN }
        ConfirmDialog(stringResource(R.string.confirm_geo_delete, affected), { confirmGeo = false }) {
            confirmGeo = false
            app.geo.delete()
        }
    }
    val info by app.geo.info.collectAsState()
    val scope = rememberCoroutineScope()
    RoundedGroup {
        Column(Modifier.padding(horizontal = 14.dp, vertical = 10.dp)) {
            Text(stringResource(R.string.geo_title))
            Text(
                when {
                    info.busy -> stringResource(R.string.loading)
                    info.loaded -> {
                        val country = stringResource(R.string.geo_loaded, info.country.build, mb(info.country.sizeMb))
                        val asn = stringResource(R.string.geo_asn_loaded, info.asn.build, mb(info.asn.sizeMb))
                        if (info.asn.loaded) "$country\n$asn" else country
                    }
                    else -> stringResource(R.string.geo_missing)
                } + (info.error?.let { " · " + problemText(it) } ?: ""),
                style = MaterialTheme.typography.bodySmall,
                color = if (info.error != null) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(top = 6.dp)) {
                OutlinedButton(enabled = !info.busy, onClick = {
                    scope.launch(Dispatchers.IO) { app.geo.download() }
                }) { Text(stringResource(if (info.loaded) R.string.update_now else R.string.download)) }
                if (info.loaded) TextButton({ confirmGeo = true }) { Text(stringResource(R.string.delete)) }
            }
            Text(
                "IP Geolocation by DB-IP (db-ip.com), CC BY 4.0",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 4.dp)
            )
        }
    }
}

@Composable
private fun TrackersSettings(app: PacketwallApp) {
    var confirmTrackers by remember { mutableStateOf(false) }
    if (confirmTrackers) {
        ConfirmDialog(stringResource(R.string.confirm_trackers_delete), { confirmTrackers = false }) {
            confirmTrackers = false
            app.trackers.delete()
        }
    }
    val info by app.trackers.info.collectAsState()
    val scope = rememberCoroutineScope()
    RoundedGroup {
        Column(Modifier.padding(horizontal = 14.dp, vertical = 10.dp)) {
            Text(stringResource(R.string.trackers_db))
            Text(
                when {
                    info.busy -> stringResource(R.string.loading)
                    info.loaded -> stringResource(
                        R.string.trackers_loaded,
                        info.domains,
                        DateFormat.getDateInstance(DateFormat.SHORT).format(Date(info.updated))
                    )
                    else -> stringResource(R.string.trackers_missing)
                } + (info.error?.let { " · " + problemText(it) } ?: ""),
                style = MaterialTheme.typography.bodySmall,
                color = if (info.error != null) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(top = 6.dp)) {
                OutlinedButton(enabled = !info.busy, onClick = {
                    scope.launch(Dispatchers.IO) { app.trackers.download() }
                }) { Text(stringResource(if (info.loaded) R.string.update_now else R.string.download)) }
                if (info.loaded) TextButton({ confirmTrackers = true }) { Text(stringResource(R.string.delete)) }
            }
            Text(
                stringResource(R.string.trackers_attribution),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 4.dp)
            )
        }
    }
}

package io.github.cinnamon415.packetwall.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.height
import kotlinx.coroutines.launch
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.unit.dp
import io.github.cinnamon415.packetwall.PacketwallApp
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.Settings

@Composable
fun SettingsScreen(app: PacketwallApp, openDrawer: () -> Unit) {
    val s by app.settings.values.collectAsState()
    ScreenScaffold(title = stringResource(R.string.nav_settings), onMenu = openDrawer) {
        Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 12.dp)) {
            ListSubheader(stringResource(R.string.settings_analysis))
            RoundedGroup {
                Row(Modifier.fillMaxWidth().clickable { app.settings.update { it.copy(capturePackets = !it.capturePackets) } }
                    .padding(horizontal = 14.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(stringResource(R.string.capture_packets))
                        Text(stringResource(R.string.capture_packets_hint), style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    Switch(s.capturePackets, { v -> app.settings.update { it.copy(capturePackets = v) } })
                }
                HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
                ChoiceRow(stringResource(R.string.buffer_size), Settings.BUFFER_SIZES, s.bufferMb, { "$it MB" }) { v ->
                    app.settings.update { it.copy(bufferMb = v) }
                }
                HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
                ChoiceRow(stringResource(R.string.snaplen), Settings.SNAPLENS, s.snaplen,
                    { if (it == 0) stringResource(R.string.snaplen_full) else "$it B" }) { v -> app.settings.update { it.copy(snaplen = v) } }
            }
            Text(stringResource(R.string.settings_apply_hint), style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(start = 4.dp, top = 6.dp))
            ListSubheader(stringResource(R.string.settings_network))
            RoundedGroup {
                SwitchRow(stringResource(R.string.lan_bypass), stringResource(R.string.lan_bypass_hint), s.lanBypass) { v ->
                    app.settings.update { it.copy(lanBypass = v) }
                }
            }
            ListSubheader(stringResource(R.string.upstream))
            UpstreamSettings(app, s)
            ListSubheader("DNS")
            DnsSettings(app, s)
            Text(stringResource(R.string.settings_apply_hint), style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(start = 4.dp, top = 6.dp))
            ListSubheader("GeoIP")
            GeoSettings(app)
            ListSubheader(stringResource(R.string.trackers))
            TrackersSettings(app)
            ListSubheader(stringResource(R.string.settings_schedules))
            SchedulesSettings(app, s)
            ListSubheader(stringResource(R.string.settings_storage))
            RoundedGroup {
                ChoiceRow(stringResource(R.string.log_keep), Settings.LOG_DAYS, s.logDays,
                    { if (it == 0) stringResource(R.string.storage_session) else pluralStringResource(R.plurals.days, it, it) }) { v ->
                    app.settings.update { it.copy(logDays = v) }
                }
                Column(Modifier.padding(start = 14.dp, end = 14.dp, bottom = 10.dp)) {
                    Text(stringResource(if (s.logDays == 0) R.string.storage_session_hint else R.string.storage_db_hint),
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    if (s.logDays > 0) {
                        Row(Modifier.fillMaxWidth().clickable { app.settings.update { it.copy(logBlockedOnly = !it.logBlockedOnly) } },
                            verticalAlignment = Alignment.CenterVertically) {
                            androidx.compose.material3.Checkbox(s.logBlockedOnly, { v -> app.settings.update { it.copy(logBlockedOnly = v) } })
                            Text(stringResource(R.string.log_blocked_only))
                        }
                        val scope = androidx.compose.runtime.rememberCoroutineScope()
                        androidx.compose.material3.TextButton({
                            scope.launch(kotlinx.coroutines.Dispatchers.IO) { app.logDb.clear(); app.connections.configureLog(app.logDb, s.logDays) }
                        }) { Text(stringResource(R.string.log_clear)) }
                    }
                }
            }
        }
    }
}

@Composable
private fun <T> ChoiceRow(title: String, options: List<T>, value: T, label: @Composable (T) -> String, onPick: (T) -> Unit) {
    Column(Modifier.padding(horizontal = 14.dp, vertical = 10.dp)) {
        Text(title)
        Row(Modifier.horizontalScroll(rememberScrollState()).padding(top = 4.dp), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            options.forEach { o -> FilterChip(o == value, { onPick(o) }, { Text(label(o)) }) }
        }
    }
}

@Composable
private fun DnsSettings(app: PacketwallApp, s: Settings.Values) {
    val stats by io.github.cinnamon415.packetwall.engine.DnsProxy.stats.collectAsState()
    val active by io.github.cinnamon415.packetwall.engine.CaptureService.dohActive.collectAsState()
    var custom by androidx.compose.runtime.saveable.rememberSaveable {
        androidx.compose.runtime.mutableStateOf(if (io.github.cinnamon415.packetwall.engine.DnsProxy.PRESETS.any { it.url == s.dohUrl }) "" else s.dohUrl)
    }
    RoundedGroup {
        listOf(0 to R.string.dns_system, 1 to R.string.dns_doh).forEach { (mode, label) ->
            Row(Modifier.fillMaxWidth().clickable { app.settings.update { it.copy(dnsMode = mode) } }.padding(end = 14.dp),
                verticalAlignment = Alignment.CenterVertically) {
                androidx.compose.material3.RadioButton(s.dnsMode == mode, { app.settings.update { it.copy(dnsMode = mode) } })
                Column {
                    Text(stringResource(label))
                    Text(stringResource(if (mode == 0) R.string.dns_system_hint else R.string.dns_doh_hint),
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
        if (s.dnsMode == 1) {
            HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
            Column(Modifier.padding(horizontal = 14.dp, vertical = 10.dp)) {
                Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    io.github.cinnamon415.packetwall.engine.DnsProxy.PRESETS.forEach { p ->
                        FilterChip(s.dohUrl == p.url, { custom = ""; app.settings.update { it.copy(dohUrl = p.url) } }, { Text(p.name) })
                    }
                }
                val ok = custom.isBlank() || custom.trim().startsWith("https://")
                androidx.compose.material3.OutlinedTextField(custom, { v ->
                    custom = v
                    if (v.trim().startsWith("https://")) app.settings.update { it.copy(dohUrl = v.trim()) }
                }, Modifier.fillMaxWidth().padding(top = 6.dp), singleLine = true, isError = !ok,
                    label = { Text(stringResource(R.string.doh_custom)) },
                    placeholder = { Text("https://dns.example/dns-query") })
                Text(s.dohUrl, style = MaterialTheme.typography.bodySmall, fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(top = 4.dp))
                if (active != null)
                    Text(stringResource(R.string.doh_stats, stats.queries, stats.failures, stats.avgMs) +
                            (stats.lastError?.let { " · $it" } ?: ""),
                        style = MaterialTheme.typography.bodySmall,
                        color = if (stats.failures > 0) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

@Composable
private fun UpstreamSettings(app: PacketwallApp, s: Settings.Values) {
    val up by io.github.cinnamon415.packetwall.engine.CaptureService.upstreamUp.collectAsState()
    val scope = androidx.compose.runtime.rememberCoroutineScope()
    var test by androidx.compose.runtime.remember { androidx.compose.runtime.mutableStateOf<String?>(null) }
    var pickApp by androidx.compose.runtime.remember { androidx.compose.runtime.mutableStateOf(false) }
    val appName = androidx.compose.runtime.remember(s.upApp) { if (s.upApp.isEmpty()) null else app.apps.byPackage(s.upApp)?.name ?: s.upApp }
    RoundedGroup {
        Row(Modifier.fillMaxWidth().clickable { app.settings.update { it.copy(upstream = !it.upstream) } }
            .padding(horizontal = 14.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(stringResource(R.string.upstream_socks))
                val relay by io.github.cinnamon415.packetwall.engine.CaptureService.udpRelayUp.collectAsState()
                Text(when (up) { true -> stringResource(R.string.upstream_up) + if (relay) " · UDP ✓" else ""; false -> stringResource(R.string.upstream_down)
                    else -> stringResource(R.string.upstream_hint) }, style = MaterialTheme.typography.bodySmall,
                    color = if (up == false) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Switch(s.upstream, { v -> app.settings.update { it.copy(upstream = v) } })
        }
        if (s.upstream) {
            HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
            Column(Modifier.padding(horizontal = 14.dp, vertical = 10.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    FilterChip(s.upAll, { app.settings.update { it.copy(upAll = true) } }, { Text(stringResource(R.string.upstream_all)) })
                    FilterChip(!s.upAll, { app.settings.update { it.copy(upAll = false) } }, { Text(stringResource(R.string.upstream_rules_only)) })
                }
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    FilterChip(s.upType == 0, { app.settings.update { it.copy(upType = 0) } }, { Text("SOCKS5") })
                    FilterChip(s.upType == 1, { app.settings.update { it.copy(upType = 1, upUdp = if (it.upUdp == 2) 1 else it.upUdp) } }, { Text("HTTP CONNECT") })
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    androidx.compose.material3.OutlinedTextField(s.upHost, { v -> app.settings.update { it.copy(upHost = v.trim()) } },
                        Modifier.weight(1f), singleLine = true, label = { Text(stringResource(R.string.host)) })
                    androidx.compose.material3.OutlinedTextField(s.upPort.toString(), { v -> v.filter(Char::isDigit).take(5).toIntOrNull()?.let { p ->
                        app.settings.update { it.copy(upPort = p) } } }, Modifier.width(100.dp), singleLine = true,
                        label = { Text(stringResource(R.string.port)) },
                        keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(keyboardType = androidx.compose.ui.text.input.KeyboardType.Number))
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    androidx.compose.material3.OutlinedTextField(s.upUser, { v -> app.settings.update { it.copy(upUser = v) } },
                        Modifier.weight(1f), singleLine = true, label = { Text(stringResource(R.string.username)) })
                    androidx.compose.material3.OutlinedTextField(s.upPass, { v -> app.settings.update { it.copy(upPass = v) } },
                        Modifier.weight(1f), singleLine = true, label = { Text(stringResource(R.string.password)) },
                        visualTransformation = androidx.compose.ui.text.input.PasswordVisualTransformation())
                }
                Row(Modifier.fillMaxWidth().clickable { pickApp = true }.padding(vertical = 6.dp)) {
                    Column(Modifier.weight(1f)) {
                        Text(stringResource(R.string.upstream_app))
                        Text(appName ?: stringResource(R.string.upstream_app_none), style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    Chevron()
                }
                Text(stringResource(R.string.upstream_udp), style = MaterialTheme.typography.labelLarge)
                Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    FilterChip(s.upUdp == 1, { app.settings.update { it.copy(upUdp = 1) } }, { Text(stringResource(R.string.upstream_udp_block)) })
                    if (s.upType == 0) FilterChip(s.upUdp == 2, { app.settings.update { it.copy(upUdp = 2) } }, { Text(stringResource(R.string.upstream_udp_proxy)) })
                    FilterChip(s.upUdp == 0, { app.settings.update { it.copy(upUdp = 0) } }, { Text(stringResource(R.string.upstream_udp_direct)) })
                }
                Text(stringResource(R.string.upstream_on_down), style = MaterialTheme.typography.labelLarge)
                Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    FilterChip(s.upOnDown == 0, { app.settings.update { it.copy(upOnDown = 0) } }, { Text(stringResource(R.string.kill_switch)) })
                    FilterChip(s.upOnDown == 1, { app.settings.update { it.copy(upOnDown = 1) } }, { Text(stringResource(R.string.go_direct)) })
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    androidx.compose.material3.OutlinedButton(onClick = {
                        test = "…"
                        scope.launch { test = upstreamTest(s) }
                    }) { Text(stringResource(R.string.check)) }
                    test?.let { Text(it, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(start = 10.dp)) }
                }
                Text(stringResource(R.string.upstream_notes), style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
    if (pickApp) AppPickerDialog(app, onDismiss = { pickApp = false }) { pkg ->
        pickApp = false; app.settings.update { it.copy(upApp = pkg) }
    }
}

/** TCP connect time to the proxy, the external IP seen through it, and for SOCKS5 a DNS query over UDP ASSOCIATE. */
private suspend fun upstreamTest(s: Settings.Values): String = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
    try {
        val addr = java.net.InetSocketAddress(java.net.InetAddress.getByName(s.upHost), s.upPort)
        val t0 = System.nanoTime()
        java.net.Socket().use { it.connect(addr, 3000) }
        val ms = (System.nanoTime() - t0) / 1_000_000
        val ip = if (s.upType == 0 && s.upUser.isNotEmpty()) null else try {
            okhttp3.OkHttpClient.Builder()
                .proxy(java.net.Proxy(if (s.upType == 1) java.net.Proxy.Type.HTTP else java.net.Proxy.Type.SOCKS, addr))
                .apply { if (s.upType == 1 && s.upUser.isNotEmpty()) proxyAuthenticator { _, r ->
                    r.request.newBuilder().header("Proxy-Authorization", okhttp3.Credentials.basic(s.upUser, s.upPass)).build() } }
                .callTimeout(8, java.util.concurrent.TimeUnit.SECONDS).build()
                .newCall(okhttp3.Request.Builder().url("https://api.ipify.org").build()).execute().use { it.body?.string()?.trim() }
        } catch (e: Exception) { "? (${e.message})" }
        val udp = if (s.upType == 1) "UDP —" else udpTest(s)
        "TCP $ms ms" + (ip?.let { " · IP $it" } ?: "") + " · $udp"
    } catch (e: Exception) { "✕ ${e.message ?: e.javaClass.simpleName}" }
}

/** DNS query for example.com to 1.1.1.1 through a fresh UDP ASSOCIATE. */
private fun udpTest(s: Settings.Values): String {
    val a = io.github.cinnamon415.packetwall.engine.UdpAssociation(s.upHost, s.upPort, s.upUser, s.upPass)
    if (!a.open()) return "UDP ✕"
    return try {
        java.net.DatagramSocket().use { ds ->
            ds.soTimeout = 3000
            val q = byteArrayOf(0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7) + "example".toByteArray() + byteArrayOf(3) +
                "com".toByteArray() + byteArrayOf(0, 0, 1, 0, 1)
            val hdr = byteArrayOf(0, 0, 0, 1, 1, 1, 1, 1, 0, 53)
            val out = hdr + q
            val t0 = System.nanoTime()
            ds.send(java.net.DatagramPacket(out, out.size, java.net.InetAddress.getByName(a.relayIp), a.relayPort))
            val buf = ByteArray(1500); val p = java.net.DatagramPacket(buf, buf.size)
            ds.receive(p)
            val ok = p.length > 12 && buf[10] == 0x12.toByte() && buf[11] == 0x34.toByte()
            if (ok) "UDP ${(System.nanoTime() - t0) / 1_000_000} ms" else "UDP ?"
        }
    } catch (e: Exception) { "UDP ✕" } finally { a.close() }
}

@Composable
private fun AppPickerDialog(app: PacketwallApp, onDismiss: () -> Unit, onPick: (String) -> Unit) {
    val all by androidx.compose.runtime.produceState<List<io.github.cinnamon415.packetwall.engine.AppInfo>>(emptyList()) {
        value = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
            app.apps.installed().filter { it.uid >= 10000 }.sortedBy { it.name.lowercase() }
        }
    }
    androidx.compose.material3.AlertDialog(onDismissRequest = onDismiss, title = { Text(stringResource(R.string.upstream_app)) },
        text = {
            androidx.compose.foundation.lazy.LazyColumn(Modifier.height(400.dp)) {
                item {
                    Row(Modifier.fillMaxWidth().clickable { onPick("") }.padding(vertical = 10.dp)) { Text(stringResource(R.string.upstream_app_none)) }
                }
                items(all.size) { i ->
                    val a = all[i]
                    Row(Modifier.fillMaxWidth().clickable { onPick(a.packageName) }.padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                        AppIcon(a, 28.dp)
                        Column(Modifier.padding(start = 10.dp)) {
                            Text(a.name)
                            Text(a.packageName, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                }
            }
        },
        confirmButton = { androidx.compose.material3.TextButton(onDismiss) { Text(stringResource(R.string.cancel)) } })
}

@Composable
private fun SchedulesSettings(app: PacketwallApp, s: Settings.Values) {
    val ctx = androidx.compose.ui.platform.LocalContext.current
    val scope = androidx.compose.runtime.rememberCoroutineScope()
    val pickDir = androidx.activity.compose.rememberLauncherForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.OpenDocumentTree()) { uri ->
        if (uri != null) {
            ctx.contentResolver.takePersistableUriPermission(uri,
                android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION or android.content.Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
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
            SwitchRow(stringResource(R.string.lists_wifi), null, s.listsWifiOnly) { v -> app.settings.update { it.copy(listsWifiOnly = v) } }
        }
        HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
        Column(Modifier.padding(horizontal = 14.dp, vertical = 10.dp)) {
            Text(stringResource(R.string.backup_auto))
            val folder = s.backupUri.takeIf { it.isNotEmpty() }?.let { android.net.Uri.parse(it).lastPathSegment?.substringAfterLast(':') }
            Text(if (folder == null) stringResource(R.string.backup_off)
                else stringResource(R.string.backup_folder, folder, if (s.lastBackup == 0L) "—"
                    else java.text.DateFormat.getDateTimeInstance(java.text.DateFormat.SHORT, java.text.DateFormat.SHORT).format(java.util.Date(s.lastBackup))),
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(top = 6.dp)) {
                androidx.compose.material3.OutlinedButton({ pickDir.launch(null) }) { Text(stringResource(R.string.backup_choose)) }
                if (s.backupUri.isNotEmpty()) {
                    androidx.compose.material3.OutlinedButton({
                        scope.launch {
                            val ok = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                                io.github.cinnamon415.packetwall.system.Schedules.backupNow(ctx)
                            }
                            android.widget.Toast.makeText(ctx, if (ok) okMsg else failMsg, android.widget.Toast.LENGTH_SHORT).show()
                        }
                    }) { Text(stringResource(R.string.backup_now)) }
                    androidx.compose.material3.TextButton({ app.settings.update { it.copy(backupUri = "") } }) { Text(stringResource(R.string.turn_off)) }
                }
            }
        }
    }
}

@Composable
private fun SwitchRow(title: String, hint: String?, value: Boolean, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth().clickable { onChange(!value) }.padding(horizontal = 14.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(title)
            if (hint != null) Text(hint, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Switch(value, onChange)
    }
}

@Composable
private fun GeoSettings(app: PacketwallApp) {
    val info by app.geo.info.collectAsState()
    val scope = androidx.compose.runtime.rememberCoroutineScope()
    RoundedGroup {
        Column(Modifier.padding(horizontal = 14.dp, vertical = 10.dp)) {
            Text(stringResource(R.string.geo_title))
            Text(when {
                info.busy -> stringResource(R.string.loading)
                info.loaded -> stringResource(R.string.geo_loaded, info.country.build, String.format(java.util.Locale.US, "%.1f", info.country.sizeMb)) +
                    (if (info.asn.loaded) "\n" + stringResource(R.string.geo_asn_loaded, info.asn.build, String.format(java.util.Locale.US, "%.1f", info.asn.sizeMb)) else "")
                else -> stringResource(R.string.geo_missing)
            } + (info.error?.let { " · $it" } ?: ""), style = MaterialTheme.typography.bodySmall,
                color = if (info.error != null) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(top = 6.dp)) {
                androidx.compose.material3.OutlinedButton(enabled = !info.busy, onClick = {
                    scope.launch(kotlinx.coroutines.Dispatchers.IO) { app.geo.download() }
                }) { Text(stringResource(if (info.loaded) R.string.update_now else R.string.download)) }
                if (info.loaded) androidx.compose.material3.TextButton({ app.geo.delete() }) { Text(stringResource(R.string.delete)) }
            }
            Text("IP Geolocation by DB-IP (db-ip.com), CC BY 4.0", style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(top = 4.dp))
        }
    }
}

@Composable
private fun TrackersSettings(app: PacketwallApp) {
    val info by app.trackers.info.collectAsState()
    val scope = androidx.compose.runtime.rememberCoroutineScope()
    RoundedGroup {
        Column(Modifier.padding(horizontal = 14.dp, vertical = 10.dp)) {
            Text(stringResource(R.string.trackers_db))
            Text(when {
                info.busy -> stringResource(R.string.loading)
                info.loaded -> stringResource(R.string.trackers_loaded, info.domains,
                    java.text.DateFormat.getDateInstance(java.text.DateFormat.SHORT).format(java.util.Date(info.updated)))
                else -> stringResource(R.string.trackers_missing)
            } + (info.error?.let { " · $it" } ?: ""), style = MaterialTheme.typography.bodySmall,
                color = if (info.error != null) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(top = 6.dp)) {
                androidx.compose.material3.OutlinedButton(enabled = !info.busy, onClick = {
                    scope.launch(kotlinx.coroutines.Dispatchers.IO) { app.trackers.download() }
                }) { Text(stringResource(if (info.loaded) R.string.update_now else R.string.download)) }
                if (info.loaded) androidx.compose.material3.TextButton({ app.trackers.delete() }) { Text(stringResource(R.string.delete)) }
            }
            Text("Tracker data: AdGuard companiesdb, CC BY-SA 4.0", style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(top = 4.dp))
        }
    }
}

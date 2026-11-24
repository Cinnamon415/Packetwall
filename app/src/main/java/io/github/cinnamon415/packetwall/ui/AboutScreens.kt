package io.github.cinnamon415.packetwall.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings as AndroidSettings
import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import io.github.cinnamon415.packetwall.BuildConfig
import io.github.cinnamon415.packetwall.PacketwallApp
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.engine.CaptureState
import io.github.cinnamon415.packetwall.engine.CaptureStatus

private class Credit(val name: String, val who: String, val license: String, val url: String?)

private val credits = listOf(
    Credit("PCAPdroid", "Emanuele Faranda", "GPL-3.0", "https://github.com/emanuele-f/PCAPdroid"),
    Credit("zdtun", "Emanuele Faranda", "LGPL-3.0", "https://github.com/emanuele-f/zdtun"),
    Credit("nDPI", "ntop", "LGPL-3.0", "https://github.com/ntop/nDPI"),
    Credit("libpcap", "The Tcpdump Group", "BSD-3-Clause", "https://www.tcpdump.org"),
    Credit("Zstandard", "Meta", "BSD-3-Clause", "https://github.com/facebook/zstd"),
    Credit("libchash", "Google", "BSD-3-Clause", null),
    Credit("OkHttp", "Square", "Apache-2.0", "https://square.github.io/okhttp/"),
    Credit("Kotlin, kotlinx", "JetBrains", "Apache-2.0", "https://kotlinlang.org"),
    Credit("AndroidX, Jetpack Compose", "Google", "Apache-2.0", "https://developer.android.com/jetpack"),
    Credit("IP to Country / ASN Lite", "DB-IP", "CC BY 4.0", "https://db-ip.com"),
    Credit("companiesdb", "AdGuard", "CC BY-SA 4.0", "https://github.com/AdguardTeam/companiesdb")
)

/** Version, guide, changelog, diagnostics and credits. */
@Composable
fun AboutScreen(app: PacketwallApp, openDrawer: () -> Unit, onGuide: () -> Unit, onChangelog: () -> Unit) {
    val ctx = LocalContext.current
    val log = rememberFileExport("text/plain")
    val report = diagnostics(app)
    val copiedMsg = stringResource(R.string.copied)
    ScreenScaffold(title = stringResource(R.string.nav_about), onMenu = openDrawer) {
        Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 12.dp)) {
            RoundedGroup(Modifier.padding(top = 8.dp)) {
                Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        Modifier.size(48.dp).clip(RoundedCornerShape(14.dp)).background(MaterialTheme.colorScheme.primary),
                        contentAlignment = Alignment.Center
                    ) { Icon(painterResource(R.drawable.ic_wall), null, tint = MaterialTheme.colorScheme.onPrimary) }
                    Spacer(Modifier.width(14.dp))
                    Column {
                        Text("Packetwall ${BuildConfig.VERSION_NAME}", style = MaterialTheme.typography.titleMedium)
                        Text(
                            stringResource(R.string.about_build, BuildConfig.VERSION_CODE),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
            Spacer(Modifier.height(10.dp))
            RoundedGroup {
                NavRow(stringResource(R.string.guide_title), stringResource(R.string.guide_sub), onGuide)
                HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
                NavRow(stringResource(R.string.changelog_title), stringResource(R.string.changelog_sub), onChangelog)
            }

            ListSubheader(stringResource(R.string.diag_title))
            RoundedGroup {
                Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    report.lines.forEach { (k, v) ->
                        Row {
                            Text(k, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            Spacer(Modifier.width(6.dp))
                            Text(v, style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Medium)
                        }
                    }
                    if (report.tip != null) {
                        Text(
                            report.tip,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.padding(top = 6.dp)
                        )
                        OutlinedButton({ openVpnSettings(ctx) }) { Text(stringResource(R.string.diag_open_vpn_settings)) }
                    }
                    FlowRow(Modifier.padding(top = 6.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        FilledTonalButton({
                            copy(ctx, report.text())
                            Toast.makeText(ctx, copiedMsg, Toast.LENGTH_SHORT).show()
                        }) {
                            Icon(painterResource(R.drawable.ic_copy), null, Modifier.size(18.dp))
                            Spacer(Modifier.width(6.dp))
                            Text(stringResource(R.string.diag_copy))
                        }
                        OutlinedButton({ log.launchText("packetwall-log.txt") { report.text() + "\n\n" + ownLog() } }) {
                            Text(stringResource(R.string.diag_save_log))
                        }
                    }
                }
            }

            ListSubheader(stringResource(R.string.credits_title))
            RoundedGroup {
                credits.forEachIndexed { i, c ->
                    if (i > 0) HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
                    Row(
                        Modifier.fillMaxWidth().clickable(enabled = c.url != null) { c.url?.let { openUrl(ctx, it) } }
                            .padding(horizontal = 14.dp, vertical = 9.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text(c.name)
                            Text(
                                "${c.who} · ${c.license}",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        if (c.url != null) Chevron()
                    }
                }
            }
            Text(
                stringResource(R.string.credits_lists),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(start = 4.dp, top = 6.dp)
            )
            Text(
                stringResource(R.string.about_license),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(start = 4.dp, top = 10.dp, bottom = 24.dp)
            )
        }
    }
}

@Composable
private fun NavRow(title: String, sub: String, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clickable(onClick = onClick).padding(horizontal = 14.dp, vertical = 11.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(Modifier.weight(1f)) {
            Text(title)
            Text(sub, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Chevron()
    }
}

private class Report(val lines: List<Pair<String, String>>, val tip: String?) {
    fun text() = "Packetwall ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})\n" +
        lines.joinToString("\n") { (k, v) -> "$k $v" } +
        "\nAndroid ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT}) · ${Build.MANUFACTURER} ${Build.MODEL}"
}

/** The engine state in one place; the same text goes to the clipboard for bug reports. */
@Composable
private fun diagnostics(app: PacketwallApp): Report {
    val state by CaptureStatus.state.collectAsState()
    val paused by CaptureStatus.pausedSince.collectAsState()
    val fw by app.firewall.state.collectAsState()
    val loaded by app.firewall.loaded.collectAsState()
    val geo by app.geo.info.collectAsState()
    val trackers by app.trackers.info.collectAsState()
    val s by app.settings.values.collectAsState()
    val doh by CaptureStatus.dohActive.collectAsState()
    val strict by CaptureStatus.privateDnsStrict.collectAsState()
    val up by CaptureStatus.upstreamUp.collectAsState()
    val always by CaptureStatus.alwaysOn.collectAsState()
    val running = state is CaptureState.Running
    val yes = stringResource(R.string.yes)
    val no = stringResource(R.string.no)
    val lines = ArrayList<Pair<String, String>>()
    lines += stringResource(R.string.diag_protection) to when {
        !running -> stringResource(R.string.status_off)
        paused != null -> stringResource(R.string.diag_paused)
        else -> stringResource(R.string.status_on)
    }
    val enabled = fw.order.count { it.enabled }
    lines += stringResource(R.string.diag_rules) to stringResource(
        R.string.diag_rules_v,
        if (loaded < 0) "—" else "$loaded",
        enabled,
        fw.order.size
    )
    val lists = fw.blocklists.filter { fw.isEnabled(it.id) }
    lines += stringResource(R.string.diag_lists) to stringResource(R.string.diag_lists_v, lists.size, lists.sumOf { it.entries })
    lines += "GeoIP:" to listOf(
        stringResource(R.string.diag_country) + " " + (geo.country.build.takeIf { geo.country.loaded } ?: "—"),
        "ASN " + (geo.asn.build.takeIf { geo.asn.loaded } ?: "—")
    ).joinToString(" · ")
    lines += stringResource(R.string.diag_trackers) to
        if (trackers.loaded) stringResource(R.string.diag_trackers_v, trackers.domains, formatDate(trackers.updated)) else "—"
    lines += "DNS:" to when {
        doh != null -> "DoH · " + (Uri.parse(doh).host ?: doh!!)
        s.dnsMode == 1 -> "DoH"
        else -> stringResource(R.string.dns_system)
    } + if (running) " · " + stringResource(if (strict) R.string.diag_pdns_strict else R.string.diag_pdns_visible) else ""
    lines += "Upstream:" to if (!s.upstream) {
        stringResource(R.string.turned_off)
    } else {
        "${s.upHost}:${s.upPort} · " + when (up) {
            true -> stringResource(R.string.diag_up)
            false -> stringResource(R.string.diag_down)
            null -> "—"
        }
    }
    lines += stringResource(R.string.diag_routes) to stringResource(if (s.lanBypass) R.string.diag_routes_lan else R.string.diag_routes_all)
    always?.let { (on, lockdown) ->
        lines += stringResource(R.string.diag_always_on) to "${if (on) yes else no} · " +
            stringResource(R.string.diag_lockdown) + " " + if (lockdown) yes else no
    }
    val tip = if (always != null && !(always!!.first && always!!.second)) stringResource(R.string.diag_tip_always_on) else null
    return Report(lines, tip)
}

private fun copy(ctx: Context, text: String) {
    val cm = ctx.getSystemService(ClipboardManager::class.java) ?: return
    cm.setPrimaryClip(ClipData.newPlainText("Packetwall", text))
}

/** The app's own log lines (logcat shows an app only its own process). */
private fun ownLog(): String = try {
    val p = ProcessBuilder("logcat", "-d", "-t", "2000", "--pid=${android.os.Process.myPid()}").redirectErrorStream(true).start()
    p.inputStream.bufferedReader().use { it.readText() }
} catch (e: Exception) {
    "logcat: ${e.message}"
}

private fun openUrl(ctx: Context, url: String) {
    runCatching { ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }
}

internal fun openVpnSettings(ctx: Context) {
    runCatching { ctx.startActivity(Intent(AndroidSettings.ACTION_VPN_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }
}

/** "How it works": the model in a few short sections. */
@Composable
fun GuideScreen(onBack: () -> Unit) {
    val sections = listOf(
        R.string.guide_1_t to R.string.guide_1,
        R.string.guide_2_t to R.string.guide_2,
        Help.SET_PRIORITY.title to Help.SET_PRIORITY.body,
        R.string.guide_4_t to R.string.guide_4,
        R.string.guide_5_t to R.string.guide_5,
        Help.PROFILES.title to Help.PROFILES.body,
        R.string.guide_7_t to R.string.guide_7,
        Help.UPSTREAM.title to Help.UPSTREAM.body,
        R.string.guide_9_t to R.string.guide_9
    )
    ScreenScaffold(title = stringResource(R.string.guide_title), onBack = onBack) {
        Column(
            Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 16.dp).padding(bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            sections.forEach { (t, b) ->
                Text(stringResource(t), style = MaterialTheme.typography.titleMedium, modifier = Modifier.padding(top = 12.dp))
                stringResource(b).split("\n\n").forEach { Text(it, style = MaterialTheme.typography.bodyMedium) }
            }
        }
    }
}

/** What changed, newest first. */
@Composable
fun ChangelogScreen(onBack: () -> Unit) {
    val versions = listOf("0.7.3" to R.string.changes_073, "0.7.2" to R.string.changes_072, "0.7.1" to R.string.changes_071, "0.7.0" to R.string.changes_070, "0.6.0" to R.string.changes_060, "0.5.0" to R.string.changes_050)
    ScreenScaffold(title = stringResource(R.string.changelog_title), onBack = onBack) {
        Column(
            Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 16.dp).padding(bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            versions.forEach { (v, res) ->
                Text(
                    v,
                    style = MaterialTheme.typography.titleMedium,
                    fontFamily = FontFamily.Monospace,
                    modifier = Modifier.padding(top = 14.dp)
                )
                stringResource(res).split("\n").forEach { line ->
                    Row {
                        Text("•", modifier = Modifier.width(16.dp))
                        Text(line, style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }
        }
    }
}

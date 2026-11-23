package io.github.cinnamon415.packetwall.e2e

import androidx.compose.ui.test.hasClickAction
import androidx.compose.ui.test.performClick
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.fw.TargetKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** SET-13/14: the databases downloaded from the internet (DB-IP, AdGuard companiesdb) and what they do. */
class DownloadsTest : E2eTest() {

    private fun settings() {
        drawer(R.string.nav_settings)
        ui.waitUntil("settings", 8000) { ui.onAllNodes(has(str(R.string.settings_apply_hint))).fetchSemanticsNodes().isNotEmpty() }
    }

    /** The button [label] of the card titled [title] (both cards have "Download" and "Delete"). */
    private fun buttonOf(title: Int, label: Int) {
        scrollIntoView(has(str(title)))
        val t = ui.onAllNodes(has(str(title))).fetchSemanticsNodes().first().boundsInWindow.top
        val m = has(str(label)) and hasClickAction()
        val nodes = ui.onAllNodes(m).fetchSemanticsNodes()
        val i = nodes.indices.filter { nodes[it].boundsInWindow.top > t }.minByOrNull { nodes[it].boundsInWindow.top }
        assertNotNull("${str(label)} under ${str(title)}", i)
        ui.onAllNodes(m)[i!!].performClick()
        ui.waitForIdle()
    }

    @Test
    @Covers("SET-14", "STAT-06")
    fun trackerLabels() {
        launch()
        settings()
        seeValue(str(R.string.trackers_missing))
        buttonOf(R.string.trackers_db, R.string.download)
        val info = waitForValue("trackers downloaded", 120_000) { app.trackers.info.value.takeIf { it.loaded } }
        assertTrue(info.domains > 1000)
        seeValue(str(R.string.trackers_loaded, info.domains, "").trimEnd(), substring = true)
        // a tracker host is labelled in the log and counted by app in the statistics
        drawer(R.string.nav_home)
        turnOn()
        Net.http("www.google-analytics.com")
        val row = Rows.await("tracker row", 10_000) { it.host == "www.google-analytics.com" && it.tracker != null }
        drawer(R.string.nav_stats)
        seeValue(str(R.string.trackers_by_app))
        seeValue(row.tracker!!, substring = true)
        tap(row.tracker!!, substring = true)
        waitText(str(R.string.chip_all))
        assertText("tracker && pkg == \"$SHELL_PKG\"")
        // delete asks first
        settings()
        buttonOf(R.string.trackers_db, R.string.delete)
        waitText(str(R.string.confirm_trackers_delete))
        tap(str(R.string.delete))
        waitFor("trackers gone") { !app.trackers.info.value.loaded }
        seeValue(str(R.string.trackers_missing))
    }

    @Test
    @Covers("SET-13", "DEC-10")
    fun geoIpCountryAndAsRules() {
        launch()
        val us = addGlobalRule(RuleSpec("US", kind = TargetKind.COUNTRY, port = 443))
        val google = addGlobalRule(RuleSpec("AS15169", kind = TargetKind.ASN, port = 80))
        settings()
        seeValue(str(R.string.geo_missing))
        buttonOf(R.string.geo_title, R.string.download)
        waitFor("GeoIP downloaded", 180_000, 1000) { app.geo.info.value.let { it.country.loaded && it.asn.loaded && !it.busy } }
        seeValue("DB-IP Country Lite", substring = true)
        seeValue("DB-IP ASN Lite", substring = true)
        // the country rule blocks a US address, the AS rule Google's; others pass
        drawer(R.string.nav_home)
        turnOn()
        assertBlocked("google-dns", ip = "8.8.8.8", port = 443, rule = us.id)
        assertBlocked("google-dns", ip = "8.8.4.4", port = 80, rule = google.id)
        // delete: asks, naming the rules that stop matching
        settings()
        buttonOf(R.string.geo_title, R.string.delete)
        waitText(str(R.string.confirm_geo_delete, 2))
        tap(str(R.string.delete))
        waitFor("GeoIP gone") { !app.geo.info.value.loaded }
        seeValue(str(R.string.geo_missing))
        assertEquals(2, app.firewall.state.value.rules.size)
    }
}

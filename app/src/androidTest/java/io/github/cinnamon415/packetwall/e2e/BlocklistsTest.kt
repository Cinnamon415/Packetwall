package io.github.cinnamon415.packetwall.e2e

import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasClickAction
import androidx.compose.ui.test.hasContentDescription
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isDialog
import androidx.compose.ui.test.isToggleable
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextClearance
import androidx.compose.ui.test.performTextInput
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.fw.Action
import io.github.cinnamon415.packetwall.fw.SetKind
import io.github.cinnamon415.packetwall.fw.TargetKind
import io.github.cinnamon415.packetwall.fw.Who
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The host's fixture server (tools/e2e/host.py), seen from the emulator. */
object Fixtures {
    const val BASE = "http://${Hosts.HOST}:${Hosts.CONTROL_PORT}"
    fun list(name: String) = "$BASE/lists/$name"

    /** GET on the control server from the shell (through the VPN when it is on); the body. */
    fun get(path: String): String = Shell.run(
        "printf 'GET $path HTTP/1.0\\r\\n\\r\\n' | timeout 5 toybox nc ${Hosts.HOST} ${Hosts.CONTROL_PORT}"
    ).substringAfter("\r\n\r\n")

    /** /lists/[name] serves [to] from now on. */
    fun switch(name: String, to: String) = get("/switch?name=$name&to=$to")

    fun hits(path: String): Int = Regex("\"${Regex.escape(path)}\": (\\d+)").find(get("/hits"))?.groupValues?.get(1)?.toInt() ?: 0
}

/** BL: blocklists; LIST: a list's entries and edits; IMPF: importing other apps' files. */
class BlocklistsTest : E2eTest() {

    private val st get() = app.firewall.state.value
    private val inDialog = hasAnyAncestor(isDialog())

    private fun dialogField(i: Int): androidx.compose.ui.test.SemanticsNodeInteraction {
        val m = hasSetTextAction() and inDialog
        return ui.onAllNodes(m)[visible(m)[i]]
    }

    private fun enabled(text: String): Boolean {
        val m = hasText(text) and hasClickAction()
        return ui.onAllNodes(m).fetchSemanticsNodes().last().config.getOrNull(SemanticsProperties.Disabled) == null
    }

    private fun openAdd() {
        drawer(R.string.nav_blocklists)
        tap(str(R.string.list_add_url_file))
        waitText(str(R.string.custom_url))
    }

    /** Adds the list at [url]; waits for its download. Returns its set id. */
    private fun addList(url: String, name: String = "", expectError: Boolean = false): Int {
        val before = st.sets.map { it.id }.toSet()
        openAdd()
        dialogField(0).performTextInput(url)
        if (name.isNotEmpty()) dialogField(1).performTextInput(name)
        tap(str(R.string.add))
        val id = waitForValue("new list") { st.blocklists.firstOrNull { it.id !in before }?.id }
        waitFor("downloaded $url", 30_000) {
            id !in app.firewall.updating.value && (st.set(id)!!.updated > 0 || st.set(id)!!.error != null)
        }
        if (!expectError) assertEquals("download of $url: ${st.set(id)!!.error}", null, st.set(id)!!.error)
        return id
    }

    @Test
    @Covers("BL-01", "BL-05", "BL-06")
    fun addByUrlValidationAndUpdateAll() {
        launch()
        drawer(R.string.nav_blocklists)
        waitText(str(R.string.no_blocklists))
        assertText(str(R.string.lists_enabled, 0, 0))
        // nothing to update yet
        assertFalse(descEnabled(str(R.string.update_all)))
        openAdd()
        assertFalse(enabled(str(R.string.add)))
        dialogField(0).performTextInput("ftp://example.com/list.txt")
        assertFalse(enabled(str(R.string.add)))
        assertTrue(dialogField(0).fetchSemanticsNode().config.getOrNull(SemanticsProperties.Error) != null)
        dialogField(0).performTextClearance()
        dialogField(0).performTextInput(Fixtures.list("block.txt"))
        assertTrue(enabled(str(R.string.add)))
        tap(str(R.string.cancel))
        // no name: the host names it
        val id = addList(Fixtures.list("block.txt"))
        assertEquals(Hosts.HOST, st.set(id)!!.name)
        assertEquals(SetKind.BLOCKLIST, st.set(id)!!.kind)
        // 4 entries, the element-hiding line skipped
        assertEquals(4, st.set(id)!!.entries)
        assertEquals(1, st.set(id)!!.skipped)
        waitText(str(R.string.entries_count, 4), substring = true)
        assertText(str(R.string.lists_enabled, 1, 4))
        // the same address again: refused
        openAdd()
        dialogField(0).performTextInput(Fixtures.list("block.txt"))
        waitText(str(R.string.list_already_added))
        assertFalse(enabled(str(R.string.add)))
        tap(str(R.string.cancel))
        // update all: asks the server again
        val hits = Fixtures.hits("/lists/block.txt")
        tapDesc(str(R.string.update_all))
        waitFor("asked again") { Fixtures.hits("/lists/block.txt") > hits }
        waitFor("done") { app.firewall.updating.value.isEmpty() }
        assertEquals(null, st.set(id)!!.error)
    }

    @Test
    @Covers("BL-02")
    fun catalogAddsAndDownloads() {
        launch()
        drawer(R.string.nav_blocklists)
        val malware = io.github.cinnamon415.packetwall.fw.Catalog.entries.filter {
            it.category ==
                io.github.cinnamon415.packetwall.fw.Catalog.Category.MALWARE
        }
        val ads = io.github.cinnamon415.packetwall.fw.Catalog.entries.first {
            it.category ==
                io.github.cinnamon415.packetwall.fw.Catalog.Category.ADS
        }
        // a category chip narrows the catalog
        dialogFreeChip(str(R.string.listcat_malware))
        waitText(malware.first().name)
        assertNoText(ads.name)
        // + adds the list and downloads it (from the internet: the real list); it leaves the catalog
        val e = malware.first { it.name.contains("mini") }
        tapDesc(str(R.string.add_list_named, e.name))
        val id = waitForValue("added") { st.blocklists.firstOrNull { it.url == e.url }?.id }
        waitFor("downloaded ${e.url}", 120_000) {
            id !in app.firewall.updating.value &&
                (st.set(id)!!.entries > 0 || st.set(id)!!.error != null)
        }
        assertEquals("download of ${e.url}", null, st.set(id)!!.error)
        assertTrue(st.set(id)!!.entries > 100)
        assertTrue(count(hasContentDescription(str(R.string.add_list_named, e.name))) == 0)
        waitText(str(R.string.entries_count, st.set(id)!!.entries), substring = true)
    }

    /** A chip outside dialogs that may sit off screen in a sideways row. */
    private fun dialogFreeChip(label: String) {
        val m = hasText(label) and androidx.compose.ui.test.isSelectable()
        ui.waitUntil("chip $label", 5000) { ui.onAllNodes(m).fetchSemanticsNodes().isNotEmpty() }
        ui.onAllNodes(m)[0].performScrollToCompat()
        ui.onAllNodes(m)[0].performClick()
        ui.waitForIdle()
    }

    @Test
    @Covers("BL-04", "DEC-11", "BL-07")
    fun listEntriesBlockAndTheSwitch() {
        launch()
        val id = addList(Fixtures.list("block.txt"), "E2E")
        drawer(R.string.nav_home)
        turnOn()
        // a plain entry: the domain and its subdomains
        assertBlocked("iana.org", rule = -id)
        assertBlocked("www.iana.org", rule = -id)
        // ||x^ with an exception @@||www.x^
        assertBlocked(Hosts.C, rule = -id)
        assertAllowed("www.${Hosts.C}")
        // a hosts line: this name only
        assertBlocked(Hosts.B, rule = -id)
        assertAllowed("www.${Hosts.B}")
        // the switch: off lets it through, on blocks again (names not asked before)
        drawer(R.string.nav_blocklists)
        setSwitch("E2E", false)
        waitFor("off") { !st.isEnabled(id) }
        assertNotBlockedName("a1.iana.org")
        setSwitch("E2E", true)
        assertBlocked("a2.iana.org", rule = -id)
        // the list's settings: reject answers NXDOMAIN; rename; delete with a confirmation
        tap("E2E")
        tapDesc(str(R.string.list_settings))
        waitText(Fixtures.list("block.txt"))
        assertText(str(R.string.list_stats, 4, 1, ""), substring = true)
        setCheck(str(R.string.reject_label), true)
        type("Mine")
        tap(str(R.string.save))
        waitFor("saved") { st.set(id)!!.reject && st.set(id)!!.name == "Mine" }
        settle()
        assertEquals(3, dnsAnswer("a3.iana.org").first)
        tapDesc(str(R.string.list_settings))
        tap(str(R.string.delete))
        waitText(str(R.string.delete_set_q, "Mine"))
        val del = hasText(str(R.string.delete)) and hasClickAction() and inDialog
        ui.onAllNodes(del)[visible(del).last()].performClick()
        waitFor("deleted") { st.set(id) == null }
        waitText(str(R.string.no_blocklists))
    }

    @Test
    @Covers("BL-03")
    fun downloadErrorsAndRecovery() {
        launch()
        // 404
        val missing = addList(Fixtures.list("e2e-missing.txt"), "Missing", expectError = true)
        drawer(R.string.nav_blocklists)
        waitText(str(R.string.problem_http_404))
        // the server gets it; Update now repairs it
        Fixtures.switch("e2e-missing.txt", "block.txt")
        tap("Missing")
        tapDesc(str(R.string.list_settings))
        tap(str(R.string.update_now))
        waitFor("repaired") { st.set(missing)!!.error == null && st.set(missing)!!.entries == 4 }
        back()
        // not a list: an error, and nothing blocked silently
        val bin = addList(Fixtures.list("bad.bin"), "Binary", expectError = true)
        drawer(R.string.nav_blocklists)
        waitText(str(R.string.problem_bad_data))
        assertEquals(0, st.set(bin)!!.entries)
        // a server that is down
        val down = addList("http://${Hosts.HOST}:9/list.txt", "Down", expectError = true)
        assertTrue(st.set(down)!!.error != null)
        waitText(str(R.string.problem_offline))
    }

    @Test
    @Covers("DEC-12")
    fun allowListIsAnException() {
        launch()
        val block = addList(Fixtures.list("block.txt"), "Block")
        val allow = addList(Fixtures.list("allow.txt"), "Exceptions")
        // the allow list: above the block list, action Allow
        drawer(R.string.nav_blocklists)
        tap("Exceptions")
        tapDesc(str(R.string.list_settings))
        val seg = hasText(str(R.string.action_allow)) and inDialog
        ui.onAllNodes(seg)[visible(seg).first()].performClick()
        tap(str(R.string.save))
        waitFor("allow") { st.set(allow)!!.action == Action.ALLOW }
        if (setPos("Exceptions") > setPos("Block")) moveSet("Exceptions", up = true)
        waitFor("allow first") { setPos("Exceptions") < setPos("Block") }
        drawer(R.string.nav_home)
        turnOn()
        assertAllowed("iana.org", rule = -allow)
        assertBlocked(Hosts.C, rule = -block)
    }

    @Test
    @Covers("LIST-01", "LIST-02", "LIST-03", "LIST-04", "LIST-05")
    fun entriesEditsSurviveAnUpdate() {
        launch()
        Fixtures.switch("e2e-dyn.txt", "dyn-v1.txt")
        val id = addList(Fixtures.list("e2e-dyn.txt"), "Dyn")
        drawer(R.string.nav_blocklists)
        tap("Dyn")
        waitText(str(R.string.list_entries))
        assertText(Hosts.C)
        assertText(Hosts.A)
        type("org")
        waitNoText(Hosts.C)
        assertText(Hosts.A)
        // switch example.org off: an edit
        // the checkbox on the row of example.org
        val label = ui.onAllNodes(has(Hosts.A)).fetchSemanticsNodes()[visible(has(Hosts.A)).first()].boundsInWindow
        val boxes = ui.onAllNodes(isToggleable()).fetchSemanticsNodes()
        val i = visible(isToggleable()).first { boxes[it].boundsInWindow.center.y in label.top - 40f..label.bottom + 40f }
        ui.onAllNodes(isToggleable())[i].performClick()
        waitText(str(R.string.entry_off), substring = true)
        waitText(str(R.string.list_my_edits, 1))
        // an own entry, checked
        tap(str(R.string.list_add_entry))
        dialogField(0).performTextInput("not a domain!")
        assertFalse(enabled(str(R.string.add)))
        dialogField(0).performTextClearance()
        dialogField(0).performTextInput("iana.org\n||example.com^")
        tap(str(R.string.add))
        waitText(str(R.string.list_my_edits, 3))
        drawer(R.string.nav_home)
        turnOn()
        assertAllowed(Hosts.A)
        assertBlocked("iana.org", rule = -id)
        assertBlocked(Hosts.B, rule = -id)
        assertBlocked(Hosts.C, rule = -id)
        // upstream changes: example.org leaves the list, iana.org comes in
        Fixtures.switch("e2e-dyn.txt", "dyn-v2.txt")
        drawer(R.string.nav_blocklists)
        tap("Dyn")
        tapDesc(str(R.string.list_settings))
        tap(str(R.string.update_now))
        waitFor("updated") { app.firewall.updating.value.isEmpty() && app.firewall.readList(id).contains("iana.org") }
        tap(str(R.string.cancel))
        // the edits are still there; the switched-off one is marked as gone
        tap(str(R.string.list_my_edits, 3))
        waitText(str(R.string.list_switched_off))
        assertText(str(R.string.edit_outdated))
        assertText(str(R.string.list_added))
        assertEquals(listOf(Hosts.A), st.set(id)!!.disabled)
        assertEquals(2, st.set(id)!!.added.size)
        // reset with a confirmation
        tap(str(R.string.list_reset_edits))
        waitText(str(R.string.list_reset_q, 3))
        val del = hasText(str(R.string.delete)) and hasClickAction() and inDialog
        ui.onAllNodes(del)[visible(del).last()].performClick()
        waitText(str(R.string.list_no_edits))
        assertTrue(st.set(id)!!.disabled.isEmpty() && st.set(id)!!.added.isEmpty())
    }

    /** Blocklists → By URL or from a file → From file → [name] in Download. */
    private fun importFile(name: String) {
        openAdd()
        tap(str(R.string.import_file))
        Docs.open(name)
    }

    @Test
    @Covers("IMPF-01", "IMPF-02", "IMPF-03", "IMPF-04")
    fun importHostsAndPcapdroid() {
        launch()
        Docs.put("e2e-hosts.txt", "# my hosts\n0.0.0.0 example.com\n0.0.0.0 example.net\n127.0.0.1 localhost\nthis is not a rule\n")
        importFile("e2e-hosts.txt")
        waitText(str(R.string.import_auto, "hosts / domains / uBO / AdGuard"))
        waitText(str(R.string.import_plan, 0, 2, 1))
        assertText("this is not a rule")
        // the name comes from the file
        assertTrue(count(hasText("e2e-hosts") and inDialog) > 0)
        val before = st.sets.map { it.id }.toSet()
        tap(str(R.string.import_action))
        waitText(str(R.string.import_done_sets, 1))
        tap(str(R.string.ok))
        val hostsSet = st.sets.first { it.id !in before }
        assertEquals("e2e-hosts", hostsSet.name)
        assertEquals(2, hostsSet.entries)
        assertEquals(st.order.last().id, hostsSet.id)
        // PCAPdroid's rules: hosts and IPs become global rules
        Docs.put("e2e-pcapdroid.json", """{"rules":[{"type":"HOST","value":"example.org"},{"type":"IP","value":"203.0.113.0/24"}]}""")
        importFile("e2e-pcapdroid.json")
        waitText(str(R.string.import_auto, "PCAPdroid"))
        waitText(str(R.string.import_plan, 2, 0, 0))
        tap(str(R.string.import_action))
        waitText(str(R.string.import_done_sets, 1))
        tap(str(R.string.ok))
        val pd = st.rules.filter { it.who == Who.Global }
        assertEquals(
            setOf(TargetKind.DOMAIN to "example.org", TargetKind.IP to "203.0.113.0/24"),
            pd.map {
                it.target.kind to
                    it.target.value
            }.toSet()
        )
        // both work
        drawer(R.string.nav_home)
        turnOn()
        assertBlocked(Hosts.B, rule = -hostsSet.id)
        assertAllowed("www.${Hosts.B}")
        assertBlocked(Hosts.A, rule = pd.first { it.target.kind == TargetKind.DOMAIN }.id)
    }

    @Test
    @Covers("IMPF-01", "IMPF-04")
    fun importNetGuardAndManualFormat() {
        launch()
        // NetGuard (apps allowed by default, system apps managed): the shell blocked on Wi-Fi and mobile = all its traffic
        Docs.put(
            "e2e-netguard.xml",
            """<?xml version='1.0' encoding='UTF-8' standalone='yes' ?><netguard><application><setting key="whitelist_wifi" type="boolean" value="false" /><setting key="whitelist_other" type="boolean" value="false" /><setting key="manage_system" type="boolean" value="true" /></application><wifi><setting key="$SHELL_PKG" type="boolean" value="true" /></wifi><mobile><setting key="$SHELL_PKG" type="boolean" value="true" /></mobile></netguard>"""
        )
        importFile("e2e-netguard.xml")
        waitText(str(R.string.import_auto, "NetGuard"))
        waitText(str(R.string.import_plan, 1, 0, 0))
        // the format can be picked by hand: as a plain list nothing is usable
        dialogChip("hosts / domains / uBO / AdGuard")
        waitFor("no import as a list") { !enabled(str(R.string.import_action)) }
        dialogChip(str(R.string.import_auto, "NetGuard"))
        waitText(str(R.string.import_plan, 1, 0, 0))
        tap(str(R.string.import_action))
        waitText(str(R.string.import_done_sets, 1))
        tap(str(R.string.ok))
        val r = st.rules.single()
        assertEquals(Who.App(SHELL_PKG), r.who)
        assertEquals(TargetKind.ALL, r.target.kind)
        assertEquals(Action.BLOCK, r.action)
    }

    @Test
    @Covers("IMPF-05")
    fun badFilesGiveAClearError() {
        launch()
        // binary: no format fits, nothing to import
        Docs.put("e2e-binary.dat", ByteArray(4096) { (it * 31 % 256).toByte() })
        importFile("e2e-binary.dat")
        waitFor("no import of a binary") { !enabled(str(R.string.import_action)) }
        tap(str(R.string.cancel))
        // over the size limit
        Shell.run("rm -f ${Docs.DIR}/e2e-huge.txt; truncate -s 101M ${Docs.DIR}/e2e-huge.txt")
        importFile("e2e-huge.txt")
        waitText(str(R.string.problem_too_large), timeoutMs = 30_000)
        assertFalse(enabled(str(R.string.import_action)))
        tap(str(R.string.cancel))
        Docs.remove("${Docs.DIR}/e2e-huge.txt")
        // a Packetwall export goes to the Packetwall import
        Docs.put("e2e-pw.json", app.firewall.exportJson())
        importFile("e2e-pw.json")
        waitText(str(R.string.import_json))
        assertText(str(R.string.import_merge))
        tap(str(R.string.cancel))
        assertTrue(st.rules.isEmpty())
    }
}

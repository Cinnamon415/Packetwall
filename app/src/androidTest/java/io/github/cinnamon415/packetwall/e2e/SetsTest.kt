package io.github.cinnamon415.packetwall.e2e

import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasContentDescription
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isPopup
import androidx.compose.ui.test.isSelectable
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTouchInput
import androidx.compose.ui.unit.dp
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.fw.FwState
import io.github.cinnamon415.packetwall.fw.TargetKind
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** SETS: sets and profiles. */
class SetsTest : E2eTest() {

    private val st get() = app.firewall.state.value
    private val main get() = str(R.string.profile_default)
    private val default get() = str(R.string.set_default)

    /** The "⋮" of the profile row [name]. */
    private fun profileMenu(name: String) {
        val m = hasContentDescription(str(R.string.more)) and hasAnyAncestor(hasText(name))
        ui.waitUntil("menu of $name", 5000) { count(m) > 0 }
        ui.onAllNodes(m)[visible(m).first()].performClick()
        ui.waitForIdle()
    }

    private fun menuItemEnabled(text: String): Boolean {
        val m = hasText(text) and hasAnyAncestor(isPopup())
        return ui.onAllNodes(m).fetchSemanticsNodes().first().config.getOrNull(SemanticsProperties.Disabled) == null
    }

    private fun radioOn(name: String): Boolean {
        val m = isSelectable() and hasAnyAncestor(hasText(name))
        return ui.onAllNodes(m).fetchSemanticsNodes().firstOrNull()?.config?.getOrNull(SemanticsProperties.Selected) == true
    }

    /** The set's dialog (still open after an export, else opened from its row). */
    private fun openSet(name: String) {
        if (!exists(str(R.string.delete_set))) tap(name)
        waitText(str(R.string.delete_set))
    }

    private fun exportTo(name: String, click: () -> Unit): String {
        val path = "${Docs.DIR}/$name"
        Docs.remove(path)
        expectToast(str(R.string.exported)) {
            click()
            Docs.save(name)
        }
        return Docs.readText(path)
    }

    @Test
    @Covers("SETS-01", "SETS-02", "SETS-03", "SETS-04")
    fun profiles() {
        launch()
        drawer(R.string.nav_sets)
        waitText(main)
        assertTrue("the only profile is active", radioOn(main))
        val n = st.order.size
        assertText(str(R.string.profile_summary, n, n))
        // one profile: it cannot be deleted
        profileMenu(main)
        assertFalse(menuItemEnabled(str(R.string.delete)))
        back()
        // a new profile from the current one becomes active
        tap(str(R.string.profile_new))
        type("Travel")
        tap(str(R.string.ok))
        waitText("Travel")
        val travel = st.profiles.first { it.name == "Travel" }
        assertEquals(travel.id, st.activeProfile)
        assertEquals(st.profiles.first { it.name == main }.sets, travel.sets)
        assertTrue(radioOn("Travel"))
        assertFalse(radioOn(main))
        // a set made now is known to Travel only; switching to Main turns it off there
        addSet("Work")
        assertTrue(st.isEnabled(setId("Work")))
        tap(main)
        waitFor("Main active") { st.activeProfile != travel.id }
        assertFalse("a set the profile does not know is off", st.isEnabled(setId("Work")))
        tap("Travel")
        waitFor("Travel active") { st.activeProfile == travel.id }
        assertTrue(st.isEnabled(setId("Work")))
        // rename
        profileMenu("Travel")
        tap(str(R.string.rename))
        type("Trip")
        tap(str(R.string.ok))
        waitText("Trip")
        assertNoText("Travel")
        // export: the profile with its sets
        profileMenu("Trip")
        val json = JSONObject(exportTo("e2e-profile.json") { tap(str(R.string.export)) })
        val state = json.getJSONObject("state")
        assertEquals("Trip", state.getJSONArray("profiles").getJSONObject(0).getString("name"))
        val names = (0 until state.getJSONArray("sets").length()).map { state.getJSONArray("sets").getJSONObject(it).getString("name") }
        assertTrue("sets in the export: $names", names.containsAll(listOf(default, "Work")))
        // delete the active profile: the first one left becomes active; undo brings it back
        profileMenu("Trip")
        tap(str(R.string.delete))
        waitFor("deleted") { st.profiles.none { it.id == travel.id } }
        assertEquals(st.profiles.first().id, st.activeProfile)
        waitText(str(R.string.undo_profile_deleted, "Trip"))
        tap(str(R.string.undo))
        waitFor("restored") { st.profiles.any { it.id == travel.id } && st.activeProfile == travel.id }
        waitText("Trip")
    }

    @Test
    @Covers("SETS-05", "SETS-06", "SETS-07")
    fun setsListSwitchAndDrag() {
        launch()
        addSet("Work")
        // at the end, on, numbered, with its rule count
        assertEquals(st.order.lastIndex, setPos("Work"))
        assertTrue(st.isEnabled(setId("Work")))
        addGlobalRule(RuleSpec(Hosts.B, set = "Work"))
        addGlobalRule(RuleSpec(Hosts.C, set = "Work"))
        drawer(R.string.nav_sets)
        waitText("Work")
        assertText(plural(R.plurals.rules_n, 2, 2))
        assertText("${setPos("Work") + 1}")
        // the switch is kept in the active profile
        setSwitch("Work", false)
        waitFor("off in the profile") { st.profile!!.sets.first { it.id == setId("Work") }.enabled == false }
        setSwitch("Work", true)
        waitFor("on in the profile") { st.profile!!.sets.first { it.id == setId("Work") }.enabled }
        // long press and drag to the top
        val before = setPos("Work")
        assertTrue(before > 0)
        val row = hasText("Work") and androidx.compose.ui.test.hasClickAction()
        ui.onAllNodes(row)[visible(row).first()].performTouchInput {
            down(center)
            advanceEventTime(800)
            repeat(20) { moveBy(Offset(0f, -(60.dp.toPx() * before + 20) / 20), delayMillis = 30) }
            up()
        }
        waitFor("Work dragged to the top") { setPos("Work") == 0 }
        waitText("Work")
    }

    @Test
    @Covers("SETS-08")
    fun setDialogRenameExportDelete() {
        launch()
        addSet("Work")
        addGlobalRule(RuleSpec(Hosts.B, set = "Work"))
        addGlobalRule(RuleSpec("203.0.113.0/24", kind = TargetKind.IP, set = "Work"))
        addGlobalRule(RuleSpec(Hosts.C, action = io.github.cinnamon415.packetwall.fw.Action.ALLOW, set = "Work"))
        val id = setId("Work")
        drawer(R.string.nav_sets)
        tap("Work")
        waitText(str(R.string.delete_set))
        type("Office")
        tap(str(R.string.save))
        waitFor("renamed") { st.set(id)?.name == "Office" }
        waitText("Office")
        // exports: JSON with the set's rules, hosts and domains with its global blocks
        openSet("Office")
        val json = JSONObject(exportTo("e2e-set.json") { tap("JSON") })
        assertEquals(3, json.getJSONObject("state").getJSONArray("rules").length())
        openSet("Office")
        val hosts = exportTo("e2e-set.hosts") { tap("hosts") }
        assertEquals("0.0.0.0 ${Hosts.B}", hosts.trim())
        openSet("Office")
        val domains = exportTo("e2e-set.txt") { tap(str(R.string.domains)) }
        assertEquals(listOf(Hosts.B, "203.0.113.0/24"), domains.trim().lines())
        // delete with a confirmation naming the rules
        openSet("Office")
        tap(str(R.string.delete_set))
        waitText(str(R.string.delete_set_rules_q, "Office", 3))
        tap(str(R.string.delete))
        waitFor("set and rules gone") { st.set(id) == null && st.rules.none { it.setId == id } }
        waitNoText("Office")
        // the default set cannot be deleted
        tap(default)
        waitText(str(R.string.save))
        assertNoText(str(R.string.delete_set))
        tap(str(R.string.cancel))
        assertTrue(st.set(FwState.DEFAULT_SET) != null)
    }

    @Test
    @Covers("SETS-09", "SETS-10")
    fun exportAllImportMergeReplaceRestore() {
        launch()
        addSet("Work")
        addGlobalRule(RuleSpec(Hosts.B, set = "Work"))
        addAppRule(shellName, RuleSpec(Hosts.C))
        drawer(R.string.nav_sets)
        val exported = st
        tapDesc(str(R.string.more))
        exportTo("e2e-all.json") { tap(str(R.string.export_json)) }
        // change things: a new set and rule, one rule gone
        addSet("Later")
        addGlobalRule(RuleSpec(Hosts.A, set = "Later"))
        app.firewall.deleteRule(exported.rules.first { it.target.value == Hosts.C }.id)
        val changed = waitForValue("changed") { st.takeIf { s -> s.rules.none { it.target.value == Hosts.C } } }
        // merge: the file's sets come in as new sets at the lowest priority
        drawer(R.string.nav_sets)
        tapDesc(str(R.string.more))
        tap(str(R.string.import_json))
        Docs.open("e2e-all.json")
        waitText(str(R.string.import_file_has, exported.sets.size, exported.rules.size, exported.groups.size, exported.profiles.size))
        tap(str(R.string.import_action))
        waitText(str(R.string.import_json_done, exported.sets.size, exported.rules.size, exported.groups.size, exported.profiles.size))
        tap(str(R.string.ok))
        val merged = st
        assertEquals(changed.sets.size + exported.sets.size, merged.sets.size)
        val newIds = merged.sets.map { it.id } - changed.sets.map { it.id }.toSet()
        assertEquals("new sets last", newIds.toSet(), merged.order.takeLast(newIds.size).map { it.id }.toSet())
        assertEquals(changed.rules.size + exported.rules.size, merged.rules.size)
        // replace: asks first, then the configuration is the file's
        tapDesc(str(R.string.more))
        tap(str(R.string.import_json))
        Docs.open("e2e-all.json")
        waitText(str(R.string.import_replace))
        tap(str(R.string.import_replace))
        tap(str(R.string.import_action))
        waitText(str(R.string.import_replace_confirm))
        tap(str(R.string.import_replace_action))
        waitText(str(R.string.import_restore))
        assertEquals(exported.rules, st.rules)
        assertEquals(exported.sets, st.sets)
        assertEquals(exported.profiles, st.profiles)
        // bring back the previous one
        expectToast(str(R.string.import_restored)) { tap(str(R.string.import_restore)) }
        waitFor("previous back") { st.rules == merged.rules && st.sets == merged.sets }
        assertEquals(merged.profiles, st.profiles)
    }

    @Test
    @Covers("SETS-11")
    fun brokenJsonChangesNothing() {
        launch()
        addGlobalRule(RuleSpec(Hosts.B))
        val before = st
        Docs.put("e2e-broken.json", "{\"format\": \"packetwall-rules\", \"state\": {\"sets\": [")
        drawer(R.string.nav_sets)
        tapDesc(str(R.string.more))
        tap(str(R.string.import_json))
        Docs.open("e2e-broken.json")
        // a readable error, an OK button, nothing else
        waitText(str(R.string.ok))
        assertNoText(str(R.string.import_action))
        assertNoText(str(R.string.import_merge))
        val shown = textsOf("").filter { it.isNotBlank() }
        assertTrue("no raw exception text: $shown", shown.none { it.contains("Exception") || it.contains("kotlinx") })
        tap(str(R.string.ok))
        assertEquals(before, st)
        // not a Packetwall file at all
        Docs.put("e2e-other.json", "{\"hello\": 1}")
        tapDesc(str(R.string.more))
        tap(str(R.string.import_json))
        Docs.open("e2e-other.json")
        waitText(str(R.string.ok))
        assertNoText(str(R.string.import_action))
        tap(str(R.string.ok))
        assertEquals(before, st)
    }
}

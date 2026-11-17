package io.github.cinnamon415.packetwall.fw

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

@OptIn(ExperimentalCoroutinesApi::class)
class FirewallStoreTest {
    @get:Rule val tmp = TemporaryFolder()

    private val uids = mapOf("com.a" to 10100, "com.b" to 10101)
    private var lastCompiled: String = ""

    private fun TestScope.store(dir: File = tmp.root) = FirewallStore(
        dir = dir,
        uidOf = { uids[it] },
        loader = { path -> lastCompiled = File(path).readText(); 0 },
        defaultSetName = "Default",
        defaultProfileName = "Main",
        lists = { url -> "||ads.$url^\n@@||ok.$url^\nexample.com##.banner\n".reader().buffered() },
        io = UnconfinedTestDispatcher(testScheduler),
        scope = TestScope(UnconfinedTestDispatcher(testScheduler)),
    )

    private fun rule(set: Int, who: Who, value: String, action: Action = Action.BLOCK) =
        Rule(0, set, who, Target(TargetKind.DOMAIN, value, true), action)

    @Test fun initialStateHasDefaultSetAndProfile() = runTest {
        val st = store().state.value
        assertEquals(listOf(FwState.DEFAULT_SET), st.order.map { it.id })
        assertEquals("Main", st.profile?.name)
    }

    @Test fun saveKeepsTheLastStateAfterManyQuickChanges() = runTest {
        val s = store()
        repeat(50) { s.addRule(rule(FwState.DEFAULT_SET, Who.Global, "host$it.example")) }
        advanceUntilIdle()
        val reloaded = store().state.value
        assertEquals(50, reloaded.rules.size)
        assertEquals("host49.example", reloaded.rules.last().target.value)
    }

    @Test fun profilesFollowTheLiveConfiguration() = runTest {
        val s = store()
        val work = s.addSet("Work")
        s.addProfile("Strict")                           // snapshot of the current order, becomes active
        val strict = s.state.value.activeProfile!!
        s.setEnabled(work, false)                        // edits the active profile ("Strict")
        assertFalse(s.state.value.profiles.first { it.id == strict }.sets.first { it.id == work }.enabled)
        val main = s.state.value.profiles.first { it.name == "Main" }.id
        s.activateProfile(main)
        assertTrue("Main had Work enabled", s.state.value.isEnabled(work))
        val later = s.addSet("Later")                    // other profiles get new sets appended, disabled
        assertFalse(s.state.value.profiles.first { it.id == strict }.sets.first { it.id == later }.enabled)
        s.deleteSet(work)
        assertTrue(s.state.value.profiles.all { p -> p.sets.none { it.id == work } })
    }

    @Test fun newUserSetsGoAboveBlocklistsAndDefaultCannotBeDeleted() = runTest {
        val s = store()
        val list = s.addBlocklist("List", "list.example")
        val user = s.addSet("Mine")
        assertEquals(listOf(FwState.DEFAULT_SET, user, list), s.state.value.order.map { it.id })
        s.deleteSet(FwState.DEFAULT_SET)
        assertTrue(s.state.value.set(FwState.DEFAULT_SET) != null)
    }

    @Test fun blocklistIsDownloadedConvertedAndCompiled() = runTest {
        val s = store()
        val id = s.addBlocklist("List", "list.example")
        advanceUntilIdle()
        assertEquals(listOf("ads.list.example", "!ok.list.example"), s.readList(id))
        val set = s.state.value.set(id)!!
        assertEquals(2, set.entries)
        assertEquals(1, set.skipped)
        s.compileNow()
        assertTrue(lastCompiled.contains("L\t1\t-$id\t1\t0\t"))
    }

    @Test fun bulkMoveDeleteAndExportOfSelectedRules() = runTest {
        val s = store()
        val other = s.addSet("Other")
        val a = s.addRule(rule(FwState.DEFAULT_SET, Who.Global, "a.example"))
        val b = s.addRule(rule(FwState.DEFAULT_SET, Who.App("com.a"), "b.example"))
        s.moveRules(setOf(a, b), other)
        assertTrue(s.state.value.rules.all { it.setId == other })
        val exported = FirewallStore.json.decodeFromString(ExportFile.serializer(), s.exportRules(setOf(b)))
        assertEquals(listOf("b.example"), exported.state.rules.map { it.target.value })
        s.deleteRules(setOf(a))
        assertEquals(listOf(b), s.state.value.rules.map { it.id })
    }

    @Test fun importMergeRemapsIdsAndReplaceSwapsEverything() = runTest {
        val src = store(tmp.newFolder("src"))
        val g = src.saveGroup(AppGroup(0, "G", listOf("com.a")))
        src.addRule(rule(FwState.DEFAULT_SET, Who.Group(g), "g.example"))
        val exported = src.exportJson()

        val dst = store(tmp.newFolder("dst"))
        dst.addRule(rule(FwState.DEFAULT_SET, Who.Global, "keep.example"))
        val sum = dst.importJson(exported, replace = false)
        assertEquals(1, sum.rules)
        val st = dst.state.value
        val imported = st.rules.first { it.target.value == "g.example" }
        assertTrue("set id remapped", imported.setId != FwState.DEFAULT_SET)
        assertEquals("group id remapped", st.groups.single().id, (imported.who as Who.Group).id)
        assertTrue(st.rules.any { it.target.value == "keep.example" })
        assertEquals("ids stay unique", st.rules.size, st.rules.map { it.id }.toSet().size)

        dst.importJson(exported, replace = true)
        assertEquals(listOf("g.example"), dst.state.value.rules.map { it.target.value })
    }

    @Test fun foreignImportLandsInNewSetsAtTheLowestPriority() = runTest {
        val s = store()
        val plan = ForeignImport.Plan(ForeignImport.Format.LIST,
            rules = listOf(Rule(0, 0, Who.App("com.a"), Target(TargetKind.DOMAIN, "pay.example", true), Action.BLOCK)),
            entries = listOf("ads.example"), important = listOf("track.example"))
        val ids = s.applyImport("Imp", plan, Action.BLOCK)
        assertEquals(3, ids.size)
        val order = s.state.value.order.map { it.id }
        assertEquals(ids.toSet(), order.takeLast(3).toSet())
        assertTrue("important above the list", order.indexOf(ids[0]) < order.indexOf(ids[1]))
    }
}

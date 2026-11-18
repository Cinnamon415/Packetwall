package io.github.cinnamon415.packetwall.fw

import java.io.File
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

@OptIn(ExperimentalCoroutinesApi::class)
class FirewallStoreTest {
    @get:Rule val tmp = TemporaryFolder()

    private val uids = mapOf("com.a" to 10100, "com.b" to 10101)
    private var lastCompiled: String = ""

    private fun TestScope.store(dir: File = tmp.root) = FirewallStore(
        dir = dir,
        uidOf = { uids[it] },
        loader = { path ->
            lastCompiled = File(path).readText()
            0
        },
        defaultSetName = "Default",
        defaultProfileName = "Main",
        lists = { url -> "||ads.$url^\n@@||ok.$url^\nexample.com##.banner\n".reader().buffered() },
        io = UnconfinedTestDispatcher(testScheduler),
        scope = TestScope(UnconfinedTestDispatcher(testScheduler))
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
        s.addProfile("Strict") // snapshot of the current order, becomes active
        val strict = s.state.value.activeProfile!!
        s.setEnabled(work, false) // edits the active profile ("Strict")
        assertFalse(s.state.value.profiles.first { it.id == strict }.sets.first { it.id == work }.enabled)
        val main = s.state.value.profiles.first { it.name == "Main" }.id
        s.activateProfile(main)
        assertTrue("Main had Work enabled", s.state.value.isEnabled(work))
        val later = s.addSet("Later") // other profiles get new sets appended, disabled
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
        val plan = ForeignImport.Plan(
            ForeignImport.Format.LIST,
            rules = listOf(Rule(0, 0, Who.App("com.a"), Target(TargetKind.DOMAIN, "pay.example", true), Action.BLOCK)),
            entries = listOf("ads.example"),
            important = listOf("track.example")
        )
        val ids = s.applyImport("Imp", plan, Action.BLOCK)
        assertEquals(3, ids.size)
        val order = s.state.value.order.map { it.id }
        assertEquals(ids.toSet(), order.takeLast(3).toSet())
        assertTrue("important above the list", order.indexOf(ids[0]) < order.indexOf(ids[1]))
    }

    @Test fun replaceImportOfAHandWrittenFileCompilesItsRules() = runTest {
        // the shape tools/e2e sends through the debug TestConfigActivity
        val text = """
            {"format": "packetwall-rules", "formatVersion": 1, "lists": {},
             "state": {"sets": [{"id": 1, "name": "Default"}, {"id": 2, "name": "Low"}],
                       "order": [{"id": 1, "enabled": true}, {"id": 2, "enabled": true}],
                       "rules": [{"id": 10, "setId": 1, "who": {"type": "global"},
                                  "target": {"kind": "DOMAIN", "value": "example.org", "subdomains": true}, "action": "BLOCK"},
                                 {"id": 11, "setId": 1, "who": {"type": "global"},
                                  "target": {"kind": "DOMAIN", "value": "www.example.org", "subdomains": false}, "action": "ALLOW"}],
                       "profiles": [{"id": 3, "name": "Main", "sets": [{"id": 1, "enabled": true}, {"id": 2, "enabled": true}]}],
                       "activeProfile": 3, "nextId": 10000}}
        """.trimIndent()
        val s = store()
        s.importJson(text, replace = true)
        s.compileNow()
        assertEquals(2, s.state.value.rules.size)
        assertTrue(lastCompiled, lastCompiled.contains("example.org"))
    }

    @Test fun deletingTheActiveProfileSwitchesToTheOthersOwnOrder() = runTest {
        val s = store()
        val work = s.addSet("Work")
        val main = s.state.value.activeProfile!!
        s.addProfile("Strict") // active now
        val strict = s.state.value.activeProfile!!
        s.setEnabled(work, false) // only in Strict
        s.deleteProfile(strict)
        assertEquals(main, s.state.value.activeProfile)
        assertTrue("Main's own switches are live again", s.state.value.isEnabled(work))
        s.setEnabled(FwState.DEFAULT_SET, true) // an edit must not copy Strict's switches into Main
        assertTrue(s.state.value.profiles.single().sets.first { it.id == work }.enabled)
    }

    @Test fun replaceKeepsABackupNeverLowersIdsAndIgnoresStaleListFiles() = runTest {
        val src = store(tmp.newFolder("src"))
        val exported = src.exportJson()
        val dst = store(tmp.newFolder("dst"))
        val list = dst.addBlocklist("Old list", null)
        dst.importList("Mine", ListParser.Result(listOf("old.example"), 0, emptyList(), 0), Action.BLOCK)
        val before = dst.state.value
        dst.importJson(exported, replace = true)
        assertTrue(dst.state.value.nextId >= before.nextId)
        assertTrue(dst.hasReplaceBackup)
        // a new list never reads a file of an earlier set with the same id
        val fresh = dst.addBlocklist("Fresh", null)
        assertEquals(emptyList<String>(), dst.readList(fresh))
        assertTrue(dst.restoreReplaceBackup())
        assertEquals(before.sets.map { it.id }, dst.state.value.sets.map { it.id })
        assertTrue(dst.state.value.sets.any { it.id == list })
    }

    @Test fun replaceNeedsAFullExport() = runTest {
        val src = store(tmp.newFolder("src"))
        val one = src.exportJson(FwState.DEFAULT_SET)
        val dst = store(tmp.newFolder("dst"))
        assertTrue(runCatching { dst.importJson(one, replace = true) }.isFailure)
    }

    @Test fun singleSetExportCarriesOnlyItsGroups() = runTest {
        val s = store()
        val used = s.saveGroup(AppGroup(0, "Used", listOf("com.a")))
        s.saveGroup(AppGroup(0, "Unused", listOf("com.b")))
        s.addRule(rule(FwState.DEFAULT_SET, Who.Group(used), "g.example"))
        val f = FirewallStore.json.decodeFromString(ExportFile.serializer(), s.exportJson(FwState.DEFAULT_SET))
        assertEquals(listOf("Used"), f.state.groups.map { it.name })
    }

    @Test fun mergeDropsRulesOfGroupsMissingFromTheFile() = runTest {
        val src = store(tmp.newFolder("src"))
        val g = src.saveGroup(AppGroup(0, "G", listOf("com.a")))
        src.addRule(rule(FwState.DEFAULT_SET, Who.Group(g), "g.example"))
        val f = FirewallStore.json.decodeFromString(ExportFile.serializer(), src.exportJson())
        val broken = FirewallStore.json.encodeToString(ExportFile.serializer(), f.copy(state = f.state.copy(groups = emptyList())))
        val dst = store(tmp.newFolder("dst"))
        val other = dst.saveGroup(AppGroup(0, "Local", listOf("com.b")))
        dst.importJson(broken, replace = false)
        assertTrue(dst.state.value.rules.none { (it.who as? Who.Group)?.id == other })
        assertTrue(dst.state.value.rules.none { it.target.value == "g.example" })
    }

    @Test fun batchUpdateCompilesOnceAndNotModifiedListsAreLeftAlone() = runTest {
        var loads = 0
        var calls = 0
        val source = object : ListSource {
            override fun open(url: String) = "||ads.$url^\n".reader().buffered()

            override fun openIfChanged(url: String, known: Validators?): Fetched? {
                calls++
                if (known?.etag == "v1") return null // 304
                return Fetched(open(url), Validators("v1", null))
            }
        }
        val s = FirewallStore(
            dir = tmp.root,
            uidOf = { uids[it] },
            loader = {
                loads++
                0
            },
            defaultSetName = "Default",
            defaultProfileName = "Main",
            lists = source,
            io = UnconfinedTestDispatcher(testScheduler),
            scope = TestScope(UnconfinedTestDispatcher(testScheduler))
        )
        val ids = listOf("a.example", "b.example", "c.example").map { s.addBlocklist(it, it) }
        advanceUntilIdle()
        assertTrue(ids.all { s.state.value.set(it)?.etag == "v1" })
        val stamp = s.listFile(ids[0]).lastModified()
        loads = 0
        calls = 0
        s.updateAllNow()
        advanceUntilIdle()
        assertEquals(3, calls)
        assertEquals("three unchanged lists: no reload at all", 0, loads)
        assertEquals(stamp, s.listFile(ids[0]).lastModified())
    }

    @Test fun listEditsSurviveUpdatesAndReachTheEngine() = runTest {
        val s = store()
        val id = s.addBlocklist("List", "list.example") // entries: ads.list.example, !ok.list.example
        advanceUntilIdle()
        s.setEntryDisabled(id, "ads.list.example", true)
        s.addEntries(id, ListParser.parse(sequenceOf("||mine.example^")).entries)
        s.compileNow()
        val path = lastCompiled.lines().first { it.startsWith("L\t") }.substringAfterLast('\t')
        val effective = File(path).readLines()
        assertEquals(listOf("!ok.list.example", "mine.example"), effective)
        // an update keeps the edits
        s.updateAllNow()
        advanceUntilIdle()
        assertEquals(listOf("ads.list.example"), s.state.value.set(id)!!.disabled)
        s.resetEdits(id)
        s.compileNow()
        assertTrue(lastCompiled.contains("$id.txt"))
    }

    @Test fun orphanListFilesAreRemoved() = runTest {
        val s = store()
        advanceUntilIdle()
        val id = s.addBlocklist("L", null)
        advanceUntilIdle()
        val lists = File(tmp.root, "lists")
        File(lists, "$id.txt").writeText("a.com\n")
        File(lists, "999.txt").writeText("old.com\n")
        File(lists, "999.edited.txt").writeText("old.com\n")
        File(lists, "notes").writeText("kept: not a list file")
        assertEquals(2, s.removeOrphanLists())
        assertTrue(File(lists, "$id.txt").exists())
        assertFalse(File(lists, "999.txt").exists())
        assertTrue(File(lists, "notes").exists())
    }
}

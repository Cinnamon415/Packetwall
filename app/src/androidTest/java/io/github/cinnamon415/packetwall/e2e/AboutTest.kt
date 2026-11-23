package io.github.cinnamon415.packetwall.e2e

import android.content.ClipboardManager
import io.github.cinnamon415.packetwall.R
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** ABOUT: version, guide, what's new, diagnostics. */
class AboutTest : E2eTest() {

    private fun about() {
        drawer(R.string.nav_about)
        waitText(str(R.string.diag_title))
    }

    /** The value of a diagnostics line ("Protection: On" → "On"). */
    private fun diag(key: Int): String = diag(str(key))

    private fun diag(key: String): String = waitForValue("diagnostics $key") {
        // a line is two texts side by side: the key, then its value
        scrollIntoView(has(key))
        val k = ui.onAllNodes(has(key), true).fetchSemanticsNodes().firstOrNull() ?: return@waitForValue null
        val all = ui.onAllNodes(
            androidx.compose.ui.test.SemanticsMatcher("a text") {
                it.config.contains(androidx.compose.ui.semantics.SemanticsProperties.Text)
            },
            true
        ).fetchSemanticsNodes()
        all.filter { n ->
            kotlin.math.abs(n.boundsInWindow.center.y - k.boundsInWindow.center.y) < 8 && n.boundsInWindow.left >= k.boundsInWindow.right
        }.minByOrNull { it.boundsInWindow.left }
            ?.config?.get(androidx.compose.ui.semantics.SemanticsProperties.Text)?.joinToString("") { it.text }
    }

    private fun diagValue(key: Int, expected: String) = waitFor("${str(key)} $expected (got ${runCatching { diag(key) }.getOrNull()})") {
        runCatching { diag(key) }.getOrNull() == expected
    }

    @Test
    @Covers("ABOUT-01", "ABOUT-02")
    fun versionGuideAndChangelog() {
        launch()
        about()
        val info = ctx.packageManager.getPackageInfo(PKG, 0)
        assertText("Packetwall ${info.versionName}")
        @Suppress("DEPRECATION")
        assertText(str(R.string.about_build, info.versionCode))
        tap(str(R.string.guide_title))
        waitText(str(R.string.guide_1_t))
        back()
        waitText(str(R.string.diag_title))
        tap(str(R.string.changelog_title))
        // the installed version is the newest entry, on top
        val release = info.versionName!!.substringBefore("-")
        waitText(release)
        val versions = textsOf(".").filter { Regex("^\\d+\\.\\d+\\.\\d+$").matches(it) }
        assertEquals("newest first: $versions", release, versions.first())
        back()
        waitText(str(R.string.diag_title))
    }

    @Test
    @Covers("ABOUT-03", "ABOUT-04")
    fun diagnosticsFollowTheState() {
        launch()
        addGlobalRule(RuleSpec(Hosts.B))
        about()
        diagValue(R.string.diag_protection, str(R.string.status_off))
        assertEquals(str(R.string.turned_off), diag("Upstream:"))
        diagValue(R.string.diag_routes, str(R.string.diag_routes_all))
        diagValue(R.string.diag_lists, str(R.string.diag_lists_v, 0, 0))
        drawer(R.string.nav_home)
        turnOn()
        about()
        diagValue(R.string.diag_protection, str(R.string.status_on))
        val st = app.firewall.state.value
        val on = st.order.count { it.enabled }
        waitFor("rules loaded: ${runCatching { diag(R.string.diag_rules) }.getOrNull()}") {
            runCatching {
                diag(R.string.diag_rules)
            }.getOrNull()?.endsWith(str(R.string.diag_rules_v, "", on, st.order.size).trimStart()) ==
                true
        }
        assertTrue(diag("DNS:").startsWith(str(R.string.dns_system)))
        // copy: the same report on the clipboard
        expectToast(str(R.string.copied)) { tap(str(R.string.diag_copy)) }
        var clip = ""
        instr.runOnMainSync {
            clip = ctx.getSystemService(ClipboardManager::class.java).primaryClip?.getItemAt(0)?.text?.toString() ?: ""
        }
        assertTrue(
            "report: $clip",
            clip.startsWith("Packetwall ") && clip.contains(str(R.string.diag_protection) + " " + str(R.string.status_on))
        )
        // save log: the report and the app's own log
        val name = "e2e-log-${System.nanoTime()}.txt"
        expectToast(str(R.string.exported)) {
            tap(str(R.string.diag_save_log))
            Docs.save(name)
        }
        val text = waitForValue("log") { Docs.readText("${Docs.DIR}/$name").takeIf { it.isNotEmpty() } }
        assertTrue(text.startsWith("Packetwall ") && text.contains(str(R.string.diag_protection)))
        assertTrue("logcat lines in the file", text.lines().size > 20)
        Docs.remove("${Docs.DIR}/$name")
    }

    @Test
    @Covers("ABOUT-05")
    fun creditsOpenTheBrowser() {
        launch()
        about()
        seeValue("PCAPdroid")
        tap("PCAPdroid")
        // another app (the browser) comes to the front with the project page
        val other = device.wait(
            androidx.test.uiautomator.Until.hasObject(androidx.test.uiautomator.By.pkg(java.util.regex.Pattern.compile("^(?!$PKG).*"))),
            10_000
        )
        assertTrue("a browser opened", other == true && device.currentPackageName != PKG)
        device.pressBack()
        backToApp()
        seeValue("PCAPdroid")
    }
}

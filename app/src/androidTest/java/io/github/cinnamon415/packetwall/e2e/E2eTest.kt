package io.github.cinnamon415.packetwall.e2e

import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.SemanticsNodeInteraction
import androidx.compose.ui.test.hasClickAction
import androidx.compose.ui.test.hasContentDescription
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.longClick
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextClearance
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.test.performTouchInput
import androidx.test.core.app.ActivityScenario
import io.github.cinnamon415.packetwall.MainActivity
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.engine.CaptureService
import kotlinx.coroutines.launch
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule

/**
 * Base of the e2e tests. Every test runs in a fresh process with cleared data (orchestrator,
 * clearPackageData). VPN consent and the notification permission are granted the way a user would
 * have granted them once; the consent dialog itself is tested in [AppShellTest].
 */
abstract class E2eTest {
    @get:Rule
    val ui = createEmptyComposeRule()

    var scenario: ActivityScenario<MainActivity>? = null

    open val grantVpn = true

    /** The one-time Always-on advice pops up the first time protection runs: off unless a test is about it. */
    open val alwaysOnTip = false

    // the register builds the list only while someone watches it: the test watches all along, whatever screen is open
    private var watcher: kotlinx.coroutines.Job? = null

    @Before
    fun baseSetUp() {
        @OptIn(kotlinx.coroutines.DelicateCoroutinesApi::class)
        watcher = kotlinx.coroutines.GlobalScope.launch { app.connections.conns.collect {} }
        Shell.run("pm grant $PKG android.permission.POST_NOTIFICATIONS; logcat -b crash -c")
        if (grantVpn) Vpn.grantConsent()
        if (!alwaysOnTip) app.settings.update { it.copy(alwaysOnTipShown = true) }
        // no check below may pass because the network is down
        if (!Net.vpnUp()) {
            var r = Net.allowed(Hosts.CONTROL)
            val end = System.currentTimeMillis() + 30_000
            while (!r.ok && System.currentTimeMillis() < end) {
                Thread.sleep(2000)
                r = Net.allowed(Hosts.CONTROL)
            }
            assertTrue("the emulator has no network (${r.line}): nothing can be tested", r.ok)
        }
    }

    @After
    fun baseTearDown() {
        watcher?.cancel()
        if (Vpn.running()) {
            CaptureService.stop(ctx)
            runCatching { Vpn.awaitDown() }
        }
        scenario?.close()
        // APP-09: no crash, no JNI error in any test
        val crash = Shell.run("logcat -d -b crash")
        assertTrue("crash during the test:\n$crash", !crash.contains(PKG))
        val jni = Shell.run("logcat -d --pid=${android.os.Process.myPid()} | grep -E 'JNI DETECTED ERROR|FATAL EXCEPTION|Fatal signal'")
        assertTrue("JNI error / fatal signal during the test:\n$jni", jni.isBlank())
    }

    fun launch(): ActivityScenario<MainActivity> {
        val s = ActivityScenario.launch(MainActivity::class.java)
        scenario = s
        ui.waitForIdle()
        return s
    }

    // ------------------------------------------------------------------ finding nodes

    fun has(text: String, substring: Boolean = false, ignoreCase: Boolean = false) =
        hasText(text, substring = substring, ignoreCase = ignoreCase)

    /** Nodes on screen only: the closed drawer stays composed beside the screen and must not count. */
    fun visible(m: SemanticsMatcher, unmerged: Boolean = false): List<Int> {
        val w = device.displayWidth
        val h = device.displayHeight
        return ui.onAllNodes(m, unmerged).fetchSemanticsNodes().mapIndexedNotNull { i, n ->
            val b = n.boundsInWindow
            i.takeIf { b.width > 0 && b.height > 0 && b.right > 0 && b.bottom > 0 && b.left < w && b.top < h }
        }
    }

    fun count(m: SemanticsMatcher, unmerged: Boolean = false) = visible(m, unmerged).size

    fun exists(text: String, substring: Boolean = false) = count(has(text, substring)) > 0 || count(has(text, substring), true) > 0

    /**
     * Effects of the screen (flow collectors, delays) run on the test's virtual clock: an update that a
     * background thread hands to one of them can wait there until the clock moves. Each poll moves it
     * one frame, unless a test drives the clock by hand.
     */
    fun pump() {
        if (ui.mainClock.autoAdvance) {
            ui.mainClock.advanceTimeBy(48)
            ui.waitForIdle()
        }
    }

    fun waitText(text: String, timeoutMs: Long = 8000, substring: Boolean = false) {
        try {
            ui.waitUntil("text \"$text\"", timeoutMs) {
                pump()
                exists(text, substring)
            }
        } catch (e: Throwable) {
            dumpTree("text $text")
            throw e
        }
    }

    fun waitNoText(text: String, timeoutMs: Long = 8000, substring: Boolean = false) {
        try {
            ui.waitUntil("no text \"$text\"", timeoutMs) {
                pump()
                !exists(text, substring)
            }
        } catch (e: Throwable) {
            dumpTree("no text $text")
            throw e
        }
    }

    fun assertText(text: String, substring: Boolean = false) = assertTrue("expected text \"$text\" on screen", exists(text, substring))

    fun assertNoText(text: String, substring: Boolean = false) = assertTrue("unexpected text \"$text\" on screen", !exists(text, substring))

    /** The clickable node that shows [text] (the last one when several do: dialogs and sheets are drawn last). */
    /** The semantics tree in logcat (tag E2ETREE), for a failing lookup. */
    fun dumpTree(why: String) {
        android.util.Log.i("E2ETREE", "---- $why")
        fun walk(n: androidx.compose.ui.semantics.SemanticsNode, depth: Int) {
            val c = n.config
            val text = c.getOrElse(androidx.compose.ui.semantics.SemanticsProperties.Text) { emptyList() }.joinToString("|") { it.text }
            val desc = c.getOrElse(androidx.compose.ui.semantics.SemanticsProperties.ContentDescription) { emptyList() }.joinToString("|")
            val click = c.contains(androidx.compose.ui.semantics.SemanticsActions.OnClick)
            android.util.Log.i("E2ETREE", "  ".repeat(depth) + "[$text] desc=[$desc] click=$click b=${n.boundsInWindow}")
            n.children.forEach { walk(it, depth + 1) }
        }
        runCatching { ui.onAllNodes(androidx.compose.ui.test.isRoot()).fetchSemanticsNodes().forEach { walk(it, 0) } }
    }

    /**
     * The clickable node that shows [text] (the last one when several do: dialogs and sheets are drawn
     * last). Some buttons keep their label out of the merged tree (extended FAB): then the label
     * itself, a touch on it lands on the button.
     */
    fun clickable(text: String, substring: Boolean = false): SemanticsNodeInteraction {
        val m = has(text, substring) and hasClickAction()
        val any = has(text, substring)
        try {
            ui.waitUntil("clickable \"$text\"", 8000) { count(m) > 0 || count(any, true) > 0 }
        } catch (e: Throwable) {
            dumpTree("clickable $text")
            throw e
        }
        return if (count(m) > 0) ui.onAllNodes(m)[visible(m).last()] else ui.onAllNodes(any, true)[visible(any, true).last()]
    }

    fun tap(text: String, substring: Boolean = false) {
        clickable(text, substring).apply { runCatching { performScrollTo() } }.performClick()
        ui.waitForIdle()
    }

    fun longTap(text: String, substring: Boolean = false) {
        val m = has(text, substring)
        ui.waitUntil("\"$text\"", 8000) { count(m) > 0 }
        ui.onAllNodes(m)[visible(m).last()].apply { runCatching { performScrollTo() } }.performTouchInput { longClick() }
        ui.waitForIdle()
    }

    fun tapDesc(desc: String) {
        val m = hasContentDescription(desc) and hasClickAction()
        val m2 = hasContentDescription(desc)
        ui.waitUntil("content description \"$desc\"", 8000) { count(m) > 0 || count(m2, true) > 0 }
        if (count(m) > 0) {
            ui.onAllNodes(m)[visible(m).last()].performClick()
        } else {
            ui.onAllNodes(m2, true)[visible(m2, true).last()].performClick()
        }
        ui.waitForIdle()
    }

    /** Whether the button with content description [desc] is enabled. */
    fun descEnabled(desc: String): Boolean {
        val m = hasContentDescription(desc)
        ui.waitUntil("content description \"$desc\"", 8000) { count(m, true) > 0 || count(m) > 0 }
        val n = ui.onAllNodes(m).fetchSemanticsNodes().lastOrNull() ?: return false
        return !n.config.contains(androidx.compose.ui.semantics.SemanticsProperties.Disabled)
    }

    /** Types into the text field that currently shows [label] (its label or placeholder) or the only field. */
    fun type(text: String, label: String? = null, clear: Boolean = true) {
        val base = if (label != null) hasSetTextAction() and hasText(label, substring = true) else hasSetTextAction()
        ui.waitUntil("text field ${label ?: ""}", 8000) { count(base) > 0 }
        // a field of an open dialog or sheet before the screen's own fields behind it
        val inDialog =
            base and androidx.compose.ui.test.hasAnyAncestor(androidx.compose.ui.test.isDialog() or androidx.compose.ui.test.isPopup())
        val m = if (count(inDialog) > 0) inDialog else base
        val n = ui.onAllNodes(m)[visible(m).last()]
        if (clear) n.performTextClearance()
        n.performTextInput(text)
        ui.waitForIdle()
    }

    /** Back from another app (Android settings, a picker) until Packetwall is in front again. */
    /**
     * App icons on screen (tagged "icon:<package>" by AppIcon with the package the image was loaded for),
     * each with the texts of its row: those beside it, at the same height.
     */
    fun iconRows(): List<Pair<String, List<String>>> {
        val tag = androidx.compose.ui.semantics.SemanticsProperties.TestTag
        val text = androidx.compose.ui.semantics.SemanticsProperties.Text
        val icons = ui.onAllNodes(
            androidx.compose.ui.test.SemanticsMatcher("an app icon") {
                it.config.getOrNull(tag)?.startsWith("icon:") ==
                    true
            },
            true
        )
            .fetchSemanticsNodes()
        val texts = ui.onAllNodes(androidx.compose.ui.test.SemanticsMatcher.keyIsDefined(text), true).fetchSemanticsNodes()
        val h = device.displayHeight
        return icons.filter { it.boundsInWindow.top >= 0 && it.boundsInWindow.bottom <= h }.map { i ->
            val b = i.boundsInWindow
            i.config[tag].removePrefix("icon:") to texts.filter { t ->
                val tb = t.boundsInWindow
                tb.left >= b.right && tb.center.y in b.top..b.bottom
            }.flatMap { t -> t.config[text].map { it.text } }
        }
    }

    fun backToApp() {
        repeat(4) {
            if (device.currentPackageName == PKG) return@repeat
            device.pressBack()
            device.wait(androidx.test.uiautomator.Until.hasObject(androidx.test.uiautomator.By.pkg(PKG).depth(0)), 2000)
        }
        ui.waitForIdle()
    }

    fun back() {
        device.pressBack()
        ui.waitForIdle()
    }

    /** Opens a top-level screen from the drawer. */
    fun drawer(navRes: Int) {
        // from a sub-screen (back arrow instead of the menu) go back to its top-level screen first
        val menu = hasContentDescription(str(R.string.menu)) and hasClickAction()
        repeat(4) { if (count(menu) == 0) back() }
        tapDesc(str(R.string.menu))
        tap(str(navRes))
    }

    // ------------------------------------------------------------------ protection

    fun turnOn() {
        tap(str(R.string.turn_on))
        Vpn.awaitUp()
    }

    fun turnOff() {
        tap(str(R.string.turn_off))
        Vpn.awaitDown()
    }
}

package io.github.cinnamon415.packetwall.e2e

import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isSelectable
import androidx.lifecycle.Lifecycle
import androidx.test.uiautomator.By
import androidx.test.uiautomator.Until
import io.github.cinnamon415.packetwall.R
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** APP: the shell around the screens. */
class AppShellTest : E2eTest() {

    /** A text only the given screen shows (the drawer label itself is also in the closed drawer). */
    private val screens = listOf(
        R.string.nav_logs to R.string.chip_blocked,
        R.string.nav_stats to R.string.speed,
        R.string.nav_files to R.string.files_open,
        R.string.nav_search to R.string.search_hint,
        R.string.nav_apps to R.string.group_new,
        R.string.nav_global to R.string.no_rules_global,
        R.string.nav_blocklists to R.string.catalog,
        R.string.nav_sets to R.string.profiles,
        R.string.nav_settings to R.string.settings_appearance,
        R.string.nav_about to R.string.diag_title,
        R.string.nav_home to R.string.recent_blocks
    )

    @Test
    @Covers("APP-02")
    fun drawerOpensEveryScreenAndMarksIt() {
        launch()
        for ((nav, marker) in screens) {
            tapDesc(str(R.string.menu))
            // the header shows the protection state
            assertText(str(R.string.status_off))
            tap(str(nav))
            waitText(str(marker))
            tapDesc(str(R.string.menu))
            val labels = screens.map { str(it.first) }.toSet()
            val selected = ui.onAllNodes(androidx.compose.ui.test.isSelected()).fetchSemanticsNodes()
                .flatMap { n -> n.config.getOrElse(androidx.compose.ui.semantics.SemanticsProperties.Text) { emptyList() }.map { it.text } }
                .filter { it in labels }
            assertEquals("selected drawer item on ${str(nav)}", listOf(str(nav)), selected)
            back()
        }
        // the header follows the state
        turnOn()
        tapDesc(str(R.string.menu))
        val onHeader = count(has(str(R.string.status_on)))
        assertTrue("drawer header shows On", onHeader >= 1)
        back()
    }

    @Test
    @Covers("APP-03")
    fun backClosesDrawerThenPopsThenLeaves() {
        val s = launch()
        drawer(R.string.nav_settings)
        waitText(str(R.string.settings_appearance))
        tapDesc(str(R.string.menu))
        waitText(str(R.string.nav_group_firewall))
        back()
        // the drawer is closed, the screen is still Settings
        ui.waitUntil(timeoutMillis = 3000) { count(has(str(R.string.nav_group_firewall))) == 0 }
        assertText(str(R.string.settings_appearance))
        drawer(R.string.nav_about)
        tap(str(R.string.changelog_title))
        waitText("0.7.2", substring = true)
        back()
        waitText(str(R.string.diag_title))
        // a top-level screen goes back to Home, Home leaves the app
        back()
        waitText(str(R.string.recent_blocks))
        device.pressBack()
        waitFor("activity finished", 5000) { s.state == Lifecycle.State.DESTROYED }
    }

    @Test
    @Covers("APP-04")
    fun rotationAndRecreationKeepScreenTabAndFilter() {
        val s = launch()
        drawer(R.string.nav_logs)
        tap(str(R.string.chip_blocked))
        type("host ~ example")
        tap(str(R.string.tab_dns))
        s.recreate()
        ui.waitForIdle()
        assertText("host ~ example")
        ui.onNode(hasText(str(R.string.tab_dns)) and isSelectable()).assertIsSelected()
        ui.onNode(hasText(str(R.string.chip_blocked)) and isSelectable()).assertIsSelected()
        device.setOrientationLeft()
        try {
            ui.waitForIdle()
            Thread.sleep(1500)
            assertText("host ~ example")
            ui.onNode(hasText(str(R.string.tab_dns)) and isSelectable()).assertIsSelected()
            ui.onNode(hasText(str(R.string.chip_blocked)) and isSelectable()).assertIsSelected()
        } finally {
            device.setOrientationNatural()
            device.unfreezeRotation()
        }
        ui.waitForIdle()
        assertText("host ~ example")
    }

    @Test
    @Covers("APP-05")
    fun otherAppsCannotSwitchProtectionOff() {
        launch()
        turnOn()
        val act = "$PKG/io.github.cinnamon415.packetwall.MainActivity"
        for (a in listOf(
            "io.github.cinnamon415.packetwall.TOGGLE_OFF",
            "io.github.cinnamon415.packetwall.STOP",
            "android.intent.action.MAIN"
        )) {
            Shell.run("am start -n $act -a $a --es protection off --ez stop true")
        }
        // the services are not exported: the shell cannot reach them either
        val svc = Shell.run(
            "am startservice -n $PKG/io.github.cinnamon415.packetwall.engine.CaptureService -a io.github.cinnamon415.packetwall.STOP 2>&1"
        )
        Thread.sleep(3000)
        assertTrue("protection is still on", Vpn.running() && Net.vpnUp())
        assertTrue(
            "the capture service is not exported: $svc",
            svc.contains("Error") || svc.contains("not exported") || svc.contains("Security")
        )
        assertAllowed(Hosts.A)
    }

    @Test
    @Covers("APP-08")
    fun alwaysOnStateWithoutProtection() {
        launch()
        drawer(R.string.nav_settings)
        waitText(str(R.string.always_on_unknown))
        tap(str(R.string.always_on_unknown))
        // the row opens Android's VPN settings
        waitObj(By.pkg("com.android.settings"), what = "Android VPN settings")
        backToApp()
        waitText(str(R.string.always_on_unknown))
        drawer(R.string.nav_home)
        turnOn()
        drawer(R.string.nav_settings)
        waitText(str(R.string.always_on_off))
    }
}

/** APP-01: the first start asks for the VPN permission. */
class VpnConsentTest : E2eTest() {
    override val grantVpn = false

    @Test
    @Covers("APP-01")
    fun consentDialogCancelThenOk() {
        Shell.run("appops set $PKG ACTIVATE_VPN default")
        launch()
        tap(str(R.string.turn_on))
        val cancel = waitObj(By.res("android:id/button2").pkg("com.android.vpndialogs"), what = "VPN consent dialog")
        expectToast(str(R.string.vpn_denied)) { cancel.click() }
        Thread.sleep(1000)
        assertFalse("protection stays off", Vpn.running())
        waitText(str(R.string.status_off))
        tap(str(R.string.turn_on))
        waitObj(By.res("android:id/button1").pkg("com.android.vpndialogs"), what = "VPN consent dialog").click()
        Vpn.awaitUp()
        waitText(str(R.string.turn_off))
        assertAllowed(Hosts.A)
    }
}

/** APP-07: the Always-on advice. */
class AlwaysOnAdviceTest : E2eTest() {
    override val alwaysOnTip = true

    @Test
    @Covers("APP-07")
    fun adviceOnceLater() {
        launch()
        turnOn()
        waitText(str(R.string.always_on_dialog_title))
        tap(str(R.string.later))
        waitNoText(str(R.string.always_on_dialog_title))
        assertTrue(app.settings.current.alwaysOnTipShown)
        turnOff()
        turnOn()
        Thread.sleep(2000)
        assertNoText(str(R.string.always_on_dialog_title))
    }

    @Test
    @Covers("APP-07")
    fun adviceOpensVpnSettings() {
        launch()
        turnOn()
        waitText(str(R.string.always_on_dialog_title))
        tap(str(R.string.diag_open_vpn_settings))
        waitObj(By.pkg("com.android.settings"), what = "Android VPN settings")
        device.pressBack()
        device.wait(Until.hasObject(By.pkg(PKG)), 5000)
        assertNoText(str(R.string.always_on_dialog_title))
        assertTrue(app.settings.current.alwaysOnTipShown)
    }
}

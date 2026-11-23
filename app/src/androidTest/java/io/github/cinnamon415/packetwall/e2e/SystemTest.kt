package io.github.cinnamon415.packetwall.e2e

import android.appwidget.AppWidgetHost
import android.appwidget.AppWidgetHostView
import android.appwidget.AppWidgetManager
import android.content.ComponentName
import android.view.View
import android.widget.TextView
import androidx.test.uiautomator.By
import androidx.test.uiautomator.Until
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.engine.CaptureStatus
import io.github.cinnamon415.packetwall.system.ProtectionTile
import io.github.cinnamon415.packetwall.system.ProtectionWidget
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** SYS: notification, quick settings tile, widget. */
class SystemTest : E2eTest() {

    private val tile get() = ComponentName(ctx, ProtectionTile::class.java).flattenToString()

    @Test
    @Covers("SYS-01", "SYS-02")
    fun notificationShowsActionsAndStopTurnsOff() {
        launch()
        turnOn()
        Shade.open()
        assertTrue("ongoing notification", Shade.has(str(R.string.notif_running), 8000))
        val acts = Shade.actions(str(R.string.notif_running)).map { it.lowercase() }
        assertEquals("actions", listOf(str(R.string.action_pause), str(R.string.action_stop)).map { it.lowercase() }, acts)
        Shade.action(str(R.string.notif_running), str(R.string.action_stop))
        Vpn.awaitDown()
        assertFalse("notification gone", Shade.has(str(R.string.notif_running), 2000))
        Shade.close()
        waitText(str(R.string.status_off))
        waitText(str(R.string.turn_on))
        // traffic goes around: not logged any more
        val t = System.currentTimeMillis()
        assertTrue(Net.allowed(Hosts.A).ok)
        Rows.assertNone("traffic after Stop", 2000) { it.firstSeen >= t }
    }

    @Test
    @Covers("SYS-03")
    fun notificationPauseAndResume() {
        launch()
        turnOn()
        Shade.open()
        Shade.action(str(R.string.notif_running), str(R.string.action_pause))
        assertTrue("paused notification", Shade.has(str(R.string.notif_paused), 8000))
        assertEquals(
            listOf(str(R.string.action_resume), str(R.string.action_stop)).map { it.lowercase() },
            Shade.actions(str(R.string.notif_paused)).map { it.lowercase() }
        )
        assertTrue(CaptureStatus.paused)
        Shade.close()
        waitText(str(R.string.status_paused))
        waitText(str(R.string.action_resume))
        Shade.open()
        Shade.action(str(R.string.notif_paused), str(R.string.action_resume))
        assertTrue("running notification again", Shade.has(str(R.string.notif_running), 8000))
        Shade.close()
        waitFor("not paused") { !CaptureStatus.paused }
        waitText(str(R.string.action_pause))
    }

    @Test
    @Covers("SYS-04")
    fun notificationOpensApp() {
        launch()
        turnOn()
        device.pressHome()
        device.wait(Until.gone(By.pkg(PKG)), 3000)
        Shade.open()
        Shade.tap(str(R.string.notif_running))
        assertNotNull("app in front", device.wait(Until.hasObject(By.pkg(PKG).depth(0)), 8000).takeIf { it })
        waitText(str(R.string.status_on))
    }

    @Test
    @Covers("SYS-05", "SYS-07")
    fun quickSettingsTileTogglesAndShowsProfile() {
        launch()
        Shell.run("cmd statusbar add-tile $tile")
        try {
            Shell.run("cmd statusbar click-tile $tile; sleep 0.5; cmd statusbar collapse")
            Vpn.awaitUp()
            waitText(str(R.string.status_on))
            device.openQuickSettings()
            // the tile: label Packetwall, subtitle = the active profile
            val profile = app.firewall.state.value.profile!!.name
            assertNotNull("tile shows the profile", device.wait(Until.findObject(By.textContains(profile)), 5000))
            device.pressBack()
            device.pressBack()
            Shell.run("cmd statusbar click-tile $tile; sleep 0.5; cmd statusbar collapse")
            Vpn.awaitDown()
            waitText(str(R.string.status_off))
            // SYS-07: off and on again in quick succession, three times: ends up on and filtering
            Shell.run("cmd statusbar click-tile $tile; sleep 0.5; cmd statusbar collapse")
            Vpn.awaitUp()
            repeat(3) { Shell.run("cmd statusbar click-tile $tile; cmd statusbar click-tile $tile") }
            Shell.run("cmd statusbar collapse")
            Vpn.awaitUp()
            assertAllowed(Hosts.A)
        } finally {
            Shell.run("cmd statusbar remove-tile $tile")
        }
    }

    @Test
    @Covers("SYS-06")
    fun widgetTogglesSwitchesProfileAndOpensApp() {
        launch()
        // a second profile to switch to
        drawer(R.string.nav_sets)
        tap(str(R.string.profile_new))
        type("Travel")
        tap(str(R.string.ok))
        waitText("Travel")
        val st = app.firewall.state.value
        val first = st.profiles.first().name
        assertEquals("the new profile is active", "Travel", st.profile?.name)
        drawer(R.string.nav_home)

        Shell.run("appwidget grantbind --package $PKG")
        val host = AppWidgetHost(ctx, 4711)
        val mgr = AppWidgetManager.getInstance(ctx)
        val id = host.allocateAppWidgetId()
        try {
            val provider = ComponentName(ctx, ProtectionWidget::class.java)
            assertTrue("widget bound", mgr.bindAppWidgetIdIfAllowed(id, provider))
            lateinit var view: AppWidgetHostView
            instr.runOnMainSync {
                host.startListening()
                view = host.createView(ctx, id, mgr.getAppWidgetInfo(id))
                view.layout(0, 0, 800, 300)
            }
            ProtectionWidget.update(ctx)
            fun text(res: Int): String {
                var t = ""
                instr.runOnMainSync { t = (view.findViewById<View>(res) as TextView).text.toString() }
                return t
            }
            waitFor("widget shows Off and the profile") {
                text(R.id.widget_status) == str(R.string.status_off) &&
                    text(R.id.widget_profile) == "Travel"
            }
            instr.runOnMainSync { view.findViewById<View>(R.id.widget_power).performClick() }
            Vpn.awaitUp()
            waitFor("widget shows On") { text(R.id.widget_status) == str(R.string.status_on) }
            waitText(str(R.string.status_on))
            instr.runOnMainSync { view.findViewById<View>(R.id.widget_profile).performClick() }
            waitFor("next profile active") { app.firewall.state.value.profile?.name == first }
            waitFor("widget shows the next profile") { text(R.id.widget_profile) == first }
            // Home shows it too
            waitText(first, substring = true)
            instr.runOnMainSync { view.findViewById<View>(R.id.widget_power).performClick() }
            Vpn.awaitDown()
            waitFor("widget shows Off") { text(R.id.widget_status) == str(R.string.status_off) }
            device.pressHome()
            device.wait(Until.gone(By.pkg(PKG)), 3000)
            instr.runOnMainSync { view.findViewById<View>(R.id.widget_status).performClick() }
            assertTrue("app opened from the widget", device.wait(Until.hasObject(By.pkg(PKG).depth(0)), 8000))
        } finally {
            instr.runOnMainSync { host.stopListening() }
            host.deleteAppWidgetId(id)
        }
    }

    @Test
    @Covers("SYS-08")
    fun anotherVpnTakesOver() {
        launch()
        turnOn()
        val other = instr.context
        Shell.run("appops set ${other.packageName} ACTIVATE_VPN allow")
        try {
            Shell.run("am start -W -n ${other.packageName}/${OtherVpnSwitch::class.java.name} --ez stop false")
            // Android revokes Packetwall's VPN: protection off, the screen says so, our tunnel is gone
            waitFor("Packetwall's VPN revoked", 15_000) { !Vpn.running() }
            backToApp()
            waitText(str(R.string.status_off))
            waitFor("the other VPN is up") { Shell.run("ip addr").contains("10.111.0.1") }
            assertFalse("Packetwall's address is gone", Shell.run("ip addr").contains("10.215.173.1"))
            // turning protection on takes it back
            turnOn()
            assertAllowed(Hosts.A)
            waitFor("the other VPN gone") { !Shell.run("ip addr").contains("10.111.0.1") }
        } finally {
            Shell.run("am start -W -n ${other.packageName}/${OtherVpnSwitch::class.java.name} --ez stop true")
            Shell.run("appops set ${other.packageName} ACTIVATE_VPN default")
        }
    }
}

/** SYS-05: the tile without VPN permission asks for it. */
class TileConsentTest : E2eTest() {
    override val grantVpn = false

    @Test
    @Covers("SYS-05")
    fun tileWithoutConsentOpensTheDialog() {
        Shell.run("appops set $PKG ACTIVATE_VPN default")
        val tile = ComponentName(ctx, ProtectionTile::class.java).flattenToString()
        Shell.run("cmd statusbar add-tile $tile")
        try {
            Shell.run("cmd statusbar click-tile $tile; sleep 0.5; cmd statusbar collapse")
            val ok = waitObj(By.res("android:id/button1").pkg("com.android.vpndialogs"), what = "VPN consent dialog from the tile")
            ok.click()
            Vpn.awaitUp()
            assertNull(android.net.VpnService.prepare(ctx))
        } finally {
            Shell.run("cmd statusbar remove-tile $tile")
            device.pressBack()
        }
    }
}

package io.github.cinnamon415.packetwall.ui

import io.github.cinnamon415.packetwall.engine.AppInfo
import org.junit.Assert.assertEquals
import org.junit.Test

class ProxyPickRowsTest {
    private val self = "io.github.cinnamon415.packetwall"
    private val apps = listOf(
        AppInfo(10100, "com.follow.clash", "FlClash", false),
        AppInfo(10101, "com.v2ray.ang", "v2rayNG", false),
        AppInfo(10102, "org.mozilla.firefox", "Firefox", false),
        AppInfo(10050, "com.android.bips", "Print service", true),
        AppInfo(10051, "com.android.vpndialogs", "VPN dialogs", true),
        AppInfo(1000, "android", "Android system", true),
        AppInfo(10200, "$self.debug", "Packetwall", false),
        AppInfo(10201, self, "Packetwall", false)
    )
    private val vpn = setOf("com.follow.clash", "com.v2ray.ang", "$self.debug", "com.android.vpndialogs")

    private fun names(rows: List<ProxyPickRow>) = rows.map {
        when (it) {
            is ProxyPickRow.Header -> if (it.vpnClients) "[vpn]" else "[other]"
            is ProxyPickRow.App -> it.app.packageName
        }
    }

    @Test
    fun vpnClientsFirstSystemHiddenSelfNever() {
        assertEquals(
            listOf("[vpn]", "com.follow.clash", "com.v2ray.ang", "[other]", "org.mozilla.firefox"),
            names(proxyPickRows(apps, vpn, "", false, "", self))
        )
    }

    @Test
    fun systemChipShowsSystemApps() {
        assertEquals(
            listOf("[vpn]", "com.follow.clash", "com.v2ray.ang", "com.android.vpndialogs", "[other]", "org.mozilla.firefox", "com.android.bips"),
            names(proxyPickRows(apps, vpn, "", true, "", self))
        )
    }

    @Test
    fun selectedSystemAppStaysVisible() {
        assertEquals(
            listOf("[vpn]", "com.follow.clash", "com.v2ray.ang", "[other]", "org.mozilla.firefox", "com.android.bips"),
            names(proxyPickRows(apps, vpn, "", false, "com.android.bips", self))
        )
    }

    @Test
    fun searchIsFlatAndMatchesNameOrPackage() {
        assertEquals(listOf("com.follow.clash"), names(proxyPickRows(apps, vpn, " flcl ", false, "", self)))
        assertEquals(listOf("com.v2ray.ang"), names(proxyPickRows(apps, vpn, "V2RAY.ANG", false, "", self)))
        assertEquals(emptyList<String>(), names(proxyPickRows(apps, vpn, "bips", false, "", self)))
        assertEquals(emptyList<String>(), names(proxyPickRows(apps, vpn, "packetwall", true, "", self)))
    }

    @Test
    fun noHeadersWithoutVpnClients() {
        assertEquals(listOf("org.mozilla.firefox", "com.follow.clash", "com.v2ray.ang"), names(proxyPickRows(apps, emptySet(), "", false, "", self)))
    }
}

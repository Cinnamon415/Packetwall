package io.github.cinnamon415.packetwall.engine

import android.net.VpnService
import android.util.Log

/** Addresses, routes and per-app exclusions of the VPN interface. */
object VpnSetup {
    const val IP4 = "10.215.173.1"

    /** The VPN's DNS address: queries to it are answered by the engine (forwarded or blocked). */
    const val DNS4 = "10.215.173.2"
    const val IP6 = "fd00:2:fd00:1:fd00:1:fd00:1"
    const val MTU = 10000
    const val FALLBACK_DNS4 = "9.9.9.10"
    const val FALLBACK_DNS6 = "2620:fe::10"
    private const val TAG = "VpnSetup"

    /** IPv4 routes into the VPN: everything, or everything except local networks (the VPN's own /30 stays inside). */
    fun ipv4Routes(lanBypass: Boolean): List<Routes.Cidr> = if (lanBypass) {
        Routes.subtract(Routes.parse("0.0.0.0/0"), Routes.LOCAL_V4) + Routes.parse("10.215.173.0/30")
    } else {
        listOf(Routes.parse("0.0.0.0/1"), Routes.parse("128.0.0.0/1"))
    }

    /**
     * Configures [b]. [excludedApps] send their traffic directly (Packetwall itself, the upstream
     * proxy app). With [dohProxy] every query must reach the IPv4 VPN DNS, so no IPv6 DNS is set.
     */
    fun configure(b: VpnService.Builder, session: String, lanBypass: Boolean, excludedApps: List<String>, dohProxy: Boolean) {
        b.setMtu(MTU)
            .setSession(session)
            .addAddress(IP4, 30)
            .addDnsServer(DNS4)
            .addAddress(IP6, 128)
            .addRoute("2000::", 3)
        ipv4Routes(lanBypass).forEach { b.addRoute(it.toString().substringBefore('/'), it.prefix) }
        if (!lanBypass) b.addRoute("fc00::", 7)
        b.setMetered(false)
        for (pkg in excludedApps) {
            try {
                b.addDisallowedApplication(pkg)
            } catch (e: Exception) {
                Log.w(TAG, "cannot exclude $pkg: $e")
            }
        }
        if (!dohProxy) {
            try {
                b.addDnsServer(FALLBACK_DNS6)
            } catch (e: IllegalArgumentException) {
                Log.w(TAG, "IPv6 DNS not set: $e")
            }
        }
    }
}

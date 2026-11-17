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
     * IPv6 routes: everything (also NAT64 prefixes such as 64:ff9b::/96, which would otherwise leave
     * the VPN), or everything except link-local, unique-local and multicast with the LAN bypass.
     */
    fun ipv6Routes(lanBypass: Boolean): List<Routes6.Cidr> =
        if (lanBypass) Routes6.subtract(Routes6.parse("::/0"), Routes6.LOCAL_V6) else listOf(Routes6.parse("::/0"))

    /**
     * Configures [b]. [excludedApps] send their traffic directly (Packetwall itself, the upstream
     * proxy app). Only the IPv4 VPN DNS is set: every query reaches the engine and goes to the
     * resolver the user chose, never to a hidden fallback.
     */
    fun configure(b: VpnService.Builder, session: String, lanBypass: Boolean, excludedApps: List<String>) {
        b.setMtu(MTU)
            .setSession(session)
            .addAddress(IP4, 30)
            .addDnsServer(DNS4)
            .addAddress(IP6, 128)
        ipv4Routes(lanBypass).forEach { b.addRoute(it.toString().substringBefore('/'), it.prefix) }
        ipv6Routes(lanBypass).forEach { b.addRoute(it.address(), it.prefix) }
        b.setMetered(false)
        for (pkg in excludedApps) {
            try {
                b.addDisallowedApplication(pkg)
            } catch (e: Exception) {
                Log.w(TAG, "cannot exclude $pkg: $e")
            }
        }
    }
}

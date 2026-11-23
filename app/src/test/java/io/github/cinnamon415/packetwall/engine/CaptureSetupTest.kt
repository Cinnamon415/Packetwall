package io.github.cinnamon415.packetwall.engine

import io.github.cinnamon415.packetwall.Settings
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CaptureSetupTest {
    private fun s(udp: Int, onDown: Int) = Settings.Values(upstream = true, upUdp = udp, upOnDown = onDown)

    @Test fun upstreamUpUsesTheProxyAndBlocksUdpOnlyWhenAsked() {
        assertEquals(UpstreamDecision(true, false), upstreamDecision(true, false, false, s(UDP_DIRECT, ON_DOWN_KILL)))
        assertEquals(UpstreamDecision(true, true), upstreamDecision(true, false, false, s(UDP_BLOCK, ON_DOWN_KILL)))
        assertEquals(UpstreamDecision(true, false), upstreamDecision(true, true, true, s(UDP_PROXY, ON_DOWN_KILL)))
    }

    @Test fun killSwitchKeepsProxyingAndBlocksUdpWithoutRelay() {
        // proxy down, kill switch: still "active" (nothing leaks) and the engine blocks what would use it
        assertEquals(UpstreamDecision(true, false, kill = true), upstreamDecision(false, false, false, s(UDP_DIRECT, ON_DOWN_KILL)))
        // relay wanted but missing: UDP must not go out directly
        assertEquals(UpstreamDecision(true, true), upstreamDecision(true, true, false, s(UDP_PROXY, ON_DOWN_KILL)))
    }

    @Test fun goDirectWhenDownDropsTheProxyEntirely() {
        val direct = 1
        assertEquals(UpstreamDecision(false, false), upstreamDecision(false, false, false, s(UDP_BLOCK, direct)))
        // up again: back through the proxy; a missing relay does not block UDP in this mode
        assertEquals(UpstreamDecision(true, false), upstreamDecision(true, true, false, s(UDP_PROXY, direct)))
    }

    @Test fun vpnRoutes() {
        assertEquals(listOf("0.0.0.0/1", "128.0.0.0/1"), VpnSetup.ipv4Routes(false).map { it.toString() })
        val bypass = VpnSetup.ipv4Routes(true)
        fun covered(ip: String) = bypass.any { it.contains(Routes.parse("$ip/32")) }
        assertTrue(covered("8.8.8.8"))
        assertTrue("the VPN's own DNS stays routed", covered(VpnSetup.DNS4))
        assertFalse(covered("192.168.1.10"))
        assertFalse(covered("10.215.173.5"))
    }

    @Test fun ipv6RoutesCoverNat64AndKeepTheLanOutside() {
        assertEquals(listOf(Routes6.parse("::/0")), VpnSetup.ipv6Routes(false))
        val bypass = VpnSetup.ipv6Routes(true)
        fun covered(ip: String) = bypass.any { it.contains(Routes6.parse("$ip/128")) }
        assertTrue("NAT64 goes through the VPN", covered("64:ff9b::808:808"))
        assertTrue(covered("2a00:1450:4001::200e"))
        assertTrue(covered("::ffff:1.2.3.4"))
        assertFalse(covered("fe80::1"))
        assertFalse(covered("fd12:3456::1"))
        assertFalse(covered("ff02::fb"))
        assertTrue("a handful of routes", bypass.size < 40)
    }
}

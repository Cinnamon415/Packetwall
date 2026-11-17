package io.github.cinnamon415.packetwall.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RoutesTest {
    @Test fun complementCoversEverythingButLocal() {
        val routes = Routes.subtract(Routes.parse("0.0.0.0/0"), Routes.LOCAL_V4)
        fun covered(ip: String) = routes.any { it.contains(Routes.parse("$ip/32")) }
        assertTrue(covered("8.8.8.8")); assertTrue(covered("1.1.1.1")); assertTrue(covered("172.32.0.1")); assertTrue(covered("11.0.0.1"))
        assertFalse(covered("192.168.240.1")); assertFalse(covered("10.215.173.2")); assertFalse(covered("172.16.5.5"))
        assertFalse(covered("169.254.1.1")); assertFalse(covered("239.255.255.250"))
        // no overlaps, and the total size is exactly 2^32 minus the excluded ranges
        val total = routes.sumOf { it.size }
        assertEquals((1L shl 32) - Routes.LOCAL_V4.sumOf { it.size }, total)
        assertEquals(40, routes.size)   // same as Python ipaddress.address_exclude
    }
}

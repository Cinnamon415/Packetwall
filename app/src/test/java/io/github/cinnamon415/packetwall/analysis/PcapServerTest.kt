package io.github.cinnamon415.packetwall.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PcapServerTest {
    private fun path(req: String) = PcapServer.readRequestPath(req.byteInputStream())

    @Test fun requestPathOfCurlAndBrowsers() {
        assertEquals("/abc", path("GET /abc HTTP/1.1\r\nHost: x\r\nUser-Agent: curl/8\r\n\r\n"))
        assertEquals("/", path("GET / HTTP/1.0\n\n"))
        assertNull(path("POST /abc HTTP/1.1\r\n\r\n"))
        assertNull(path(""))
        assertNull(path("garbage"))
    }

    @Test fun tokenCheck() {
        assertTrue(PcapServer.constantTimeEquals("k3y", "k3y"))
        assertFalse(PcapServer.constantTimeEquals("k3", "k3y"))
        assertFalse("an empty key never matches", PcapServer.constantTimeEquals("", ""))
        val t = PcapServer.newToken()
        assertEquals(12, t.length)
        assertTrue(t.all { it in "abcdefghijkmnpqrstuvwxyz23456789" })
        assertTrue(PcapServer.newToken() != t)
    }
}

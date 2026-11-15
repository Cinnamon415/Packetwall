package io.github.cinnamon415.packetwall.analysis

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Expected JA3/JA4 values were computed by Wireshark 4.7 (tls.handshake.ja3 / ja4) on the same bytes. */
class TlsInfoTest {
    private fun res(name: String): ByteArray {
        val hex = javaClass.classLoader!!.getResource("tls/$name")!!.readText().trim()
        return ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }

    @Test fun chromeLikeTls13() {
        val c = TlsInfo.client(res("stream1-client.hex"))!!
        assertEquals("en.wikipedia.org", c.sni)
        assertEquals(listOf("h2", "http/1.1"), c.alpn)
        assertEquals("453d9517ed6323ba001b3a2e1b964f87", c.ja3)
        assertEquals("t13d1516h2_8daaf6152771_d8a2da3f94cd", c.ja4())
        val s = TlsInfo.server(res("stream1-server.hex"))!!
        assertEquals(0x0304, s.version)
        assertTrue(s.certEncrypted)
        assertNull(s.cert)
    }

    @Test fun secondStream() {
        val c = TlsInfo.client(res("stream2-client.hex"))!!
        assertEquals("content-autofill.googleapis.com", c.sni)
        assertEquals("d2dc8fa959f784a8f2336504a5ba941e", c.ja3)
        assertEquals("t13d1516h2_8daaf6152771_d8a2da3f94cd", c.ja4())
    }

    @Test fun tls12WithCertificate() {
        val c = TlsInfo.client(res("tls12-client.hex"))!!
        assertEquals("test.packetwall.example", c.sni)
        assertEquals("196ca7f20d1ace3acb0125b56fe2e6fe", c.ja3)
        assertEquals("t12d1409h2_1257f90867e7_36cef8aed422", c.ja4())
        val s = TlsInfo.server(res("tls12-server.hex"))!!
        assertEquals(0x0303, s.version)
        assertEquals("http/1.1", s.alpn)
        assertEquals("ECDHE_RSA_AES_256_GCM_SHA384", TlsInfo.cipherName(s.cipher))
        assertNotNull(s.cert)
        assertTrue(s.cert!!.subjectX500Principal.name.contains("CN=test.packetwall.example"))
    }
}

package io.github.cinnamon415.packetwall

import javax.crypto.KeyGenerator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Test

class SecretBoxTest {
    private val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    private val box = SecretBox { key }

    @Test fun roundTripWithAFreshIvEachTime() {
        val a = box.seal("pä55 word")
        val b = box.seal("pä55 word")
        assertNotEquals("random IV", a, b)
        assertFalse(a.contains("word"))
        assertEquals("pä55 word", box.open(a))
        assertEquals("", box.open(box.seal("")))
    }

    @Test fun tamperedOrForeignValuesDoNotDecrypt() {
        val sealed = java.util.Base64.getDecoder().decode(box.seal("secret"))
        sealed[sealed.size - 1] = (sealed[sealed.size - 1] + 1).toByte()
        assertNull(box.open(java.util.Base64.getEncoder().encodeToString(sealed)))
        val other = SecretBox { KeyGenerator.getInstance("AES").apply { init(256) }.generateKey() }
        assertNull(other.open(box.seal("secret")))
        assertNull(box.open("not base64 !"))
        assertNull(box.open("AAAA"))
    }
}

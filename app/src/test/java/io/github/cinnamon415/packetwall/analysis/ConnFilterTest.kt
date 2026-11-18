package io.github.cinnamon415.packetwall.analysis

import io.github.cinnamon415.packetwall.engine.AppInfo
import io.github.cinnamon415.packetwall.engine.Conn
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ConnFilterTest {
    private fun conn(app: String, pkg: String, host: String?, port: Int, proto: String, blocked: Boolean, bytes: Long = 100) = Conn(
        1, 10100, AppInfo(10100, pkg, app, false), 4, 6, "10.215.173.1", 40000,
        "1.2.3.4", port, proto, host, null, bytes, 0, 1, 0, 0, 0, 0, 3, blocked, 0
    )

    private val tbank = conn("T-Bank", "com.idamob.tinkoff.android", "api.tinkoff.ru", 443, "TLS", blocked = true)
    private val chrome = conn("Chrome", "com.android.chrome", "example.com", 80, "HTTP", blocked = false, bytes = 50_000)

    @Test fun expressions() {
        val f = ConnFilter.compile("app == \"T-Bank\" && blocked")
        assertTrue(f(tbank))
        assertFalse(f(chrome))
        val g = ConnFilter.compile("host ~ example || port == 443")
        assertTrue(g(tbank))
        assertTrue(g(chrome))
        val h = ConnFilter.compile("!(proto == TLS) and bytes > 10000")
        assertFalse(h(tbank))
        assertTrue(h(chrome))
        assertTrue(ConnFilter.compile("not blocked")(chrome))
        assertTrue(ConnFilter.compile("pkg ~ tinkoff")(tbank))
    }

    @Test fun plainSearch() {
        assertTrue(ConnFilter.compile("tinkoff")(tbank))
        assertFalse(ConnFilter.compile("tinkoff")(chrome))
        assertTrue(ConnFilter.compile("")(chrome))
    }

    @Test fun errors() {
        val e = runCatching { ConnFilter.compile("hots == x") }.exceptionOrNull()
        assertTrue(e is ConnFilter.ParseError)
        assertEquals(0, (e as ConnFilter.ParseError).pos)
        assertTrue(runCatching { ConnFilter.compile("(port == 1") }.exceptionOrNull() is ConnFilter.ParseError)
    }

    @Test fun helpExamplesParse() {
        // the filter help inserts these: each must be a valid expression that does something
        io.github.cinnamon415.packetwall.ui.FILTER_EXAMPLES.forEach { e ->
            val f = ConnFilter.compile(e)
            listOf(tbank, chrome).forEach { f(it) }
        }
        assertTrue(ConnFilter.compile("app == \"Chrome\" && port == 443")(chrome.copy(dstPort = 443)))
        assertTrue(ConnFilter.compile("!(proto == TLS) && port != 53")(chrome))
    }
}

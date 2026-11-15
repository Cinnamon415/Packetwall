package io.github.cinnamon415.packetwall.fw

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ListParserTest {
    private fun c(s: String) = ListParser.convert(s)

    @Test fun hosts() {
        assertEquals("=ads.example.com", c("0.0.0.0 ads.example.com"))
        assertEquals("=ads.example.com", c("127.0.0.1\tads.example.com # comment"))
        assertEquals("", c("127.0.0.1 localhost"))
        assertEquals("", c("::1 ip6-localhost"))
    }

    @Test fun plainAndIp() {
        assertEquals("tracker.example.org", c("tracker.example.org"))
        assertEquals("=**.example.org", c("*.example.org"))
        assertEquals("203.0.113.0/24", c("203.0.113.0/24"))
        assertEquals("2001:db8::/32", c("2001:db8::/32"))
        assertNull(c("not a domain"))
    }

    @Test fun adblock() {
        assertEquals("ads.example.com", c("||ads.example.com^"))
        assertEquals("!good.example.com", c("@@||good.example.com^"))
        assertEquals("ads.example.com", c("||ads.example.com^\$important"))
        assertEquals("=**.example.com", c("||*.example.com^"))
        assertEquals("=exact.example.com", c("|https://exact.example.com^"))
        assertNull(c("||example.com/path/ad.js"))
        assertNull(c("||example.com^\$app=com.foo"))
        assertNull(c("example.com##.banner"))
        assertNull(c("/regex[0-9]+/"))
    }

    @Test fun dnsmasq() {
        assertEquals("ads.example.com", c("address=/ads.example.com/0.0.0.0"))
        assertEquals("ads.example.com", c("server=/ads.example.com/"))
    }

    @Test fun report() {
        val r = ListParser.parse(sequenceOf("! Title: test", "||a.example.com^", "||a.example.com^", "example.com##.x", "", "# c"))
        assertEquals(listOf("a.example.com"), r.entries)
        assertEquals(1, r.skipped)
        assertEquals(2, r.comments)
    }

    @Test fun baseDomain() {
        assertEquals("example.com", ListParser.baseDomain("a.b.example.com"))
        assertEquals("example.co.uk", ListParser.baseDomain("x.example.co.uk"))
        assertEquals("tbank.ru", ListParser.baseDomain("api.tbank.ru"))
    }
}

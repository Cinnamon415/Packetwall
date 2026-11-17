package io.github.cinnamon415.packetwall

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class LimitsTest {
    @Test fun longLinesAreSkippedAndCrLfStripped() {
        val text = "a.example\r\n" + "x".repeat(5000) + "\nb.example\nc.example"
        assertEquals(listOf("a.example", "b.example", "c.example"), text.reader().cappedLines(1_000_000, 4096, "t").toList())
    }

    @Test fun tooMuchInTotalThrows() {
        val text = "a.example\n".repeat(1000)
        assertTrue(runCatching { text.reader().cappedLines(5000, 4096, "t").toList() }.exceptionOrNull() is TooLargeException)
    }

    @Test fun cappedStream() {
        assertEquals(10, ByteArray(10).inputStream().readCapped(10, "t").size)
        assertTrue(runCatching { ByteArray(11).inputStream().readCapped(10, "t") }.exceptionOrNull() is TooLargeException)
        assertEquals(Problem.TooLarge, Problem.of(TooLargeException("t")))
        assertEquals(Problem.TooLarge, Problem.of(OutOfMemoryError()))
    }
}

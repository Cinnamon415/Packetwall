package io.github.cinnamon415.packetwall.ui

import java.time.LocalDateTime
import java.time.ZoneId
import org.junit.Assert.assertEquals
import org.junit.Test

class FormatDayTest {
    private fun ms(y: Int, mo: Int, d: Int, h: Int) = LocalDateTime.of(y, mo, d, h, 0).atZone(ZoneId.systemDefault()).toInstant().toEpochMilli()

    @Test
    fun todayIsNamed() {
        assertEquals("today", formatDay(ms(2026, 11, 22, 1), "today", now = ms(2026, 11, 22, 23)))
    }

    @Test
    fun otherDaysShowTheDate() {
        assertEquals("21.11.2026", formatDay(ms(2026, 11, 21, 23), "today", now = ms(2026, 11, 22, 1)))
    }
}

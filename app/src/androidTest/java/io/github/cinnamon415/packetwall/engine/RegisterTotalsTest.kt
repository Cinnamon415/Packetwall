package io.github.cinnamon415.packetwall.engine

import androidx.test.platform.app.InstrumentationRegistry
import io.github.cinnamon415.packetwall.engine.model.ConnectionDescriptor
import io.github.cinnamon415.packetwall.engine.model.ConnectionUpdate
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Test

/** The log keeps the newest N connections; the session totals (the home tiles) keep counting past that. */
class RegisterTotalsTest {
    private val ctx = InstrumentationRegistry.getInstrumentation().targetContext

    private fun conn(id: Int) = ConnectionDescriptor(id, 4, 6, "10.215.173.1", "203.0.113.$id", "", 40000 + id, 80, 0, 4, 2000, 0, false, 0)

    private fun blocked(id: Int, on: Boolean) = ConnectionUpdate(id).apply {
        update_type = ConnectionUpdate.UPDATE_STATS
        status = if (on) 0x0400 else 0
    }

    private fun ConnectionsRegister.await(t: ConnectionsRegister.Totals) = runBlocking { withTimeout(5000) { totals.first { it == t } } }

    @Test
    fun totalsGoPastTheCap() {
        val r = ConnectionsRegister(AppsResolver(ctx), maxConns = 3)
        r.onUpdate(Array(5) { conn(it + 1) }, null)
        r.await(ConnectionsRegister.Totals(5, 0))
        // blocked later by a rule change, then one of them unblocked
        r.onUpdate(arrayOf(conn(6)), arrayOf(blocked(4, true), blocked(5, true), blocked(6, true)))
        r.await(ConnectionsRegister.Totals(6, 3))
        r.onUpdate(null, arrayOf(blocked(5, false)))
        r.await(ConnectionsRegister.Totals(6, 2))
        // the list itself stays at the cap
        runBlocking { withTimeout(5000) { r.conns.first { it.size == 3 } } }
        assertEquals(listOf(6, 5, 4), r.conns.value.map { it.id })
        // a new session starts from zero
        r.reset()
        assertEquals(ConnectionsRegister.Totals(), r.totals.value)
    }
}

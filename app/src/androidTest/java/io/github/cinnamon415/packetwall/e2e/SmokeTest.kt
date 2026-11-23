package io.github.cinnamon415.packetwall.e2e

import io.github.cinnamon415.packetwall.R
import org.junit.Test

class SmokeTest : E2eTest() {
    /** APP-09 is checked after every test (E2eTest.baseTearDown: crash buffer, JNI errors). */
    @Test
    @Covers("APP-09")
    fun harnessWorks() {
        launch()
        waitText(str(R.string.status_off))
        turnOn()
        waitText(str(R.string.status_on))
        val row = assertAllowed(Hosts.A)
        android.util.Log.i("E2E", "row: $row")
        assertAllowed("one.one.one.one", Hosts.CF_IP)
        android.util.Log.i(
            "E2E",
            "all: " +
                Rows.all().joinToString("\n") {
                    "${it.app.packageName} ${it.protoLabel} ${it.host} ${it.dstIp}:${it.dstPort} b=${it.blocked} r=${it.fwRule}"
                }
        )
        turnOff()
    }
}

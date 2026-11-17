package io.github.cinnamon415.packetwall

import io.github.cinnamon415.packetwall.fw.ForeignImport
import java.io.IOException
import java.net.BindException
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import javax.net.ssl.SSLHandshakeException
import kotlinx.serialization.SerializationException
import org.junit.Assert.assertEquals
import org.junit.Test

class ProblemTest {
    @Test fun exceptionsMapToWhatTheUserCanActOn() {
        assertEquals(Problem.Offline, Problem.of(UnknownHostException("x.example")))
        assertEquals(Problem.Offline, Problem.of(ConnectException("refused")))
        assertEquals(Problem.Timeout, Problem.of(SocketTimeoutException()))
        assertEquals(Problem.Secure, Problem.of(SSLHandshakeException("bad cert")))
        assertEquals(Problem.Http(503), Problem.of(HttpStatusException(503)))
        assertEquals(Problem.BadData, Problem.of(SerializationException("bad json")))
        assertEquals(Problem.BadData, Problem.of(BadDataException("empty")))
        assertEquals(Problem.PortInUse(5000), Problem.of(BindException("in use"), port = 5000))
        assertEquals(
            Problem.Unsupported(ForeignImport.Unsupported.Reason.SINGBOX_BINARY),
            Problem.of(ForeignImport.Unsupported(ForeignImport.Unsupported.Reason.SINGBOX_BINARY))
        )
        assertEquals(Problem.Other("disk full"), Problem.of(IOException("disk full")))
    }

    @Test fun encodeDecodeRoundTripAndOldMessages() {
        val all = listOf(
            Problem.Offline,
            Problem.Timeout,
            Problem.Secure,
            Problem.Http(404),
            Problem.BadData,
            Problem.PortInUse(5000),
            Problem.FileAccess,
            Problem.Unsupported(ForeignImport.Unsupported.Reason.RETHINK_NO_DB),
            Problem.Other("something odd")
        )
        all.forEach { assertEquals(it, Problem.decode(it.encode())) }
        // an error message saved by an older version stays readable
        assertEquals(Problem.Other("Unable to resolve host"), Problem.decode("Unable to resolve host"))
        assertEquals(Problem.Other("http:abc"), Problem.decode("http:abc"))
    }
}

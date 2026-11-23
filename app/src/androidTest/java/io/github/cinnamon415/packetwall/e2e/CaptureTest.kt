package io.github.cinnamon415.packetwall.e2e

import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.isToggleable
import androidx.compose.ui.test.performClick
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.ui.capturesDir
import java.io.DataInputStream
import java.io.File
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** A pcapng stream read block by block (little-endian, as the app writes it). */
class PcapngReader(input: InputStream) {
    private val d = DataInputStream(input)

    /** The next block: its type and body; null at the end of the stream. */
    fun next(): Pair<Int, ByteArray>? {
        val head = ByteArray(8)
        try {
            d.readFully(head)
        } catch (_: java.io.EOFException) {
            return null
        }
        val bb = ByteBuffer.wrap(head).order(ByteOrder.LITTLE_ENDIAN)
        val type = bb.getInt(0)
        val len = bb.getInt(4)
        val rest = ByteArray(len - 8)
        d.readFully(rest)
        return type to rest
    }

    companion object {
        const val SHB = 0x0A0D0D0A
        const val EPB = 6
    }
}

/** CAP: the Recording tab of the log (buffer, saving, streaming, recording to disk); FILE: File analysis. */
class CaptureTest : E2eTest() {

    private val s get() = app.settings.current
    private val dir get() = capturesDir(app)

    private fun captures() {
        drawer(R.string.nav_logs)
        tab(R.string.tab_captures)
        waitText(str(R.string.export))
    }

    private fun streamSwitch(on: Boolean) {
        val m = isToggleable()
        ui.waitUntil("stream switch", 5000) { count(m) > 0 }
        val n = ui.onAllNodes(m)[visible(m).first()]
        val now =
            n.fetchSemanticsNode().config.getOrNull(SemanticsProperties.ToggleableState) == androidx.compose.ui.state.ToggleableState.On
        if (now != on) n.performClick()
        waitFor("stream ${if (on) "on" else "off"}") { s.stream == on }
    }

    private fun control(path: String): Int {
        val c = java.net.URL("${Fixtures.BASE}$path").openConnection() as java.net.HttpURLConnection
        return try {
            c.responseCode
        } finally {
            c.disconnect()
        }
    }

    /** Reads an HTTP reply head; returns the status line. */
    private fun httpHead(input: InputStream): String {
        val b = StringBuilder()
        while (!b.endsWith("\r\n\r\n")) {
            val ch = input.read()
            if (ch < 0) break
            b.append(ch.toChar())
        }
        return b.lineSequence().first()
    }

    /** Connects to the stream and asks for [path]; the status line and the socket. */
    private fun connect(host: String, port: Int, path: String): Pair<String, Socket> {
        val sock = Socket()
        sock.connect(InetSocketAddress(host, port), 5000)
        sock.soTimeout = 10_000
        sock.getOutputStream().write("GET $path HTTP/1.0\r\n\r\n".toByteArray())
        return httpHead(sock.getInputStream()) to sock
    }

    /** Reads blocks until a packet arrives (the shell makes traffic meanwhile); the section header comes first. */
    private fun expectPackets(sock: Socket) {
        val r = PcapngReader(sock.getInputStream())
        val first = r.next()
        assertEquals("a section header first", PcapngReader.SHB, first?.first)
        val traffic = Thread { repeat(3) { Net.http(Hosts.A) } }.apply { start() }
        var packets = 0
        val end = System.currentTimeMillis() + 15_000
        while (packets == 0 && System.currentTimeMillis() < end) {
            val b = r.next() ?: break
            if (b.first == PcapngReader.EPB) packets++
        }
        traffic.join()
        assertTrue("packets in the stream", packets > 0)
    }

    @Test
    @Covers("CAP-02", "CAP-06", "FILE-02", "FILE-03", "FILE-05")
    fun saveThenAnalyseTheFile() {
        launch()
        dir.listFiles()?.forEach { it.delete() }
        turnOn()
        repeat(2) { assertAllowed(Hosts.A) }
        captures()
        assertText(str(R.string.files_go, 0))
        expectToast(str(R.string.capture_saved)) { tap(str(R.string.save_capture)) }
        val saved = waitForValue("saved file") { dir.listFiles()?.singleOrNull() }
        assertTrue(saved.name.matches(Regex("packetwall-\\d{8}-\\d{6}\\.pcapng")))
        val packets = Pcapng.packets(saved.readBytes())
        assertTrue(packets.isNotEmpty())
        waitText(str(R.string.files_go, 1))
        // the button leads to File analysis, where the file is listed with its size and date
        tap(str(R.string.files_go, 1))
        waitText(str(R.string.files_recordings))
        assertText(saved.name)
        tap(saved.name)
        // the file: its name, how many packets and connections
        waitText(str(R.string.tab_conns))
        assertText(saved.name)
        val summary = textsOf(" · ").first { Regex("^\\d+ \\D+ · \\d+ ").containsMatchIn(it) }
        assertTrue("summary $summary", summary.startsWith(str(R.string.file_summary, packets.size, 0).substringBefore(" ·")))
        // the connections, with the log's filter
        waitText(Hosts.A)
        type("host == \"${Hosts.A}\"")
        waitNoText(Hosts.CONTROL)
        assertText(Hosts.A)
        type("host ==")
        val f = ui.onAllNodes(hasSetTextAction())[0]
        assertTrue("a bad expression is marked", f.fetchSemanticsNode().config.getOrNull(SemanticsProperties.Error) != null)
        type("")
        // a row opens the connection from the file
        tap(Hosts.A)
        waitText(str(R.string.conn_overview))
        back()
        // packets: every one, in order; one opens the packet screen
        tab(R.string.conn_packets)
        val m = androidx.compose.ui.test.hasClickAction() and androidx.compose.ui.test.hasText("TCP", substring = true)
        ui.waitUntil("packet rows", 8000) { count(m) > 0 }
        ui.onAllNodes(m)[visible(m).first()].performClick()
        waitFor("packet screen") { exists(str(R.string.dir_out), true) || exists(str(R.string.dir_in), true) }
        back()
        back()
        // export a copy: the same bytes
        waitText(str(R.string.files_recordings))
        val name = "e2e-copy-${System.nanoTime()}.pcapng"
        expectToast(str(R.string.exported)) {
            tapDesc(str(R.string.export))
            Docs.save(name)
        }
        val copy = waitForValue("copy") { Docs.read("${Docs.DIR}/$name").takeIf { it.isNotEmpty() } }
        assertTrue("the copy is the file", copy.contentEquals(saved.readBytes()))
        Docs.remove("${Docs.DIR}/$name")
        // delete asks first
        tapDesc(str(R.string.delete))
        waitText(str(R.string.confirm_delete_file, saved.name))
        tap(str(R.string.cancel))
        assertTrue(saved.exists())
        tapDesc(str(R.string.delete))
        tap(str(R.string.delete))
        waitText(str(R.string.no_captures))
        assertFalse(saved.exists())
    }

    @Test
    @Covers("FILE-01", "FILE-04", "FILE-06")
    fun openFilesFromThePicker() {
        launch()
        turnOn()
        repeat(2) { assertAllowed(Hosts.A) }
        captures()
        tap(str(R.string.save_capture))
        val saved = waitForValue("saved file") { dir.listFiles()?.maxByOrNull { it.lastModified() } }
        val bytes = saved.readBytes()
        val n = Pcapng.packets(bytes).size
        val name = "e2e-open-${System.nanoTime()}.pcapng"
        Docs.put(name, bytes)
        drawer(R.string.nav_files)
        tap(str(R.string.files_choose))
        Docs.open(name)
        waitText(str(R.string.tab_conns))
        assertText(name)
        assertText(str(R.string.file_summary, n, app.let { OpenedCount.conns() }))
        back()
        // in Recent: when and how many packets
        waitText(str(R.string.files_recent))
        assertText(name)
        assertTrue(textsOf("· $n").isNotEmpty())
        // opened again from Recent, still listed once
        tap(name)
        waitText(str(R.string.tab_conns))
        back()
        waitText(str(R.string.files_recent))
        assertEquals(1, count(has(name)))
        // a cut file opens with what it has
        val cut = "e2e-cut-${System.nanoTime()}.pcapng"
        Docs.put(cut, bytes.copyOf(bytes.size / 2 + 7))
        tap(str(R.string.files_choose))
        Docs.open(cut)
        waitText(str(R.string.tab_conns))
        val got = waitForValue("packets of the cut file") {
            textsOf(" · ").firstNotNullOfOrNull { Regex("^(\\d+) ").find(it)?.groupValues?.get(1)?.toInt() }
        }
        assertTrue("fewer packets from half a file: $got of $n", got in 1 until n)
        back()
        // not a capture: a readable error, the app goes on
        val junk = "e2e-junk-${System.nanoTime()}.pcapng"
        Docs.put(junk, "this is not a capture file at all".toByteArray())
        tap(str(R.string.files_choose))
        Docs.open(junk)
        ui.waitUntil("error shown", 10_000) { textsOf("").any { it.isNotBlank() && it !in listOf(str(R.string.files_choose)) } }
        waitText(str(R.string.files_choose))
        assertNoText(str(R.string.tab_conns))
        listOf(name, cut, junk).forEach { Docs.remove("${Docs.DIR}/$it") }
    }

    /** The connections of the open file (its subtitle counts them). */
    private object OpenedCount {
        fun conns() = io.github.cinnamon415.packetwall.ui.OpenedFile.current!!.conns.value.size
    }

    @Test
    @Covers("CAP-04")
    fun streamOverUsb() {
        launch()
        turnOn()
        captures()
        streamSwitch(true)
        waitText(str(R.string.stream_usb_running, 0))
        // the way a PC connects: adb forward to the device socket
        val port = 57012
        assertEquals(200, control("/forward?port=$port&remote=localabstract:$PKG.pcap"))
        try {
            val (status, sock) = connect(Hosts.HOST, port, "/")
            sock.use {
                assertTrue("HTTP reply: $status", status.contains("200"))
                waitText(str(R.string.stream_usb_running, 1))
                expectPackets(sock)
            }
            // a client that left is noticed when the next packets fail to reach it
            waitFor("client gone: ${app.pcapServer.state.value}", 30_000, 1000) {
                Net.http(Hosts.A)
                app.pcapServer.state.value.clients == 0
            }
            waitText(str(R.string.stream_usb_running, 0))
        } finally {
            control("/unforward?port=$port")
        }
        // how to connect: the commands for USB
        tap(str(R.string.stream_how))
        waitText(str(R.string.stream_sheet_title))
        assertText("adb forward tcp:57012 localabstract:$PKG.pcap")
        back()
        // off: nothing listens
        streamSwitch(false)
        waitText(str(R.string.stream_off))
        assertFalse(app.pcapServer.state.value.running)
    }

    @Test
    @Covers("CAP-04")
    fun streamOverTheLocalNetworkNeedsTheKey() {
        launch()
        turnOn()
        captures()
        streamSwitch(true)
        tap(str(R.string.stream_lan))
        waitFor("lan") { s.streamLan && s.streamToken.isNotEmpty() }
        assertText(str(R.string.stream_lan_warn))
        val st = waitForValue("listening") { app.pcapServer.state.value.takeIf { it.running && it.lan && it.address.isNotEmpty() } }
        waitText(str(R.string.stream_lan_running, st.address, st.port, 0))
        // no key, a wrong key: refused
        connect(st.address, st.port, "/").let { (status, sock) ->
            sock.close()
            assertTrue(status, status.contains("403"))
        }
        connect(st.address, st.port, "/wrong").let { (status, sock) ->
            sock.close()
            assertTrue(status, status.contains("403"))
        }
        // the key: the stream
        val token = s.streamToken
        val (status, sock) = connect(st.address, st.port, "/$token")
        sock.use {
            assertTrue(status, status.contains("200"))
            expectPackets(sock)
        }
        // a new key: the old one stops working; the sheet shows the link with the new one
        tap(str(R.string.stream_how))
        waitText(str(R.string.stream_sheet_title))
        tap(str(R.string.stream_new_token))
        waitFor("new key") { s.streamToken != token }
        waitFor("restarted with the new key") { app.pcapServer.state.value.running }
        assertText("/${s.streamToken}", substring = true)
        Thread.sleep(500)
        connect(st.address, st.port, "/$token").let { (status, sock) ->
            sock.close()
            assertTrue(status, status.contains("403"))
        }
        back()
    }

    @Test
    @Covers("CAP-05")
    fun recordToDisk() {
        launch()
        dir.listFiles()?.forEach { it.delete() }
        captures()
        assertText(str(R.string.record_off))
        drawer(R.string.nav_settings)
        seeValue(str(R.string.record_to_disk))
        tap(str(R.string.record_to_disk))
        waitFor("record on") { s.record }
        drawer(R.string.nav_home)
        turnOn()
        repeat(2) { assertAllowed(Hosts.A) }
        captures()
        // the file being written and its size
        val file = waitForValue("recording", 15_000) { app.recorder.state.value.file }
        assertTrue(file, file.matches(Regex("ring-\\d{8}-\\d{6}\\.pcapng")))
        waitText(file, substring = true)
        val f = File(dir, file)
        // flushed at least once a second: readable while it is written
        waitFor("packets on disk") { runCatching { Pcapng.packets(f.readBytes()).isNotEmpty() }.getOrDefault(false) }
        waitText(str(R.string.files_go, 1))
        // listed in File analysis
        tap(str(R.string.files_go, 1))
        waitText(file)
        // off: the recorder stops
        drawer(R.string.nav_settings)
        seeValue(str(R.string.record_to_disk))
        tap(str(R.string.record_to_disk))
        waitFor("record off") { !s.record && !app.recorder.state.value.running }
        captures()
        waitText(str(R.string.record_off))
    }
}

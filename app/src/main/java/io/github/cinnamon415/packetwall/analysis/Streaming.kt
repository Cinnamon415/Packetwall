package io.github.cinnamon415.packetwall.analysis

import android.net.LocalServerSocket
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.util.Log
import io.github.cinnamon415.packetwall.Problem
import java.io.Closeable
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.MessageDigest
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * pcap-over-IP: a live pcapng stream for Wireshark on a computer. Every client has its own bounded
 * queue; one that cannot keep up is disconnected. Two modes, neither open to other apps:
 *
 * - USB (default): an abstract unix socket [socketName], reached with
 *   `adb forward tcp:57012 localabstract:<socketName>`. Only adb (shell, uid 2000) and root may connect,
 *   checked with the peer's credentials, so apps on the phone cannot read the traffic.
 * - Local network: TCP on the Wi-Fi/Ethernet address only, and the client must ask for
 *   `GET /<token>` (e.g. `curl -sN http://<ip>:<port>/<token> | wireshark -k -i -`).
 *
 * At most [MAX_CLIENTS] clients at a time.
 */
class PcapServer(private val store: PacketStore, private val socketName: String, private val lanAddress: () -> InetAddress?) {
    data class State(
        val running: Boolean = false,
        val port: Int = 0,
        val lan: Boolean = false,
        val clients: Int = 0,
        /** The address the LAN mode listens on, for the instructions. */
        val address: String = "",
        val error: Problem? = null
    )
    private val _state = MutableStateFlow(State())
    val state: StateFlow<State> = _state
    private var closer: (() -> Unit)? = null
    private val clients = CopyOnWriteArrayList<Client>()

    private inner class Client(private val out: OutputStream, private val closeable: Closeable) : PacketStore.Sink {
        val q = LinkedBlockingQueue<ByteArray>(4096)

        @Volatile var alive = true
        override fun onBlock(block: ByteArray) {
            if (alive && !q.offer(block)) close()
        }
        fun run() {
            try {
                val o = out.buffered(64 * 1024)
                while (alive) {
                    val b = q.poll(1, TimeUnit.SECONDS) ?: run {
                        o.flush()
                        null
                    } ?: continue
                    o.write(b)
                    if (q.isEmpty()) o.flush()
                }
            } catch (_: IOException) {
                // the client went away
            } catch (_: InterruptedException) {
            } finally {
                close()
            }
        }
        fun close() {
            if (!alive) return
            alive = false
            store.removeSink(this)
            try {
                closeable.close()
            } catch (_: IOException) {}
            clients.remove(this)
            _state.value = _state.value.copy(clients = clients.size)
        }
    }

    /** Registers a client unless the limit is reached; returns false when it was refused. */
    private fun admit(out: OutputStream, closeable: Closeable): Boolean {
        if (clients.size >= MAX_CLIENTS) return false
        val c = Client(out, closeable)
        clients.add(c)
        store.addSink(c)
        _state.value = _state.value.copy(clients = clients.size)
        Thread({ c.run() }, "PcapClient").start()
        return true
    }

    @Synchronized
    fun start(port: Int, lan: Boolean, token: String) {
        stop()
        try {
            if (lan) startLan(port, token) else startLocal()
        } catch (e: Exception) {
            Log.w(TAG, "cannot start the stream server", e)
            _state.value = State(lan = lan, port = port, error = Problem.of(e, port))
        }
    }

    private fun startLocal() {
        val server = LocalServerSocket(socketName)
        val closed = AtomicBoolean(false)
        closer = {
            closed.set(true)
            server.close()
            // accept() is not interrupted by close() on every Android version: wake it up
            try {
                LocalSocket().use { it.connect(LocalSocketAddress(socketName)) }
            } catch (_: IOException) {}
        }
        _state.value = State(running = true, port = 0, lan = false)
        Thread({
            while (!closed.get()) {
                val sock = try {
                    server.accept()
                } catch (_: IOException) {
                    break
                }
                if (closed.get()) {
                    sock.close()
                    break
                }
                val uid = try {
                    sock.peerCredentials.uid
                } catch (_: IOException) {
                    -1
                }
                if (uid != UID_ROOT && uid != UID_SHELL) {
                    Log.w(TAG, "refused a local client with uid $uid")
                    sock.close()
                    continue
                }
                Thread({ localHandshake(sock) }, "PcapHandshake").start()
            }
        }, "PcapServer").start()
    }

    /** A client that says `GET …` (curl) gets an HTTP header first; one that says nothing (nc) the raw stream. */
    private fun localHandshake(sock: LocalSocket) {
        try {
            sock.soTimeout = 400
            val input = sock.inputStream
            val first = try {
                input.read()
            } catch (_: IOException) {
                NOTHING_SENT // read timeout: a raw client
            }
            if (first == -1) {
                sock.close()
                return
            }
            sock.soTimeout = 2000
            val out = sock.outputStream
            if (first == 'G'.code) {
                readRequestPath(input) // skip the rest of the request
                out.write("HTTP/1.0 200 OK\r\nContent-Type: application/vnd.tcpdump.pcap\r\nCache-Control: no-store\r\n\r\n".toByteArray())
                out.flush()
            }
            sock.soTimeout = 0
            if (!admit(out, sock)) sock.close()
        } catch (_: IOException) {
            try {
                sock.close()
            } catch (_: IOException) {}
        }
    }

    private fun startLan(port: Int, token: String) {
        val addr = lanAddress() ?: throw NoLanException()
        val server = ServerSocket(port, 8, addr)
        closer = { server.close() }
        _state.value = State(running = true, port = port, lan = true, address = addr.hostAddress ?: "")
        Thread({
            while (!server.isClosed) {
                val sock = try {
                    server.accept()
                } catch (_: IOException) {
                    break
                }
                Thread({ handshake(sock, token) }, "PcapHandshake").start()
            }
        }, "PcapServer").start()
    }

    /** Minimal HTTP: `GET /<token>` gets the stream, anything else a 403 (or 503 when full). */
    private fun handshake(sock: Socket, token: String) {
        try {
            sock.soTimeout = 5000
            sock.tcpNoDelay = true
            val path = readRequestPath(sock.getInputStream())
            val out = sock.getOutputStream()
            when {
                path == null || !constantTimeEquals(path.trimStart('/'), token) -> {
                    out.write("HTTP/1.0 403 Forbidden\r\nContent-Length: 0\r\n\r\n".toByteArray())
                    sock.close()
                }
                clients.size >= MAX_CLIENTS -> {
                    out.write("HTTP/1.0 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n".toByteArray())
                    sock.close()
                }
                else -> {
                    out.write(
                        "HTTP/1.0 200 OK\r\nContent-Type: application/vnd.tcpdump.pcap\r\nCache-Control: no-store\r\n\r\n".toByteArray()
                    )
                    out.flush()
                    sock.soTimeout = 0
                    if (!admit(out, sock)) sock.close()
                }
            }
        } catch (_: IOException) {
            try {
                sock.close()
            } catch (_: IOException) {}
        }
    }

    @Synchronized
    fun stop() {
        closer?.invoke()
        closer = null
        clients.forEach { it.close() }
        _state.value = State()
    }

    /** The phone has no Wi-Fi or Ethernet address to listen on. */
    class NoLanException : IOException("no Wi-Fi or Ethernet address")

    companion object {
        private const val TAG = "PcapServer"
        const val MAX_CLIENTS = 3
        private const val UID_ROOT = 0
        private const val UID_SHELL = 2000
        private const val NOTHING_SENT = -2

        /** The path of the request line (`GET /x HTTP/1.1` -> `/x`); headers are skipped; null if not a GET. */
        fun readRequestPath(input: InputStream): String? {
            val head = StringBuilder()
            while (head.length < 4096 && !head.endsWith("\r\n\r\n") && !head.endsWith("\n\n")) {
                val b = input.read()
                if (b < 0) break
                head.append(b.toChar())
            }
            val parts = head.lineSequence().firstOrNull()?.trim()?.split(' ') ?: return null
            return if (parts.size >= 2 && parts[0] == "GET") parts[1] else null
        }

        fun constantTimeEquals(a: String, b: String): Boolean = b.isNotEmpty() && MessageDigest.isEqual(a.toByteArray(), b.toByteArray())

        /** 12 characters from a-z and 2-9: easy to type, about 60 bits. */
        fun newToken(): String {
            val alphabet = "abcdefghijkmnpqrstuvwxyz23456789"
            val r = SecureRandom()
            return String(CharArray(12) { alphabet[r.nextInt(alphabet.length)] })
        }
    }
}

/**
 * Continuous recording to disk: pcapng files rotated by size and age, only the newest [keep] kept
 * ("ring buffer by size and time", spec 5).
 *
 * [onBlock] runs on the capture thread (under the packet store lock), so it only enqueues; a writer
 * thread does the disk I/O. If the disk cannot keep up, blocks are dropped and counted instead of
 * slowing down the device's traffic.
 */
class DiskRecorder(private val store: PacketStore, private val dir: File) : PacketStore.Sink {
    data class State(
        val running: Boolean = false,
        val file: String? = null,
        val bytes: Long = 0,
        val files: Int = 0,
        val dropped: Long = 0,
        /** The rotation settings it runs with, so a change can restart it. */
        val maxMb: Int = 0,
        val maxMinutes: Int = 0,
        val keep: Int = 0
    )

    private val _state = MutableStateFlow(State())
    val state: StateFlow<State> = _state

    private val queue = LinkedBlockingQueue<ByteArray>(QUEUE_BLOCKS)

    @Volatile private var running = false
    private var writer: Thread? = null

    // writer thread only
    private var out: OutputStream? = null
    private var written = 0L
    private var lastStateMs = 0L
    private var openedAt = 0L
    private var maxBytes = 0L
    private var maxAgeMs = 0L
    private var keep = 0

    @Synchronized
    fun start(maxMb: Int, maxMinutes: Int, keepFiles: Int) {
        stop()
        dir.mkdirs()
        maxBytes = maxMb.toLong() shl 20
        maxAgeMs = maxMinutes * 60_000L
        keep = keepFiles
        queue.clear()
        running = true
        _state.value = State(running = true, maxMb = maxMb, maxMinutes = maxMinutes, keep = keepFiles)
        writer = Thread(::writeLoop, "DiskRecorder").also {
            it.isDaemon = true
            it.start()
        }
        store.addSink(this) // the first block is the file header
    }

    @Synchronized
    fun stop() {
        if (!running) return
        running = false
        store.removeSink(this)
        writer?.interrupt()
        writer?.join(2_000)
        writer = null
        _state.value = _state.value.copy(running = false)
    }

    override fun onBlock(block: ByteArray) {
        if (running && !queue.offer(block)) _state.value = _state.value.copy(dropped = _state.value.dropped + 1)
    }

    private fun writeLoop() {
        try {
            while (running) {
                // wake up at least once a second to flush, so the current file is readable
                val block = queue.poll(1, TimeUnit.SECONDS)
                if (block == null) {
                    out?.flush()
                    continue
                }
                write(block)
                if (queue.isEmpty()) out?.flush()
            }
        } catch (_: InterruptedException) {
        } catch (e: IOException) {
            Log.w(TAG, "write failed, stopping", e)
            running = false
            _state.value = _state.value.copy(running = false)
        } finally {
            // drain what is left so a stopped recording is complete
            try {
                while (true) write(queue.poll() ?: break)
                out?.close()
            } catch (_: IOException) {
            }
            out = null
        }
    }

    private fun write(block: ByteArray) {
        val header = isSectionHeader(block)
        val expired = written >= maxBytes || System.currentTimeMillis() - openedAt >= maxAgeMs
        if (out == null || (!header && expired)) rotate(if (header) null else store.header())
        out!!.write(block)
        written += block.size
        // at most once a second: the Captures card recomposes on every state change
        val now = System.currentTimeMillis()
        if (now - lastStateMs >= 1000) {
            lastStateMs = now
            _state.value = _state.value.copy(bytes = written)
        }
    }

    private fun rotate(header: ByteArray?) {
        out?.close()
        val f = File(dir, "ring-${SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())}.pcapng")
        out = f.outputStream().buffered(256 * 1024)
        written = 0
        openedAt = System.currentTimeMillis()
        if (header != null) {
            out!!.write(header)
            written += header.size
        }
        val all = dir.listFiles { x -> x.name.startsWith("ring-") }?.sortedByDescending { it.name } ?: emptyList()
        all.drop(keep).forEach { it.delete() }
        _state.value = _state.value.copy(file = f.name, files = minOf(all.size, keep))
    }

    private companion object {
        const val TAG = "DiskRecorder"
        const val QUEUE_BLOCKS = 8192

        private val SHB_MAGIC = byteArrayOf(0x0A, 0x0D, 0x0D, 0x0A)

        fun isSectionHeader(b: ByteArray) = b.size >= 4 && (0 until 4).all { b[it] == SHB_MAGIC[it] }
    }
}

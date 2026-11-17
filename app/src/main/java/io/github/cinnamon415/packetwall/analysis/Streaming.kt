package io.github.cinnamon415.packetwall.analysis

import android.util.Log
import java.io.File
import java.io.IOException
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * pcap-over-IP: a TCP server that sends a live pcapng stream to every client, e.g.
 *   adb forward tcp:57012 tcp:57012 && nc 127.0.0.1 57012 | wireshark -k -i -
 * Each client has its own bounded queue; a client that cannot keep up is disconnected.
 */
class PcapServer(private val store: PacketStore) {
    data class State(
        val running: Boolean = false,
        val port: Int = 0,
        val lan: Boolean = false,
        val clients: Int = 0,
        val error: String? = null
    )
    private val _state = MutableStateFlow(State())
    val state: StateFlow<State> = _state
    private var server: ServerSocket? = null
    private val clients = CopyOnWriteArrayList<Client>()

    private inner class Client(val sock: Socket) : PacketStore.Sink {
        val q = LinkedBlockingQueue<ByteArray>(4096)

        @Volatile var alive = true
        override fun onBlock(block: ByteArray) {
            if (alive && !q.offer(block)) close()
        }
        fun run() {
            try {
                val out = sock.getOutputStream().buffered(64 * 1024)
                while (alive) {
                    val b = q.poll(1, TimeUnit.SECONDS) ?: run {
                        out.flush()
                        null
                    } ?: continue
                    out.write(b)
                    if (q.isEmpty()) out.flush()
                }
            } catch (e: Exception) { } finally {
                close()
            }
        }
        fun close() {
            if (!alive) return
            alive = false
            store.removeSink(this)
            try {
                sock.close()
            } catch (_: Exception) {}
            clients.remove(this)
            _state.value = _state.value.copy(clients = clients.size)
        }
    }

    @Synchronized
    fun start(port: Int, lan: Boolean) {
        stop()
        try {
            val s = ServerSocket(port, 4, if (lan) null else InetAddress.getByName("127.0.0.1"))
            server = s
            _state.value = State(true, port, lan, 0)
            Thread({
                while (!s.isClosed) {
                    val sock = try {
                        s.accept()
                    } catch (e: Exception) {
                        break
                    }
                    sock.tcpNoDelay = true
                    val c = Client(sock)
                    clients.add(c)
                    store.addSink(c)
                    _state.value = _state.value.copy(clients = clients.size)
                    Thread({ c.run() }, "PcapClient").start()
                }
            }, "PcapServer").start()
        } catch (e: Exception) {
            Log.w("PcapServer", "cannot listen on $port", e)
            _state.value = State(error = e.message ?: e.javaClass.simpleName)
        }
    }

    @Synchronized
    fun stop() {
        server?.close()
        server = null
        clients.forEach { it.close() }
        _state.value = State()
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
    data class State(val running: Boolean = false, val file: String? = null, val bytes: Long = 0, val files: Int = 0, val dropped: Long = 0)

    private val _state = MutableStateFlow(State())
    val state: StateFlow<State> = _state

    private val queue = LinkedBlockingQueue<ByteArray>(QUEUE_BLOCKS)

    @Volatile private var running = false
    private var writer: Thread? = null

    // writer thread only
    private var out: OutputStream? = null
    private var written = 0L
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
        _state.value = State(running = true)
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
        _state.value = _state.value.copy(bytes = written)
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

package io.github.cinnamon415.packetwall.e2e

import android.app.Instrumentation
import android.content.Context
import android.os.ParcelFileDescriptor
import android.view.accessibility.AccessibilityEvent
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.UiDevice
import io.github.cinnamon415.packetwall.PacketwallApp
import io.github.cinnamon415.packetwall.engine.CaptureState
import io.github.cinnamon415.packetwall.engine.CaptureStatus
import io.github.cinnamon415.packetwall.engine.Conn
import java.io.ByteArrayOutputStream
import java.util.concurrent.TimeoutException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail

/** The catalog items of docs/E2E.md that a test proves (all of their consequences, not a part). */
@Retention(AnnotationRetention.RUNTIME)
@Target(AnnotationTarget.FUNCTION, AnnotationTarget.CLASS)
annotation class Covers(vararg val ids: String)

val instr: Instrumentation get() = InstrumentationRegistry.getInstrumentation()
val ctx: Context get() = instr.targetContext
val app: PacketwallApp get() = ctx.applicationContext as PacketwallApp
val device: UiDevice get() = UiDevice.getInstance(instr)
val PKG: String get() = ctx.packageName

/** The test traffic comes from the shell (uid 2000): it goes through the VPN, Packetwall's own traffic does not. */
const val SHELL_PKG = "com.android.shell"
const val SHELL_UID = 2000

fun str(id: Int, vararg args: Any): String = ctx.getString(id, *args)
fun plural(id: Int, n: Int, vararg args: Any): String = ctx.resources.getQuantityString(id, n, *args)

/** Polls [cond] until it holds; fails with [what] after [timeoutMs]. */
fun waitFor(what: String, timeoutMs: Long = 10_000, step: Long = 200, cond: () -> Boolean) {
    val end = System.currentTimeMillis() + timeoutMs
    while (System.currentTimeMillis() < end) {
        if (runCatching(cond).getOrDefault(false)) return
        Thread.sleep(step)
    }
    fail("timed out after $timeoutMs ms waiting for: $what")
}

fun <T> waitForValue(what: String, timeoutMs: Long = 10_000, step: Long = 200, get: () -> T?): T {
    val end = System.currentTimeMillis() + timeoutMs
    while (System.currentTimeMillis() < end) {
        runCatching(get).getOrNull()?.let { return it }
        Thread.sleep(step)
    }
    fail("timed out after $timeoutMs ms waiting for: $what")
    error("unreachable")
}

/** Shell commands as uid 2000. The script goes to `sh` on stdin, so pipes and quotes work. */
object Shell {
    fun run(script: String): String {
        val fds = instr.uiAutomation.executeShellCommandRw("sh")
        ParcelFileDescriptor.AutoCloseOutputStream(fds[1]).use { it.write((script + "\nexit\n").toByteArray()) }
        return ParcelFileDescriptor.AutoCloseInputStream(fds[0]).use { it.readBytes().decodeToString() }
    }
}

/** What a plain HTTP request from the shell got: the first reply line (or the error) and how long it took. */
data class Reply(val line: String, val ms: Long) {
    val ok get() = line.startsWith("HTTP/1.")
    val status get() = if (ok) line.split(' ').getOrNull(1)?.toIntOrNull() else null
}

object Net {
    /** HTTP/1.0 GET with toybox nc (resolves [host] through the system resolver when [ip] is null). */
    fun http(host: String, ip: String? = null, port: Int = 80, timeoutS: Int = 6, path: String = "/"): Reply {
        val target = ip ?: host
        // timed here: the device shell (mksh) has 32-bit arithmetic, nanosecond sums overflow there
        val t0 = System.nanoTime()
        val out = Shell.run(
            "printf 'GET $path HTTP/1.0\\r\\nHost: $host\\r\\n\\r\\n' | timeout $timeoutS toybox nc $target $port 2>&1 | head -1"
        ).trim()
        return Reply(out, (System.nanoTime() - t0) / 1_000_000)
    }

    /** Allowed traffic is proven by a server reply; one retry for a cold DNS cache on the host. */
    fun allowed(host: String, ip: String? = null, port: Int = 80): Reply {
        var r = http(host, ip, port, timeoutS = 10)
        if (!r.ok) {
            Thread.sleep(1000)
            r = http(host, ip, port, timeoutS = 10)
        }
        return r
    }

    /** Raw DNS A query over UDP to [server]; all reply bytes as hex ([] = no reply). */
    fun dnsUdp(server: String, name: String, timeoutS: Int = 3): List<String> {
        val q = "\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00" +
            name.split('.').joinToString("") { p -> "\\x%02x%s".format(p.length, p) } + "\\x00\\x00\\x01\\x00\\x01"
        return Shell.run("printf '$q' | timeout ${timeoutS + 1} toybox nc -u -w $timeoutS $server 53 | od -An -tx1").split(Regex("\\s+"))
            .filter { it.isNotEmpty() }
    }

    fun ping(ip: String, n: Int = 2): Int =
        Shell.run("ping -c $n -W 3 -i 0.5 $ip 2>&1 | grep -o '[0-9]* received'").trim().split(' ').firstOrNull()?.toIntOrNull() ?: 0

    fun vpnUp(): Boolean = Shell.run("ip addr show tun0 2>/dev/null").contains("10.215.173.1")
}

/** The known targets. Names are real sites (plain HTTP on port 80); the control proves the network is alive. */
object Hosts {
    const val CONTROL = "www.wikipedia.org"
    const val A = "example.org"
    const val A_WWW = "www.example.org"
    const val B = "example.com"
    const val C = "example.net"
    const val CF_IP = "1.1.1.1"

    /** The host machine as seen from the emulator; tools/e2e/host.py serves lists, the proxy and its log there. */
    const val HOST = "10.0.2.2"
    const val CONTROL_PORT = 8099
}

/** The live connection log, read in-process (the same register the Log screen shows). */
object Rows {
    fun all(): List<Conn> = app.connections.conns.value

    fun of(host: String? = null, ip: String? = null, port: Int? = null, pkg: String? = SHELL_PKG): List<Conn> = all().filter { c ->
        (host == null || c.host.equals(host, true)) &&
            (ip == null || c.dstIp == ip) &&
            (port == null || c.dstPort == port) &&
            (pkg == null || c.app.packageName == pkg)
    }

    fun await(what: String, timeoutMs: Long = 8000, pred: (Conn) -> Boolean): Conn {
        val end = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < end) {
            all().lastOrNull(pred)?.let { return it }
            Thread.sleep(200)
        }
        fail("no log row: $what. Rows:\n" + dump())
        error("unreachable")
    }

    fun dump(n: Int = 25) = all().takeLast(n).joinToString("\n") {
        "#${it.id} ${it.app.packageName} ${it.protoLabel} ${it.host} ${it.dstIp}:${it.dstPort} blocked=${it.blocked} rule=${it.fwRule} st=${it.status}"
    }

    /** No row matching [pred] appears within [ms]. */
    fun assertNone(what: String, ms: Long = 3000, pred: (Conn) -> Boolean) {
        Thread.sleep(ms)
        val rows = all().filter(pred)
        assertTrue("unexpected log rows for $what: ${rows.map { it.title + " " + it.dstPort }}", rows.isEmpty())
    }
}

/**
 * Proves a block: the request got no server reply, a control request right after did (the network is
 * alive), and the log has the blocked row with the expected reason ([rule] > 0 rule id, < 0 a list).
 */
fun assertBlocked(host: String, ip: String? = null, port: Int = 80, rule: Int? = null, fast: Boolean = false): Conn {
    settle()
    val r = Net.http(host, ip, port)
    assertTrue("$host:$port should be blocked, got \"${r.line}\"\nRows:\n${Rows.dump()}", !r.ok)
    if (fast) assertTrue("$host:$port should be refused at once, took ${r.ms} ms (${r.line})", r.ms < 1500)
    val c = Net.allowed(Hosts.CONTROL)
    assertTrue("control request failed, the network is down: ${c.line}", c.ok)
    val row = Rows.await("$host blocked") { x ->
        x.app.packageName == SHELL_PKG &&
            x.blocked &&
            (if (ip != null) x.dstIp == ip else x.host.equals(host, true)) &&
            (port == 53 || x.dstPort == port || ip == null)
    }
    if (rule != null) assertEquals("reason of the block of $host", rule, row.fwRule)
    return row
}

/** Proves an allowed connection: a server reply and an allowed (not blocked) row in the log. */
fun assertAllowed(host: String, ip: String? = null, port: Int = 80, rule: Int? = null): Conn {
    settle()
    val r = Net.allowed(host, ip, port)
    if (!r.ok) {
        Thread.sleep(1000)
        fail(
            "$host:$port should be allowed, got \"${r.line}\". Rows:\n${Rows.dump()}\nRules: ${app.firewall.state.value.rules}\nOrder: ${app.firewall.state.value.order}"
        )
    }
    val row = Rows.await("$host allowed") { x ->
        x.app.packageName == SHELL_PKG &&
            !x.blocked &&
            x.dstPort == port &&
            (if (ip != null) x.dstIp == ip else x.host.equals(host, true))
    }
    if (rule != null) assertEquals("rule that allowed $host", rule, row.fwRule)
    return row
}

/** Rule edits compile after a 250 ms pause (a burst of edits compiles once): let the last one land. */
fun settle() = Thread.sleep(500)

object Vpn {
    fun grantConsent() {
        Shell.run("appops set $PKG ACTIVATE_VPN allow")
    }

    fun running() = CaptureStatus.state.value is CaptureState.Running

    /** Waits for tun0 and for the engine to have compiled the rules and started its loop. */
    fun awaitUp() {
        waitFor("protection running", 20_000) { running() && Net.vpnUp() }
        Thread.sleep(2000)
    }

    fun awaitDown() {
        waitFor("protection stopped", 15_000) { !running() && !Net.vpnUp() }
    }
}

/** Text toasts are shown by System UI; their text reaches us as an accessibility event. */
fun expectToast(text: String, timeoutMs: Long = 5000, action: () -> Unit) {
    try {
        instr.uiAutomation.executeAndWaitForEvent({ action() }, { e ->
            e.eventType == AccessibilityEvent.TYPE_NOTIFICATION_STATE_CHANGED && e.text.any { it?.toString()?.contains(text) == true }
        }, timeoutMs)
    } catch (e: TimeoutException) {
        fail("no toast \"$text\"")
    }
}

/** A minimal pcapng reader: the packets (raw IP) of the Enhanced Packet Blocks. */
object Pcapng {
    fun packets(b: ByteArray): List<ByteArray> {
        require(b.size >= 28) { "not a pcapng file (${b.size} bytes)" }
        val bb = java.nio.ByteBuffer.wrap(b)
        require(bb.getInt(0) == 0x0A0D0D0A) { "no section header" }
        bb.order(
            if (bb.order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt(8) ==
                0x1A2B3C4D
            ) {
                java.nio.ByteOrder.LITTLE_ENDIAN
            } else {
                java.nio.ByteOrder.BIG_ENDIAN
            }
        )
        val out = ArrayList<ByteArray>()
        var off = 0
        while (off + 12 <= b.size) {
            val type = bb.getInt(off)
            val len = bb.getInt(off + 4)
            require(len >= 12 && off + len <= b.size) { "bad block at $off" }
            if (type == 6) {
                val cap = bb.getInt(off + 20)
                out += b.copyOfRange(off + 28, off + 28 + cap)
            }
            off += len
        }
        return out
    }

    /** (destination IP, source port, destination port) of an IPv4 TCP/UDP packet; null otherwise. */
    fun tuple(p: ByteArray): Triple<String, Int, Int>? {
        if (p.isEmpty() || (p[0].toInt() shr 4) != 4) return null
        val ihl = (p[0].toInt() and 0xf) * 4
        val proto = p[9].toInt()
        if (proto != 6 && proto != 17) return null
        val dst = (16..19).joinToString(".") { (p[it].toInt() and 0xff).toString() }
        val sp = ((p[ihl].toInt() and 0xff) shl 8) or (p[ihl + 1].toInt() and 0xff)
        val dp = ((p[ihl + 2].toInt() and 0xff) shl 8) or (p[ihl + 3].toInt() and 0xff)
        return Triple(dst, sp, dp)
    }
}

/** A TLS 1.2 Client Hello (no 1.3: the server's certificate then travels in clear, so the app can show it). */
object Tls {
    fun clientHello(sni: String): ByteArray {
        val ext = ByteArrayOutputStream()
        fun ByteArrayOutputStream.u8(v: Int) = write(v and 0xff)
        fun ByteArrayOutputStream.u16(v: Int) {
            u8(v shr 8)
            u8(v)
        }
        fun ByteArrayOutputStream.u24(v: Int) {
            u8(v shr 16)
            u16(v)
        }
        fun ByteArrayOutputStream.ext(type: Int, body: ByteArray) {
            u16(type)
            u16(body.size)
            write(body)
        }
        fun bytes(f: ByteArrayOutputStream.() -> Unit) = ByteArrayOutputStream().apply(f).toByteArray()
        val name = sni.toByteArray()
        ext.ext(
            0x0000,
            bytes {
                u16(name.size + 3)
                u8(0)
                u16(name.size)
                write(name)
            }
        )
        ext.ext(
            0x000a,
            bytes {
                u16(6)
                u16(0x001d)
                u16(0x0017)
                u16(0x0018)
            }
        )
        ext.ext(
            0x000b,
            bytes {
                u8(1)
                u8(0)
            }
        )
        val sigs = listOf(0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201)
        ext.ext(
            0x000d,
            bytes {
                u16(sigs.size * 2)
                sigs.forEach { u16(it) }
            }
        )
        ext.ext(0xff01, byteArrayOf(0))
        val ciphers = listOf(0xc02f, 0xc02b, 0xc030, 0xc02c, 0xcca8, 0xcca9, 0x009c, 0x009d, 0x002f, 0x0035)
        val e = ext.toByteArray()
        val hello = bytes {
            u16(0x0303)
            write(ByteArray(32).also { java.util.Random().nextBytes(it) })
            u8(0)
            u16(ciphers.size * 2)
            ciphers.forEach { u16(it) }
            u8(1)
            u8(0)
            u16(e.size)
            write(e)
        }
        val hs = bytes {
            u8(1)
            u24(hello.size)
            write(hello)
        }
        return bytes {
            u8(0x16)
            u16(0x0301)
            u16(hs.size)
            write(hs)
        }
    }

    /** Sends a Client Hello for [sni] to [ip]:443 from the shell; the number of bytes the server sent back. */
    fun hello(ip: String, sni: String): Int {
        val b64 = android.util.Base64.encodeToString(clientHello(sni), android.util.Base64.NO_WRAP)
        return Shell.run(
            "f=/data/local/tmp/pw-hello.bin; echo '$b64' | base64 -d > \$f; (cat \$f; sleep 3) | timeout 6 toybox nc $ip 443 | wc -c; rm -f \$f"
        ).trim().toIntOrNull() ?: 0
    }
}

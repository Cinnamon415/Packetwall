package io.github.cinnamon415.packetwall

import java.io.FilterInputStream
import java.io.InputStream
import java.io.Reader

/**
 * Size limits for data from outside (list servers, imported files, downloaded databases): the UI and
 * the VPN share one process, so running out of memory on a hostile file would also stop protection.
 */
object Limits {
    const val LIST_CHARS = 200L shl 20
    const val LINE_CHARS = 4096
    const val IMPORT_BYTES = 100L shl 20
    const val UNPACKED_BYTES = 300L shl 20

    /** A capture file is read as a stream onto disk (parser process): the limit is about disk space. */
    const val CAPTURE_BYTES = 2L shl 30
    const val TRACKERS_BYTES = 50L shl 20
}

/** More data than [Limits] allow. */
class TooLargeException(what: String) : BadDataException("too large: $what")

/** Throws [TooLargeException] once more than [max] bytes were read. */
class CappedInputStream(input: InputStream, private val max: Long, private val what: String) : FilterInputStream(input) {
    private var count = 0L

    private fun add(n: Int): Int {
        if (n > 0) {
            count += n
            if (count > max) throw TooLargeException(what)
        }
        return n
    }

    override fun read(): Int = super.read().also { if (it >= 0) add(1) }

    override fun read(b: ByteArray, off: Int, len: Int): Int = add(super.read(b, off, len))
}

fun InputStream.readCapped(max: Long, what: String): ByteArray = CappedInputStream(this, max, what).use { it.readBytes() }

/**
 * Lines of this reader: lines longer than [maxLine] characters are skipped (no list entry is that
 * long), and more than [maxChars] characters in total throw [TooLargeException].
 */
fun Reader.cappedLines(maxChars: Long, maxLine: Int, what: String): Sequence<String> = sequence {
    val buf = CharArray(8192)
    val line = StringBuilder()
    var total = 0L
    var tooLong = false
    while (true) {
        val n = read(buf)
        if (n < 0) break
        total += n
        if (total > maxChars) throw TooLargeException(what)
        for (i in 0 until n) {
            val c = buf[i]
            if (c == '\n') {
                if (!tooLong) yield(line.toString().removeSuffix("\r"))
                line.setLength(0)
                tooLong = false
            } else if (!tooLong) {
                if (line.length >= maxLine) {
                    tooLong = true
                    line.setLength(0)
                } else {
                    line.append(c)
                }
            }
        }
    }
    if (!tooLong && line.isNotEmpty()) yield(line.toString().removeSuffix("\r"))
}

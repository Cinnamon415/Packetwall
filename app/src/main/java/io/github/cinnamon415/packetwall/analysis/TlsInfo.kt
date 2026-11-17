package io.github.cinnamon415.packetwall.analysis

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * TLS handshake details from the reassembled client (↑) and server (↓) streams of a connection:
 * SNI, ALPN, JA3 / JA4 client fingerprints, negotiated version and cipher, server certificate
 * (only visible up to TLS 1.2 — TLS 1.3 encrypts it).
 */
object TlsInfo {
    data class Client(
        val version: Int,
        val sni: String?,
        val alpn: List<String>,
        val ciphers: List<Int>,
        val extensions: List<Int>,
        val groups: List<Int>,
        val pointFormats: List<Int>,
        val sigAlgs: List<Int>,
        val supportedVersions: List<Int>
    ) {
        val ja3String get() = listOf(
            version.toString(),
            ciphers.joinToString("-"),
            extensions.joinToString("-"),
            groups.joinToString("-"),
            pointFormats.joinToString("-")
        ).joinToString(",")
        val ja3 get() = hex(MessageDigest.getInstance("MD5").digest(ja3String.toByteArray()))

        /** JA4 (FoxIO, https://github.com/FoxIO-LLC/ja4), TCP variant. */
        fun ja4(quic: Boolean = false): String {
            val v = (supportedVersions.ifEmpty { listOf(version) }).maxOrNull() ?: version
            val ver = when (v) {
                0x0304 -> "13"
                0x0303 -> "12"
                0x0302 -> "11"
                0x0301 -> "10"
                0x0300 -> "s3"
                else -> "00"
            }
            val alpnPart = alpn.firstOrNull()?.takeIf { it.isNotEmpty() }?.let { a ->
                val f = a.first()
                val l = a.last()
                if (f.code in 33..126 &&
                    l.code in 33..126
                ) {
                    "$f$l"
                } else {
                    hex(byteArrayOf(a.first().code.toByte())).take(1) +
                        hex(byteArrayOf(a.last().code.toByte())).takeLast(1)
                }
            } ?: "00"
            val a = "${if (quic) "q" else "t"}$ver${if (sni != null) "d" else "i"}" +
                "%02d".format(minOf(ciphers.size, 99)) + "%02d".format(minOf(extensions.size, 99)) + alpnPart
            val c = ciphers.map { "%04x".format(it) }.sorted().joinToString(",")
            val exts = extensions.filter { it != 0x0000 && it != 0x0010 }.map { "%04x".format(it) }.sorted().joinToString(",")
            val sigs = sigAlgs.joinToString(",") { "%04x".format(it) }
            val b = if (ciphers.isEmpty()) "000000000000" else sha12(c)
            val cpart = if (exts.isEmpty()) "000000000000" else sha12(if (sigs.isEmpty()) exts else "${exts}_$sigs")
            return "${a}_${b}_$cpart"
        }
    }

    data class Server(val version: Int, val cipher: Int, val alpn: String?, val cert: X509Certificate?, val certEncrypted: Boolean)

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    private fun sha12(s: String) = hex(MessageDigest.getInstance("SHA-256").digest(s.toByteArray())).take(12)
    private fun grease(v: Int) = (v and 0x0f0f) == 0x0a0a && (v shr 8) == (v and 0xff)

    private class R(val b: ByteArray) {
        fun u8(o: Int) = if (o in b.indices) b[o].toInt() and 0xff else 0
        fun u16(o: Int) = (u8(o) shl 8) or u8(o + 1)
        fun u24(o: Int) = (u8(o) shl 16) or u16(o + 1)
    }

    /** Concatenates the bodies of the handshake records at the start of a stream. */
    private fun handshakeBytes(stream: ByteArray): ByteArray {
        val r = R(stream)
        val out = ByteArrayOutputStream()
        var o = 0
        while (o + 5 <= stream.size) {
            val type = r.u8(o)
            val len = r.u16(o + 3)
            if (type !in 0x14..0x17 || r.u8(o + 1) != 3) break
            if (type == 0x16) out.write(stream, o + 5, minOf(len, stream.size - o - 5))
            if (type == 0x17) break // encrypted from here on
            o += 5 + len
        }
        return out.toByteArray()
    }

    /** Handshake messages (type, body) in a handshake byte stream. */
    private fun messages(hs: ByteArray): List<Pair<Int, ByteArray>> {
        val r = R(hs)
        val out = ArrayList<Pair<Int, ByteArray>>()
        var o = 0
        while (o + 4 <= hs.size) {
            val t = r.u8(o)
            val l = r.u24(o + 1)
            if (o + 4 + l > hs.size) {
                out.add(t to hs.copyOfRange(o + 4, hs.size))
                break
            } // truncated
            out.add(t to hs.copyOfRange(o + 4, o + 4 + l))
            o += 4 + l
        }
        return out
    }

    fun client(stream: ByteArray): Client? {
        val hello = messages(handshakeBytes(stream)).firstOrNull { it.first == 1 }?.second ?: return null
        val r = R(hello)
        val version = r.u16(0)
        var o = 2 + 32
        o += 1 + r.u8(o) // session id
        val cl = r.u16(o)
        o += 2
        val ciphers = (0 until cl / 2).map { r.u16(o + it * 2) }.filterNot(::grease)
        o += cl
        o += 1 + r.u8(o) // compression
        val extEnd = minOf(hello.size, o + 2 + r.u16(o))
        o += 2
        val exts = ArrayList<Int>()
        val groups = ArrayList<Int>()
        val pf = ArrayList<Int>()
        val sigs = ArrayList<Int>()
        val sv = ArrayList<Int>()
        val alpn = ArrayList<String>()
        var sni: String? = null
        while (o + 4 <= extEnd) {
            val t = r.u16(o)
            val l = r.u16(o + 2)
            val v = o + 4
            if (!grease(t)) exts.add(t)
            when (t) {
                0x0000 -> if (l >= 5) sni = String(hello, v + 5, minOf(r.u16(v + 3), hello.size - v - 5), Charsets.ISO_8859_1)
                0x000a -> (0 until r.u16(v) / 2).map { r.u16(v + 2 + it * 2) }.filterNot(::grease).let(groups::addAll)
                0x000b -> (0 until r.u8(v)).map { r.u8(v + 1 + it) }.let(pf::addAll)
                0x000d -> (0 until r.u16(v) / 2).map { r.u16(v + 2 + it * 2) }.let(sigs::addAll)
                0x0010 -> {
                    var a =
                        v + 2
                    while (a <
                        v + l
                    ) {
                        val n = r.u8(a)
                        if (a + 1 + n <=
                            hello.size
                        ) {
                            alpn.add(String(hello, a + 1, n, Charsets.ISO_8859_1))
                        }
                        a += 1 + n
                    }
                }
                0x002b -> (0 until r.u8(v) / 2).map { r.u16(v + 1 + it * 2) }.filterNot(::grease).let(sv::addAll)
            }
            o = v + l
        }
        return Client(version, sni, alpn, ciphers, exts, groups, pf, sigs, sv)
    }

    fun server(stream: ByteArray): Server? {
        val msgs = messages(handshakeBytes(stream))
        val hello = msgs.firstOrNull { it.first == 2 }?.second ?: return null
        val r = R(hello)
        var version = r.u16(0)
        var o = 2 + 32
        o += 1 + r.u8(o)
        val cipher = r.u16(o)
        o += 2
        o += 1 // compression
        var alpn: String? = null
        if (o + 2 <= hello.size) {
            val end = minOf(hello.size, o + 2 + r.u16(o))
            o += 2
            while (o + 4 <= end) {
                val t = r.u16(o)
                val l = r.u16(o + 2)
                val v = o + 4
                if (t == 0x002b && l == 2) version = r.u16(v)
                if (t == 0x0010 && l >= 3) alpn = String(hello, v + 3, minOf(r.u8(v + 2), hello.size - v - 3), Charsets.ISO_8859_1)
                o = v + l
            }
        }
        val tls13 = version == 0x0304
        val cert = if (tls13) {
            null
        } else {
            msgs.firstOrNull { it.first == 11 }?.second?.let { body ->
                val cr = R(body)
                val first = cr.u24(3)
                if (6 + first > body.size) {
                    null
                } else {
                    try {
                        CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(body, 6, first)) as X509Certificate
                    } catch (e: Exception) {
                        null
                    }
                }
            }
        }
        return Server(version, cipher, alpn, cert, tls13)
    }

    fun versionName(v: Int) = when (v) {
        0x0304 -> "TLS 1.3"
        0x0303 -> "TLS 1.2"
        0x0302 -> "TLS 1.1"
        0x0301 -> "TLS 1.0"
        0x0300 -> "SSL 3.0"
        else -> "0x%04x".format(v)
    }

    private val cipherNames = mapOf(
        0x1301 to "TLS_AES_128_GCM_SHA256", 0x1302 to "TLS_AES_256_GCM_SHA384",
        0x1303 to "TLS_CHACHA20_POLY1305_SHA256",
        0xc02b to "ECDHE_ECDSA_AES_128_GCM_SHA256", 0xc02c to "ECDHE_ECDSA_AES_256_GCM_SHA384", 0xc02f to "ECDHE_RSA_AES_128_GCM_SHA256",
        0xc030 to "ECDHE_RSA_AES_256_GCM_SHA384", 0xcca8 to "ECDHE_RSA_CHACHA20_POLY1305", 0xcca9 to "ECDHE_ECDSA_CHACHA20_POLY1305",
        0x009c to "RSA_AES_128_GCM_SHA256", 0x009d to "RSA_AES_256_GCM_SHA384", 0x002f to "RSA_AES_128_CBC_SHA",
        0x0035 to "RSA_AES_256_CBC_SHA"
    )
    fun cipherName(c: Int) = cipherNames[c] ?: "0x%04x".format(c)
}

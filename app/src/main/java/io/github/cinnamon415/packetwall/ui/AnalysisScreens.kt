package io.github.cinnamon415.packetwall.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectHorizontalDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.cinnamon415.packetwall.PacketwallApp
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.analysis.Dissector
import io.github.cinnamon415.packetwall.analysis.PacketStore
import io.github.cinnamon415.packetwall.engine.Conn
import io.github.cinnamon415.packetwall.ui.theme.LocalExtraColors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.math.ln
import kotlin.math.max

/** One row of the packets list. */
class PktRow(val p: PacketStore.Pkt, val s: Dissector.Summary, val relSeq: Long?, val relAck: Long?, val dt: Long)

/** Packets of a connection, refreshed while the view is visible. */
@Composable
fun rememberConnPackets(app: PacketwallApp, c: Conn): List<PktRow>? {
    val rows by produceState<List<PktRow>?>(null, c.id) {
        while (true) {
            value = withContext(Dispatchers.Default) { buildRows(app.packets.packetsOf(c)) }
            delay(800)
        }
    }
    return rows
}

fun buildRows(pkts: List<PacketStore.Pkt>): List<PktRow> {
    if (pkts.isEmpty()) return emptyList()
    val t0 = pkts.first().ts
    val base = HashMap<Boolean, Long>()
    val sums = pkts.map { Dissector.summary(it.block, it.dataOff, it.capLen) }
    pkts.forEachIndexed { i, p -> sums[i].tcpSeq?.let { if (!base.containsKey(p.tx)) base[p.tx] = it } }
    return pkts.mapIndexed { i, p ->
        val s = sums[i]
        val rs = s.tcpSeq?.let { seq -> base[p.tx]?.let { (seq - it) and 0xffffffffL } }
        val ra = if (s.tcpFlags and 0x10 != 0) s.tcpAck?.let { ack -> base[!p.tx]?.let { (ack - it) and 0xffffffffL } } else null
        PktRow(p, s, rs, ra, p.ts - t0)
    }
}

private fun fmtDelta(us: Long): String = when {
    us < 1000 -> "+$us µs"
    us < 1_000_000 -> String.format(Locale.US, "+%.1f ms", us / 1000.0)
    else -> String.format(Locale.US, "+%.2f s", us / 1e6)
}

// ------------------------------------------------------------------ Packets tab

@Composable
fun PacketsTab(app: PacketwallApp, c: Conn, onOpenPacket: (Long) -> Unit) {
    val rows = rememberConnPackets(app, c)
    var range by remember { mutableStateOf<Pair<Float, Float>?>(null) }
    val captureOn = app.settings.current.capturePackets
    when {
        rows == null -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { Text(stringResource(R.string.loading)) }
        rows.isEmpty() -> EmptyHint(stringResource(if (captureOn) R.string.no_packets else R.string.capture_off))
        else -> {
            val t0 = rows.first().p.ts
            val span = max(1L, rows.last().p.ts - t0)
            val shown = range?.let { (a, b) -> rows.filter { r -> ((r.p.ts - t0).toFloat() / span) in a..b } } ?: rows
            Column {
                Timeline(rows, span, range, { range = it })
                Text(stringResource(R.string.packets_shown, shown.size, rows.size) +
                        if (range != null) " · " + stringResource(R.string.tap_to_reset) else "",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp))
                HorizontalDivider()
                LazyColumn(contentPadding = PaddingValues(bottom = 24.dp)) {
                    items(shown, key = { it.p.seq }) { r ->
                        PacketRow(r) { onOpenPacket(r.p.seq) }
                        HorizontalDivider(color = MaterialTheme.colorScheme.surfaceContainerHigh)
                    }
                }
            }
        }
    }
}

/** Bars: height = size (log), color = direction, ✕ = dropped. Drag to select a range, tap to reset. */
@Composable
private fun Timeline(rows: List<PktRow>, span: Long, range: Pair<Float, Float>?, onRange: (Pair<Float, Float>?) -> Unit) {
    val up = LocalExtraColors.current.up
    val down = LocalExtraColors.current.down
    val drop = MaterialTheme.colorScheme.error
    val sel = MaterialTheme.colorScheme.primary.copy(alpha = 0.12f)
    val axis = MaterialTheme.colorScheme.outlineVariant
    val t0 = rows.first().p.ts
    val maxLen = rows.maxOf { it.p.origLen }.coerceAtLeast(2)
    var dragStart by remember { mutableStateOf(0f) }
    Surface(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp), shape = RoundedCornerShape(12.dp),
        color = MaterialTheme.colorScheme.surfaceContainerLow) {
        Canvas(Modifier.fillMaxWidth().height(76.dp).padding(horizontal = 8.dp, vertical = 6.dp)
            .pointerInput(rows.size) {
                detectHorizontalDragGestures(
                    onDragStart = { o -> dragStart = (o.x / size.width).coerceIn(0f, 1f); onRange(dragStart to dragStart) },
                ) { change, _ ->
                    val x = (change.position.x / size.width).coerceIn(0f, 1f)
                    onRange(minOf(dragStart, x) to maxOf(dragStart, x))
                }
            }
            .pointerInput(Unit) { detectTapGestures { onRange(null) } }) {
            val mid = size.height / 2
            drawLine(axis, Offset(0f, mid), Offset(size.width, mid), 1f)
            range?.let { (a, b) -> drawRect(sel, Offset(a * size.width, 0f), Size(max(2f, (b - a) * size.width), size.height)) }
            for (r in rows) {
                val x = (r.p.ts - t0).toFloat() / span * size.width
                val h = (ln(r.p.origLen.toFloat()) / ln(maxLen.toFloat())) * (mid - 2)
                when {
                    r.p.dropped -> {
                        val s = 4.dp.toPx()
                        drawLine(drop, Offset(x - s, mid - h / 2 - s), Offset(x + s, mid - h / 2 + s), 2.5f)
                        drawLine(drop, Offset(x - s, mid - h / 2 + s), Offset(x + s, mid - h / 2 - s), 2.5f)
                    }
                    r.p.tx -> drawLine(up, Offset(x, mid), Offset(x, mid - h), 2.5f)
                    else -> drawLine(down, Offset(x, mid), Offset(x, mid + h), 2.5f)
                }
            }
        }
    }
}

@Composable
private fun PacketRow(r: PktRow, onClick: () -> Unit) {
    val muted = MaterialTheme.colorScheme.onSurfaceVariant
    val (arrow, color) = when {
        r.p.dropped -> "✕" to MaterialTheme.colorScheme.error
        r.p.tx -> "↑" to LocalExtraColors.current.up
        else -> "↓" to LocalExtraColors.current.down
    }
    Row(Modifier.fillMaxWidth().clickable(onClick = onClick).padding(horizontal = 12.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically) {
        Text(arrow, color = color, fontWeight = FontWeight.Bold, modifier = Modifier.width(20.dp))
        Column(Modifier.weight(1f)) {
            Text(buildAnnotatedString {
                withStyle(SpanStyle(fontWeight = FontWeight.SemiBold)) { append(r.s.proto) }
                append("  "); append(r.s.info)
            }, style = MaterialTheme.typography.bodyMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
            val line2 = listOfNotNull(fmtDelta(r.dt), r.relSeq?.let { "seq $it" }, r.relAck?.let { "ack $it" }).joinToString(" · ")
            Text(line2, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace, color = muted, maxLines = 1)
        }
        Text("${r.p.origLen}", style = MaterialTheme.typography.bodySmall, color = muted, fontFamily = FontFamily.Monospace)
    }
}

// ------------------------------------------------------------------ Packet screen

@Composable
fun PacketScreen(app: PacketwallApp, connId: Int, seq: Long, onBack: () -> Unit) {
    val conn = remember(connId) { app.connections.conns.value.firstOrNull { it.id == connId } }
    val pkt = remember(seq) { conn?.let { app.packets.packetsOf(it) }?.firstOrNull { it.seq == seq } ?: app.packets.all().firstOrNull { it.seq == seq } }
    var selected by remember { mutableStateOf<Dissector.Field?>(null) }
    if (pkt == null) {
        ScreenScaffold(title = "#$seq", onBack = onBack) { EmptyHint(stringResource(R.string.packet_gone)) }
        return
    }
    val sum = remember(pkt) { Dissector.summary(pkt.block, pkt.dataOff, pkt.capLen) }
    val tree = remember(pkt) { Dissector.tree(pkt.block, pkt.dataOff, pkt.capLen) }
    val time = remember(pkt) { SimpleDateFormat("HH:mm:ss.SSS", Locale.getDefault()).format(Date(pkt.ts / 1000)) }
    val dir = stringResource(when { pkt.dropped -> R.string.dir_dropped; pkt.tx -> R.string.dir_out; else -> R.string.dir_in })
    ScreenScaffold(title = "${sum.proto} ${sum.info}", subtitle = "$time · $dir · ${pkt.origLen} B" +
            if (pkt.capLen < pkt.origLen) " (${pkt.capLen})" else "", onBack = onBack) {
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(vertical = 4.dp)) {
            tree.forEachIndexed { i, f -> FieldNode(f, 0, selected, expandedByDefault = i == tree.lastIndex) { selected = it } }
        }
        HorizontalDivider()
        Box(Modifier.weight(1f).fillMaxWidth().background(MaterialTheme.colorScheme.surfaceContainerLow)) {
            HexView(pkt.block, pkt.dataOff, pkt.capLen, selected)
        }
    }
}

@Composable
private fun FieldNode(f: Dissector.Field, depth: Int, selected: Dissector.Field?, expandedByDefault: Boolean, onSelect: (Dissector.Field) -> Unit) {
    var open by rememberSaveable(f.name, f.start) { mutableStateOf(expandedByDefault) }
    val isSel = selected === f
    Row(Modifier.fillMaxWidth()
        .background(if (isSel) MaterialTheme.colorScheme.secondaryContainer else Color.Transparent)
        .clickable { onSelect(f); if (f.children.isNotEmpty()) open = !open }
        .padding(start = (12 + depth * 16).dp, end = 12.dp, top = 5.dp, bottom = 5.dp)) {
        Text(if (f.children.isEmpty()) " " else if (open) "▾" else "▸", modifier = Modifier.width(16.dp),
            color = MaterialTheme.colorScheme.outline)
        Text(buildAnnotatedString {
            withStyle(SpanStyle(fontWeight = if (depth == 0) FontWeight.SemiBold else FontWeight.Normal)) { append(f.name) }
            if (f.value.isNotEmpty()) { append(": "); withStyle(SpanStyle(fontFamily = FontFamily.Monospace)) { append(f.value) } }
        }, style = MaterialTheme.typography.bodyMedium)
    }
    if (open) f.children.forEach { FieldNode(it, depth + 1, selected, false, onSelect) }
}

/** 8 bytes per line so it fits a phone without horizontal scrolling. */
@Composable
private fun HexView(b: ByteArray, off: Int, len: Int, sel: Dissector.Field?) {
    val hi = MaterialTheme.colorScheme.primary.copy(alpha = 0.25f)
    val muted = MaterialTheme.colorScheme.onSurfaceVariant
    val text = remember(b, sel) {
        buildAnnotatedString {
            val a = sel?.start ?: -1
            val z = sel?.let { it.start + it.len } ?: -1
            var i = 0
            while (i < len) {
                withStyle(SpanStyle(color = muted)) { append("%04x  ".format(i)) }
                for (j in 0 until 8) {
                    val k = i + j
                    if (k < len) {
                        val h = "%02x".format(b[off + k])
                        if (k in a until z) withStyle(SpanStyle(background = hi)) { append(h) } else append(h)
                        append(if (j == 3) "  " else " ")
                    } else append(if (j == 3) "    " else "   ")
                }
                append(" ")
                for (j in 0 until 8) {
                    val k = i + j
                    if (k >= len) break
                    val ch = (b[off + k].toInt() and 0xff).let { if (it in 32..126) it.toChar() else '·' }
                    if (k in a until z) withStyle(SpanStyle(background = hi)) { append(ch) } else append(ch)
                }
                append("\n")
                i += 8
            }
        }
    }
    Text(text, fontFamily = FontFamily.Monospace, fontSize = 12.sp, lineHeight = 16.sp,
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(12.dp))
}

// ------------------------------------------------------------------ Data tab

class DataBlock(val tx: Boolean, val bytes: ByteArray)

fun payloadBlocks(rows: List<PktRow>, limit: Int = 256 * 1024): List<DataBlock> {
    val out = ArrayList<DataBlock>()
    val seen = HashSet<Pair<Boolean, Long>>()
    var cur: java.io.ByteArrayOutputStream? = null
    var curTx = true
    var total = 0
    for (r in rows) {
        if (r.p.dropped || r.s.payloadLen <= 0) continue
        if (r.s.tcpSeq != null && !seen.add(r.p.tx to r.s.tcpSeq)) continue   // retransmission
        if (cur == null || curTx != r.p.tx) {
            cur?.let { out.add(DataBlock(curTx, it.toByteArray())) }
            cur = java.io.ByteArrayOutputStream(); curTx = r.p.tx
        }
        val start = r.p.dataOff + r.s.payloadOff
        val n = minOf(r.s.payloadLen, r.p.dataOff + r.p.capLen - start, limit - total)
        if (n <= 0) break
        cur.write(r.p.block, start, n)
        total += n
    }
    cur?.let { out.add(DataBlock(curTx, it.toByteArray())) }
    return out
}

private fun printable(b: ByteArray): Boolean {
    if (b.isEmpty()) return true
    val n = minOf(b.size, 512)
    var ok = 0
    for (i in 0 until n) { val c = b[i].toInt() and 0xff; if (c in 32..126 || c == 9 || c == 10 || c == 13) ok++ }
    return ok >= n * 0.9
}

@Composable
fun DataTab(app: PacketwallApp, c: Conn) {
    val rows = rememberConnPackets(app, c)
    var mode by rememberSaveable { mutableStateOf(0) } // 0 auto, 1 text, 2 hex
    val blocks = remember(rows) { rows?.let { payloadBlocks(it) } ?: emptyList() }
    Column {
        Row(Modifier.padding(horizontal = 12.dp, vertical = 6.dp), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            listOf(R.string.mode_auto, R.string.mode_text, R.string.mode_hex).forEachIndexed { i, s ->
                FilterChip(mode == i, { mode = i }, { Text(stringResource(s)) })
            }
        }
        if (rows != null && blocks.isEmpty()) EmptyHint(stringResource(R.string.no_payload))
        LazyColumn(contentPadding = PaddingValues(start = 12.dp, end = 12.dp, bottom = 24.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            items(blocks.size) { i ->
                val blk = blocks[i]
                val asText = when (mode) { 1 -> true; 2 -> false; else -> printable(blk.bytes) }
                val color = if (blk.tx) LocalExtraColors.current.up else LocalExtraColors.current.down
                Surface(shape = RoundedCornerShape(12.dp), color = MaterialTheme.colorScheme.surfaceContainerLow) {
                    Column(Modifier.padding(10.dp)) {
                        Text("${if (blk.tx) "↑" else "↓"} ${formatBytes(blk.bytes.size.toLong())}", color = color,
                            style = MaterialTheme.typography.labelLarge)
                        val shown = blk.bytes.copyOf(minOf(blk.bytes.size, if (asText) 16384 else 4096))
                        Text(if (asText) shown.toString(Charsets.ISO_8859_1).map { ch -> if (ch.code in 32..126 || ch == '\n' || ch == '\t') ch else if (ch == '\r') '\u0000' else '·' }
                                .filter { it != '\u0000' }.joinToString("")
                            else hexLines(shown),
                            fontFamily = FontFamily.Monospace, fontSize = 12.sp, lineHeight = 16.sp,
                            modifier = Modifier.horizontalScroll(rememberScrollState()))
                        if (shown.size < blk.bytes.size)
                            Text(stringResource(R.string.more_bytes, blk.bytes.size - shown.size), style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
        }
    }
}

private fun hexLines(b: ByteArray): String = buildString {
    var i = 0
    while (i < b.size) {
        append("%04x  ".format(i))
        for (j in 0 until 8) if (i + j < b.size) append("%02x ".format(b[i + j])) else append("   ")
        append(" ")
        for (j in 0 until 8) if (i + j < b.size) { val c = b[i + j].toInt() and 0xff; append(if (c in 32..126) c.toChar() else '·') }
        append('\n'); i += 8
    }
}

// ------------------------------------------------------------------ HTTP tab

@Composable
fun HttpTab(app: PacketwallApp, c: Conn) {
    val rows = rememberConnPackets(app, c)
    val blocks = remember(rows) { rows?.let { payloadBlocks(it, 64 * 1024) } ?: emptyList() }
    // TLS details from the reassembled streams (a ClientHello often spans several segments)
    val tlsClient = remember(blocks) { blocks.firstOrNull { it.tx }?.let { io.github.cinnamon415.packetwall.analysis.TlsInfo.client(it.bytes) } }
    val tlsServer = remember(blocks) { blocks.firstOrNull { !it.tx }?.let { io.github.cinnamon415.packetwall.analysis.TlsInfo.server(it.bytes) } }
    val req = blocks.firstOrNull { it.tx && Regex("^[A-Z]+ \\S+ HTTP/1").containsMatchIn(String(it.bytes, 0, minOf(it.bytes.size, 64), Charsets.ISO_8859_1)) }
    val resp = blocks.firstOrNull { !it.tx && String(it.bytes, 0, minOf(it.bytes.size, 8), Charsets.ISO_8859_1).startsWith("HTTP/") }
    Column(Modifier.verticalScroll(rememberScrollState()).padding(12.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        when {
            req != null || resp != null -> {
                req?.let { HttpMessage(stringResource(R.string.http_request), it.bytes, LocalExtraColors.current.up) }
                resp?.let { HttpMessage(stringResource(R.string.http_response), it.bytes, LocalExtraColors.current.down) }
            }
            tlsClient != null -> {
                Text(stringResource(R.string.http_encrypted), color = MaterialTheme.colorScheme.onSurfaceVariant)
                TlsDetails(tlsClient, tlsServer)
            }
            c.l7proto.contains("QUIC", true) -> Text(stringResource(R.string.http_quic), color = MaterialTheme.colorScheme.onSurfaceVariant)
            rows == null -> Text(stringResource(R.string.loading))
            else -> Text(stringResource(R.string.no_http), color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun HttpMessage(title: String, bytes: ByteArray, color: Color) {
    val text = String(bytes, Charsets.ISO_8859_1)
    val head = text.substringBefore("\r\n\r\n")
    val body = text.substringAfter("\r\n\r\n", "")
    Text(title, style = MaterialTheme.typography.labelLarge, color = color)
    RoundedGroup {
        val lines = head.split("\r\n")
        Text(lines.first(), fontFamily = FontFamily.Monospace, fontWeight = FontWeight.SemiBold,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp))
        lines.drop(1).forEach { l -> KvRow(l.substringBefore(":"), l.substringAfter(":").trim()) }
    }
    if (body.isNotEmpty()) {
        val preview = if (printable(body.toByteArray(Charsets.ISO_8859_1))) body.take(4000) else stringResource(R.string.binary_body, body.length)
        Text(preview, fontFamily = FontFamily.Monospace, fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
fun KvRow(k: String, v: String) {
    Row(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 6.dp)) {
        Text(k, color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall, modifier = Modifier.width(120.dp))
        Text(v, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
    }
}


@Composable
private fun TlsDetails(c: io.github.cinnamon415.packetwall.analysis.TlsInfo.Client, s: io.github.cinnamon415.packetwall.analysis.TlsInfo.Server?) {
    val tls = io.github.cinnamon415.packetwall.analysis.TlsInfo
    Text(stringResource(R.string.tls_client), style = MaterialTheme.typography.labelLarge, color = LocalExtraColors.current.up)
    RoundedGroup {
        KvRow("SNI", c.sni ?: "—")
        KvRow("ALPN", c.alpn.joinToString(", ").ifEmpty { "—" })
        KvRow(stringResource(R.string.tls_offered), (c.supportedVersions.ifEmpty { listOf(c.version) }).joinToString(", ") { tls.versionName(it) })
        KvRow(stringResource(R.string.tls_ciphers), "${c.ciphers.size}")
        KvRow("JA4", c.ja4())
        KvRow("JA3", c.ja3)
    }
    if (s != null) {
        Text(stringResource(R.string.tls_server), style = MaterialTheme.typography.labelLarge, color = LocalExtraColors.current.down)
        RoundedGroup {
            KvRow(stringResource(R.string.tls_version), tls.versionName(s.version))
            KvRow(stringResource(R.string.tls_cipher), tls.cipherName(s.cipher))
            KvRow("ALPN", s.alpn ?: "—")
            val cert = s.cert
            when {
                cert != null -> {
                    KvRow(stringResource(R.string.tls_subject), cert.subjectX500Principal.name)
                    KvRow(stringResource(R.string.tls_issuer), cert.issuerX500Principal.name)
                    KvRow(stringResource(R.string.tls_valid), "${java.text.DateFormat.getDateInstance().format(cert.notBefore)} — " +
                            java.text.DateFormat.getDateInstance().format(cert.notAfter))
                    val sans = try { cert.subjectAlternativeNames?.mapNotNull { it.getOrNull(1)?.toString() } } catch (e: Exception) { null }
                    if (!sans.isNullOrEmpty()) KvRow("SAN", sans.take(6).joinToString(", ") + if (sans.size > 6) " +${sans.size - 6}" else "")
                }
                s.certEncrypted -> KvRow(stringResource(R.string.tls_cert), stringResource(R.string.tls_cert_encrypted))
                else -> KvRow(stringResource(R.string.tls_cert), "—")
            }
        }
    }
}

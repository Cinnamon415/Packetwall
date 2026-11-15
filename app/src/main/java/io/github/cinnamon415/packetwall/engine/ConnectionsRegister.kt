package io.github.cinnamon415.packetwall.engine

import io.github.cinnamon415.packetwall.engine.model.CaptureStats
import io.github.cinnamon415.packetwall.engine.model.ConnectionDescriptor
import io.github.cinnamon415.packetwall.engine.model.ConnectionUpdate
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

/** Immutable snapshot of a connection for the UI. */
data class Conn(
    val id: Int,
    val uid: Int,
    val app: AppInfo,
    val ipver: Int,
    val ipproto: Int,
    val srcIp: String,
    val srcPort: Int,
    val dstIp: String,
    val dstPort: Int,
    val l7proto: String,
    val host: String?,
    val url: String?,
    val sentBytes: Long,
    val rcvdBytes: Long,
    val sentPkts: Int,
    val rcvdPkts: Int,
    val blockedPkts: Int,
    val firstSeen: Long,
    val lastSeen: Long,
    val status: Int,
    val blocked: Boolean,
    /** Matched rule: > 0 rule id, < 0 = -(set id) of a blocklist, 0 = none. */
    val fwRule: Int,
) {
    val active get() = status < ConnectionDescriptor.CONN_STATUS_CLOSED
    val l4 get() = when (ipproto) { 6 -> "TCP"; 17 -> "UDP"; 1, 58 -> "ICMP"; else -> "IP/$ipproto" }
    val protoLabel get() = l7proto.ifEmpty { l4 }
    val bytes get() = sentBytes + rcvdBytes
    val title get() = host?.takeIf { it.isNotEmpty() } ?: dstIp
}

data class Stats(
    val bytesSent: Long = 0, val bytesRcvd: Long = 0,
    val pktsSent: Int = 0, val pktsRcvd: Int = 0,
    val activeConns: Int = 0, val totalConns: Int = 0, val dnsQueries: Int = 0,
)

/**
 * Holds the connections reported by the native engine. Updates arrive on the capture thread;
 * snapshots are published to the UI at most every [PUBLISH_MS].
 */
class ConnectionsRegister(private val apps: AppsResolver, private val maxConns: Int = 20_000) {
    private val lock = Any()
    private val byId = LinkedHashMap<Int, ConnectionDescriptor>()
    @Volatile private var dirty = false

    private val _conns = MutableStateFlow<List<Conn>>(emptyList())
    val conns: StateFlow<List<Conn>> = _conns
    private val _stats = MutableStateFlow(Stats())
    val stats: StateFlow<Stats> = _stats

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    init {
        scope.launch {
            while (true) {
                delay(PUBLISH_MS)
                if (dirty) publish()
            }
        }
    }

    fun reset() {
        synchronized(lock) { byId.clear() }
        _stats.value = Stats()
        dirty = true
    }

    fun onUpdate(newConns: Array<ConnectionDescriptor?>?, updates: Array<ConnectionUpdate?>?) {
        synchronized(lock) {
            newConns?.forEach { c -> if (c != null) byId[c.incr_id] = c }
            updates?.forEach { u -> if (u != null) byId[u.incr_id]?.processUpdate(u) }
            while (byId.size > maxConns) {
                val first = byId.keys.iterator().next()
                byId.remove(first)
            }
        }
        dirty = true
    }

    fun onStats(s: CaptureStats) {
        _stats.value = Stats(s.bytes_sent, s.bytes_rcvd, s.pkts_sent, s.pkts_rcvd,
            s.active_conns, s.tot_conns, s.num_dns_queries)
    }

    private fun publish() {
        dirty = false
        val snap = synchronized(lock) {
            byId.values.map { c ->
                Conn(c.incr_id, c.uid, apps.get(c.uid), c.ipver, c.ipproto, c.src_ip, c.src_port,
                    c.dst_ip, c.dst_port, c.l7proto ?: "", c.info, c.url, c.sent_bytes, c.rcvd_bytes,
                    c.sent_pkts, c.rcvd_pkts, c.blocked_pkts, c.first_seen, c.last_seen, c.status, c.is_blocked, c.fw_rule)
            }
        }
        _conns.value = snap.asReversed()
    }

    companion object {
        const val PUBLISH_MS = 500L
    }
}

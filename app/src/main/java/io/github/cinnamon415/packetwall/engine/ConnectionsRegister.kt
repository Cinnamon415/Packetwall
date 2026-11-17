package io.github.cinnamon415.packetwall.engine

import android.util.Log
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
import kotlinx.coroutines.runBlocking

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
    /** Sent through the upstream proxy. */
    val proxied: Boolean = false,
    val country: String = "",
    /** Tracking company of the host, looked up once (null = none or unknown). */
    val tracker: String? = null
) {
    val active get() = status < ConnectionDescriptor.CONN_STATUS_CLOSED
    val l4 get() = when (ipproto) {
        6 -> "TCP"
        17 -> "UDP"
        1, 58 -> "ICMP"
        else -> "IP/$ipproto"
    }
    val protoLabel get() = l7proto.ifEmpty { l4 }
    val bytes get() = sentBytes + rcvdBytes
    val title get() = host?.takeIf { it.isNotEmpty() } ?: dstIp
}

data class Stats(
    val bytesSent: Long = 0,
    val bytesRcvd: Long = 0,
    val pktsSent: Int = 0,
    val pktsRcvd: Int = 0,
    val activeConns: Int = 0,
    val totalConns: Int = 0,
    val dnsQueries: Int = 0
)

/**
 * Holds the connections reported by the native engine. The capture thread only records what
 * changed (under a short lock); every [PUBLISH_MS] the changed connections are converted, closed
 * ones are written to the log, and the list for the UI is rebuilt only while someone watches it.
 */
class ConnectionsRegister(private val apps: AppsResolver, private val maxConns: Int = 20_000) {
    private val lock = Any()

    // capture thread side (under lock)
    private val byId = LinkedHashMap<Int, ConnectionDescriptor>()
    private var changed = HashSet<Int>()
    private var evicted = HashSet<Int>()
    private var cleared = false

    // publisher side (scope's single consumer)
    private val view = LinkedHashMap<Int, Conn>()
    private var viewDirty = true

    @Volatile private var dirty = false

    /** Names the tracking company of a host; set by the app once the tracker database is known. */
    @Volatile var trackerOf: (String?) -> String? = { null }

    private val _conns = MutableStateFlow<List<Conn>>(emptyList())
    val conns: StateFlow<List<Conn>> = _conns
    private val _stats = MutableStateFlow(Stats())
    val stats: StateFlow<Stats> = _stats

    /** Recent totals (time ms, sent, received) for the speed chart. */
    data class Sample(val t: Long, val sent: Long, val rcvd: Long)
    private val _history = MutableStateFlow<List<Sample>>(emptyList())
    val history: StateFlow<List<Sample>> = _history
    private val samples = ArrayDeque<Sample>()

    // one publisher at a time: the periodic tick, a new subscriber and reset() never overlap
    private val publisher = Dispatchers.Default.limitedParallelism(1)
    private val scope = CoroutineScope(SupervisorJob() + publisher)

    // Persistent log: closed connections are written to [db] when [keepDays] > 0
    @Volatile private var db: LogDb? = null

    @Volatile private var keepDays = 0

    @Volatile var blockedOnly = false

    @Volatile private var stored: List<Conn> = emptyList()
    private val saved = HashSet<Int>()
    private var lastPurge = 0L

    /** Enables/disables the persistent log; purges old rows and reloads the history. */
    fun configureLog(logDb: LogDb, days: Int) = scope.launch {
        db = logDb
        keepDays = days
        if (days > 0) {
            logDb.purge(System.currentTimeMillis() - days * 86_400_000L)
            lastPurge = System.currentTimeMillis()
            stored = loadStored(logDb)
        } else {
            stored = emptyList()
        }
        viewDirty = true
        dirty = true
    }

    private fun loadStored(d: LogDb) = d.load(HISTORY_ROWS, apps).map { it.copy(tracker = trackerOf(it.host)) }

    private fun persist(list: List<Conn>) {
        val d = db ?: return
        if (keepDays <= 0 || list.isEmpty()) return
        try {
            d.insert(list)
        } catch (e: Exception) {
            Log.w("ConnectionsRegister", "log insert", e)
        }
    }

    init {
        scope.launch {
            while (true) {
                delay(PUBLISH_MS)
                if (dirty) publish()
            }
        }
        // someone started watching: build the list now instead of waiting for the next change
        scope.launch {
            _conns.subscriptionCount.collect { n -> if (n > 0 && viewDirty) publish() }
        }
    }

    /** Starts a new session. Blocks until done (call off the main thread, before the capture starts). */
    fun reset() {
        runBlocking(publisher) {
            publish() // brings the view up to date and writes what is closed
            // keep what the previous session did not write yet (still open at the stop)
            val left = view.values.filter { it.id !in saved && (!blockedOnly || it.blocked) }
            persist(left)
            synchronized(lock) {
                byId.clear()
                changed.clear()
                evicted.clear()
            }
            view.clear()
            saved.clear()
            db?.let { if (keepDays > 0 && left.isNotEmpty()) stored = loadStored(it) }
            viewDirty = true
            dirty = true
        }
        _stats.value = Stats()
        synchronized(samples) { samples.clear() }
        _history.value = emptyList()
    }

    fun onUpdate(newConns: Array<ConnectionDescriptor?>?, updates: Array<ConnectionUpdate?>?) {
        synchronized(lock) {
            newConns?.forEach { c ->
                if (c != null) {
                    byId[c.incr_id] = c
                    changed.add(c.incr_id)
                }
            }
            updates?.forEach { u ->
                if (u != null) {
                    byId[u.incr_id]?.let {
                        it.processUpdate(u)
                        changed.add(u.incr_id)
                    }
                }
            }
            while (byId.size > maxConns) {
                val first = byId.keys.iterator().next()
                byId.remove(first)
                changed.remove(first)
                evicted.add(first)
            }
        }
        dirty = true
    }

    fun onStats(s: CaptureStats) {
        // speed history: one sample a second (stats arrive about every 300 ms), 10 minutes
        val now = System.currentTimeMillis()
        synchronized(samples) {
            if (samples.isEmpty() || now - samples.last().t >= 1000) {
                samples.addLast(Sample(now, s.bytes_sent, s.bytes_rcvd))
                while (samples.size > HISTORY) samples.removeFirst()
                _history.value = samples.toList()
            }
        }
        _stats.value = Stats(
            s.bytes_sent,
            s.bytes_rcvd,
            s.pkts_sent,
            s.pkts_rcvd,
            s.active_conns,
            s.tot_conns,
            s.num_dns_queries
        )
    }

    private fun toConn(c: ConnectionDescriptor) = Conn(
        c.incr_id, c.uid, apps.get(c.uid), c.ipver, c.ipproto, c.src_ip, c.src_port,
        c.dst_ip, c.dst_port, c.l7proto ?: "", c.info, c.url, c.sent_bytes, c.rcvd_bytes,
        c.sent_pkts, c.rcvd_pkts, c.blocked_pkts, c.first_seen, c.last_seen, c.status, c.is_blocked, c.fw_rule, c.proxied,
        c.country ?: "", trackerOf(c.info)
    )

    /** Publisher thread only. */
    private fun publish() {
        dirty = false
        // take the changes under the lock: O(changed), not O(all connections)
        val updated: List<Conn>
        val gone: Set<Int>
        synchronized(lock) {
            updated = changed.mapNotNull { id -> byId[id]?.let(::toConn) }
            gone = evicted
            changed = HashSet()
            evicted = HashSet()
        }
        if (updated.isNotEmpty() || gone.isNotEmpty()) viewDirty = true
        val toSave = ArrayList<Conn>()
        for (c in updated) {
            // keep the first-seen order: a known id is replaced in place
            view[c.id] = c
            if (keepDays > 0 && !c.active && (!blockedOnly || c.blocked) && saved.add(c.id)) toSave.add(c)
        }
        for (id in gone) {
            view.remove(id)
            saved.remove(id)
        }
        persist(toSave)
        purgeDaily()
        if (viewDirty && _conns.subscriptionCount.value > 0) {
            viewDirty = false
            val snap = view.values.toList().asReversed()
            _conns.value = if (keepDays > 0) snap + stored else snap
        }
    }

    /** A VPN that runs for weeks still drops log rows older than the retention. */
    private fun purgeDaily() {
        val d = db ?: return
        val now = System.currentTimeMillis()
        if (keepDays <= 0 || now - lastPurge < 86_400_000L) return
        lastPurge = now
        try {
            d.purge(now - keepDays * 86_400_000L)
        } catch (e: Exception) {
            Log.w("ConnectionsRegister", "log purge", e)
        }
    }

    companion object {
        const val PUBLISH_MS = 500L
        const val HISTORY = 600
        const val HISTORY_ROWS = 5000
    }
}

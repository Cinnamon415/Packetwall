package io.github.cinnamon415.packetwall.engine

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

/** Persistent connection log (closed connections), kept for N days when enabled in the settings. */
class LogDb(ctx: Context) : SQLiteOpenHelper(ctx, "log.db", null, 1) {
    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """CREATE TABLE conns(
            id INTEGER PRIMARY KEY AUTOINCREMENT, first_seen INTEGER, last_seen INTEGER, uid INTEGER,
            ipver INTEGER, ipproto INTEGER, l7 TEXT, src_ip TEXT, src_port INTEGER, dst_ip TEXT, dst_port INTEGER,
            host TEXT, url TEXT, sent INTEGER, rcvd INTEGER, pkts_sent INTEGER, pkts_rcvd INTEGER, blocked_pkts INTEGER,
            blocked INTEGER, fw_rule INTEGER, proxied INTEGER, country TEXT)"""
        )
        db.execSQL("CREATE INDEX conns_time ON conns(first_seen)")
    }

    override fun onUpgrade(db: SQLiteDatabase, o: Int, n: Int) {}

    // deleted rows (purge, "clear the saved log") are overwritten, not left in free pages
    override fun onConfigure(db: SQLiteDatabase) {
        db.rawQuery("PRAGMA secure_delete = ON", null).use { it.moveToFirst() }
    }

    fun insert(list: List<Conn>) {
        if (list.isEmpty()) return
        val db = writableDatabase
        db.beginTransaction()
        try {
            for (c in list) {
                db.insert(
                    "conns",
                    null,
                    ContentValues().apply {
                        put("first_seen", c.firstSeen)
                        put("last_seen", c.lastSeen)
                        put("uid", c.uid)
                        put("ipver", c.ipver)
                        put("ipproto", c.ipproto)
                        put("l7", c.l7proto)
                        put("src_ip", c.srcIp)
                        put("src_port", c.srcPort)
                        put("dst_ip", c.dstIp)
                        put("dst_port", c.dstPort)
                        put("host", c.host)
                        put("url", c.url)
                        put("sent", c.sentBytes)
                        put("rcvd", c.rcvdBytes)
                        put("pkts_sent", c.sentPkts)
                        put("pkts_rcvd", c.rcvdPkts)
                        put("blocked_pkts", c.blockedPkts)
                        put("blocked", if (c.blocked) 1 else 0)
                        put("fw_rule", c.fwRule)
                        put("proxied", if (c.proxied) 1 else 0)
                        put("country", c.country)
                    }
                )
            }
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    /** Most recent rows first; ids are negative so they never clash with live connections. */
    fun load(limit: Int, apps: AppsResolver): List<Conn> {
        val out = ArrayList<Conn>()
        readableDatabase.rawQuery(
            "SELECT id, first_seen, last_seen, uid, ipver, ipproto, l7, src_ip, src_port, dst_ip, dst_port, " +
                "host, url, sent, rcvd, pkts_sent, pkts_rcvd, blocked_pkts, blocked, fw_rule, proxied, country " +
                "FROM conns ORDER BY first_seen DESC LIMIT ?",
            arrayOf(limit.toString())
        ).use { c ->
            while (c.moveToNext()) {
                val uid = c.getInt(3)
                out.add(
                    Conn(
                        -c.getInt(0), uid, apps.get(uid), c.getInt(4), c.getInt(5), c.getString(7) ?: "", c.getInt(8),
                        c.getString(9) ?: "", c.getInt(10), c.getString(6) ?: "", c.getString(11), c.getString(12),
                        c.getLong(13), c.getLong(14), c.getInt(15), c.getInt(16), c.getInt(17), c.getLong(1), c.getLong(2),
                        CLOSED, c.getInt(18) != 0, c.getInt(19), c.getInt(20) != 0, c.getString(21) ?: ""
                    )
                )
            }
        }
        return out
    }

    fun purge(olderThanMs: Long) {
        writableDatabase.delete("conns", "first_seen < ?", arrayOf(olderThanMs.toString()))
    }
    fun clear() {
        writableDatabase.delete("conns", null, null)
    }
    fun count(): Long = readableDatabase.compileStatement("SELECT COUNT(*) FROM conns").simpleQueryForLong()

    companion object {
        private const val CLOSED = 3 // ConnectionDescriptor.CONN_STATUS_CLOSED
    }
}

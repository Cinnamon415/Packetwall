package io.github.cinnamon415.packetwall.fw

import android.database.sqlite.SQLiteDatabase
import java.io.File
import java.io.InputStream
import java.util.zip.ZipInputStream

/** Reads the rule tables of a RethinkDNS backup (.rbk zip containing "bravedns.db"). */
object RethinkReader {
    fun read(zip: InputStream, tmpDir: File): ForeignImport.RethinkRows {
        val db = File(tmpDir, "rethink-import.db")
        var found = false
        ZipInputStream(zip).use { z ->
            while (true) {
                val e = z.nextEntry ?: break
                if (e.name.substringAfterLast('/') == "bravedns.db") {
                    db.outputStream().use { z.copyTo(it) }
                    found = true
                    break
                }
            }
        }
        if (!found) throw ForeignImport.Unsupported(ForeignImport.Unsupported.Reason.RETHINK_NO_DB)
        try {
            SQLiteDatabase.openDatabase(db.path, null, SQLiteDatabase.OPEN_READONLY).use { d ->
                fun hasTable(t: String) =
                    d.rawQuery("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", arrayOf(t)).use { it.moveToFirst() }
                val domains = if (!hasTable("CustomDomain")) {
                    emptyList()
                } else {
                    d.rawQuery("SELECT domain, uid, status, type FROM CustomDomain", null).use { c ->
                        buildList {
                            while (c.moveToNext()) {
                                add(
                                    ForeignImport.RethinkRows.Domain(
                                        c.getString(0) ?: "",
                                        c.getInt(1),
                                        c.getInt(2),
                                        c.getInt(3) == 1
                                    )
                                )
                            }
                        }
                    }
                }
                val ips = if (!hasTable("CustomIp")) {
                    emptyList()
                } else {
                    d.rawQuery("SELECT ipAddress, port, protocol, uid, status, isActive FROM CustomIp", null).use { c ->
                        buildList {
                            while (c.moveToNext()) {
                                add(
                                    ForeignImport.RethinkRows.Ip(
                                        c.getString(0) ?: "",
                                        c.getInt(1),
                                        c.getString(2) ?: "",
                                        c.getInt(3),
                                        c.getInt(4),
                                        c.getInt(5) != 0
                                    )
                                )
                            }
                        }
                    }
                }
                val apps = if (!hasTable("AppInfo")) {
                    emptyList()
                } else {
                    d.rawQuery("SELECT packageName, uid, firewallStatus, connectionStatus FROM AppInfo", null).use { c ->
                        buildList {
                            while (c.moveToNext()) {
                                add(
                                    ForeignImport.RethinkRows.AppRow(c.getString(0) ?: "", c.getInt(1), c.getInt(2), c.getInt(3))
                                )
                            }
                        }
                    }
                }
                return ForeignImport.RethinkRows(domains, ips, apps)
            }
        } finally {
            db.delete()
        }
    }
}

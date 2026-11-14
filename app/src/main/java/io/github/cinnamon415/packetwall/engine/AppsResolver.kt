package io.github.cinnamon415.packetwall.engine

import android.content.Context
import android.content.pm.PackageManager
import android.os.Process
import java.util.concurrent.ConcurrentHashMap

data class AppInfo(val uid: Int, val packageName: String, val name: String, val isSystem: Boolean)

/** Maps Linux uids to apps. Thread-safe: queried from the capture thread and the UI. */
class AppsResolver(private val ctx: Context) {
    private val cache = ConcurrentHashMap<Int, AppInfo>()

    fun get(uid: Int): AppInfo = cache.getOrPut(uid) { resolve(uid) }

    private fun resolve(uid: Int): AppInfo {
        special(uid)?.let { return it }
        val pm = ctx.packageManager
        val pkgs = pm.getPackagesForUid(uid)
        if (pkgs.isNullOrEmpty())
            return AppInfo(uid, "uid:$uid", "uid $uid", true)
        val pkg = pkgs.sorted().first()
        return try {
            val ai = pm.getApplicationInfo(pkg, 0)
            val label = pm.getApplicationLabel(ai).toString()
            val sys = (ai.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
            AppInfo(uid, pkg, if (pkgs.size > 1) "$label (+${pkgs.size - 1})" else label, sys)
        } catch (e: PackageManager.NameNotFoundException) {
            AppInfo(uid, pkg, pkg, true)
        }
    }

    private fun special(uid: Int): AppInfo? = when (uid) {
        -1 -> AppInfo(uid, "unknown", "Unknown (−1)", true)
        0 -> AppInfo(uid, "root", "root", true)
        Process.SYSTEM_UID -> AppInfo(uid, "android", "Android System", true)
        1001 -> AppInfo(uid, "phone", "Phone (radio)", true)
        1051 -> AppInfo(uid, "netd", "netd (DNS)", true)
        1052 -> AppInfo(uid, "dns_tether", "DNS tether", true)
        else -> null
    }
}

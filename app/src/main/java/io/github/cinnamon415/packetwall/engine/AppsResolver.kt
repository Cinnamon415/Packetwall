package io.github.cinnamon415.packetwall.engine

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Process
import io.github.cinnamon415.packetwall.R
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

data class AppInfo(val uid: Int, val packageName: String, val name: String, val isSystem: Boolean)

/** Maps Linux uids to apps. Thread-safe: queried from the capture thread and the UI. */
class AppsResolver(private val ctx: Context) {
    private val cache = ConcurrentHashMap<Int, AppInfo>()
    private val _changes = MutableStateFlow(0)

    /** Bumped when apps are installed, updated or removed (see [onPackagesChanged]). */
    val changes: StateFlow<Int> = _changes

    /** A package was added, replaced or removed: uids and names may differ now. */
    fun onPackagesChanged() {
        cache.clear()
        _changes.value++
    }

    fun get(uid: Int): AppInfo = cache.getOrPut(uid) { resolve(uid) }

    /** Package (or pseudo-package of a system uid) to uid; null if not installed. */
    fun uidOf(pkg: String): Int? {
        SPECIAL.entries.firstOrNull { it.value == pkg }?.let { return it.key }
        if (pkg.startsWith("uid:")) return pkg.removePrefix("uid:").toIntOrNull()
        return try {
            ctx.packageManager.getApplicationInfo(pkg, 0).uid
        } catch (e: PackageManager.NameNotFoundException) {
            null
        }
    }

    /** Installed apps (one entry per package) plus the system pseudo-apps. */
    fun installed(): List<AppInfo> {
        val pm = ctx.packageManager
        val list = pm.getInstalledApplications(0).map { ai ->
            AppInfo(
                ai.uid,
                ai.packageName,
                pm.getApplicationLabel(ai).toString(),
                (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            )
        }
        return SPECIAL.keys.map { get(it) } + list.filter { it.packageName !in SPECIAL.values }
    }

    /** Info for a package, also when it is not the "main" package of its uid. */
    fun byPackage(pkg: String): AppInfo? {
        uidOf(pkg)?.let { uid -> if (SPECIAL.containsKey(uid) || pkg.startsWith("uid:")) return get(uid) }
        return try {
            val pm = ctx.packageManager
            val ai = pm.getApplicationInfo(pkg, 0)
            AppInfo(
                ai.uid,
                pkg,
                pm.getApplicationLabel(ai).toString(),
                (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            )
        } catch (e: PackageManager.NameNotFoundException) {
            null
        }
    }

    private fun resolve(uid: Int): AppInfo {
        special(uid)?.let { return it }
        val pm = ctx.packageManager
        val pkgs = pm.getPackagesForUid(uid)
        if (pkgs.isNullOrEmpty()) {
            return AppInfo(uid, "uid:$uid", "uid $uid", true)
        }
        val pkg = pkgs.sorted().first()
        return try {
            val ai = pm.getApplicationInfo(pkg, 0)
            val label = pm.getApplicationLabel(ai).toString()
            val sys = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            AppInfo(uid, pkg, if (pkgs.size > 1) "$label (+${pkgs.size - 1})" else label, sys)
        } catch (e: PackageManager.NameNotFoundException) {
            AppInfo(uid, pkg, pkg, true)
        }
    }

    private fun special(uid: Int): AppInfo? = SPECIAL[uid]?.let { pkg -> AppInfo(uid, pkg, specialName(uid), true) }

    private fun specialName(uid: Int): String = when (uid) {
        -1 -> ctx.getString(R.string.app_unknown)
        0 -> "root"
        Process.SYSTEM_UID -> ctx.getString(R.string.app_android_system)
        1001 -> ctx.getString(R.string.app_phone)
        1051 -> "netd (DNS)"
        1052 -> ctx.getString(R.string.app_dns_tether)
        else -> "uid $uid"
    }

    companion object {
        /** System uids without a package of their own, mapped to pseudo-package names. */
        val SPECIAL = linkedMapOf(
            -1 to "unknown",
            0 to "root",
            Process.SYSTEM_UID to "android",
            1001 to "phone",
            1051 to "netd",
            1052 to "dns_tether"
        )
    }
}

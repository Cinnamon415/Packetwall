package io.github.cinnamon415.packetwall.system

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import android.util.Log
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import io.github.cinnamon415.packetwall.PacketwallApp
import io.github.cinnamon415.packetwall.Settings
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.TimeUnit

/** Periodic jobs: blocklist updates and the automatic backup of the rules. */
object Schedules {
    private const val LISTS = "update-lists"
    private const val BACKUP = "backup"
    private const val KEEP_BACKUPS = 7

    fun apply(ctx: Context, s: Settings.Values) {
        val wm = WorkManager.getInstance(ctx)
        if (s.listsAutoUpdate) {
            val c = Constraints.Builder()
                .setRequiredNetworkType(if (s.listsWifiOnly) NetworkType.UNMETERED else NetworkType.CONNECTED)
                .setRequiresBatteryNotLow(true)
                .build()
            wm.enqueueUniquePeriodicWork(
                LISTS,
                ExistingPeriodicWorkPolicy.UPDATE,
                PeriodicWorkRequestBuilder<UpdateListsWorker>(1, TimeUnit.DAYS).setConstraints(c).build()
            )
        } else {
            wm.cancelUniqueWork(LISTS)
        }

        if (s.backupUri.isNotEmpty()) {
            wm.enqueueUniquePeriodicWork(
                BACKUP,
                ExistingPeriodicWorkPolicy.UPDATE,
                PeriodicWorkRequestBuilder<BackupWorker>(1, TimeUnit.DAYS).build()
            )
        } else {
            wm.cancelUniqueWork(BACKUP)
        }
    }

    /** Writes packetwall-backup-<date>.json into the chosen folder and keeps the last [KEEP_BACKUPS]. */
    fun backupNow(ctx: Context): Boolean {
        val app = ctx.applicationContext as PacketwallApp
        val tree = app.settings.current.backupUri.takeIf { it.isNotEmpty() }?.let(Uri::parse) ?: return false
        return try {
            val cr = ctx.contentResolver
            val dir = DocumentsContract.buildDocumentUriUsingTree(tree, DocumentsContract.getTreeDocumentId(tree))
            val name = "packetwall-backup-${SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())}.json"
            val doc = DocumentsContract.createDocument(cr, dir, "application/json", name) ?: return false
            cr.openOutputStream(doc, "wt")!!.bufferedWriter().use { it.write(app.firewall.exportJson()) }
            prune(ctx, tree)
            app.settings.update { it.copy(lastBackup = System.currentTimeMillis()) }
            true
        } catch (e: Exception) {
            Log.w("Schedules", "backup failed", e)
            false
        }
    }

    private fun prune(ctx: Context, tree: Uri) {
        val children = DocumentsContract.buildChildDocumentsUriUsingTree(tree, DocumentsContract.getTreeDocumentId(tree))
        val found = ArrayList<Pair<String, String>>() // name, id
        ctx.contentResolver.query(
            children,
            arrayOf(
                DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_DOCUMENT_ID
            ),
            null,
            null,
            null
        )?.use { c ->
            while (c.moveToNext()) {
                val n = c.getString(0) ?: continue
                if (n.startsWith("packetwall-backup-") && n.endsWith(".json")) found.add(n to c.getString(1))
            }
        }
        found.sortedByDescending { it.first }.drop(KEEP_BACKUPS).forEach { (_, id) ->
            try {
                DocumentsContract.deleteDocument(ctx.contentResolver, DocumentsContract.buildDocumentUriUsingTree(tree, id))
            } catch (
                _: Exception
            ) {}
        }
    }
}

class UpdateListsWorker(ctx: Context, p: WorkerParameters) : CoroutineWorker(ctx, p) {
    override suspend fun doWork(): Result {
        val failed = (applicationContext as PacketwallApp).firewall.updateAllNow()
        return if (failed == 0) Result.success() else Result.retry()
    }
}

class BackupWorker(ctx: Context, p: WorkerParameters) : CoroutineWorker(ctx, p) {
    override suspend fun doWork(): Result = if (Schedules.backupNow(applicationContext)) Result.success() else Result.retry()
}

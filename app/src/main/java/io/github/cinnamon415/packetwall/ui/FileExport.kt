package io.github.cinnamon415.packetwall.ui

import android.content.Context
import android.net.Uri
import android.util.Log
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.platform.LocalContext
import io.github.cinnamon415.packetwall.R
import java.io.OutputStream
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * "Save as…" through the system file picker. [launch] asks for a file name; once the user picks a
 * place, the writer runs on the IO dispatcher and a toast reports success or failure.
 */
class FileExport internal constructor(private val start: (String, (OutputStream) -> Unit) -> Unit) {
    fun launch(fileName: String, write: (OutputStream) -> Unit) = start(fileName, write)

    /** The text is produced on the IO dispatcher too, after the user picked the file. */
    fun launchText(fileName: String, text: () -> String) = launch(fileName) { out ->
        out.bufferedWriter().use { it.write(text()) }
    }
}

/** The name a document provider shows for [uri] (OpenableColumns.DISPLAY_NAME), or null. */
fun displayName(ctx: android.content.Context, uri: android.net.Uri): String? = runCatching {
    ctx.contentResolver.query(uri, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
        if (c.moveToFirst()) c.getString(0) else null
    }
}.getOrNull()

@Composable
fun rememberFileExport(mime: String, onDone: (ok: Boolean) -> Unit = {}): FileExport {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val done by rememberUpdatedState(onDone)
    // The writer waits in a process-wide map under a saveable key while the picker is open, so a
    // rotation or theme change (activity recreated) does not lose it. After process death it is
    // gone: then the user is told the export failed instead of silently nothing.
    val key = rememberSaveable { UUID.randomUUID().toString() }
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument(mime)) { uri ->
        val write = PendingWrites.take(key)
        when {
            uri == null -> {}
            write == null -> Toast.makeText(ctx, R.string.export_failed, Toast.LENGTH_SHORT).show()
            else -> scope.launch {
                val ok = writeTo(ctx, uri, write)
                Toast.makeText(ctx, if (ok) R.string.exported else R.string.export_failed, Toast.LENGTH_SHORT).show()
                done(ok)
            }
        }
    }
    return remember(launcher) {
        FileExport { name, write ->
            PendingWrites.put(key, write)
            launcher.launch(name)
        }
    }
}

private object PendingWrites {
    private val map = ConcurrentHashMap<String, (OutputStream) -> Unit>()

    fun put(key: String, w: (OutputStream) -> Unit) {
        map[key] = w
    }

    fun take(key: String) = map.remove(key)
}

/** Writes [uri] (truncating it) on the IO dispatcher. Returns false, with a log line, on failure. */
suspend fun writeTo(ctx: Context, uri: Uri, write: (OutputStream) -> Unit): Boolean = withContext(Dispatchers.IO) {
    runCatching {
        val out = ctx.contentResolver.openOutputStream(uri, "wt") ?: error("cannot open $uri")
        out.use(write)
    }.onFailure { Log.w("FileExport", "export to $uri failed", it) }.isSuccess
}

/** Keeps letters, digits, '.', '_' and '-'; everything else becomes '_'. */
fun safeFileName(name: String) = name.replace(Regex("[^A-Za-z0-9._-]+"), "_")

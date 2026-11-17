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
import androidx.compose.ui.platform.LocalContext
import io.github.cinnamon415.packetwall.R
import java.io.OutputStream
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

@Composable
fun rememberFileExport(mime: String, onDone: (ok: Boolean) -> Unit = {}): FileExport {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val done by rememberUpdatedState(onDone)
    // the writer for the picker that is open right now (lost with the process, then nothing is written)
    val pending = remember { PendingWrite() }
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument(mime)) { uri ->
        val write = pending.take()
        if (uri != null && write != null) {
            scope.launch {
                val ok = writeTo(ctx, uri, write)
                Toast.makeText(ctx, if (ok) R.string.exported else R.string.export_failed, Toast.LENGTH_SHORT).show()
                done(ok)
            }
        }
    }
    return remember(launcher) {
        FileExport { name, write ->
            pending.set(write)
            launcher.launch(name)
        }
    }
}

private class PendingWrite {
    private var write: ((OutputStream) -> Unit)? = null

    fun set(w: (OutputStream) -> Unit) {
        write = w
    }

    fun take() = write.also { write = null }
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

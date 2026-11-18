package io.github.cinnamon415.packetwall.analysis

import android.app.Service
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import io.github.cinnamon415.packetwall.Limits
import io.github.cinnamon415.packetwall.Problem
import java.io.File
import java.io.IOException
import java.util.concurrent.Executors
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.suspendCancellableCoroutine

/**
 * Parses capture files in its own process (":parser", see the manifest). A file that is huge,
 * damaged or hostile can at worst take this process down; the VPN and the UI live in the main
 * process and keep running. The result is a directory written by [CaptureFile.parse].
 */
class ParserService : Service() {
    private val worker = Executors.newSingleThreadExecutor()

    private val messenger = Messenger(
        Handler(Looper.getMainLooper()) { msg ->
            val req = Bundle(msg.data)
            val reply = msg.replyTo
            worker.execute {
                val res = Bundle()
                try {
                    val out = File(req.getString(K_OUT)!!)
                    val path = req.getString(K_PATH)
                    val input = if (path !=
                        null
                    ) {
                        File(path).inputStream()
                    } else {
                        contentResolver.openInputStream(Uri.parse(req.getString(K_URI)))
                    }
                    val s = (input ?: throw IOException("cannot open")).use { CaptureFile.parse(it, out, Limits.CAPTURE_BYTES) }
                    res.putInt(K_PACKETS, s.packets)
                } catch (e: Throwable) {
                    res.putString(K_ERROR, Problem.of(e).encode())
                }
                runCatching { reply?.send(Message.obtain().apply { data = res }) }
            }
            true
        }
    )

    override fun onBind(intent: Intent): IBinder = messenger.binder

    /** A failure reported by the parser process, or the process gone (out of memory, crash). */
    class Failed(val problem: Problem) : IOException(problem.encode())

    companion object {
        private const val K_URI = "uri"
        private const val K_PATH = "path"
        private const val K_OUT = "out"
        private const val K_PACKETS = "packets"
        private const val K_ERROR = "error"

        /** Parses a content [uri] or a file [path] into [out] in the parser process; returns the packet count. */
        suspend fun parse(ctx: Context, uri: String?, path: String?, out: File): Int = suspendCancellableCoroutine { cont ->
            val app = ctx.applicationContext
            var bound = true
            fun unbind(conn: ServiceConnection) {
                if (bound) {
                    bound = false
                    runCatching { app.unbindService(conn) }
                }
            }
            lateinit var conn: ServiceConnection
            val replies = Handler(Looper.getMainLooper()) { msg ->
                unbind(conn)
                if (cont.isActive) {
                    val err = msg.data.getString(K_ERROR)
                    if (err != null) cont.resumeWithException(Failed(Problem.decode(err))) else cont.resume(msg.data.getInt(K_PACKETS))
                }
                true
            }
            conn = object : ServiceConnection {
                override fun onServiceConnected(name: ComponentName, binder: IBinder) {
                    val req = Bundle().apply {
                        putString(K_URI, uri)
                        putString(K_PATH, path)
                        putString(K_OUT, out.path)
                    }
                    runCatching {
                        Messenger(binder).send(
                            Message.obtain().apply {
                                data = req
                                replyTo = Messenger(replies)
                            }
                        )
                    }.onFailure { gone(this) }
                }

                // the parser process died before answering: most likely out of memory
                override fun onServiceDisconnected(name: ComponentName) = gone(this)

                override fun onBindingDied(name: ComponentName) = gone(this)

                override fun onNullBinding(name: ComponentName) = gone(this)

                private fun gone(c: ServiceConnection) {
                    unbind(c)
                    if (cont.isActive) cont.resumeWithException(Failed(Problem.ParserCrashed))
                }
            }
            if (!app.bindService(Intent(app, ParserService::class.java), conn, Context.BIND_AUTO_CREATE)) {
                bound = false
                cont.resumeWithException(Failed(Problem.ParserCrashed))
            }
            cont.invokeOnCancellation { Handler(Looper.getMainLooper()).post { unbind(conn) } }
        }
    }
}

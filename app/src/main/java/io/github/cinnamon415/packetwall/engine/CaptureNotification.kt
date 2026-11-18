package io.github.cinnamon415.packetwall.engine

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import io.github.cinnamon415.packetwall.MainActivity
import io.github.cinnamon415.packetwall.R

/** The ongoing "protection is on" notification of the foreground service. */
object CaptureNotification {
    const val ID = 1
    private const val CHANNEL_ID = "status"

    fun build(ctx: Context): Notification {
        val nm = ctx.getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(CHANNEL_ID) == null) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, ctx.getString(R.string.notif_channel_status), NotificationManager.IMPORTANCE_LOW)
            )
        }
        val stop = PendingIntent.getService(
            ctx,
            1,
            Intent(ctx, CaptureService::class.java).setAction(CaptureService.ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE
        )
        val paused = CaptureStatus.paused
        val pause = PendingIntent.getService(
            ctx,
            2,
            Intent(ctx, CaptureService::class.java).setAction(if (paused) CaptureService.ACTION_RESUME else CaptureService.ACTION_PAUSE),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        return Notification.Builder(ctx, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_wall)
            .setContentTitle(ctx.getString(if (paused) R.string.notif_paused else R.string.notif_running))
            .apply { if (paused) setContentText(ctx.getString(R.string.paused_hint)) }
            .setContentIntent(openApp(ctx))
            .setOngoing(true)
            .addAction(
                Notification.Action.Builder(
                    null,
                    ctx.getString(if (paused) R.string.action_resume else R.string.action_pause),
                    pause
                ).build()
            )
            .addAction(Notification.Action.Builder(null, ctx.getString(R.string.action_stop), stop).build())
            .build()
    }

    fun openApp(ctx: Context): PendingIntent = PendingIntent.getActivity(
        ctx,
        0,
        Intent(ctx, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
        PendingIntent.FLAG_IMMUTABLE
    )
}

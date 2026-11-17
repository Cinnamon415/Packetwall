package io.github.cinnamon415.packetwall.system

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.widget.RemoteViews
import io.github.cinnamon415.packetwall.MainActivity
import io.github.cinnamon415.packetwall.PacketwallApp
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.engine.CaptureService
import io.github.cinnamon415.packetwall.engine.CaptureState
import io.github.cinnamon415.packetwall.engine.CaptureStatus

/** Home screen widget: power button + active profile (tap the name to switch to the next profile). */
class ProtectionWidget : AppWidgetProvider() {
    override fun onUpdate(ctx: Context, mgr: AppWidgetManager, ids: IntArray) = update(ctx)

    override fun onReceive(ctx: Context, intent: Intent) {
        when (intent.action) {
            ACTION_TOGGLE -> {
                if (CaptureStatus.state.value is CaptureState.Running) {
                    CaptureService.stop(ctx)
                } else if (VpnService.prepare(ctx) != null) {
                    ctx.startActivity(
                        Intent(ctx, MainActivity::class.java).setAction(MainActivity.ACTION_TOGGLE_ON)
                            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    )
                } else {
                    CaptureService.start(ctx)
                }
            }
            ACTION_NEXT_PROFILE -> {
                val fw = (ctx.applicationContext as PacketwallApp).firewall
                val st = fw.state.value
                if (st.profiles.isNotEmpty()) {
                    val i = st.profiles.indexOfFirst { it.id == st.activeProfile }
                    fw.activateProfile(st.profiles[(i + 1) % st.profiles.size].id)
                }
                update(ctx)
            }
            else -> super.onReceive(ctx, intent)
        }
    }

    companion object {
        const val ACTION_TOGGLE = "io.github.cinnamon415.packetwall.widget.TOGGLE"
        const val ACTION_NEXT_PROFILE = "io.github.cinnamon415.packetwall.widget.NEXT_PROFILE"

        fun update(ctx: Context) {
            val mgr = AppWidgetManager.getInstance(ctx)
            val ids = mgr.getAppWidgetIds(ComponentName(ctx, ProtectionWidget::class.java))
            if (ids.isEmpty()) return
            val on = CaptureStatus.state.value is CaptureState.Running
            val profile = (ctx.applicationContext as PacketwallApp).firewall.state.value.profile?.name ?: ""
            fun pi(action: String, code: Int) = PendingIntent.getBroadcast(
                ctx,
                code,
                Intent(ctx, ProtectionWidget::class.java).setAction(action),
                PendingIntent.FLAG_IMMUTABLE
            )
            val v = RemoteViews(ctx.packageName, R.layout.widget_protection).apply {
                setImageViewResource(R.id.widget_power, if (on) R.drawable.widget_power_on else R.drawable.widget_power_off)
                setTextViewText(R.id.widget_status, ctx.getString(if (on) R.string.status_on else R.string.status_off))
                setTextViewText(R.id.widget_profile, profile)
                setOnClickPendingIntent(R.id.widget_power, pi(ACTION_TOGGLE, 1))
                setOnClickPendingIntent(R.id.widget_profile, pi(ACTION_NEXT_PROFILE, 2))
                setOnClickPendingIntent(
                    R.id.widget_status,
                    PendingIntent.getActivity(
                        ctx,
                        3,
                        Intent(ctx, MainActivity::class.java),
                        PendingIntent.FLAG_IMMUTABLE
                    )
                )
            }
            mgr.updateAppWidget(ids, v)
        }
    }
}

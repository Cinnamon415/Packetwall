package io.github.cinnamon415.packetwall.system

import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.util.Log
import io.github.cinnamon415.packetwall.MainActivity
import io.github.cinnamon415.packetwall.PacketwallApp
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.engine.CaptureService
import io.github.cinnamon415.packetwall.engine.CaptureState

/** Quick settings tile: protection on/off, the active profile as subtitle. */
class ProtectionTile : TileService() {
    override fun onStartListening() = refresh()

    override fun onClick() {
        val running = CaptureService.state.value is CaptureState.Running
        if (running) {
            CaptureService.stop(this)
        } else if (VpnService.prepare(this) != null) {
            openApp(MainActivity.ACTION_TOGGLE_ON) // VPN consent needs an activity
        } else {
            try {
                CaptureService.start(this)
            } catch (e: Exception) {
                Log.w("ProtectionTile", "cannot start from the tile", e)
                openApp(MainActivity.ACTION_TOGGLE_ON)
            }
        }
        refresh(!running)
    }

    private fun openApp(action: String) {
        val i = Intent(this, MainActivity::class.java).setAction(action).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (Build.VERSION.SDK_INT >= 34) {
            startActivityAndCollapse(PendingIntent.getActivity(this, 0, i, PendingIntent.FLAG_IMMUTABLE))
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(i)
        }
    }

    private fun refresh(on: Boolean = CaptureService.state.value is CaptureState.Running) {
        val tile = qsTile ?: return
        tile.state = if (on) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = getString(R.string.app_name)
        val profile = (application as PacketwallApp).firewall.state.value.profile?.name
        tile.subtitle = if (on) profile ?: getString(R.string.status_on) else getString(R.string.status_off)
        tile.updateTile()
    }
}

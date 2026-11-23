package io.github.cinnamon415.packetwall.system

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.util.Log
import io.github.cinnamon415.packetwall.PacketwallApp
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.engine.CaptureService
import io.github.cinnamon415.packetwall.engine.CaptureState
import io.github.cinnamon415.packetwall.engine.CaptureStatus

/** Quick settings tile: protection on/off, the active profile as subtitle. */
class ProtectionTile : TileService() {
    override fun onStartListening() = refresh()

    override fun onClick() {
        // the last command, not the state: a second quick tap turns protection on again
        val running = CaptureStatus.wanted.value
        if (running) {
            CaptureService.stop(this)
        } else if (VpnService.prepare(this) != null) {
            askConsent() // the VPN consent dialog needs an activity
        } else {
            try {
                CaptureService.start(this)
            } catch (e: Exception) {
                Log.w("ProtectionTile", "cannot start from the tile", e)
                askConsent()
            }
        }
        refresh(!running)
    }

    // the Intent overload is only used below API 34, where the PendingIntent one does not exist
    @SuppressLint("StartActivityAndCollapseDeprecated")
    private fun askConsent() {
        val i = Intent(this, VpnConsentActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (Build.VERSION.SDK_INT >= 34) {
            startActivityAndCollapse(PendingIntent.getActivity(this, 0, i, PendingIntent.FLAG_IMMUTABLE))
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(i)
        }
    }

    private fun refresh(on: Boolean = CaptureStatus.state.value is CaptureState.Running) {
        val tile = qsTile ?: return
        tile.state = if (on) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = getString(R.string.app_name)
        val profile = (application as PacketwallApp).firewall.state.value.profile?.name
        tile.subtitle = if (on) profile ?: getString(R.string.status_on) else getString(R.string.status_off)
        tile.updateTile()
    }
}

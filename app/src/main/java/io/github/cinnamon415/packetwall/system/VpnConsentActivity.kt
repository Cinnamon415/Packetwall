package io.github.cinnamon415.packetwall.system

import android.net.VpnService
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import io.github.cinnamon415.packetwall.R
import io.github.cinnamon415.packetwall.engine.CaptureService

/**
 * Turns protection on from the tile or the widget when the system VPN consent dialog is needed
 * (that dialog needs an activity). Not exported: other apps cannot start or stop protection.
 */
class VpnConsentActivity : ComponentActivity() {
    private val consent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { res ->
        if (res.resultCode == RESULT_OK) {
            CaptureService.start(this)
        } else {
            Toast.makeText(this, R.string.vpn_denied, Toast.LENGTH_SHORT).show()
        }
        finish()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // after a recreation the pending consent result is delivered to the callback above
        if (savedInstanceState != null) return
        val intent = VpnService.prepare(this)
        if (intent != null) {
            consent.launch(intent)
        } else {
            CaptureService.start(this)
            finish()
        }
    }
}

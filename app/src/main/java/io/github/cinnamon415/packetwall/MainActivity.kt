package io.github.cinnamon415.packetwall

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import io.github.cinnamon415.packetwall.engine.CaptureService
import io.github.cinnamon415.packetwall.ui.AppRoot
import io.github.cinnamon415.packetwall.ui.theme.PacketwallTheme

class MainActivity : ComponentActivity() {

    private val vpnConsent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { res ->
        if (res.resultCode == RESULT_OK) {
            CaptureService.start(this)
        } else {
            Toast.makeText(this, R.string.vpn_denied, Toast.LENGTH_SHORT).show()
        }
    }

    private val notifPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notifPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }

        val app = application as PacketwallApp
        setContent {
            PacketwallTheme {
                AppRoot(app = app, onToggleProtection = ::toggleProtection)
            }
        }
        handleIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    /** The tile / widget asked to turn protection on but the VPN consent is still needed. */
    private fun handleIntent(intent: Intent?) {
        when (intent?.action) {
            ACTION_TOGGLE_ON -> {
                intent.action = null
                toggleProtection(true)
            }
            ACTION_TOGGLE_OFF -> {
                intent.action = null
                toggleProtection(false)
            }
        }
    }

    companion object {
        const val ACTION_TOGGLE_ON = "io.github.cinnamon415.packetwall.TOGGLE_ON"
        const val ACTION_TOGGLE_OFF = "io.github.cinnamon415.packetwall.TOGGLE_OFF"
    }

    private fun toggleProtection(on: Boolean) {
        if (!on) {
            CaptureService.stop(this)
            return
        }
        val consent = VpnService.prepare(this)
        if (consent != null) vpnConsent.launch(consent) else CaptureService.start(this)
    }
}

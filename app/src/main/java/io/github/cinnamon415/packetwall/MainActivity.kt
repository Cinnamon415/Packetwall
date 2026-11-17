package io.github.cinnamon415.packetwall

import android.Manifest
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
    }

    // The launcher activity is exported, so it acts on no intent extras or actions: other apps
    // must not be able to switch protection. The tile and widget use VpnConsentActivity.

    private fun toggleProtection(on: Boolean) {
        if (!on) {
            CaptureService.stop(this)
            return
        }
        val consent = VpnService.prepare(this)
        if (consent != null) vpnConsent.launch(consent) else CaptureService.start(this)
    }
}

package io.github.cinnamon415.packetwall

import android.Manifest
import android.content.pm.PackageManager
import android.graphics.Color
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
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
            val s by app.settings.values.collectAsState()
            val dark = when (s.theme) {
                THEME_LIGHT -> false
                THEME_DARK -> true
                else -> isSystemInDarkTheme()
            }
            // status and navigation bar icons follow the app's theme, not only the system's
            LaunchedEffect(dark) {
                val bars = if (dark) {
                    SystemBarStyle.dark(Color.TRANSPARENT)
                } else {
                    SystemBarStyle.light(Color.TRANSPARENT, Color.TRANSPARENT)
                }
                enableEdgeToEdge(statusBarStyle = bars, navigationBarStyle = bars)
            }
            PacketwallTheme(dark = dark) {
                AppRoot(app = app, onToggleProtection = ::toggleProtection)
            }
        }
    }

    private companion object {
        const val THEME_LIGHT = 1
        const val THEME_DARK = 2
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

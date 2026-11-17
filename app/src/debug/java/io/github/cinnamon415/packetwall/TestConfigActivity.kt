package io.github.cinnamon415.packetwall

import android.app.Activity
import android.os.Bundle
import android.util.Base64
import android.util.Log
import io.github.cinnamon415.packetwall.engine.CaptureService
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject

/**
 * Debug builds only. Applies a test configuration sent by tools/e2e:
 *   am start -n <pkg>/io.github.cinnamon415.packetwall.TestConfigActivity \
 *       --es fw <base64 export JSON> --es settings <base64 {"key": value}>
 * The firewall state replaces the current one (import with replace); settings are written and reloaded.
 */
class TestConfigActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val app = application as PacketwallApp
        try {
            intent.getStringExtra("settings")?.let { b64 ->
                val obj = Json.parseToJsonElement(String(Base64.decode(b64, Base64.DEFAULT))).jsonObject
                val ed = getSharedPreferences("settings", MODE_PRIVATE).edit().clear()
                for ((k, v) in obj) {
                    val p = v as JsonPrimitive
                    when {
                        p.booleanOrNull != null && !p.isString -> ed.putBoolean(k, p.booleanOrNull!!)
                        p.intOrNull != null && !p.isString -> ed.putInt(k, p.intOrNull!!)
                        else -> ed.putString(k, p.content)
                    }
                }
                ed.commit()
                app.settings.reload()
            }
            intent.getStringExtra("fw")?.let { b64 ->
                app.firewall.importJson(String(Base64.decode(b64, Base64.DEFAULT)), replace = true)
                app.firewall.compileNow()
            }
            Log.i("TestConfig", "applied (protection running: ${CaptureService.state.value})")
        } catch (e: Exception) {
            Log.e("TestConfig", "cannot apply", e)
        }
        finish()
    }
}

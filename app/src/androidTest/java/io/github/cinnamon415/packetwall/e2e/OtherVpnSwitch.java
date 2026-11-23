package io.github.cinnamon415.packetwall.e2e;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;

/** {@code am start -n <test pkg>/…OtherVpnSwitch --ez stop false|true}: starts or stops {@link OtherVpn} from its own package. */
public class OtherVpnSwitch extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Intent i = new Intent(this, OtherVpn.class);
        if (getIntent().getBooleanExtra("stop", false)) i.setAction(OtherVpn.STOP);
        startService(i);
        finish();
    }
}

package io.github.cinnamon415.packetwall.e2e;

import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;

/**
 * A second VPN app (the test package): establishing it makes Android revoke Packetwall's VPN, as
 * when the user turns on another VPN. It routes nothing of use (a documentation range only).
 * Java: it runs in the test package's own process, which has no Kotlin runtime.
 */
public class OtherVpn extends VpnService {
    public static final String STOP = "stop";
    private ParcelFileDescriptor fd;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && STOP.equals(intent.getAction())) {
            close();
            stopSelf();
            return START_NOT_STICKY;
        }
        // consent was granted through appops; prepare() makes this app the current VPN app
        if (fd == null && prepare(this) == null) {
            fd = new Builder().setSession("e2e other VPN").addAddress("10.111.0.1", 32).addRoute("198.51.100.0", 24).establish();
        }
        return START_NOT_STICKY;
    }

    @Override
    public void onRevoke() {
        close();
        super.onRevoke();
    }

    @Override
    public void onDestroy() {
        close();
        super.onDestroy();
    }

    private void close() {
        try {
            if (fd != null) fd.close();
        } catch (Exception ignored) {
        }
        fd = null;
    }
}

# End-to-end tests

Run on a rooted emulator (AOSP x86_64 image, `adb root` works) with the debug APK.

```
python3 tools/e2e/proxy.py > /tmp/proxy.log 2>&1 &      # SOCKS5 :1081 (+UDP), HTTP CONNECT :3128 (user/secret)
PROXY_LOG=/tmp/proxy.log python3 tools/e2e/e2e.py --apk app/build/outputs/apk/debug/app-debug.apk
python3 tools/e2e/e2e.py doh route_rule                 # only some scenarios
```

Each scenario writes `files/firewall.json` and the settings, restarts protection from adb and checks
real traffic from the emulator shell (uid 0, pseudo-app `root`). The GeoIP scenario needs the
databases downloaded once in Settings → GeoIP. Needs `capinfos` (Wireshark) on the host.

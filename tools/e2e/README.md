# End-to-end tests

Two layers:

- **Instrumented tests** (`app/src/androidTest/.../e2e`) drive the real UI on an emulator and prove each
  behaviour of `docs/E2E.md` on traffic, the log and the saved state. Every test runs in a fresh process with
  cleared data. Run them with

  ```
  tools/e2e/run-instrumented.sh                         # all (about 1.5 h)
  tools/e2e/run-instrumented.sh SettingsTest 'LogTest#search'
  python3 tools/e2e/coverage.py                         # catalog items with / without a test
  ```

  The emulator needs internet (example.org, the tracker and GeoIP downloads). `host.py` runs beside it: list
  fixtures and an `ETag` server (`/lists/…`), SOCKS5 :1081 with UDP ASSOCIATE and HTTP CONNECT :3128
  (`user`/`secret`) whose log the tests read (`/log`), and `/forward` for the USB stream test (`adb forward`).
  The emulator reaches the host at 10.0.2.2.

- **Root scenarios** (`e2e.py`, below) for what needs `su` or reboots.

## Root scenarios

Run on a rooted emulator (AOSP x86_64 image, `adb root` works) with the debug APK.

```
python3 tools/e2e/proxy.py > /tmp/proxy.log 2>&1 &      # SOCKS5 :1081 (+UDP), HTTP CONNECT :3128 (user/secret)
PROXY_LOG=/tmp/proxy.log python3 tools/e2e/e2e.py --apk app/build/outputs/apk/debug/app-debug.apk
python3 tools/e2e/e2e.py doh route_rule                 # only some scenarios
```

Each scenario writes `files/firewall.json` and the settings, restarts protection from adb and checks
real traffic from the emulator shell (uid 0, pseudo-app `root`). The GeoIP scenario needs the
databases downloaded once in Settings → GeoIP. Needs `capinfos` (Wireshark) on the host.

`proxy_app` and `proxy_app_lockdown` play the chain's local proxy app (FlClash, v2rayNG…) with a
`toybox nc` relay on 127.0.0.1:1090 that runs as the UID of an installed app (`su`). The lockdown
scenario turns on Always-on VPN + "Block connections without VPN" for Packetwall, reboots the
emulator, checks the chain, then turns them off and reboots again.

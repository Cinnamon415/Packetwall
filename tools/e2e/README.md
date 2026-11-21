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

`proxy_app` and `proxy_app_lockdown` play the chain's local proxy app (FlClash, v2rayNG…) with a
`toybox nc` relay on 127.0.0.1:1090 that runs as the UID of an installed app (`su`). The lockdown
scenario turns on Always-on VPN + "Block connections without VPN" for Packetwall, reboots the
emulator, checks the chain, then turns them off and reboots again.

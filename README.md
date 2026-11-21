# Packetwall

[![Build](https://github.com/Cinnamon415/Packetwall/actions/workflows/build.yml/badge.svg)](https://github.com/Cinnamon415/Packetwall/actions/workflows/build.yml)

Android firewall and traffic analyzer (VPN-based, no root required).

- Rules: global (domains, IPs, countries, ports) and per-app, grouped in prioritized rule sets and profiles.
- Blocklists: subscriptions in hosts / domain-list / uBlock-AdGuard formats, converted on import.
- Analysis: connection log, packets timeline, protocol tree and hex, DNS log, pcapng export.

Status: early development (milestone M0). Design notes: `docs/SPEC.md`, interactive prototype: `docs/concepts/prototype.html`.

## Build

Requirements: Android SDK (compileSdk 37), NDK 28.2.13676358, CMake 3.22.1, JDK 17+.

```
git submodule update --init --depth 1
./gradlew assembleDebug
```

Release signing reads `../Packetwall-keys/keystore.properties` (outside the repository); without it the release build is unsigned.

GitHub Actions (`.github/workflows/build.yml`) runs the unit tests and lint and builds the debug APK
on every push and pull request; the APK is attached to the run as an artifact. A signed release APK
is built too when the repository has these secrets: `SIGNING_KEYSTORE_BASE64` (the keystore,
base64), `SIGNING_STORE_PASSWORD`, `SIGNING_KEY_ALIAS`, `SIGNING_KEY_PASSWORD`.

## License

GPL-3.0-or-later. The native capture engine is adapted from [PCAPdroid](https://github.com/emanuele-f/PCAPdroid)
by Emanuele Faranda (GPL-3.0), and uses zdtun and nDPI (LGPL-3.0), zstd and libpcap.
The changes made to PCAPdroid's native code and to zdtun are listed in [docs/NATIVE_CHANGES.md](docs/NATIVE_CHANGES.md).


## Status (2026-11-16)

Firewall (rule engine, sets, profiles, blocklists, imports from PCAPdroid / NetGuard / AFWall+ /
RethinkDNS / sing-box / uBO), traffic analysis (packets, protocol tree + hex, TLS JA3/JA4, DNS / HTTP
logs, pcapng export, live pcap-over-IP, ring recording, statistics, tracker labels, GeoIP / ASN),
built-in DoH and an upstream chain (SOCKS5 with UDP, HTTP CONNECT, kill switch, per-rule routing).
See `docs/SPEC.md` for the decisions and `tools/e2e/` for the end-to-end tests.

Third-party data downloaded on request: DB-IP Lite (CC BY 4.0), AdGuard companiesdb (CC BY-SA 4.0).

## Chain with a proxy client

Packetwall keeps the VPN and forwards traffic to v2rayNG, NekoBox, Hiddify, FlClash, Clash Meta or sing-box running in proxy-only mode: see [docs/CHAIN.md](docs/CHAIN.md) (Russian).

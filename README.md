# Packetwall

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

## License

GPL-3.0-or-later. The native capture engine is adapted from [PCAPdroid](https://github.com/emanuele-f/PCAPdroid)
by Emanuele Faranda (GPL-3.0), and uses zdtun and nDPI (LGPL-3.0), zstd and libpcap.


## Status (2026-11-16)

Firewall (rule engine, sets, profiles, blocklists, imports from PCAPdroid / NetGuard / AFWall+ /
RethinkDNS / sing-box / uBO), traffic analysis (packets, protocol tree + hex, TLS JA3/JA4, DNS / HTTP
logs, pcapng export, live pcap-over-IP, ring recording, statistics, tracker labels, GeoIP / ASN),
built-in DoH and an upstream chain (SOCKS5 with UDP, HTTP CONNECT, kill switch, per-rule routing).
See `docs/SPEC.md` for the decisions and `tools/e2e/` for the end-to-end tests.

Third-party data downloaded on request: DB-IP Lite (CC BY 4.0), AdGuard companiesdb (CC BY-SA 4.0).

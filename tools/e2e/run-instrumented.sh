#!/usr/bin/env bash
# Runs the instrumented e2e tests (app/src/androidTest) against one emulator.
#   tools/e2e/run-instrumented.sh                       # everything
#   tools/e2e/run-instrumented.sh SettingsTest LogTest  # some classes
#   tools/e2e/run-instrumented.sh 'LogTest#search'      # one test
# Needs a running emulator with internet; ANDROID_SERIAL picks it (default: the first emulator-*).
# Starts tools/e2e/host.py (fixtures, test proxies, adb forward for the stream test) for the run.
set -euo pipefail
cd "$(dirname "$0")/../.."

if [ -z "${ANDROID_SERIAL:-}" ]; then
  ANDROID_SERIAL=$(adb devices | awk '/^emulator-/{print $1; exit}')
  [ -n "$ANDROID_SERIAL" ] || { echo "no emulator found (adb devices)"; exit 1; }
fi
export ANDROID_SERIAL
echo "device: $ANDROID_SERIAL"

log=$(mktemp -t pw-host.XXXXXX)
if ! curl -s -m 2 http://127.0.0.1:8099/hits >/dev/null; then
  python3 tools/e2e/host.py >"$log" 2>&1 &
  host_pid=$!
  trap 'kill $host_pid 2>/dev/null || true' EXIT
  for _ in $(seq 20); do curl -s -m 1 http://127.0.0.1:8099/hits >/dev/null && break; sleep 0.5; done
  echo "host.py running (log: $log)"
else
  echo "host.py already running"
fi

pkg=io.github.cinnamon415.packetwall.e2e
args=()
if [ $# -gt 0 ]; then
  classes=$(printf "$pkg.%s," "$@")
  args+=("-Pandroid.testInstrumentationRunnerArguments.class=${classes%,}")
fi
status=0
./gradlew -q connectedDebugAndroidTest "${args[@]}" || status=$?

python3 tools/e2e/coverage.py | head -12 || true
echo "results: app/build/outputs/androidTest-results/connected/"
exit $status

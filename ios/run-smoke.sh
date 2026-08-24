#!/usr/bin/env bash
#
# Build librats for the iOS simulator, compile ios/smoke/smoke.swift against it,
# and run it on a simulator. Verifies at runtime what a compile cannot: that the
# module map reaches the C ABI from Swift, that Swift closures survive the trip
# through the ABI's C callbacks, and that the reactor, transport and Noise
# handshake actually work under iOS.
#
# Usage: ios/run-smoke.sh [simulator-udid]
#        (default: whichever simulator is already booted, else an iPhone is booted)
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="${REPO_ROOT}/build/ios-smoke"
STAGE_DIR="${WORK_DIR}/stage"
DEPLOYMENT_TARGET="${IOS_DEPLOYMENT_TARGET:-15.0}"

CMAKE="${CMAKE:-$(command -v cmake || echo /opt/homebrew/bin/cmake)}"
if [[ ! -x "${CMAKE}" ]]; then
    echo "error: cmake not found. Install it (brew install cmake) or set CMAKE=/path/to/cmake" >&2
    exit 1
fi

# The simulator runs on the host's architecture; building only that arch keeps the
# smoke loop fast. The XCFramework build covers x86_64 as well.
HOST_ARCH="$(uname -m)"

mkdir -p "${WORK_DIR}"

echo "==> building librats for iphonesimulator (${HOST_ARCH})"
"${CMAKE}" -S "${REPO_ROOT}/ios" -B "${WORK_DIR}/build" \
    -DCMAKE_SYSTEM_NAME=iOS \
    -DCMAKE_OSX_SYSROOT=iphonesimulator \
    -DCMAKE_OSX_ARCHITECTURES="${HOST_ARCH}" \
    -DCMAKE_OSX_DEPLOYMENT_TARGET="${DEPLOYMENT_TARGET}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="${STAGE_DIR}" \
    > "${WORK_DIR}/configure.log" 2>&1 \
    || { tail -30 "${WORK_DIR}/configure.log" >&2; exit 1; }

"${CMAKE}" --build "${WORK_DIR}/build" --parallel > "${WORK_DIR}/build.log" 2>&1 \
    || { tail -40 "${WORK_DIR}/build.log" >&2; exit 1; }
"${CMAKE}" --install "${WORK_DIR}/build" > "${WORK_DIR}/install.log" 2>&1 \
    || { tail -20 "${WORK_DIR}/install.log" >&2; exit 1; }

echo "==> compiling smoke.swift"
# -I on the staged include dir is all Swift needs: clang finds module.modulemap
# there and `import LibRats` resolves to the C ABI. -lc++ because librats is a
# C++ static library and Swift does not link the C++ runtime on its own.
xcrun -sdk iphonesimulator swiftc \
    -target "${HOST_ARCH}-apple-ios${DEPLOYMENT_TARGET}-simulator" \
    -I "${STAGE_DIR}/include" \
    -L "${STAGE_DIR}/lib" -lrats -lc++ \
    "${REPO_ROOT}/ios/smoke/smoke.swift" \
    -o "${WORK_DIR}/smoke"

# Pick a simulator: the argument, else one already booted, else boot an iPhone.
UDID="${1:-$(xcrun simctl list devices booted | grep -oE '[0-9A-F-]{36}' | head -1)}"

if [[ -z "${UDID}" ]]; then
    UDID="$(xcrun simctl list devices available \
            | grep iPhone | grep -oE '[0-9A-F-]{36}' | head -1)"
    [[ -n "${UDID}" ]] || { echo "error: no iPhone simulator available" >&2; exit 1; }
    echo "==> booting ${UDID}"
    xcrun simctl boot "${UDID}"
    xcrun simctl bootstatus "${UDID}"
fi

echo "==> running on ${UDID}"
echo
# The library logs to stderr; the test's own verdict goes to stdout.
if xcrun simctl spawn "${UDID}" "${WORK_DIR}/smoke" 2>"${WORK_DIR}/librats.log"; then
    echo
    echo "librats log: ${WORK_DIR}/librats.log"
else
    status=$?
    echo
    echo "smoke test FAILED (exit ${status}); librats log:" >&2
    tail -40 "${WORK_DIR}/librats.log" >&2
    exit "${status}"
fi

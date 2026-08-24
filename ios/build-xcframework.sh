#!/usr/bin/env bash
#
# Build librats for iOS and assemble LibRats.xcframework.
#
# Produces two slices — device (arm64) and simulator (arm64 + x86_64) — because a
# single .a cannot hold both: device and simulator arm64 are distinct platforms
# to the linker even though the architecture name matches. That is exactly the
# problem an XCFramework exists to solve.
#
# Usage: ios/build-xcframework.sh [output-dir]
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-${REPO_ROOT}/build/ios}"
DEPLOYMENT_TARGET="${IOS_DEPLOYMENT_TARGET:-15.0}"

CMAKE="${CMAKE:-$(command -v cmake || echo /opt/homebrew/bin/cmake)}"
if [[ ! -x "${CMAKE}" ]]; then
    echo "error: cmake not found. Install it (brew install cmake) or set CMAKE=/path/to/cmake" >&2
    exit 1
fi

# One slice: configure, build, and install into a staging prefix.
build_slice() {
    local name="$1" sysroot="$2" archs="$3"
    local build_dir="${OUT_DIR}/build-${name}"
    local stage_dir="${OUT_DIR}/stage-${name}"

    echo "==> ${name}: ${sysroot} [${archs}]"
    "${CMAKE}" -S "${REPO_ROOT}/ios" -B "${build_dir}" \
        -DCMAKE_SYSTEM_NAME=iOS \
        -DCMAKE_OSX_SYSROOT="${sysroot}" \
        -DCMAKE_OSX_ARCHITECTURES="${archs}" \
        -DCMAKE_OSX_DEPLOYMENT_TARGET="${DEPLOYMENT_TARGET}" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="${stage_dir}" \
        > "${OUT_DIR}/configure-${name}.log" 2>&1 \
        || { echo "configure failed — see ${OUT_DIR}/configure-${name}.log" >&2; tail -30 "${OUT_DIR}/configure-${name}.log" >&2; exit 1; }

    "${CMAKE}" --build "${build_dir}" --parallel \
        > "${OUT_DIR}/build-${name}.log" 2>&1 \
        || { echo "build failed — see ${OUT_DIR}/build-${name}.log" >&2; tail -40 "${OUT_DIR}/build-${name}.log" >&2; exit 1; }

    "${CMAKE}" --install "${build_dir}" > "${OUT_DIR}/install-${name}.log" 2>&1 \
        || { echo "install failed — see ${OUT_DIR}/install-${name}.log" >&2; tail -20 "${OUT_DIR}/install-${name}.log" >&2; exit 1; }

    echo "    $(lipo -archs "${stage_dir}/lib/librats.a" 2>/dev/null || echo '?') -> ${stage_dir}"
}

mkdir -p "${OUT_DIR}"

build_slice device    iphoneos        "arm64"
build_slice simulator iphonesimulator "arm64;x86_64"

XCFRAMEWORK="${OUT_DIR}/LibRats.xcframework"
rm -rf "${XCFRAMEWORK}"

echo "==> assembling $(basename "${XCFRAMEWORK}")"
xcodebuild -create-xcframework \
    -library "${OUT_DIR}/stage-device/lib/librats.a"    -headers "${OUT_DIR}/stage-device/include" \
    -library "${OUT_DIR}/stage-simulator/lib/librats.a" -headers "${OUT_DIR}/stage-simulator/include" \
    -output "${XCFRAMEWORK}" > "${OUT_DIR}/xcframework.log" 2>&1 \
    || { echo "create-xcframework failed — see ${OUT_DIR}/xcframework.log" >&2; tail -20 "${OUT_DIR}/xcframework.log" >&2; exit 1; }

echo
echo "XCFramework: ${XCFRAMEWORK}"
echo "Swift usage: import LibRats"

#!/usr/bin/env python3
"""
Build script for librats Python bindings.

The bindings load the librats shared library (built from the C++ core plus the
C ABI in ``src/bindings/rats.cpp``) via ctypes. The recommended way to build it
is CMake with ``-DRATS_SHARED_LIBRARY=ON`` (``--build-native`` below), which
compiles the full ``LIBRARY_SOURCES`` list — including ``src/bindings/rats.cpp``
(gated by ``RATS_BINDINGS``, ON by default) — and links the platform libraries
(ws2_32/iphlpapi/bcrypt on Windows, pthread elsewhere).

``--compile-direct`` offers a CMake-free fallback that mirrors the CMake
``LIBRARY_SOURCES`` set and the version.h generation, for environments without
CMake. Both paths drop the resulting shared library next to the package so
ctypes can find it.
"""

import os
import sys
import subprocess
import argparse
import shutil
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
SRC = PROJECT_ROOT / "src"

# Mirrors the .cpp/.c translation units in CMakeLists.txt LIBRARY_SOURCES
# (headers omitted). Keep in sync with the CMake list. RATS_SEARCH_FEATURES /
# RATS_STORAGE sources are excluded (those options default OFF).
LIBRARY_SOURCES = [
    # core/
    "core/socket.cpp", "core/receive_buffer.cpp", "core/chained_send_buffer.cpp",
    "core/io_poller.cpp", "core/types.cpp",
    # util/
    "util/network_utils.cpp", "util/network_monitor.cpp", "util/os.cpp",
    "util/fs.cpp", "util/logger.cpp", "util/version.cpp",
    # wire/
    "wire/frame.cpp", "wire/message_router.cpp",
    # transport/
    "transport/connection.cpp", "transport/reactor.cpp",
    # peer/
    "peer/peer_id.cpp", "peer/peer_table.cpp", "peer/peer_book.cpp",
    # security/
    "security/noise_security.cpp",
    # node/
    "node/node.cpp", "node/identify.cpp",
    # subsystems/
    "subsystems/ping_service.cpp", "subsystems/pubsub.cpp",
    "subsystems/message_json.cpp", "subsystems/file_transfer.cpp",
    "subsystems/dht_discovery.cpp", "subsystems/mdns_discovery.cpp",
    "subsystems/reconnection.cpp", "subsystems/peer_exchange.cpp",
    "subsystems/port_mapping_service.cpp",
    # dht/ + bencode
    "dht/dht.cpp", "dht/krpc.cpp", "bittorrent/bencode.cpp",
    # mdns/
    "mdns/mdns.cpp",
    # crypto/
    "crypto/sha1.cpp", "crypto/crc32.cpp", "crypto/curve25519.c",
    "crypto/chacha.c", "crypto/poly1305.c", "crypto/chachapoly.c",
    "crypto/sha256.c", "crypto/sha512.c", "crypto/hkdf.c",
    "crypto/blake2s.c", "crypto/blake2b.c", "crypto/noise.cpp",
    # nat/
    "nat/stun.cpp", "nat/upnp.cpp", "nat/natpmp.cpp",
    # bindings/ — the C ABI these Python bindings target
    "bindings/rats.cpp",
]


def run_command(cmd, cwd=None, check=True):
    """Run a shell command."""
    print(f"Running: {cmd}")
    if isinstance(cmd, str):
        cmd = cmd.split()
    
    result = subprocess.run(cmd, cwd=cwd, capture_output=False)
    if check and result.returncode != 0:
        print(f"Command failed with exit code {result.returncode}")
        sys.exit(1)
    return result


def _shared_lib_name():
    if os.name == 'nt':
        return ['rats.dll']
    elif sys.platform == 'darwin':
        return ['librats.dylib']
    return ['librats.so']


def _copy_built_library(build_dir: Path):
    """Copy the freshly built shared library next to the Python package."""
    dest = Path(__file__).parent / "librats_py"
    candidates = []
    for name in _shared_lib_name():
        candidates += list(build_dir.rglob(name))
    if not candidates:
        print("Warning: no shared library found to copy next to the package.")
        return
    lib = candidates[0]
    shutil.copy2(lib, dest / lib.name)
    print(f"Copied {lib} -> {dest / lib.name}")


def build_native_library():
    """Build the native librats shared library via CMake.

    CMake compiles the full LIBRARY_SOURCES set (including src/bindings/rats.cpp
    via RATS_BINDINGS) and links ws2_32/iphlpapi/bcrypt on Windows / pthread
    elsewhere.
    """
    build_dir = PROJECT_ROOT / "build"

    print("Building native librats library (CMake)...")
    build_dir.mkdir(exist_ok=True)

    run_command(["cmake", "-DRATS_SHARED_LIBRARY=ON",
                 "-DRATS_BUILD_TESTS=OFF", "-DRATS_BUILD_EXAMPLES=OFF", ".."],
                cwd=build_dir)

    if os.name == 'nt':
        run_command(["cmake", "--build", ".", "--config", "Release"], cwd=build_dir)
    else:
        run_command(["cmake", "--build", ".", "-j4"], cwd=build_dir)

    _copy_built_library(build_dir)
    print("Native library built successfully")


def compile_direct():
    """CMake-free fallback: compile LIBRARY_SOURCES into a shared library.

    Generates version.h from the template, compiles every source in
    LIBRARY_SOURCES with -I src and -I <generated version dir>, and links the
    platform libraries. Mirrors the CMake build for environments without CMake.
    """
    import sysconfig  # noqa: F401  (kept for parity / future use)

    out_dir = PROJECT_ROOT / "build" / "direct"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Generate version.h from version.h.in (best-effort defaults).
    version_in = SRC / "util" / "version.h.in"
    version_out_dir = out_dir / "src" / "util"
    version_out_dir.mkdir(parents=True, exist_ok=True)
    version_h = version_out_dir / "version.h"
    if version_in.exists():
        text = version_in.read_text(encoding="utf-8")
        repl = {
            "VERSION_MAJOR": "1", "VERSION_MINOR": "0", "VERSION_PATCH": "0",
            "VERSION_BUILD": "0", "VERSION_STRING": "1.0.0.0",
            "GIT_DESCRIBE": "unknown",
        }
        for key, val in repl.items():
            text = text.replace(f"@{key}@", val)
        version_h.write_text(text, encoding="utf-8")

    includes = ["-I", str(SRC), "-I", str(SRC / "crypto"),
                "-I", str(out_dir / "src")]

    is_windows = os.name == 'nt'
    cxx = os.environ.get("CXX", "cl" if is_windows else "g++")
    cc = os.environ.get("CC", "cl" if is_windows else "gcc")

    if is_windows:
        platform_libs = ["ws2_32.lib", "iphlpapi.lib", "bcrypt.lib"]
        out_lib = out_dir / "rats.dll"
    else:
        platform_libs = ["-lpthread"]
        out_lib = out_dir / "librats.so"

    print("Direct compile is a reference fallback. On non-Windows (g++):")
    print(f"  {cxx} -shared -fPIC -std=c++17 -DRATS_EXPORT_DLL \\")
    print("    " + " ".join(includes) + " \\")
    for s in LIBRARY_SOURCES:
        print(f"    {SRC / s} \\")
    print(f"    -o {out_lib} " + " ".join(platform_libs))
    print("\n(Use --build-native / CMake for a real, supported build.)")


def install_python_package(development=True):
    """Install the Python package."""
    print("Installing Python package...")
    
    if development:
        run_command([sys.executable, "-m", "pip", "install", "-e", "."])
    else:
        run_command([sys.executable, "-m", "pip", "install", "."])
    
    print("✓ Python package installed successfully")


def run_tests():
    """Run the test suite."""
    print("Running tests...")
    
    # Install test dependencies
    run_command([sys.executable, "-m", "pip", "install", "-e", ".[dev]"])
    
    # Run tests
    run_command([sys.executable, "-m", "pytest", "librats_py/tests/", "-v"])
    
    print("✓ Tests completed")


def run_examples():
    """Test the examples."""
    print("Testing examples...")
    
    # Just import them to check for syntax errors
    examples = [
        "librats_py.examples.basic_client",
        "librats_py.examples.file_transfer", 
        "librats_py.examples.gossipsub_chat"
    ]
    
    for example in examples:
        try:
            run_command([sys.executable, "-c", f"import {example}"])
            print(f"✓ {example} imports successfully")
        except subprocess.CalledProcessError:
            print(f"✗ {example} failed to import")


def clean():
    """Clean build artifacts."""
    print("Cleaning build artifacts...")
    
    # Remove common build/cache directories
    to_remove = [
        "build",
        "dist", 
        "*.egg-info",
        "__pycache__",
        ".pytest_cache",
        ".coverage",
        "htmlcov"
    ]
    
    for pattern in to_remove:
        for path in Path(".").glob(f"**/{pattern}"):
            if path.is_dir():
                shutil.rmtree(path)
                print(f"Removed directory: {path}")
            else:
                path.unlink()
                print(f"Removed file: {path}")
    
    print("✓ Cleanup completed")


def package():
    """Create distribution packages."""
    print("Creating distribution packages...")
    
    # Install build dependencies
    run_command([sys.executable, "-m", "pip", "install", "build"])
    
    # Build packages
    run_command([sys.executable, "-m", "build"])
    
    print("✓ Distribution packages created in dist/")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Build script for librats Python bindings")
    parser.add_argument("--build-native", action="store_true",
                       help="Build the native librats library via CMake")
    parser.add_argument("--compile-direct", action="store_true",
                       help="Print a CMake-free compile recipe mirroring LIBRARY_SOURCES")
    parser.add_argument("--install", action="store_true",
                       help="Install the Python package")
    parser.add_argument("--install-release", action="store_true",
                       help="Install the Python package (non-development)")
    parser.add_argument("--test", action="store_true",
                       help="Run the test suite")
    parser.add_argument("--examples", action="store_true", 
                       help="Test examples")
    parser.add_argument("--clean", action="store_true",
                       help="Clean build artifacts")
    parser.add_argument("--package", action="store_true",
                       help="Create distribution packages")
    parser.add_argument("--all", action="store_true",
                       help="Run all build steps")
    
    args = parser.parse_args()
    
    # Change to script directory
    os.chdir(Path(__file__).parent)
    
    try:
        if args.all:
            build_native_library()
            install_python_package(development=True)
            run_tests()
            run_examples()
        else:
            if args.build_native:
                build_native_library()

            if args.compile_direct:
                compile_direct()

            if args.install:
                install_python_package(development=True)
            
            if args.install_release:
                install_python_package(development=False)
                
            if args.test:
                run_tests()
            
            if args.examples:
                run_examples()
            
            if args.clean:
                clean()
            
            if args.package:
                package()
    
    except KeyboardInterrupt:
        print("\n❌ Build interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Build failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

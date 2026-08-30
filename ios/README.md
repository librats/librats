# librats on iOS

Status: **spike**. The C++ core cross-compiles for iOS (device + simulator), and a
Swift program drives it through the C ABI — two nodes complete a Noise_XX
handshake over the loopback and echo an encrypted message, verified running on a
simulator. What is not here yet is an idiomatic Swift API, packaging, and an
answer to app backgrounding; see [Remaining work](#remaining-work).

## Why this is smaller than the Android binding

Android needs JNI: 753 lines of C++ bridge plus 758 lines of Java, because every
function and every callback has to be hand-marshalled across the JNI boundary.

Swift imports C headers directly. [`module.modulemap`](module.modulemap) declares
one header — [`librats/bindings/rats.h`](../src/librats/bindings/rats.h), the same
70-function C ABI every other binding is built on — and Swift can then call all of
it with no bridge layer at all. `rats.h` is plain C (`stddef.h`, `stdint.h`, and
the preprocessor-only `rats_export.h`), which is what makes that possible.

So the Swift wrapper that still needs writing is for *ergonomics* — optionals,
`Error`, `async`, ARC lifetime — not for mechanics. The Java class in
[`android/src/main/java/com/librats/RatsNode.java`](../android/src/main/java/com/librats/RatsNode.java)
is the reference for what that surface should cover.

## Build

```bash
ios/build-xcframework.sh          # -> build/ios/LibRats.xcframework
```

Two slices, because one static archive cannot hold both: device (`arm64`) and
simulator (`arm64` + `x86_64`). Device and simulator `arm64` are different
platforms to the linker even though the architecture name matches — which is the
problem an XCFramework exists to solve.

Then in Xcode: drop `LibRats.xcframework` into *Frameworks, Libraries, and
Embedded Content*, and `import LibRats` from Swift.

To configure a single slice by hand, see the header comment in
[`CMakeLists.txt`](CMakeLists.txt). That file follows the same rule as the Android
module — it never duplicates the source list, it just configures the root
`CMakeLists.txt` for the platform and pulls it in with `add_subdirectory`.

The library is built **static** on purpose: it links into the app binary, so there
is no embedded dylib to code-sign and no dynamic-loader cost at launch.

## Smoke test

```bash
ios/run-smoke.sh                  # optionally: ios/run-smoke.sh <simulator-udid>
```

Builds the simulator slice, compiles [`smoke/smoke.swift`](smoke/smoke.swift)
against it, and runs it on a simulator. It proves the parts a compile cannot:
that `import LibRats` resolves, that Swift closures survive conversion to the
ABI's C callbacks and fire on reactor threads, and that the reactor, transport and
handshake really run under iOS. Expected output ends in `PASS`.

## What the spike established

Everything platform-specific in the core is Darwin-generic and needed no change:
`kqueue` in [`io_poller.cpp`](../src/librats/core/io_poller.cpp) is the reactor
backend, `getifaddrs` enumerates interfaces, `sysctl`/`mach` report the host, and
there is no `fork`/`exec`/`system` anywhere. `data_dir` is caller-supplied
(defaulting to empty), which is already the right shape for the iOS sandbox — the
app passes its own Documents or Application Support path.

One real incompatibility turned up. **`<net/route.h>` ships only in the macOS
SDK.** The `PF_ROUTE` socket and its sysctl still work on iOS, but the message
declarations are not public, so two files could not compile:

- [`network_monitor.cpp`](../src/librats/util/network_monitor.cpp) used route
  messages to watch for interface and route changes. On iOS it now takes the
  polling fallback that already existed for platforms with no backend.
- [`network_utils.cpp`](../src/librats/util/network_utils.cpp) used the routing
  table to find the default gateway. On iOS it falls through to
  `append_gateway_heuristics()`, which every platform already ran as a fallback.

Both were gated to macOS with `TARGET_OS_OSX` rather than removed, so macOS keeps
the route-socket backend exactly as before.

## iOS constraints to design around

These are platform facts, not porting gaps.

**Backgrounding.** iOS suspends an app seconds after it leaves the foreground:
reactor threads freeze and sockets are torn down. A node cannot hold connections
in the background the way it can on Android with a foreground service, and there
is no sanctioned workaround — claiming an audio or VoIP background mode to keep
sockets alive is a common cause of App Store rejection. Plan for foreground-only
operation and make *resume* fast instead: `ReconnectionService` plus a persisted
`data_dir` (so the `PeerId` is stable) already covers most of it. The Swift API
needs explicit lifecycle hooks so an app can stop and restart the node cleanly.

**Discovery.** Done, and it did not need a new subsystem. `MdnsDiscovery` now
selects its backend at compile time through the `MdnsBackend` alias: raw-socket
multicast everywhere else, Bonjour (`dns_sd.h`) on Apple. The raw socket is not an
option here — since iOS 14, sending or receiving multicast directly requires
`com.apple.developer.networking.multicast`, an entitlement Apple grants only on
request — while routing through `mDNSResponder` needs no entitlement at all.

`dns_sd` turned out to be a better fit than `NWBrowser`, which was the original
plan: it is a C API in `libSystem` on both macOS and iOS, so there is no
Objective-C++, no extra framework to link, and `DNSServiceRegister` advertises the
port the node *already* listens on rather than standing up a second listener of its
own. See [`mdns_dnssd.h`](../src/librats/mdns/mdns_dnssd.h).

Two Info.plist keys are required of the consuming app, and both fail silently:
`NSBonjourServices` must list `_librats._tcp` or browsing returns nothing, and
`NSLocalNetworkUsageDescription` must be present or iOS cannot ask for the
local-network consent Bonjour depends on.

Both backends speak standard mDNS, so an iOS node and an Android one find each
other on the same Wi-Fi. `tests/test_mdns_dnssd.cpp` covers the Apple backend;
`test_mdns.cpp` remains excluded there, since the socket it drives is unused.

**NAT traversal.** UPnP and NAT-PMP are plain UDP to the gateway and need no
entitlement, but gateway detection on iOS is heuristic (see above) and on cellular
CGNAT port mapping is moot regardless. `HolePunch` and `Relay` carry more weight
on mobile. A proper fix for gateway detection is `SCDynamicStoreCopyValue` on
`State:/Network/Global/IPv4`, which is public API on iOS.

**Interoperability is free.** iOS, Android, Node.js, Python and native C++ all
compile the same core, so they share one wire format and one handshake. Two
conditions: every platform must use the same `protocol` string (default
`"librats/1.0"` — it is bound into the Noise prologue, so a mismatch is a
handshake failure, not a friendly error) and the same `Security` mode. Feature
flags may differ safely: an unknown message type is logged and dropped, and the
connection survives.

## Remaining work

- An idiomatic Swift `RatsNode` wrapper over the C ABI, at parity with the Java API.
- Packaging: a Swift Package / podspec, and a CI job building the XCFramework.
- A backgrounding story wired into the Swift lifecycle.
- `get_os_name()` in [`os.cpp`](../src/librats/util/os.cpp) reports `"macOS"` on
  iOS, and the `machdep.cpu.brand_string` sysctl does not exist on ARM. Cosmetic,
  but both want a `TARGET_OS_IPHONE` branch.
- Test coverage: the GoogleTest suite is host-only today. Running it on a
  simulator would need a test-host app bundle.

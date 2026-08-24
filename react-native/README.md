# react-native-librats

React Native bindings for librats, built on [Nitro Modules](https://nitro.margelo.com).

Status: **working on both platforms.** Core messaging and peer events, file
transfer, and pub/sub, verified running on an iOS simulator and an Android
emulator by the [example app](#example-app). Discovery (DHT, mDNS) and NAT
traversal controls are not here yet — see [Scope](#scope-of-this-slice).

## Why Nitro

Nitro can implement a HybridObject in **C++ for both platforms**, and librats is
already C++. So there is exactly one implementation —
[`cpp/HybridRatsNode.cpp`](cpp/HybridRatsNode.cpp) — shared by iOS and Android,
with no JNI bridge and no Swift wrapper to keep in sync. For comparison, the
native Android binding needs 753 lines of JNI plus 758 lines of Java to do less.

This binding calls the **C++ `Node` API directly** rather than going through the
C ABI in `src/librats/bindings/rats.h`. The C ABI exists to cross an FFI boundary
(ctypes, JNI, N-API); Nitro is a C++ consumer with no such boundary, so routing
through it would only add hex-string formatting and extra copies. The C ABI
remains the reference for *which* capabilities to expose.

## Install

```bash
npm install react-native-librats react-native-nitro-modules
cd ios && pod install
```

Requires the New Architecture and Hermes (both are the default from React Native
0.82, where the legacy bridge was removed).

The published package ships Nitro's generated sources. Working from a clone of
this repository, they are not in the tree — run `npm install` in `react-native/`
first, which installs the codegen and runs it via the `prepare` script.

## Usage

```ts
import { createNode, encodeUtf8, decodeUtf8 } from 'react-native-librats'

// Configure first, then attach listeners, then start. librats fixes config at
// construction, and it stores handlers without a lock while reactor threads read
// them -- so every on*() call has to happen before start(), which throws otherwise.
const node = createNode({
  listenPort: 8080,
  protocol: 'myapp/1.0',   // must be identical on every platform of your app
})

node.onPeerConnected((peerId) => console.log('connected', peerId))
node.onMessage('chat', (peerId, data) => {
  console.log(peerId, decodeUtf8(data))
})

node.start()
node.connect('192.168.1.42', 8080)

node.broadcast('chat', encodeUtf8('hello'))
```

`encodeUtf8` / `decodeUtf8` are exported because **Hermes has no `TextDecoder`**
(it does provide `TextEncoder`), so the symmetric pair you would reach for does
not exist on React Native and fails only at runtime, inside a message handler.

`protocol` is bound into the Noise handshake prologue, so a mismatch between your
iOS and Android builds is a **handshake failure**, not a readable error. Define it
once in shared JS and pass the same value everywhere — which is one quiet
advantage of driving both platforms from JS.

### App lifecycle

A node owns live sockets and reactor threads. iOS suspends the app shortly after
it backgrounds and tears the sockets down regardless of what you do, and Android
needs a foreground service to survive. Stop on background, start on resume:

```ts
AppState.addEventListener('change', (state) => {
  if (state === 'active') node.start()
  else node.stop()
})
```

Set `dataDir` to an app-writable path (iOS: inside the sandbox, e.g. Documents;
Android: `filesDir`) so the node keeps a stable identity across those restarts.

## Threading

librats dispatches every event on a reactor thread, never the JS thread. All
listeners here are **async Nitro callbacks**, which Nitro schedules back onto the
JS thread — so your handlers are safe, but they do not run synchronously with the
native event. Do not convert them to Nitro's `Sync<>` callbacks: those may only be
called from the JS thread, which is exactly what a reactor thread is not.

## Buffers

One copy in each direction, which is the minimum a correct implementation can do:

- **Outbound** (`send`/`broadcast`): the JS `ArrayBuffer` is passed straight to
  librats as a `ByteView`. Safe because `Node::send` copies into an owned `Bytes`
  before returning, so nothing retains the JS pointer.
- **Inbound** (`onMessage`): copied via `ArrayBuffer::copy`. The `ByteView` from
  librats points into the connection's receive buffer, which is recycled as soon
  as the handler returns, so it cannot be wrapped — the listener gets a buffer it
  owns and may keep.

Text has to be encoded somewhere, and Hermes ships `TextEncoder` but **not**
`TextDecoder`. Use the exported `encodeUtf8` / `decodeUtf8` rather than the global
pair, which fails only at runtime.

## Layout

| Path | Role |
|------|------|
| [`src/specs/RatsNode.nitro.ts`](src/specs/RatsNode.nitro.ts) | The TypeScript spec — the source of truth Nitrogen generates from |
| [`src/index.ts`](src/index.ts) | `createNode()` helper |
| [`cpp/HybridRatsNode.{hpp,cpp}`](cpp/HybridRatsNode.cpp) | The shared C++ implementation |
| [`nitro.json`](nitro.json) | Nitro config: namespaces, module names, autolinking |
| [`android/CMakeLists.txt`](android/CMakeLists.txt) | Pulls in the root librats CMake build |
| [`LibratsRN.podspec`](LibratsRN.podspec) | Consumes `ios/build-xcframework.sh` output |
| `nitrogen/generated/` | Codegen output — regenerate, never edit |

Regenerate after changing the spec:

```bash
npm run nitrogen
```

Then **re-run `pod install`** (and re-sync Gradle) before building. CocoaPods
copies the generated headers into `Pods/Headers/Public/LibratsRN/` at install
time, so a spec that adds a type — a new config struct, say — fails the iOS build
with `'YourNewType.hpp' file not found` until the pod is reinstalled. Nitrogen
prints this reminder itself; it is easy to skip and costs a full build to notice.

Neither platform wrapper duplicates librats' source list: both configure the root
`CMakeLists.txt` and pull it in, the same rule the `android/` and `ios/` modules
follow.

## File transfer

Opt-in like every librats capability — call `enableFileTransfer()` before
`start()`, on both the sending and receiving node.

**Files never cross the JS bridge.** The native side streams them by path, so a
multi-gigabyte transfer costs the JS thread nothing beyond the progress events.
That is why the API takes paths rather than `ArrayBuffer`s.

```ts
const node = createNode({ dataDir })
node.enableFileTransfer({ tempDirectory: `${cacheDir}/rats-transfers` })

// The receiver must answer every offer -- an ignored one occupies the sender
// until it times out.
node.onFileOffer((offer) => {
  if (offer.size < 100_000_000) {
    node.acceptFile(offer.peerId, offer.transferId, `${docsDir}/${offer.name}`)
  } else {
    node.rejectFile(offer.peerId, offer.transferId)
  }
})

node.onFileProgress((p) => {
  console.log(`${p.percent.toFixed(0)}% at ${p.transferRateBps / 1024} KiB/s, eta ${p.etaMs}ms`)
})

node.onFileComplete((transferId, success, path) => {
  console.log(success ? `saved to ${path}` : 'transfer failed')
})

node.start()

const transferId = node.sendFile(peerId, `${docsDir}/photo.jpg`)  // 0 = unreadable
node.pauseTransfer(peerId, transferId)
node.resumeTransfer(peerId, transferId)
node.cancelTransfer(peerId, transferId)
```

`tempDirectory` is **required**. The library default is `"."`, the process working
directory, which is not writable on either mobile platform — so the binding
rejects an empty value up front rather than letting every transfer fail later at
the first temp-file write. Use a cache path (iOS Caches, Android `cacheDir`):
it holds only in-progress downloads, which are moved to their destination once
the whole-file SHA-256 verifies.

Two things worth knowing about the data model. `transferId` is a JS `number` and
that is exact, not a rounding compromise: ids come from a counter starting at 1,
so they stay far inside the 2^53 a double represents precisely — no `bigint`
needed. And `offer.name` plus every `offer.files[].relativePath` come from the
peer, so treat them as untrusted; the library validates manifest paths against
traversal before writing, but if you build a destination path or a UI label out of
them, sanitise them yourself.

`sendDirectory()` sends a whole tree as one transfer, and `transferStats()`
returns cumulative byte and completion counters.

## Pub/sub

Real GossipSub, not floodsub: each subscribed topic keeps a bounded mesh,
published messages are pushed along it, and a lazy IHAVE/IWANT layer recovers
anything missed. Opt in with `enablePubSub()` before `start()`.

```ts
node.enablePubSub()                     // or { meshTarget, heartbeatIntervalMs, ... }

node.subscribe('rooms/general', (peerId, topic, data) => {
  console.log(topic, decodeUtf8(data))
})

node.start()
node.publish('rooms/general', encodeUtf8('hello everyone'))
```

Three behaviours that surprise people:

- **A subscribed publisher hears itself.** Publishing delivers to this node's own
  listener too, with `peerId` set to your `localId` — so a chat UI does not need
  to echo locally, but it does need to compare against `localId` if it wants to
  tell its own messages apart. A node that is not subscribed to the topic has no
  listener and sees nothing.
- **A fresh subscription is not immediately reachable.** `SUBSCRIBE` is announced
  asynchronously and mesh `GRAFT`s ride the heartbeat, so publishing right after
  subscribing reaches nobody. Wait until `meshPeers(topic)` (or at least
  `topicPeers(topic)`) contains the peer you expect — that is exactly what the
  example's pub/sub test does.
- **Delivery is best-effort and unordered**, and a message arrives once even
  though several mesh peers hold it. This is not a reliable queue.

`topic` is a global namespace shared by every node on your `protocol`, so prefix
it if collisions matter.

Unlike `onMessage` and the peer events, `subscribe`/`unsubscribe` are safe to call
**after** `start()` — `PubSub` guards its topic tables with a mutex, whereas the
core's channel router does not. Only `enablePubSub()` has to precede `start()`.

### Why there is no `setValidator`

librats lets you gate inbound messages per topic with a validator returning
accept / reject / ignore. That is deliberately **not** exposed here.

The validator's return value is consumed inline, on a reactor thread, to decide
whether to deliver *and whether to forward* the message. JS can only be touched on
the JS thread, so honouring it would mean blocking a reactor thread on the JS
thread for every inbound message — stalling every peer on that reactor, and
inviting deadlock. Nitro's `Sync<>` callbacks do not rescue this either: they may
only be called *from* the JS thread, which is precisely what a reactor thread is
not.

If you need to drop messages, do it in the `subscribe` listener. The difference is
that you cannot prevent the message being forwarded to the rest of the mesh — for
that, a validator has to live in native code.

## DHT discovery

Joins the BitTorrent Mainline DHT — a real, public, multi-million-node network —
and finds peers by announcing under a hash derived from `discoveryKey`. Opt in
with `enableDht()` before `start()`.

```ts
const node = createNode({ dataDir, protocol: 'myapp/1.0' })
node.enableDht({ discoveryKey: 'myapp-v1' })   // or {} for the node's protocol

node.onPeerConnected((peerId) => console.log('peer', peerId))
node.start()

const s = node.dhtStatus()   // { running, port, portV6, discoveryHash, externalAddress }
```

**There is no `onPeerDiscovered`.** The subsystem does not hand peers back for you
to dial — it dials them itself through the node, so discovery surfaces as ordinary
`onPeerConnected` events. The only thing separating a DHT-found peer from one you
dialled is that you never called `connect()` for it.

Expect it to be slow. Joining, announcing and searching each run on their own
interval, so the first discovery usually lands tens of seconds after `start()`.
`dhtStatus().externalAddress` is a useful progress signal: it fills in once STUN
or in-DHT voting resolves the public IP.

Unlike mDNS, this needs **no special iOS entitlement** — it is plain UDP to other
nodes rather than multicast, so nothing has to be requested from Apple.

Two configuration notes. `discoveryKey` namespaces who finds whom; leaving it
empty uses the node's `protocol`, so peers of the same app version meet and
mismatched protocols — which could not handshake anyway — never do. And `dataDir`
holds the routing table so a restart bootstraps warm; it defaults to the node's
own `dataDir`, because the library's fallback is the working directory, which is
not writable on mobile. With neither set, persistence silently does nothing and
every start is a cold bootstrap.

## Scope of this slice

Core: `configure`, `start`, `stop`, `isRunning`, `listenPort`, `localId`,
`connect`, `peerCount`, `peerIds`, `send`, `broadcast`, `onMessage`,
`onPeerConnected`, `onPeerDisconnected`.

File transfer: `enableFileTransfer`, `sendFile`, `sendDirectory`, `acceptFile`,
`rejectFile`, `pauseTransfer`, `resumeTransfer`, `cancelTransfer`,
`transferStats`, `onFileOffer`, `onFileProgress`, `onFileComplete`.

Pub/sub: `enablePubSub`, `subscribe`, `unsubscribe`, `publish`, `isSubscribed`,
`subscribedTopics`, `topicPeers`, `meshPeers`. Not `setValidator` — see above.

Discovery: `enableDht`, `dhtStatus`.

Not yet: mDNS discovery (which on iOS wants an `NWBrowser`-backed subsystem rather
than the library's raw-socket multicast, to avoid needing Apple's multicast
entitlement), NAT traversal controls, typed JSON messaging, and the storage and
BitTorrent modules.

## Example app

[`example/`](example) is a React Native app that verifies the binding on a single
device: it creates two nodes in-process, dials one from the other over the
loopback, completes a Noise handshake, and checks that a message comes back
echoed. Same check as the Swift smoke test in `ios/`, driven through JS.

```bash
# The binding itself first: nitrogen/generated/ is not in the repository, and
# both `pod install` and Gradle fail on their autolinking include without it.
# `npm install` here installs the codegen and runs it (the `prepare` script).
cd react-native
npm install

cd example
npm install
npm start -- --port 8082          # 8081 is often taken
# iOS
cd ios && pod install && cd ..
npx react-native run-ios
# Android
npx react-native run-android
```

Press **chat test** or **file test**; each log ends in `PASS`. The file test
writes a 512 KiB file, offers it from one node to the other, accepts it, and
compares the received bytes against what was sent. First `pod install` builds
`LibRats.xcframework` from the C++ core, which takes a few minutes.

The example deliberately has no safe-area library: `react-native-safe-area-context`'s
Fabric component references debug-only RN symbols that RN 0.87's *prebuilt* core
does not export, so linking the iOS app fails with a wall of undefined
`facebook::react::Sealable` / `ShadowNode::getDebugName` symbols. Explicit padding
costs nothing here and removes a whole class of build fragility.

The Android build compiles the whole librats core per ABI, so for a debug loop set
`reactNativeArchitectures` in `example/android/gradle.properties` to just the one
you need — the module honours it.

### What is verified

**Both platforms, both tests, end to end** — iOS on a simulator and Android on an
emulator (`libLibratsRN.so`, arm64-v8a, with the librats core linked in):

| | iOS simulator | Android emulator |
|---|---|---|
| Handshake, encrypted echo, disconnect event | `PASS` | `PASS` |
| 512 KiB file: offer, accept, 10 progress events, complete | `PASS` | `PASS` |
| Received bytes compared against source | identical | identical |

Also verified: Nitrogen generates from the spec; the C++ compiles clean
(`-Wall -Wextra`, zero warnings); TypeScript typechecks in both the module and
the example.

Not yet verified: **a physical device.** Everything above ran on a simulator and
an emulator, so nothing here exercises real ARM hardware, a real network
interface, or store packaging.

### Android platform notes

Two things showed up on Android that are worth knowing:

- **Network-change detection falls back to polling.** Android's SELinux policy
  denies `bind` on a `netlink_route_socket` for `untrusted_app`, so the Linux
  netlink backend in `network_monitor.cpp` cannot start. It handles that: it logs
  a warning and falls back to polling, which is why nothing breaks. You will see
  the denial as an `avc: denied { bind } ... netlink_route_socket` line in
  logcat, paired with librats' own `W/netmon: netlink bind() failed (13);
  falling back to polling` — both are expected, not a bug. (iOS lands in the same
  polling fallback for a different reason: `<net/route.h>` is macOS-only.)
- **librats' logs reach logcat through `__android_log_print`.** The logger writes
  to `std::cout`/`std::cerr` everywhere else, but an Android app's stdout goes
  nowhere by default, so an `#if defined(__ANDROID__)` branch in `util/logger.h`
  routes console output through the platform logger instead. The log module
  becomes the logcat tag and the librats level becomes the Android priority, so
  the core shows up as `I/node`, `I/socket`, `I/noise`, `W/netmon` and so on:

  ```sh
  adb logcat --pid=$(adb shell pidof com.libratsexample) node:I socket:I noise:I netmon:I '*:S'
  ```

  Timestamps and colors are left off on this path because logcat adds its own.
  The default level is still `INFO`; the file sink is unchanged.

### Things that cost a build to find

Worth knowing before you change the build files:

- **Hermes has no `TextDecoder`** (it does have `TextEncoder`), so the obvious
  symmetric pair does not exist on React Native and fails only at runtime, inside
  a message handler. That is why this package exports `encodeUtf8`/`decodeUtf8`.
- **Do not add the XCFramework's headers to `HEADER_SEARCH_PATHS`.** CocoaPods
  already adds `$(PODS_XCFRAMEWORKS_BUILD_DIR)/LibratsRN/Headers` for the slice
  being built. Naming both slices yourself puts two copies of the framework's
  `module.modulemap` in scope and clang fails with *redefinition of module
  'LibRats'*; making it SDK-conditional is worse, because
  `HEADER_SEARCH_PATHS[sdk=...]` *replaces* the unconditional value and silently
  drops every React header.
- **A Nitro module still needs a `ReactPackage` on Android.** React Native's
  autolinking scans for a class implementing `ReactPackage` and skips the
  dependency entirely when it finds none — so without
  [`LibratsRNPackage.kt`](android/src/main/java/com/librats/rn/LibratsRNPackage.kt)
  the Gradle project is never added and the module just does not exist on Android,
  with no error. That class is also where `LibratsRNOnLoad.initializeNative()`
  gets called; Nitrogen generates it but nothing invokes it for you.
- **`sendFile()` returning a non-zero id does not mean the peer exists.** It
  checks only that the file is readable, then queues an offer; sending to an id
  that is not connected fails silently and the transfer simply never progresses,
  timing out after `transferTimeoutSecs`. Watch for this with the two peer ids in
  a pair: each side's `onPeerConnected` reports *the other* node, so the id the
  dialling side learns is the listener's — passing that back to the listener's own
  `sendFile()` has it offering the file to itself. Confirm delivery with
  `onFileProgress`/`onFileComplete`, not with the return value.
- **`dhtStatus().discoveryHash` is all zeros until `start()`.** The hash is
  derived when the subsystem attaches, which happens inside `start()` — and with
  an empty `discoveryKey` the key is not even known before then, since it
  resolves to the node's protocol at attach time. (Reading it early used to
  return *uninitialised* bytes: `DhtDiscovery::hash_` was declared without an
  initialiser, so the same call gave zeros on one platform and garbage on the
  other. Fixed in `src/librats/subsystems/dht_discovery.h`; the example test is
  what surfaced it.)
- **Pin the module's Android `ndkVersion` to the app's.** With no `ndkVersion`,
  AGP builds the library against the newest NDK installed, while the APK packages
  the `libc++_shared.so` from the *app's* NDK (27.1.12297006 in the RN 0.87
  template). Build against a newer one and the library ends up needing libc++
  symbols that copy does not export — most visibly
  `__cxa_init_primary_exception`, which newer libc++ emits for the
  `std::promise`/`make_exception_ptr` path. The build succeeds and the app then
  dies at launch with `UnsatisfiedLinkError: dlopen failed: cannot locate
  symbol ...`. `android/build.gradle` now inherits `rootProject.ndkVersion`.
  Do **not** "fix" this with `c++_static`: several .so files here exchange C++
  types across boundaries (Nitro and JSI), which a per-library static libc++
  quietly breaks.
- **Resolve symlinks before walking up a path in CMake.** An example app reaches
  this package through `node_modules/react-native-librats -> ../..`, and
  `CMAKE_CURRENT_SOURCE_DIR` keeps the *linked* path — so a plain `../..` lands in
  `node_modules`, not the repository root, and `add_subdirectory()` fails with
  "does not contain a CMakeLists.txt file". `get_filename_component(... REALPATH)`
  fixes it. The same applies to any npm or yarn workspace.
- **CocoaPods skips `prepare_command` for local path pods**, which is what a
  linked module in an example app is. The example's `Podfile` builds the
  XCFramework itself for that reason.
- The codegen package is **`nitrogen`**; the older `nitro-codegen` is deprecated.

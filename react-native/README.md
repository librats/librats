# react-native-librats

React Native bindings for librats, built on [Nitro Modules](https://nitro.margelo.com).

Status: **working on both platforms** for core messaging, peer events, file
transfer and pub/sub, which the [example app](#example-app) has run on an iOS
simulator and an Android emulator. The rest of the surface — live messages, path
statistics, peer info, discovery, NAT traversal, JSON messaging, ping and
reconnection — is compiled against the generated Nitro headers but has not yet
been run on a device; see [What is verified](#what-is-verified).

## Why Nitro

Nitro can implement a HybridObject in **C++ for both platforms**, and librats is
already C++. So there is exactly one implementation —
[`cpp/HybridRatsNode.cpp`](cpp/HybridRatsNode.cpp) — shared by iOS and Android,
with no JNI bridge and no Swift wrapper to keep in sync. (The native Android
binding needs a JNI layer plus a Java class to do the same.)

This binding calls the **C++ `Node` API directly** rather than going through the
C ABI in `src/librats/bindings/rats.h`. The C ABI exists to cross an FFI boundary
(ctypes, JNI, N-API); Nitro is a C++ consumer with no such boundary, so routing
through it would only add hex-string formatting and extra copies. The C ABI
remains the reference for *which* capabilities to expose, and the two cover the
same ground apart from BitTorrent, which is not exposed here.

## Install

The package is not on npm yet; install it from a checkout of this repository:

```bash
# in react-native/: installs the Nitro codegen and runs it (the `prepare` script)
npm install

# in your app
npm install <path-to-librats>/react-native react-native-nitro-modules
cd ios && pod install
```

Requires the New Architecture and Hermes (both are the default from React Native
0.82, where the legacy bridge was removed).

Nitro's generated sources are not in the tree, which is why the `npm install`
inside `react-native/` has to come first.

## Usage

```ts
import { createNode, encodeUtf8, decodeUtf8 } from 'react-native-librats'

// Configure first, then enable subsystems and attach listeners, then start.
// librats fixes config at construction, and it keeps listeners and subsystems in
// tables reactor threads read without a lock -- so those calls throw after start().
const node = createNode({
  listenPort: 8080,
  protocol: 'myapp/1.0',   // must be identical on every platform of your app
})

node.onPeerConnected((peerId) => console.log('connected', peerId))
node.onPeerDisconnected((peerId, reason) => console.log('gone', peerId, reason))
node.onMessage('chat', (peerId, data) => {
  console.log(peerId, decodeUtf8(data))
})

node.start()
node.connect('192.168.1.42', 8080)

node.broadcast('chat', encodeUtf8('hello'))
```

Every other `RatsConfig` field is optional and mirrors `librats::NodeConfig`:
transports and which one a dial tries first (UDP by default, TCP raced after
`transportFallbackMs`), `dialOnly`, `maxPeers`, `security`, the send-queue limit,
the UDP congestion controller and windows, and so on — the spec documents each.

`reason` in `onPeerDisconnected` is worth branching on. `'slow_consumer'` means
this node kept sending while the peer's queue was full: `send()` returning false
(or `peerWritable()`) was the warning, and `onPeerWritable` says when to resume.
Redialing without slowing down just repeats it.

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

## Live messages and path statistics

A message sent with a lifetime is *live*: worth delivering only within that many
milliseconds. It is repaired while it can still arrive in time and dropped whole
once it cannot, and it is ordered with nothing — number your frames if order
matters. The receiver's `onMessage` gets it like any other.

```ts
node.send(peerId, 'video', frame, 150)     // at most 30000 ms, at most 4 MiB
```

For a sender that sizes itself to the path, `pathStats(peerId)` returns what the
transport currently knows: the congestion controller's `bandwidthBps`, round
trips, loss, `queuedBytes`, and how many live messages expired. Sampling runs
only when asked for — set `pathSampleMs`, or register `onPeerPath` (which then
samples every 100 ms and sends each sample across to the JS thread, so prefer the
getter when you only need the figures now and then).

## Discovery and NAT traversal

All opt-in, before `start()`:

| Call | What it does |
|------|--------------|
| `enableDht({ port?, discoveryKey? })` | Finds peers through the mainline DHT; the key defaults to `protocol`. |
| `enableMdns()` | Finds peers on the local network. On iOS 14+ raw multicast needs the `com.apple.developer.networking.multicast` entitlement. |
| `enablePeerExchange()` | Connected peers trade addresses, so one contact is enough. |
| `enablePortMapping({ upnp?, natpmp? })` | Asks the router to forward the listen port. Moot on cellular CGNAT. |
| `enableHolePunch(serveRendezvous?)` | UDP hole punching through a peer both sides share; `punchPeer(id)` starts one. |
| `enableRelay(serve?)` | Reaches a peer nothing else can, through a node both ends hold; `connectViaRelay(id)` starts one. Leave `serve` off on a phone — it carries other peers' traffic. |

`natMapping` reports what the mesh has shown about this node's NAT;
`'endpoint_dependent'` (symmetric) means punching cannot work from here.
`peerInfo(id).transport` is `'relay'` for a relayed peer.

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

node.onFileComplete((transferId, peerId, success, path) => {
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

## JSON messaging

`enableJson()` adds typed messages carrying a JSON document. JSON crosses the
bridge as text, so stringify and parse on the JS side:

```ts
node.enableJson()
node.onJson('presence', (peerId, json) => console.log(peerId, JSON.parse(json)))
node.start()
node.sendJson(peerId, 'presence', JSON.stringify({ status: 'away' }))
```

`onJson`, `onceJson` and `offJson` are safe on a running node; invalid JSON in
`sendJson`/`broadcastJson` throws.

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

## Scope

Core: `configure`, `start`, `stop`, `isRunning`, `listenPort`, `localId`,
`protocol`, `transports`, `natMapping`, `observedAddresses`, `connect`,
`disconnect`, `peerCount`, `peerIds`, `peerInfo`, `maxPeers`, `send`,
`broadcast`, `peerWritable`, `pathStats`, `onMessage`, `onPeerConnected`,
`onPeerDisconnected`, `onDialFailed`, `onPeerWritable`, `onPeerPath`.

Discovery and NAT traversal: `enableDht`, `enableMdns`, `enablePeerExchange`,
`enablePortMapping`, `enableHolePunch`, `punchPeer`, `enableRelay`,
`connectViaRelay`.

File transfer: `enableFileTransfer`, `sendFile`, `sendDirectory`, `acceptFile`,
`rejectFile`, `pauseTransfer`, `resumeTransfer`, `cancelTransfer`,
`transferStats`, `onFileOffer`, `onFileProgress`, `onFileComplete`.

Pub/sub: `enablePubSub`, `subscribe`, `unsubscribe`, `publish`, `isSubscribed`,
`subscribedTopics`, `topicPeers`, `meshPeers`. Not `setValidator` — see above.

JSON messaging: `enableJson`, `onJson`, `onceJson`, `offJson`, `sendJson`,
`broadcastJson`. Ping and reconnection: `enablePing`, `peerRttMs`,
`enableReconnect`, `addReconnect`, `removeReconnect`.

Not here: the storage and BitTorrent modules.

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

Press **chat test**, **file test** or **pubsub test**; each log ends in `PASS`. The file test
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

**Both platforms, end to end** — iOS on a simulator and Android on an emulator
(`libLibratsRN.so`, arm64-v8a, with the librats core linked in). These runs
predate the current API surface:

| | iOS simulator | Android emulator |
|---|---|---|
| Handshake, encrypted echo, disconnect event | `PASS` | `PASS` |
| 512 KiB file: offer, accept, 10 progress events, complete | `PASS` | `PASS` |
| Received bytes compared against source | identical | identical |

Since then the binding grew live messages, path statistics, peer info,
discovery, NAT traversal, JSON messaging, ping and reconnection. For that version:
Nitrogen 0.37 generates from the spec, and the C++ compiles against the generated
headers with no warnings under `-Wall -Wextra` (checked on a desktop host, not
with the NDK or Xcode); the module and the example typecheck with `tsc`. It has
not been rebuilt for or run on either platform.

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

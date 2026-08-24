# react-native-librats

React Native bindings for librats, built on [Nitro Modules](https://nitro.margelo.com).

Status: **working on both platforms.** Messaging, file transfer, pub/sub, DHT and
mDNS discovery, NAT traversal, typed JSON messaging, peer exchange, distributed
storage and BitTorrent are all bound, and verified by the
[example app](#example-app) on an iOS simulator and on two physical Android
devices. Only spider mode is deliberately left out — see
[Scope](#scope-of-this-slice).

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

Unlike `enableMdns()`, this needs nothing declared and asks the user for no
permission — it is plain UDP to other nodes, not multicast.

Two configuration notes. `discoveryKey` namespaces who finds whom; leaving it
empty uses the node's `protocol`, so peers of the same app version meet and
mismatched protocols — which could not handshake anyway — never do. And `dataDir`
holds the routing table so a restart bootstraps warm; it defaults to the node's
own `dataDir`, because the library's fallback is the working directory, which is
not writable on mobile. With neither set, persistence silently does nothing and
every start is a cold bootstrap.

## mDNS discovery

For peers on the same Wi-Fi. The node advertises `_librats._tcp` with its listen
port, browses for the same type, and dials what it finds — no key to agree on, no
bootstrap node, and no internet connection at all.

```ts
node.enableMdns()                              // before start()
node.enableMdns({ instanceName: 'kitchen' })   // default: rats-<peer id prefix>
```

Like the DHT it dials for you, so discovery arrives as `onPeerConnected`. Unlike
the DHT it is quick — a peer on the same network usually appears in a second or
two, which makes it by far the easiest way to get two devices talking.

**Each platform needs one declaration, and both fail silently.** A missing
declaration is indistinguishable from an empty network: no error, no peers.

*iOS* needs two Info.plist keys in the consuming app:

```xml
<key>NSLocalNetworkUsageDescription</key>
<string>Finds other devices running this app on your network.</string>
<key>NSBonjourServices</key>
<array><string>_librats._tcp</string></array>
```

Without `NSBonjourServices` listing the type, browsing returns nothing; without the
usage description iOS cannot show the local-network prompt, so consent is denied by
default. The first `start()` triggers that prompt — and the user can refuse it.

*Android* needs `CHANGE_WIFI_MULTICAST_STATE`, which **this package's manifest
already merges into your app**, so there is nothing to add. What it does not do is
hold a `WifiManager.MulticastLock`. The Wi-Fi stack is documented to filter
multicast frames not addressed to the device, though in practice most modern
hardware delivers them anyway while awake. If discovery works with the screen on
and stops when the device dozes, that filtering is the reason, and the app needs to
take the lock — the permission to do so is already declared.

Under the hood the two platforms use different backends, because iOS 14 gates
direct multicast behind an entitlement Apple grants only on request: Apple
platforms go through Bonjour (`mDNSResponder`), everything else uses a multicast
socket directly. Both speak standard mDNS, so an iPhone and an Android phone
discover each other normally — the split is invisible on the wire and in this API.

Three things will defeat it regardless of setup: a device on cellular only (no
local network to discover on), Wi-Fi client isolation on guest networks, and VPNs
that capture all traffic.

## NAT traversal

Three mechanisms, in order of preference, plus one read-only signal that tells you
which of them can work.

```ts
node.enablePortMapping()                 // ask the router to forward the port
node.enableHolePunch()                   // both sides dial at the same instant
node.enableRelay({ serve: false })       // carry the stream through a third node
node.start()

node.natStatus()          // { mapping, observationCount, externalEndpoints }
node.portMappingStatus()  // { externalIp, externalTcpPort, externalUdpPort }
node.punch(peerId)            // false = attempt could not even start
node.connectViaRelay(peerId)  // false = no usable relay known
```

**Start with `natStatus().mapping`** when a cross-network dial fails. It needs no
subsystem — the node collects it from the identify exchange for free — and it
answers the only question that matters:

| `mapping` | Meaning |
|---|---|
| `unknown` | Fewer than two independent UDP observations yet. Not a failure. |
| `open` | No NAT in the path; an ordinary dial already reaches you. |
| `endpointIndependent` | One external port for every destination — **punchable**. |
| `endpointDependent` | A fresh mapping per destination (symmetric) — **a punch cannot work**; relay is the only way through. |

That last row is the one with budget attached. A punch is free; a relay needs a
node that is actually reachable, which in practice means **a server you run**. So
whether your users land on `endpointDependent` decides whether this is
peer-to-peer software or peer-to-peer software plus infrastructure — and on mobile
carrier networks, `endpointDependent` is common. Measure it on real networks
before committing to a design.

`punch()` and `connectViaRelay()` are non-blocking and their return value only
says whether an attempt could be *started* — success arrives as `onPeerConnected`.
`punch()` returns false with no peer in common to carry the rendezvous, or while a
target is in cooldown after earlier failures.

`serve: false` is the default on `enableRelay` and the right answer on mobile:
carrying other peers' traffic costs bandwidth and battery, and a phone is rarely
reachable enough to be useful as a relay anyway.

Port mapping maps TCP and UDP independently, because a router may grant one and
refuse the other — hence two separate ports in `portMappingStatus()`. Behind
carrier-grade NAT it will simply never succeed: there is no router of yours to ask.

## Typed JSON messaging

A named-type message bus carrying JSON, separate from the raw channels of
`send`/`onMessage` — it rides `MessageType::Typed` with its own `[type][payload]`
framing.

```ts
node.enableJsonMessaging()

node.onJson('chat', (peerId, json) => {
  const { text } = JSON.parse(json)
})

node.start()
node.sendJson(peerId, 'chat', JSON.stringify({ text: 'hi' }))
```

**Use this for interoperability, not ergonomics.** Its reason to exist is talking
to non-RN peers that already use librats' `MessageJson` — a C++, Java or Python
node. If you control both ends, **raw channels are the cheaper choice**:
`send`/`onMessage` already give you named routing and the authenticated peer id,
and you would be calling `JSON.stringify` either way. This path additionally
parses your string into the library's JSON type and re-serialises it for the wire,
so it does strictly more work than passing the bytes yourself.

JSON crosses the boundary as a **string**, not an object. That keeps the contract
unambiguous and lets Hermes' native `JSON.parse`/`stringify` do the work, rather
than a bespoke object bridge with its own edge cases around nested arrays and
number precision.

Three behaviours that differ from the rest of this API:

- **`onJson` is additive.** Several handlers can coexist for one type and all fire
  in registration order — unlike `onMessage` and `subscribe`, where registering
  again replaces. `offJson(type)` removes them all.
- **`peerId` cannot be spoofed.** It is the authenticated id from the handshake,
  not a field inside the payload.
- **Invalid JSON throws** at the call rather than failing silently later, and
  `sendJson`/`broadcastJson` return false for "peer not connected" / "no peers".
  Those booleans are accurate, not optimistic: the library's callback runs inline
  before the call returns.

## Keepalive and reconnection

Two small subsystems that matter far more on a phone than on a desktop.

```ts
node.enablePing({ intervalMs: 10000 })
node.enableReconnection()          // peer book persists under dataDir by default
node.start()

node.peerRtt(peerId)               // ms, or -1 if no probe has returned
node.alivePeerCount()              // peers that actually answered
node.addReconnectTarget(`${host}:${port}`)
node.knownPeers(16)                // best-known peers from the book
```

**Ping is not about latency numbers.** A peer behind NAT can vanish without either
side's socket noticing, and a connection that looks fine is the worst kind of broken.
`alivePeerCount()` is the honest count; `peerCount` is only the number of sockets that
have not yet been told they are dead. `peerRtt()` returns **-1** when nothing has come
back yet — which is also what an unreachable peer looks like, since the probe that
would have measured it never returned.

**Reconnection is what makes a mobile peer stay connected at all.** Networks change,
radios sleep, NAT bindings expire; without it every drop needs the app to notice and
re-dial. It reconciles targets against the peers actually connected each tick, so a
peer that came back on an *inbound* link is left alone instead of dialled again. The
peer book defaults to `<dataDir>/peers.json` — the library's own default is
memory-only, which on a phone means forgetting every peer on every restart, so the
binding co-locates it with the node's state instead.

## BitTorrent

A real BitTorrent client — magnets, `.torrent` files, trackers, peer exchange, and
the Mainline DHT. Opt in with `enableBittorrent()` before `start()`.

```ts
const node = createNode({ dataDir, protocol: 'myapp/1.0' })
node.enableDht()                                   // first, so the two share one DHT
node.enableBittorrent({ downloadPath: `${dataDir}/torrents` })
node.start()

const hash = node.addMagnet('magnet:?xt=urn:btih:...')
const s = node.torrentStatus(hash)   // { exists, name, hasMetadata, progress, ... }
```

**It is not part of the node's mesh.** This is the one subsystem that brings its own
transport: `bittorrent::Client` runs its own reactor and listener and speaks the swarm
protocol. No torrent peer appears in `peerIds`, `onPeerConnected`, or any channel —
the two peer sets are entirely separate. What they share is the DHT: with
`enableDht()` also attached the client borrows that same Kademlia node instead of
standing up a second one, so there is one routing table for both. `enableDht()` must
come first for that to happen; `bittorrentStats().usingNodeDht` tells you whether it
did. Without a DHT it still runs, on trackers and peer exchange alone.

**Progress is polled, not pushed.** There is no `onTorrentProgress`, because the
underlying client exposes state rather than events. Poll `torrentStatus()` while a
download is live — once a second is plenty. A magnet also starts with no metadata: the
info dict is fetched from peers first (BEP 9), so `hasMetadata` is false for a moment
and the name, size and file list arrive with it.

`addMagnet()` resumes rather than restarts. It reads any resume file saved beside the
destination, so re-adding a torrent after a restart continues from the pieces already
on disk — and skips the metadata fetch entirely when the resume file carries the info
dict. Call `saveResumeData()` or `saveAllResumeData()` before backgrounding to make
that work.

To show a torrent before committing to the download, `fetchTorrentMetadata()` adds a
temporary metadata-only torrent, waits for the info dict, and removes it again —
giving you the name, total size and file list for an info hash alone.

**Build cost.** This is the only subsystem here with a size penalty worth stating:
it is compiled out unless the native build defines `RATS_SEARCH_FEATURES`, which this
package forces on for both platforms, and enabling it added **17 MB** to the Android
arm64 debug library (54 → 71 MB, unstripped). A release build pays a smaller but real
share of that. If the feature is not worth it to you, drop the
`set(RATS_SEARCH_FEATURES ON ...)` line from `android/CMakeLists.txt` and
`../ios/CMakeLists.txt` together with the BitTorrent methods in the spec.

Spider mode — the DHT-wide infohash crawler the C++ subsystem exposes for
rats-search — is deliberately not bound. It is a search-engine feature rather than an
app one, and it crawls continuously, which is not something a phone should be doing.

## Scope of this slice

Core: `configure`, `start`, `stop`, `isRunning`, `listenPort`, `localId`,
`connect`, `peerCount`, `peerIds`, `send`, `broadcast`, `onMessage`,
`onPeerConnected`, `onPeerDisconnected`.

File transfer: `enableFileTransfer`, `sendFile`, `sendDirectory`, `acceptFile`,
`rejectFile`, `pauseTransfer`, `resumeTransfer`, `cancelTransfer`,
`transferStats`, `onFileOffer`, `onFileProgress`, `onFileComplete`.

Pub/sub: `enablePubSub`, `subscribe`, `unsubscribe`, `publish`, `isSubscribed`,
`subscribedTopics`, `topicPeers`, `meshPeers`. Not `setValidator` — see above.

Discovery: `enableDht`, `dhtStatus`, `enableMdns`.

NAT traversal: `natStatus`, `enablePortMapping`, `portMappingStatus`,
`enableHolePunch`, `punch`, `enableRelay`, `connectViaRelay`.

Typed JSON: `enableJsonMessaging`, `sendJson`, `broadcastJson`, `onJson`,
`onceJson`, `offJson`.

Peer exchange: `enablePeerExchange`.

Keepalive / reconnection: `enablePing`, `peerRtt`, `alivePeerCount`,
`enableReconnection`, `addReconnectTarget`, `removeReconnectTarget`,
`reconnectTargetCount`, `knownPeers`.

BitTorrent: `enableBittorrent`, `addMagnet`, `addTorrentFile`, `removeTorrent`,
`pauseTorrent`, `resumeTorrent`, `torrentStatus`, `torrentInfoHashes`,
`bittorrentStats`, `saveResumeData`, `saveAllResumeData`, `fetchTorrentMetadata`.
Not spider mode — see above.

Storage: `enableStorage`, `putString`, `putInt`, `putDouble`, `putBinary`,
`putJson`, `getString`, `getInt`, `getDouble`, `getBinary`, `getJson`,
`getValueType`, `removeKey`, `hasKey`, `storageKeys`, `storageKeysWithPrefix`,
`storageCount`, `clearStorage`, `saveStorage`, `loadStorage`, `compactStorage`,
`requestStorageSync`, `isStorageSynced`, `storageStats`, `onStorageChange`.

Nothing is left unbound now except spider mode. Checked against the source tree
rather than from memory: `dht_service`, `hole_punch_service` and `relay_service` are
internal interfaces, not subsystems you attach.

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

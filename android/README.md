# librats for Android

Java bindings for [librats](../README.md): `com.librats.RatsNode` over a JNI
bridge (`src/main/cpp/librats_jni.cpp`) to the library's C API
(`src/librats/bindings/rats.h`). Setup and building are in
[INTEGRATION.md](INTEGRATION.md).

## The model

A `RatsNode` is one node. Bare, it is encrypted transport (Noise XX over UDP or
TCP, both on the same port), a self-certifying peer id, dialing, and messages on
named channels. Everything else is opt-in: discovery (DHT, mDNS, peer exchange),
NAT traversal (port mapping, hole punching, relaying), pub/sub, JSON messaging,
file transfer, ping and reconnection each have an `enable*` method.

- **Enable subsystems and register the node's callbacks before `start()`.**
  Afterwards both throw `RatsException` with `ErrorCode.ALREADY_STARTED`; using a
  subsystem that was never enabled throws with `ErrorCode.NOT_ENABLED`.
- **Callbacks run on a reactor thread.** Keep them short, never block in them,
  and hop to the UI thread (`runOnUiThread`) before touching views. Never close
  the node from inside one of its callbacks.
- **Close the node.** `RatsNode` is `AutoCloseable`; `close()` stops it and
  frees it, along with the callbacks it holds.

Failures throw `RatsException`, whose `errorCode()` is the C API's error code.
Peer ids are 64-character lowercase hex strings.

## Quick start

```java
RatsNode node = new RatsNode(new RatsNode.Config()
        .listenPort(8080)
        .dataDir(getFilesDir().getAbsolutePath()));   // same identity across restarts

node.onPeerConnected(peerId -> Log.d(TAG, "+ " + peerId));
node.onPeerDisconnected((peerId, reason) -> Log.d(TAG, "- " + peerId + " " + reason));
node.on("chat", (peerId, data) ->
        Log.d(TAG, peerId + ": " + new String(data, StandardCharsets.UTF_8)));
node.enableMdns();

node.start();
node.connect("192.168.1.100", 8080);
node.broadcast("chat", "Hello!".getBytes(StandardCharsets.UTF_8));
// ...
node.close();
```

mDNS needs one more thing on a real device: most of them drop Wi-Fi multicast
unless the app holds a `WifiManager.MulticastLock` (the library's manifest
already requests the permission for it). The [example app](examples/) shows how.

## Configuration

`RatsNode.Config` mirrors `rats_config_t`. Setters chain; anything unset is the
library default.

| Setter | Default | |
|---|---|---|
| `protocol(String)` | `"librats/1.0"` | app id bound into the handshake; peers with a different one cannot connect |
| `dataDir(String)` | none | where the identity, DHT routing table and reconnect list live; without it, a new identity every run |
| `security(Security)` | `NOISE` | `PLAINTEXT` turns encryption off |
| `listenPort(int)` | `0` | shared by both transports; 0 is ephemeral |
| `bindAddress(String)` | `"::"` | dual-stack, every interface |
| `dialOnly(boolean)` | `false` | no listener |
| `maxPeers(int)` | `0` | cap on established peers, enforced on inbound; 0 is unlimited |
| `transports(Transport...)` | both | which of `UDP`, `TCP` to run |
| `preferredTransport(Transport)` | `UDP` | tried first by a dial |
| `transportFallbackMs(int)` | 1200 | how long the preferred transport dials alone before the other is raced; `Config.FALLBACK_NEVER` never races it |
| `sendQueueLimit(long)` | 8 MiB | bytes a peer's queue may hold before a sender that keeps going has it dropped; `peerWritable` turns false at a quarter of it |
| `pathSampleMs(int)` | `0` | path sampling interval for `pathStats`; 0 samples only while an `onPeerPath` callback is registered, every 100 ms |
| `congestionControl(Congestion)` | `BBR` | or `RENO`; UDP only |
| `udpReceiveWindow(long)` | 16 MiB | ceiling of one UDP connection's flow-control window |
| `udpReceiveBudget(long)` | 64 MiB | out-of-order bytes all UDP connections together may hold |
| `udpOffload(boolean)` | `true` | kernel segmentation offload for UDP where available |
| `reactorThreads(int)` | 1 | I/O threads |
| `networkMonitor(boolean)` | `true` | react to interface and address changes (one mostly idle thread) |

An impossible combination — `preferredTransport(TCP)` with only `UDP` running,
say — makes the constructor throw.

## Peers and messages

```java
node.connect(host, port);                  // success: onPeerConnected, failure: onDialFailed
node.disconnect(peerId);
String[] ids = node.peerIds();
PeerInfo info = node.peerInfo(peerId);     // transport(), direction(), address(), transports(); null if gone

node.send(peerId, "chat", bytes);          // reliable, in order
node.broadcast("chat", bytes);
node.send(peerId, "video", frame, 150);    // live: delivered within 150 ms or dropped whole
```

A message with a lifetime is *live*: it is repaired while it can still arrive in
time and dropped whole once it cannot, never arrives partly or twice, and is
ordered with nothing. It is meant for audio and video frames; the lifetime is at
most `RatsNode.LIVE_MAX_LIFETIME_MS` (30 s) and the payload at most
`RatsNode.LIVE_MAX_PAYLOAD` (4 MiB). The receiver needs nothing special.

`send` returning means the message was queued, not delivered. If you send in
bulk, check `peerWritable(peerId)` after each send; when it says false, stop
until `onPeerWritable` fires. A sender that keeps going loses the peer with
`CloseReason.SLOW_CONSUMER`.

`pathStats(peerId)` (or the `onPeerPath` callback) reports what the transport
knows about the path: bandwidth estimate, pacing rate, round trip, queued and
in-flight bytes, loss, and how many live messages expired — what a live encoder
sizes its bitrate by.

### Callbacks

All are functional interfaces. The node-level ones must be registered before
`start()`; several may coexist.

| Register with | Interface |
|---|---|
| `on(channel, …)` | `MessageCallback.onMessage(String peerId, byte[] data)` |
| `onPeerConnected` / `onPeerWritable` | `PeerCallback.onPeer(String peerId)` |
| `onPeerDisconnected` | `PeerDisconnectCallback.onPeerDisconnected(String peerId, CloseReason reason)` |
| `onDialFailed` | `DialFailedCallback.onDialFailed(String address)` — numeric addresses only |
| `onPeerPath` | `PathCallback.onPeerPath(String peerId, PathStats stats)` |

## Subsystems

Enable each before `start()`.

| Subsystem | Enable | Then |
|---|---|---|
| DHT discovery | `enableDht()`, `enableDht(port, discoveryKey)` | — |
| mDNS discovery | `enableMdns()` | — |
| Peer exchange | `enablePeerExchange()` | — |
| Port mapping | `enablePortMapping()`, `enablePortMapping(upnp, natpmp)` | — |
| Hole punching | `enableHolePunch()`, `enableHolePunch(serveRendezvous)` | `punchPeer(peerId)`, `natMapping()` |
| Relaying | `enableRelay()`, `enableRelay(serve)` | `connectViaRelay(peerId)` |
| Pub/sub | `enablePubsub()` | `subscribe`, `unsubscribe`, `publish` |
| JSON messaging | `enableJson()` | `onJson`, `onceJson`, `offJson`, `sendJson`, `broadcastJson` |
| File transfer | `enableFileTransfer(tempDir)` | `onFileOffer`, `onFileProgress`, `onFileComplete`, `sendFile`, `sendDirectory`, `acceptFile`, `rejectFile`, `cancelFile`, `pauseFile`, `resumeFile` |
| Ping | `enablePing()` | `peerRttMs(peerId)` |
| Reconnection | `enableReconnect()` | `addReconnect`, `removeReconnect` |

### NAT traversal

```java
node.enablePortMapping();     // UPnP IGD + NAT-PMP
node.enableHolePunch();       // punch, and pass other peers' rendezvous along
node.enableRelay();           // the last resort
node.start();

node.punchPeer(peerId);       // success arrives as onPeerConnected
if (node.natMapping() == NatMapping.ENDPOINT_DEPENDENT) {
    // symmetric NAT: punching cannot work from here, a relay still can
}
```

A punch needs a peer both sides are connected to, with hole punching enabled, to
pass the rendezvous along. A relay carries the connection itself through such a
peer; it stays encrypted end to end, and `peerInfo(peerId).transport()` reports
`Transport.RELAY`. With both enabled, a punch that cannot work falls back to a
relay by itself, and a relayed peer moves to a direct connection when a later
punch succeeds. `enableRelay(true)` also carries other peers' connections, which
costs this node their bandwidth.

`punchPeer` and `connectViaRelay` throw with `ErrorCode.DECLINED` when there is
nothing to do or nothing to try with: already connected, already trying, or no
peer that can help.

### File transfer

The sender offers; the receiver accepts or rejects by `(peerId, transferId)`.

```java
node.enableFileTransfer(getCacheDir().getAbsolutePath());
node.onFileOffer((peerId, transferId, name, size, isDirectory) ->
        node.acceptFile(peerId, transferId, new File(downloads, name).getPath()));
node.onFileProgress(p -> Log.d(TAG, p.transferId() + " " + p.status() + " "
        + p.bytesTransferred() + "/" + p.totalBytes()));
node.onFileComplete((peerId, transferId, success, path) -> { });
node.start();

long id = node.sendFile(peerId, "/path/to/file");   // throws NO_SUCH_PEER / NOT_FOUND
```

The three file callbacks hold one handler each; registering again replaces it.

## Process-wide

`RatsNode.setLogLevel(LogLevel)`, `setLogFile(String)`, `version()`,
`versionInfo()`, `gitDescribe()`, `abi()`. Native log lines go to logcat, tagged
with the module that wrote them (`node`, `reactor`, `dht`, …); the JNI bridge's
own errors are tagged `LibRatsJNI`.

## Not wrapped

BitTorrent (`rats_enable_bittorrent`, `rats_bt_*`) is in the C API only, and only
works in a build with `RATS_SEARCH_FEATURES`.

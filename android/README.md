# librats — Android library

Android bindings for [librats](../README.md), a C++17 peer-to-peer networking
library: a JNI bridge (`librats_jni.cpp`) over the C ABI
(`src/librats/bindings/rats.h`), and a Java API around it (`com.librats.RatsNode`).

## The model

A `RatsNode` is one librats node. On its own it gives you secure transport
(Noise XX over TCP **or** the library's reliable stream over UDP, both on the
same port), a self-certifying peer id, manual dialing, and raw messaging on named
channels — nothing else. Discovery (DHT/mDNS), pub/sub, typed JSON messaging,
file transfer, NAT port mapping, hole punching, RTT probing and reconnection are
**opt-in subsystems**: you pay only for what you turn on.

Three rules follow from that:

- **Enable subsystems and register callbacks before `start()`.** Enabling after
  start throws with `ErrorCode.ALREADY_STARTED`; using a subsystem before its
  enable throws with `ErrorCode.NOT_ENABLED`.
- **Callbacks fire on an internal reactor thread.** Do not block in them, and
  marshal to the UI thread (`runOnUiThread`) before touching views.
- **Close the node.** `RatsNode` is `AutoCloseable`; `close()` stops it and frees
  the native resources. A finalizer is only a last-resort safety net.

Fallible methods throw `RatsException`, which carries the underlying
`ErrorCode`. Peer ids are 64-char lowercase hex strings.

## Layout

```
android/
├── src/main/
│   ├── cpp/
│   │   ├── librats_jni.cpp     # JNI bridge to src/librats/bindings/rats.h
│   │   └── CMakeLists.txt      # builds the core + the bridge
│   ├── java/com/librats/
│   │   ├── RatsNode.java       # the API, plus RatsNode.Config
│   │   ├── RatsException.java  # carries an ErrorCode
│   │   ├── ErrorCode.java  Security.java  Transport.java
│   │   ├── NatMapping.java  LogLevel.java  FileTransferStatus.java
│   │   └── *Callback.java      # callback interfaces (all functional)
│   └── AndroidManifest.xml
├── examples/                   # example app
└── README.md
```

## Integration

1. Copy this module into your project (e.g. `librats/`).
2. `settings.gradle`:
   ```gradle
   include ':librats'
   project(':librats').projectDir = new File('librats')
   ```
3. `app/build.gradle`:
   ```gradle
   dependencies { implementation project(':librats') }
   ```
4. Permissions:
   ```xml
   <uses-permission android:name="android.permission.INTERNET" />
   <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
   <uses-permission android:name="android.permission.ACCESS_WIFI_STATE" />
   <uses-permission android:name="android.permission.CHANGE_WIFI_MULTICAST_STATE" />
   ```

See [INTEGRATION.md](INTEGRATION.md) for the details.

## Quick start

```java
import com.librats.RatsNode;
import java.nio.charset.StandardCharsets;

RatsNode node = new RatsNode(new RatsNode.Config()
        .listenPort(8080)
        .dataDir(getFilesDir().getAbsolutePath()));   // stable identity across restarts

// Everything below happens before start().
node.onPeerConnected(peerId -> Log.d(TAG, "+ " + peerId));
node.onPeerDisconnected((peerId, reason) -> Log.d(TAG, "- " + peerId + " (" + reason + ")"));
node.on("chat", (peerId, data) ->
        Log.d(TAG, peerId + ": " + new String(data, StandardCharsets.UTF_8)));
node.enableMdns();

node.start();
node.connect("192.168.1.100", 8080);
node.broadcast("chat", "Hello!".getBytes(StandardCharsets.UTF_8));
```

`RatsNode` is `AutoCloseable`, so a short-lived node reads as:

```java
try (RatsNode node = new RatsNode(8080)) {
    node.start();
    ...
}
```

### Configuration

`RatsNode.Config` mirrors `rats_config_t`; every setter returns `this` and every
field has a working default.

| Setter | Default | Meaning |
|---|---|---|
| `listenPort(int)` | `0` | inbound port shared by both transports; 0 = ephemeral |
| `enableListen(boolean)` | `true` | `false` makes a dial-only node |
| `bindAddress(String)` | `"::"` | dual-stack wildcard by default |
| `security(Security)` | `NOISE` | or `PLAINTEXT` |
| `dataDir(String)` | — | persistent identity + subsystem state |
| `protocol(String)` | `"librats/1.0"` | handshake app id; peers must match |
| `maxPeers(long)` | `0` | established-peer cap; 0 = unlimited |
| `enableTcp` / `enableUdp` | `true` | which wires to accept and dial on |
| `preferredTransport(Transport)` | `UDP` | which one a dial tries first |
| `transportFallbackMs(int)` | `1200` | delay before racing the other; 0 disables |

### Messaging

```java
// Raw bytes on a named channel.
node.send(peerId, "chat", payload);
node.broadcast("chat", payload);
node.on("chat", (peer, data) -> { /* ... */ });        // before start()

// Typed JSON messaging.
node.enableJson();                                     // before start()
node.onJson("ping", (peer, json) -> { /* ... */ });    // before start()
node.sendJson(peerId, "ping", "{\"t\":1}");
node.broadcastJson("announce", "{\"hi\":true}");

// Pub/sub topics.
node.enablePubsub();                                   // before start()
node.subscribe("news", (peer, topic, data) -> { });    // before start()
node.publish("news", payload);
node.unsubscribe("news");
```

### File transfer

Push model: a peer offers a file or directory tree, and the receiver accepts or
rejects it by `(peerId, transferId)`.

```java
node.enableFileTransfer(getCacheDir().getAbsolutePath());   // before start()
node.onFileOffer((peerId, transferId, name, size, isDir) ->
        node.acceptFile(peerId, transferId, downloadDir + "/" + name));
node.onFileProgress((transferId, peerId, done, total, status) -> { });
node.onFileComplete((transferId, peerId, success, path) -> { });

long id = node.sendFile(peerId, "/path/to/file.txt");   // 0 if refused outright
long dirId = node.sendDirectory(peerId, "/path/to/dir");
// Live control: cancelFile / pauseFile / resumeFile(peerId, transferId)
```

### Discovery and NAT traversal

Port forwarding is the easy path; hole punching covers the networks where it
fails — mobile carriers in particular. Punching needs peers that relay the
rendezvous, so leave `serveAsRelay` on unless you have a reason not to.

```java
node.enableDht();                     // mainline DHT, ephemeral port
node.enableMdns();                    // same Wi-Fi
node.enablePortMapping();             // UPnP IGD + NAT-PMP
node.enableHolePunch();               // and relay other peers' rendezvous
node.enableRelay();                   // last resort, for the pairs a punch cannot reach

node.start();

node.punchPeer(peerId);               // success arrives as onPeerConnected
if (node.natMapping() == NatMapping.ENDPOINT_DEPENDENT) {
    // symmetric NAT — punching cannot work from here, but a relay still can
}
```

`enableRelay()` routes the connection itself through a node both ends already reach,
which is the only way through a symmetric NAT. It stays encrypted end to end — the
relay moves ciphertext — and the peer behaves like any other, except that
`peerTransport(peerId)` reports `Transport.RELAY`. With both enabled the ladder runs
itself: a punch that cannot work falls back to a relay, and a relayed peer keeps
trying to become a direct one. Pass `true` to also carry OTHER peers' connections,
which spends real bandwidth and is therefore off by default.

### Liveness and reconnection

```java
node.enablePing();                    // before start()
node.enableReconnect();               // before start()
node.start();

long rtt = node.peerRttMs(peerId);    // ms, or -1 if unknown
node.addReconnect("192.168.1.100", 8080);
node.removeReconnect("192.168.1.100", 8080);
```

## API reference

**Lifecycle** — `start()`, `stop()`, `close()`

**Identity / info** — `listenPort()`, `localId()`, `protocol()`,
`transports()` → `EnumSet<Transport>`

**Connections** — `connect(host, port)`, `peerCount()`, `peerIds()`,
`setMaxPeers(long)`, `maxPeers()`, `peerTransport(peerId)` → `Transport` or null,
`peerTransports(peerId)` → `EnumSet<Transport>` or null

**Raw channel messaging** — `send(peerId, channel, data)`,
`broadcast(channel, data)`, `on(channel, MessageCallback)`

**Peer events** — `onPeerConnected(PeerCallback)`, `onPeerDisconnected(PeerDisconnectCallback)` (the callback is told *why*: `"RATS_CLOSE_SLOW_CONSUMER"` means this node was sending faster than the link drained), `onPeerWritable(PeerCallback)` plus `peerWritable(String)`

**Subsystems** *(enable before start)*

| Subsystem | Enable | Then |
|---|---|---|
| DHT discovery | `enableDht(dhtPort, discoveryKey)` / `enableDht()` | — |
| mDNS discovery | `enableMdns()` | — |
| NAT port mapping | `enablePortMapping(upnp, natpmp)` / `enablePortMapping()` | — |
| Hole punching | `enableHolePunch(serveAsRelay)` / `enableHolePunch()` | `punchPeer(peerId)`, `natMapping()` |
| Pub/sub | `enablePubsub()` | `subscribe`, `unsubscribe`, `publish` |
| Typed JSON | `enableJson()` | `onJson`, `onceJson`, `offJson`, `sendJson`, `broadcastJson` |
| File transfer | `enableFileTransfer(tempDir)` | `onFileOffer`/`onFileProgress`/`onFileComplete`, `sendFile`, `sendDirectory`, `acceptFile`, `rejectFile`, `cancelFile`, `pauseFile`, `resumeFile` |
| Liveness | `enablePing()` | `peerRttMs(peerId)` |
| Reconnection | `enableReconnect()` | `addReconnect`, `removeReconnect` |

**Static** — `setLogLevel(LogLevel)`, `setLogFile(String)`, `version()`,
`versionInfo()`, `gitDescribe()`, `abi()`

### Callback interfaces

All are `@FunctionalInterface`, so a lambda or method reference works anywhere.

| Interface | Method |
|---|---|
| `PeerCallback` | `onPeer(String peerId)` |
| `MessageCallback` | `onMessage(String peerId, byte[] data)` |
| `TopicCallback` | `onTopicMessage(String peerId, String topic, byte[] data)` |
| `JsonCallback` | `onJsonMessage(String peerId, String json)` |
| `FileOfferCallback` | `onFileOffer(String peerId, long transferId, String name, long size, boolean isDirectory)` |
| `FileProgressCallback` | `onFileProgress(long transferId, String peerId, long bytesTransferred, long totalBytes, FileTransferStatus status)` |
| `FileCompleteCallback` | `onFileComplete(long transferId, String peerId, boolean success, String path)` |

### Enums

`ErrorCode` · `Security` · `Transport` · `NatMapping` · `LogLevel` ·
`FileTransferStatus`

## Building

Android Studio, NDK 21+, CMake 3.22.1+, minSdk 21. The native build pulls in the
repository-root `CMakeLists.txt` (with `RATS_BINDINGS ON`) to compile the core
library and the C ABI, then links the JNI bridge against it. ABIs: arm64-v8a,
armeabi-v7a, x86_64, x86.

```bash
cd android
./gradlew assembleRelease
```

## What the C ABI does not expose

ICE/STUN/TURN and connection strategies, runtime encryption toggles and Noise key
inspection, configuration load/save, granular logging (colours, timestamps,
rotation, retention), historical peers and statistics JSON have no C entry
points, so there is no Java surface for them. Use `enablePortMapping` /
`enableHolePunch`, `Config.security(…)` and `Config.dataDir(…)`, `enableDht` /
`enableMdns`, `enableReconnect`, and `setLogLevel` / `setLogFile` instead.

BitTorrent (`rats_enable_bittorrent`, `rats_bt_*`) exists in the C ABI but is not
wrapped here; it is only functional in a build with `RATS_SEARCH_FEATURES`.

## License

Follows the main librats project license.

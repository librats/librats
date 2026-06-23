# LibRats Android Library

Android JNI bindings for LibRats, a C++ peer-to-peer networking library. This
module wraps the canonical LibRats C ABI (`src/bindings/rats.h`) in a JNI bridge
(`librats_jni.cpp`) and a high-level Java API (`com.librats.RatsClient`).

## Model

A `RatsClient` wraps a native node. The model is peer-id-centric:

- **Peers** are identified by 64-char lowercase hex ids.
- **Messages** flow over named **channels** (raw bytes), typed **JSON** message
  types, or pub/sub **topics**.
- **Subsystems are opt-in.** DHT, mDNS, port mapping, pub/sub, JSON messaging,
  file transfer, ping (RTT), and reconnection must each be enabled with the
  matching `enable*()` method **before** `start()`. Enabling after start returns
  `ERR_ALREADY_STARTED`; using a subsystem before enabling it returns
  `ERR_NOT_ENABLED`.
- **Security** is Noise XX (encrypted + authenticated) by default, or plaintext.

## Features

- Direct peer connections (`connect`), peer enumeration, max-peer cap
- Raw-byte messaging on named channels (`send` / `broadcast` / `on`)
- Pub/sub topics (`enablePubsub` + `subscribe` / `publish`)
- Typed JSON messaging (`enableJson` + `onJson` / `sendJson` / `broadcastJson`)
- File and directory transfer (offer / accept / reject / progress / complete)
- Discovery: DHT (`enableDht`), mDNS (`enableMdns`)
- NAT port mapping (`enablePortMapping`, UPnP + NAT-PMP)
- Liveness: ping/RTT (`enablePing` + `getPeerRttMs`)
- Automatic reconnection (`enableReconnect` + `addReconnect`)

## Directory Structure

```
android/
├── src/main/
│   ├── cpp/
│   │   ├── librats_jni.cpp    # JNI bridge to src/bindings/rats.h
│   │   └── CMakeLists.txt     # builds core + JNI
│   ├── java/com/librats/
│   │   ├── RatsClient.java        # main API
│   │   ├── RatsException.java     # keyed off rats_error_t
│   │   └── *Callback.java         # callback interfaces
│   └── AndroidManifest.xml
├── examples/                  # example app
└── README.md
```

## Integration

1. **Copy the library** into your project (e.g. `librats/`).
2. **settings.gradle**:
   ```gradle
   include ':librats'
   project(':librats').projectDir = new File('librats')
   ```
3. **app/build.gradle**:
   ```gradle
   dependencies { implementation project(':librats') }
   ```

### Required Permissions

```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
<uses-permission android:name="android.permission.ACCESS_WIFI_STATE" />
<uses-permission android:name="android.permission.CHANGE_WIFI_MULTICAST_STATE" />
```

## Quick Start

```java
import com.librats.RatsClient;
import com.librats.MessageCallback;
import java.nio.charset.StandardCharsets;

RatsClient client = new RatsClient(8080); // listen on 8080

// Register callbacks and enable subsystems BEFORE start().
client.setConnectionCallback(peerId -> Log.d("LibRats", "connected: " + peerId));
client.setDisconnectCallback(peerId -> Log.d("LibRats", "disconnected: " + peerId));
client.on("chat", (peerId, data) ->
        Log.d("LibRats", peerId + ": " + new String(data, StandardCharsets.UTF_8)));
client.enableMdns();

client.start();

// Dial a peer and broadcast on a channel.
client.connect("192.168.1.100", 8080);
client.broadcast("chat", "Hello!".getBytes(StandardCharsets.UTF_8));
```

### Full Configuration

```java
RatsClient.Config cfg = new RatsClient.Config();
cfg.listenPort = 8080;
cfg.enableListen = true;            // false = dial-only node
cfg.bindAddress = null;             // null = dual-stack "::"
cfg.security = RatsClient.SECURITY_NOISE;   // or SECURITY_PLAINTEXT
cfg.dataDir = "/data/.../rats";     // persistent identity + subsystem state
cfg.protocol = "myapp/1.0";         // handshake app id; peers must match
cfg.maxPeers = 50;                  // 0 = unlimited
RatsClient client = new RatsClient(cfg);
```

### Messaging

```java
// Raw bytes on a named channel.
client.send(peerId, "chat", payload);
client.broadcast("chat", payload);
client.on("chat", (peer, data) -> { /* ... */ });

// Typed JSON messaging.
client.enableJson();                                  // before start()
client.onJson("ping", (peer, json) -> { /* ... */ }); // before start()
client.sendJson(peerId, "ping", "{\"t\":1}");
client.broadcastJson("announce", "{\"hi\":true}");

// Pub/sub topics.
client.enablePubsub();                                // before start()
client.subscribe("news", (peer, topic, data) -> { /* ... */ }); // before start()
client.publish("news", payload);
client.unsubscribe("news");
```

### File Transfer

Push model: a peer offers a file/directory and the receiver accepts or rejects
by `(peerId, transferId)`.

```java
client.enableFileTransfer("/data/.../tmp");           // before start()
client.setFileOfferCallback((peerId, transferId, name, size, isDir) ->
        client.acceptFile(peerId, transferId, "/data/.../downloads/" + name));
client.setFileProgressCallback((transferId, peerId, sent, total, status) -> {});
client.setFileCompleteCallback((transferId, success, path) -> {});

long id = client.sendFile(peerId, "/path/to/file.txt");   // 0 on failure
long dirId = client.sendDirectory(peerId, "/path/to/dir");
// Live control: cancelFile / pauseFile / resumeFile(peerId, transferId)
```

### Discovery, NAT, Liveness, Reconnect

```java
client.enableDht(0, null);            // DHT (ephemeral port, default key)
client.enableMdns();                  // local-network discovery
client.enablePortMapping(true, true); // UPnP + NAT-PMP

client.enablePing();                  // before start()
long rtt = client.getPeerRttMs(peerId);   // ms, or -1 if unknown

client.enableReconnect();             // before start()
client.addReconnect("192.168.1.100", 8080);
client.removeReconnect("192.168.1.100", 8080);
```

## API Reference

### RatsClient

**Lifecycle / identity**
- `RatsClient(int listenPort)`, `RatsClient(Config)`
- `int start()`, `void stop()`, `void destroy()`
- `int getListenPort()`, `String getLocalId()`
- `String getProtocol()` — handshake app id (e.g. `"librats/1.0"`)

**Connections**
- `int connect(String host, int port)`
- `int getPeerCount()`, `String[] getPeerIds()`
- `void setMaxPeers(long)`, `long getMaxPeers()`

**Messaging (channels)**
- `int send(String peerId, String channel, byte[] data)`
- `int broadcast(String channel, byte[] data)`
- `int on(String channel, MessageCallback)`
- `int setConnectionCallback(ConnectionCallback)`
- `int setDisconnectCallback(DisconnectCallback)`

**Pub/sub**
- `int enablePubsub()`
- `int subscribe(String topic, TopicMessageCallback)`, `int unsubscribe(String topic)`
- `int publish(String topic, byte[] data)`

**Typed JSON**
- `int enableJson()`
- `int onJson(String type, JsonMessageCallback)`, `int onceJson(...)`, `int offJson(String type)`
- `int sendJson(String peerId, String type, String json)`, `int broadcastJson(String type, String json)`

**File transfer**
- `int enableFileTransfer(String tempDir)`
- `int setFileOfferCallback(FileOfferCallback)`, `int setFileProgressCallback(FileProgressCallback)`, `int setFileCompleteCallback(FileCompleteCallback)`
- `long sendFile(String peerId, String path)`, `long sendDirectory(String peerId, String dirPath)`
- `int acceptFile(String peerId, long transferId, String destPath)`, `int rejectFile(String peerId, long transferId)`
- `int cancelFile(...)`, `int pauseFile(...)`, `int resumeFile(...)`

**Discovery / NAT / liveness / reconnect**
- `int enableDht(int dhtPort, String discoveryKey)`, `int enableDht()`, `int enableMdns()`
- `int enablePortMapping(boolean upnp, boolean natpmp)`
- `int enablePing()`, `long getPeerRttMs(String peerId)`
- `int enableReconnect()`, `int addReconnect(String host, int port)`, `int removeReconnect(String host, int port)`

**Static**
- `void setLogLevel(int level)` (`LOG_DEBUG/INFO/WARN/ERROR`), `void setLogFile(String path)`
- `String getVersionString()`, `int[] getVersion()`, `String getGitDescribe()`, `int getAbi()`
- `String errorString(int error)`

### Callback Interfaces

- `ConnectionCallback` — `onConnected(String peerId)`
- `DisconnectCallback` — `onDisconnected(String peerId)`
- `MessageCallback` — `onMessage(String peerId, byte[] data)`
- `TopicMessageCallback` — `onTopicMessage(String peerId, String topic, byte[] data)`
- `JsonMessageCallback` — `onJsonMessage(String peerId, String json)`
- `FileOfferCallback` — `onFileOffer(String peerId, long transferId, String name, long size, boolean isDirectory)`
- `FileProgressCallback` — `onFileProgress(long transferId, String peerId, long bytesTransferred, long totalBytes, int status)`
- `FileCompleteCallback` — `onFileComplete(long transferId, boolean success, String path)`

### Error codes (`rats_error_t`)

`OK` (0), `ERR_INVALID_ARG` (1), `ERR_NOT_STARTED` (2), `ERR_ALREADY_STARTED`
(3), `ERR_NOT_ENABLED` (4), `ERR_NO_SUCH_PEER` (5), `ERR_BIND` (6),
`ERR_INTERNAL` (7). Methods return one of these; `RatsException` carries the
code via `getErrorCode()`.

## Building

- Android Studio, NDK 21+, CMake 3.22.1+, minSDK 21.
- The native build pulls in the repository-root `CMakeLists.txt` (with
  `RATS_BINDINGS ON`) to compile the core library + C ABI, then links the JNI
  bridge against it. ABIs: arm64-v8a, armeabi-v7a, x86_64, x86.

```bash
cd android
./gradlew assembleRelease
```

## Threading

Callbacks fire on an internal reactor thread — do not block in them, and marshal
to the UI thread (`runOnUiThread`) before touching views. Call `destroy()` to
release native resources.

## Removed in the rewrite

The following old-API features no longer exist and have been removed: ICE /
STUN / TURN and connection strategies, encryption enable/keys and Noise key
inspection, configuration load/save (use `Config.dataDir`), granular logging
(colors / timestamps / rotation / retention / console toggles — use
`setLogLevel` / `setLogFile`), historical peers, statistics JSON
(connection / gossipsub / file-transfer), and automatic-discovery toggles (use
`enableDht` / `enableMdns`).

## License

Follows the main LibRats project license.

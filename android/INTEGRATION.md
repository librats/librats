# LibRats Android Integration Guide

## Overview

This module provides JNI bindings for the LibRats C++ peer-to-peer networking
library, wrapping the canonical C ABI (`src/bindings/rats.h`). Android apps can:

- Dial peers and accept inbound connections
- Send/receive raw-byte messages on named channels
- Use typed JSON messaging and pub/sub topics
- Transfer files and directories between peers
- Discover peers via DHT and mDNS
- Probe peer RTT and auto-reconnect to dropped peers

Security is Noise XX (encrypted + authenticated) by default.

## Quick Integration

### 1. Add to Your Project

Copy the `android/` directory into your project, e.g. `librats-android`.

### 2. settings.gradle

```gradle
include ':librats-android'
project(':librats-android').projectDir = new File('librats-android')
```

### 3. Dependency (app/build.gradle)

```gradle
dependencies {
    implementation project(':librats-android')
}
```

### 4. AndroidManifest.xml

```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
<uses-permission android:name="android.permission.ACCESS_WIFI_STATE" />
<uses-permission android:name="android.permission.CHANGE_WIFI_MULTICAST_STATE" />
```

## Usage Example

```java
import com.librats.RatsClient;
import java.nio.charset.StandardCharsets;

public class P2PService {
    private RatsClient client;

    public void initializeP2P() {
        client = new RatsClient(8080); // listen on 8080

        // Register callbacks and enable subsystems BEFORE start().
        client.setConnectionCallback(peerId -> Log.d("P2P", "connected: " + peerId));
        client.on("chat", (peerId, data) ->
                Log.d("P2P", peerId + ": " + new String(data, StandardCharsets.UTF_8)));
        client.enableMdns();

        client.start();
    }

    public void connectToPeer(String host, int port) {
        client.connect(host, port);
    }

    public void broadcast(String message) {
        client.broadcast("chat", message.getBytes(StandardCharsets.UTF_8));
    }

    public void cleanup() {
        if (client != null) {
            client.stop();
            client.destroy();
        }
    }
}
```

## Architecture

```
┌─────────────────────────────────────────┐
│           Android Application           │
├─────────────────────────────────────────┤
│          Java API (com.librats)         │
├─────────────────────────────────────────┤
│         JNI Layer (librats_jni.cpp)     │
├─────────────────────────────────────────┤
│      LibRats C ABI (bindings/rats.h)    │
├─────────────────────────────────────────┤
│       LibRats Core (C++ implementation) │
└─────────────────────────────────────────┘
```

## Key Concepts

- **Peer-id-centric.** Peers are 64-char lowercase hex ids (no socket handles).
  `ConnectionCallback` / `DisconnectCallback` deliver a peer-id `String`.
- **Opt-in subsystems.** Call the matching `enable*()` and register callbacks
  **before** `start()`. Enabling after start returns `ERR_ALREADY_STARTED`;
  using a subsystem before enabling returns `ERR_NOT_ENABLED`.
- **Error model.** Fallible methods return a `rats_error_t` code
  (`RatsClient.OK == 0`); `RatsClient.errorString(code)` gives a name.

### Callback Interfaces

- `ConnectionCallback` — `onConnected(String peerId)`
- `DisconnectCallback` — `onDisconnected(String peerId)`
- `MessageCallback` — `onMessage(String peerId, byte[] data)` (channel bytes)
- `TopicMessageCallback` — `onTopicMessage(String peerId, String topic, byte[] data)`
- `JsonMessageCallback` — `onJsonMessage(String peerId, String json)`
- `FileOfferCallback` / `FileProgressCallback` / `FileCompleteCallback`

## Building

The native build pulls in the repository-root `CMakeLists.txt` with
`RATS_BINDINGS ON`, compiling the core `rats` library plus the C ABI
(`src/bindings/rats.cpp`) and the generated `version.h`, then links the JNI
bridge (`librats_jni.so`) against it.

Supported ABIs: arm64-v8a, armeabi-v7a, x86_64, x86.

## Requirements

- Minimum SDK: Android 5.0 (API 21)
- NDK: 21+
- CMake: 3.22.1+

## Threading

- Callbacks run on an internal reactor thread; do not block in them.
- Use `runOnUiThread()` for UI updates.
- Call `destroy()` to release native resources.

## Removed from the previous binding

ICE/STUN/TURN and connection strategies, encryption enable/keys, configuration
load/save (use `Config.dataDir`), granular logging controls, historical peers,
statistics JSON, and automatic-discovery toggles have been removed. Use
`enableDht` / `enableMdns` for discovery and `setLogLevel` / `setLogFile` for
logging.

## Troubleshooting

- Build: ensure NDK and CMake are installed and the repository root is reachable
  from the module so core sources compile.
- Runtime: grant the required permissions; raise verbosity with
  `RatsClient.setLogLevel(RatsClient.LOG_DEBUG)`; check native logs with
  `adb logcat -s LibRatsJNI`.
- Network: verify peers are reachable and ports are open.

## License

Follows the main LibRats project license.

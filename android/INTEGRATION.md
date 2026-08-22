# LibRats Android Integration Guide

## Overview

This module provides JNI bindings for the LibRats C++ peer-to-peer networking
library, wrapping the canonical C ABI (`src/librats/bindings/rats.h`). Android apps can:

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
import com.librats.RatsNode;
import java.nio.charset.StandardCharsets;

public class P2PService {
    private RatsNode node;

    public void initializeP2P(File dataDir) {
        node = new RatsNode(new RatsNode.Config()
                .listenPort(8080)
                .dataDir(dataDir.getAbsolutePath()));   // stable identity across restarts

        // Callbacks and enables all go in before start().
        node.onPeerConnected(peerId -> Log.d("P2P", "+ " + peerId));
        node.on("chat", (peerId, data) ->
                Log.d("P2P", peerId + ": " + new String(data, StandardCharsets.UTF_8)));
        node.enableMdns();

        node.start();
    }

    public void connectToPeer(String host, int port) {
        node.connect(host, port);
    }

    public void broadcast(String message) {
        node.broadcast("chat", message.getBytes(StandardCharsets.UTF_8));
    }

    public void cleanup() {
        if (node != null) {
            node.close();   // stops the node and releases the native resources
            node = null;
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
- **Opt-in subsystems.** Call the matching `enable*()` and register callbacks
  **before** `start()`. Enabling after start throws with
  `ErrorCode.ALREADY_STARTED`; using a subsystem before enabling throws with
  `ErrorCode.NOT_ENABLED`.
- **Error model.** Fallible methods throw `RatsException`, which carries the
  underlying `ErrorCode`; getters return their value.
- **Ownership.** `RatsNode` is `AutoCloseable`: `close()` stops the node and
  releases the native resources. The finalizer is only a safety net.

### Callback Interfaces

All are `@FunctionalInterface`, so a lambda works anywhere one is expected.

- `PeerCallback` — `onPeer(String peerId)` (both connect and disconnect)
- `MessageCallback` — `onMessage(String peerId, byte[] data)` (channel bytes)
- `TopicCallback` — `onTopicMessage(String peerId, String topic, byte[] data)`
- `JsonCallback` — `onJsonMessage(String peerId, String json)`
- `FileOfferCallback` / `FileProgressCallback` / `FileCompleteCallback`

## Building

The native build pulls in the repository-root `CMakeLists.txt` with
`RATS_BINDINGS ON`, compiling the core `rats` library plus the C ABI
(`src/librats/bindings/rats.cpp`) and the generated `version.h`, then links the JNI
bridge (`librats_jni.so`) against it.

Supported ABIs: arm64-v8a, armeabi-v7a, x86_64, x86.

## Requirements

- Minimum SDK: Android 5.0 (API 21)
- NDK: 21+
- CMake: 3.22.1+

## Threading

- Callbacks run on an internal reactor thread; do not block in them.
- Use `runOnUiThread()` for UI updates.
- Call `close()` (or use try-with-resources) to release native resources.

## What the C ABI does not expose

ICE/STUN/TURN and connection strategies, runtime encryption toggles and key
inspection, configuration load/save, granular logging controls, historical peers
and statistics JSON have no C entry points and therefore no Java surface. Use
`enablePortMapping` / `enableHolePunch` for NAT traversal, `Config.security(…)`
and `Config.dataDir(…)` for security and persistence, `enableDht` / `enableMdns`
for discovery, and `setLogLevel` / `setLogFile` for logging.

## Troubleshooting

- Build: ensure NDK and CMake are installed and the repository root is reachable
  from the module so core sources compile.
- Runtime: grant the required permissions; raise verbosity with
  `RatsNode.setLogLevel(LogLevel.DEBUG)`; check native logs with
  `adb logcat -s LibRatsJNI`.
- Network: verify peers are reachable and ports are open.

## License

Follows the main LibRats project license.

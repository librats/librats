# Adding librats to an Android app

The API is described in [README.md](README.md); this page is about getting the
module into a project and building it.

## Requirements

- minSdk 21, compileSdk 35 (see `build.gradle`)
- Android Studio with the NDK and CMake 3.22.1 installed
- the whole librats repository: the module's native build pulls in the
  repository-root `CMakeLists.txt`, so `android/` cannot be copied out alone

## Wiring it in

Point your app's Gradle settings at the `android/` directory of a librats
checkout:

```gradle
// settings.gradle
include ':librats'
project(':librats').projectDir = new File('../librats/android')
```

```gradle
// app/build.gradle
dependencies {
    implementation project(':librats')
}
```

The library's manifest adds `INTERNET` and `CHANGE_WIFI_MULTICAST_STATE` to your
app. The second is there for mDNS: most devices drop Wi-Fi multicast unless the
app holds a `WifiManager.MulticastLock`, which the library cannot take for you
since it has no `Context`:

```java
WifiManager wifi = (WifiManager) context.getApplicationContext()
        .getSystemService(Context.WIFI_SERVICE);
WifiManager.MulticastLock lock = wifi.createMulticastLock("librats-mdns");
lock.setReferenceCounted(false);
lock.acquire();   // release() when the node is closed
```

`consumer-rules.pro` keeps the `com.librats` package intact under R8/ProGuard:
the JNI bridge reaches its classes, fields and callback methods by name.

## How it is built

`src/main/cpp/CMakeLists.txt` adds the repository root as a subdirectory with
`RATS_BINDINGS` on (tests, examples and the client off), which builds the core
`rats` library and the C API, then links `librats_jni.so` against it. ABIs:
arm64-v8a, armeabi-v7a, x86_64, x86.

```
┌──────────────────────────────┐
│ your app                     │
├──────────────────────────────┤
│ com.librats (Java)           │
├──────────────────────────────┤
│ librats_jni.cpp              │
├──────────────────────────────┤
│ C API (bindings/rats.h)      │
├──────────────────────────────┤
│ librats core (C++)           │
└──────────────────────────────┘
```

To build the module on its own:

```bash
cd android
./gradlew assembleRelease
```

## Troubleshooting

- **`UnsatisfiedLinkError` when `RatsNode` is first used.** Either
  `librats_jni.so` is missing for the device's ABI, or `JNI_OnLoad` refused it:
  the native bridge and the Java classes come from different versions, or R8
  renamed something it reaches by name. `adb logcat -s LibRatsJNI` names what it
  could not find.
- **mDNS finds nobody.** Hold a `MulticastLock` (above), and check the devices
  are on the same Wi-Fi network; many guest and enterprise networks block
  multicast between clients.
- **More detail.** `RatsNode.setLogLevel(LogLevel.DEBUG)`; native logs appear in
  logcat under their module name.

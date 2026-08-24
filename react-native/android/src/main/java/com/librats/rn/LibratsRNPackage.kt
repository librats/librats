package com.librats.rn

import com.facebook.react.ReactPackage
import com.facebook.react.bridge.NativeModule
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.uimanager.ViewManager
import com.margelo.nitro.librats.LibratsRNOnLoad

/**
 * Exports no native modules and no view managers -- the HybridObject reaches JS
 * through Nitro's JSI registry, not through the React bridge.
 *
 * It exists for two reasons anyway:
 *
 *  1. It loads the native library. Nitrogen generates LibratsRNOnLoad with an
 *     idempotent initializeNative(), but nothing calls it on its own; doing it
 *     here means libLibratsRN.so is loaded (and JNI_OnLoad has registered every
 *     autolinked HybridObject) before any JS can ask for one.
 *
 *  2. React Native's Android autolinking requires it. The CLI scans a package's
 *     android/ sources for a class implementing ReactPackage and skips the
 *     dependency entirely when it finds none -- so without this class the Gradle
 *     project is never added to the build, and the module silently does not exist
 *     on Android. (iOS has no equivalent requirement; the podspec is enough.)
 */
class LibratsRNPackage : ReactPackage {
  init {
    LibratsRNOnLoad.initializeNative()
  }

  override fun createNativeModules(
    reactContext: ReactApplicationContext
  ): List<NativeModule> = emptyList()

  override fun createViewManagers(
    reactContext: ReactApplicationContext
  ): List<ViewManager<*, *>> = emptyList()
}

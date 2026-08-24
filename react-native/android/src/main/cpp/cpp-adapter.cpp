#include <fbjni/fbjni.h>
#include <jni.h>

#include "LibratsRNOnLoad.hpp"

// Registers the Nitro HybridObjects listed under "autolinking" in nitro.json
// (here: RatsNode -> HybridRatsNode) when Android loads libLibratsRN.so.
//
// Note the symbol is registerAllNatives(); the example in the generated
// LibratsRNOnLoad.hpp header still says registerNatives(), which does not exist.
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
  return facebook::jni::initialize(vm, [] {
    margelo::nitro::librats::registerAllNatives();
  });
}

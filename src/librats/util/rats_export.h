#pragma once

/**
 * @file rats_export.h
 * @brief Symbol visibility for the shared build.
 *
 * RATS_API marks the supported public surface — the types and functions that
 * cross the library boundary. It is what makes `RATS_SHARED_LIBRARY=ON` usable:
 * on MSVC a symbol without __declspec(dllexport) simply is not in the DLL, so an
 * unmarked class links fine in a static build and fails to link in a shared one.
 *
 * Three states, selected by the build:
 *   - RATS_EXPORT_DLL — set PRIVATE while compiling the shared library itself.
 *   - RATS_IMPORT_DLL — set INTERFACE on the exported target, so consumers of the
 *     shared library get __declspec(dllimport). Conan's CMakeDeps builds its own
 *     config from conanfile.py's package_info() rather than from ratsConfig.cmake,
 *     so the define is declared in BOTH places — keep them in sync.
 *   - neither — the static build, where RATS_API expands to nothing.
 *
 * Marking a class exports every member, including private ones and the vtable;
 * that is deliberate, because inline members in these headers reach privates.
 * A class whose members are all defined inline in the header needs no marking —
 * the consumer's compiler emits them. The abstract interfaces (Subsystem,
 * PeerNetwork, ConnectionDelegate, …) are marked anyway: MSVC warns C4275 when an
 * exported class derives from a non-exported base.
 *
 */

#ifdef _WIN32
  #if defined(RATS_EXPORT_DLL)
    #define RATS_API __declspec(dllexport)
  #elif defined(RATS_IMPORT_DLL)
    #define RATS_API __declspec(dllimport)
  #else
    #define RATS_API
  #endif

  #if defined(_MSC_VER) && (defined(RATS_EXPORT_DLL) || defined(RATS_IMPORT_DLL))
    // C4251: an exported class has a std:: data member that is not itself
    // exported (Node alone has vector/mutex/thread/unique_ptr/atomic members).
    // C4275: an exported class derives from a non-exported base.
    //
    // Both warn about the same thing: the layout of those members must match on
    // both sides of the DLL. That is already a hard requirement here — the public
    // API passes std::string/std::vector/std::function by value, so a consumer
    // must build with the same toolset, the same runtime (/MD) and the same
    // _ITERATOR_DEBUG_LEVEL regardless. Conan and vcpkg enforce it via the
    // profile/triplet. Silenced for the whole translation unit rather than
    // per-class so consumers including these headers stay warning-clean.
    #pragma warning(disable: 4251)
    #pragma warning(disable: 4275)
  #endif
#else
  #if __GNUC__ >= 4
    #define RATS_API __attribute__((visibility("default")))
  #else
    #define RATS_API
  #endif
#endif

require "json"

# Read as UTF-8 explicitly: CocoaPods evaluates a podspec under the shell's
# locale, and on a machine without LANG set that defaults to US-ASCII, which
# makes any non-ASCII byte in package.json a hard parse error.
package = JSON.parse(File.read(File.join(__dir__, "package.json"), :encoding => "UTF-8"))

Pod::Spec.new do |s|
  # The name must match `iosModuleName` in nitro.json -- it is the clang module
  # name the generated code is compiled into.
  s.name         = "LibratsRN"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.license      = package["license"]
  s.authors      = "librats"
  s.homepage     = "https://librats.com"
  s.platforms    = { :ios => "15.0" }
  s.source       = { :git => "https://github.com/DEgITx/librats.git", :tag => "#{s.version}" }

  # This binding's own C++ -- one implementation shared with Android.
  s.source_files = "cpp/**/*.{hpp,cpp}"

  # --- librats core ---------------------------------------------------------
  # The core is consumed as the XCFramework that ios/build-xcframework.sh
  # produces, rather than by listing librats' sources here: the source list
  # lives in the root CMakeLists.txt and must not be duplicated.
  #
  # `prepare_command` builds it on `pod install` when it is missing. That is the
  # right shape while this package lives inside the repository; a published
  # package would ship the prebuilt XCFramework in the tarball instead, so
  # consumers need neither CMake nor the C++ sources.
  s.prepare_command = <<-CMD
    set -e
    if [ ! -d "ios/LibRats.xcframework" ]; then
      echo "[librats] building LibRats.xcframework (first pod install only)..."
      mkdir -p ios
      # vendor/librats/ios exists in a package installed from npm; ../ios is the
      # repository layout. Same reasoning as android/CMakeLists.txt.
      if [ -x "vendor/librats/ios/build-xcframework.sh" ]; then
        vendor/librats/ios/build-xcframework.sh "$(pwd)/ios/build" >/dev/null
      else
        ../ios/build-xcframework.sh "$(pwd)/ios/build" >/dev/null
      fi
      cp -R "$(pwd)/ios/build/LibRats.xcframework" ios/
    fi
  CMD

  s.vendored_frameworks = "ios/LibRats.xcframework"

  # Nitro's generated sources, the NitroModules dependency, and the C++20 /
  # Swift-interop build settings.
  load File.join(__dir__, "nitrogen/generated/ios/LibratsRN+autolinking.rb")
  add_nitrogen_files(s)

  # No HEADER_SEARCH_PATHS for the XCFramework on purpose. CocoaPods already adds
  # "$(PODS_XCFRAMEWORKS_BUILD_DIR)/LibratsRN/Headers", which resolves to the one
  # slice being built, so librats' headers are reachable as "librats/node/node.h"
  # exactly as they are in-tree.
  #
  # Adding the slice paths by hand breaks two ways, both of which cost a build to
  # discover: naming both slices puts two copies of the framework's
  # module.modulemap in scope and clang fails with "redefinition of module
  # 'LibRats'", and any SDK-conditional HEADER_SEARCH_PATHS[sdk=...] *replaces*
  # the unconditional value rather than extending it, silently dropping every
  # React header.
  s.pod_target_xcconfig = (s.attributes_hash["pod_target_xcconfig"] || {}).merge({
    "CLANG_CXX_LIBRARY" => "libc++",
  })

  install_modules_dependencies(s) if respond_to?(:install_modules_dependencies)
end

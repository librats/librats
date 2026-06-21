{
  "targets": [
    {
      "target_name": "librats",
      "product_name": "librats",
      "sources": [
        "src/librats_node.cpp"
      ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")",
        # librats headers. "bindings/rats.h" is the canonical C ABI; it pulls in
        # util/rats_export.h, both under src/. native-src/src is used when the
        # package is installed from npm (sources bundled there); ../src in dev.
        "native-src/src",
        "../src",
        # Generated headers (version.h) produced by the CMake build into
        # build-native/src/. Mirrors PROJECT_BINARY_DIR/src in CMakeLists.txt.
        "build-native/src"
      ],
      "dependencies": [
        "<!(node -p \"require('node-addon-api').gyp\")"
      ],
      "cflags!": [ "-fno-exceptions" ],
      "cflags_cc!": [ "-fno-exceptions" ],
      "cflags_cc": [ "-std=c++17" ],
      "xcode_settings": {
        "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
        "CLANG_CXX_LIBRARY": "libc++",
        "CLANG_CXX_LANGUAGE_STANDARD": "c++17",
        "MACOSX_DEPLOYMENT_TARGET": "10.13"
      },
      "msvs_settings": {
        "VCCLCompilerTool": {
          "ExceptionHandling": 1,
          "RuntimeLibrary": 2,
          "AdditionalOptions": [ "/std:c++17" ]
        }
      },
      "defines": [ "NAPI_DISABLE_CPP_EXCEPTIONS" ],
      "conditions": [
        ["OS=='win'", {
          # Link the prebuilt static archive produced by scripts/build-librats.js
          # (CMake builds rats.lib with RATS_BINDINGS=ON, so the rats_* C ABI is
          # already inside). Plus the platform networking/crypto libs.
          "configurations": {
            "Debug": {
              "msvs_settings": {
                "VCCLCompilerTool": {
                  "RuntimeLibrary": 3
                },
                "VCLinkerTool": {
                  "AdditionalDependencies": [
                    "<(module_root_dir)/build-native/lib/Debug/rats.lib",
                    "ws2_32.lib",
                    "iphlpapi.lib",
                    "bcrypt.lib"
                  ]
                }
              }
            },
            "Release": {
              "msvs_settings": {
                "VCCLCompilerTool": {
                  "RuntimeLibrary": 2
                },
                "VCLinkerTool": {
                  "AdditionalDependencies": [
                    "<(module_root_dir)/build-native/lib/Release/rats.lib",
                    "ws2_32.lib",
                    "iphlpapi.lib",
                    "bcrypt.lib"
                  ]
                }
              }
            }
          },
          "defines": [
            "WIN32_LEAN_AND_MEAN",
            "_WIN32_WINNT=0x0600"
          ]
        }],
        ["OS=='linux'", {
          "libraries": [
            "<(module_root_dir)/build-native/lib/librats.a"
          ],
          "libraries!": [
            "-undefined dynamic_lookup"
          ],
          "link_settings": {
            "libraries": [
              "-lpthread"
            ]
          }
        }],
        ["OS=='mac'", {
          "libraries": [
            "<(module_root_dir)/build-native/lib/librats.a"
          ],
          "link_settings": {
            "libraries": [
              "-lpthread"
            ]
          }
        }]
      ]
    }
  ]
}

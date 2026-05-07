from conan import ConanFile
from conan.tools.cmake import CMake, CMakeDeps, CMakeToolchain, cmake_layout
from conan.tools.files import copy, get
from conan.tools.scm import Version
import os


class LibratsConan(ConanFile):
    name = "librats"
    license = "MIT"
    url = "https://github.com/DEgITx/librats"
    homepage = "https://github.com/DEgITx/librats"
    description = (
        "C++17 peer-to-peer networking library: encrypted P2P (Noise XX), "
        "DHT/mDNS discovery, NAT traversal (STUN/TURN/ICE), GossipSub "
        "pub/sub, file transfer, optional BitTorrent."
    )
    topics = ("p2p", "networking", "dht", "noise-protocol", "ice",
              "gossipsub", "bittorrent", "nat-traversal")

    settings = "os", "arch", "compiler", "build_type"
    options = {
        "shared":          [True, False],
        "fPIC":            [True, False],
        "search_features": [True, False],   # BitTorrent client
        "storage":         [True, False],   # Distributed storage
        "bindings":        [True, False],   # C API
    }
    default_options = {
        "shared":          False,
        "fPIC":            True,
        "search_features": False,
        "storage":         False,
        "bindings":        True,
    }

    exports_sources = (
        "CMakeLists.txt",
        "cmake/*",
        "src/*",
        "tests/*",
        "examples/*",
        "3rdparty/*",
        "version.rc.in",
        "LICENSE",
    )

    def config_options(self):
        if self.settings.os == "Windows":
            del self.options.fPIC

    def configure(self):
        if self.options.shared:
            self.options.rm_safe("fPIC")
        # Pure C++ library; no C-only ABI considerations to expose.
        self.settings.rm_safe("compiler.libcxx")
        self.settings.rm_safe("compiler.cppstd")

    def validate(self):
        if self.settings.compiler.get_safe("cppstd"):
            from conan.tools.build import check_min_cppstd
            check_min_cppstd(self, 17)

    def layout(self):
        cmake_layout(self)

    def generate(self):
        tc = CMakeToolchain(self)
        # Conan controls library kind via the standard `shared` option;
        # mirror it onto the project's RATS_* switches.
        tc.cache_variables["RATS_SHARED_LIBRARY"] = bool(self.options.shared)
        tc.cache_variables["RATS_STATIC_LIBRARY"] = not bool(self.options.shared)
        tc.cache_variables["RATS_BUILD_TESTS"] = False
        tc.cache_variables["RATS_BUILD_EXAMPLES"] = False
        tc.cache_variables["RATS_BINDINGS"] = bool(self.options.bindings)
        tc.cache_variables["RATS_SEARCH_FEATURES"] = bool(self.options.search_features)
        tc.cache_variables["RATS_STORAGE"] = bool(self.options.storage)
        tc.cache_variables["RATS_INSTALL"] = True
        # Provide a deterministic version when building outside a git checkout.
        tc.cache_variables["RATS_VERSION_OVERRIDE"] = str(self.version)
        tc.generate()

        deps = CMakeDeps(self)
        deps.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()
        copy(self, "LICENSE",
             src=self.source_folder,
             dst=os.path.join(self.package_folder, "licenses"))

    def package_info(self):
        self.cpp_info.set_property("cmake_file_name", "rats")
        self.cpp_info.set_property("cmake_target_name", "rats::rats")
        self.cpp_info.libs = ["rats"]
        self.cpp_info.includedirs = ["include/librats", "include/librats/crypto"]

        if self.options.search_features:
            self.cpp_info.defines.append("RATS_SEARCH_FEATURES")
        if self.options.storage:
            self.cpp_info.defines.append("RATS_STORAGE")

        if self.settings.os in ("Linux", "FreeBSD"):
            self.cpp_info.system_libs = ["pthread"]
        elif self.settings.os == "Windows":
            self.cpp_info.system_libs = ["ws2_32", "iphlpapi", "bcrypt"]
        elif self.settings.os == "Android":
            # Android NDK provides log/dl; threading is in libc.
            self.cpp_info.system_libs = ["log"]

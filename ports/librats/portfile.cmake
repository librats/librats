vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO librats/librats
    REF "${VERSION}"
    SHA512 77efccd059b6faaac14824f2a62e04682cc900f4b40e2ea294c8a0a65e20db0d81d43e946f34f00433306f96af9daa896557bbcd639b094a5bae7cf00e6e83a3
    HEAD_REF master
)

vcpkg_check_features(
    OUT_FEATURE_OPTIONS FEATURE_OPTIONS
    FEATURES
        bindings         RATS_BINDINGS
        search-features  RATS_SEARCH_FEATURES
        storage          RATS_STORAGE
)

string(COMPARE EQUAL "${VCPKG_LIBRARY_LINKAGE}" "dynamic" RATS_SHARED)
string(COMPARE EQUAL "${VCPKG_LIBRARY_LINKAGE}" "static" RATS_STATIC)

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        ${FEATURE_OPTIONS}
        -DRATS_SHARED_LIBRARY=${RATS_SHARED}
        -DRATS_STATIC_LIBRARY=${RATS_STATIC}
        -DRATS_BUILD_TESTS=OFF
        -DRATS_BUILD_CLIENT=OFF
        -DRATS_BUILD_EXAMPLES=OFF
        -DRATS_INSTALL=ON
        -DRATS_VERSION_OVERRIDE=${VERSION}
)

vcpkg_cmake_install()

vcpkg_cmake_config_fixup(PACKAGE_NAME rats CONFIG_PATH lib/cmake/rats)

# Headers only — drop debug copy and any binaries that landed under share/.
file(REMOVE_RECURSE
    "${CURRENT_PACKAGES_DIR}/debug/include"
    "${CURRENT_PACKAGES_DIR}/debug/share"
)

vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE")

vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO alphacep/vosk-api
    REF a428d65966b17252eef524f6c21a5b9f85867cb5
    SHA512 b1b159178d34ed0a24928d730509c38dccd0fab287982d954d21a14f6a3867ecb9c9d8d544dcf7dffa5042dacfccb5442b56d22d1621dc58d52cde37200d0939
    HEAD_REF master
    PATCHES
        0000-fix-for-vcpkg.patch
)

string(COMPARE EQUAL "${VCPKG_LIBRARY_LINKAGE}" "dynamic" BUILD_SHARED)

vcpkg_cmake_configure(
    SOURCE_PATH ${SOURCE_PATH}
    OPTIONS
        -DBUILD_SHARED_LIBS=${BUILD_SHARED}
)

vcpkg_cmake_install()
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")
vcpkg_cmake_config_fixup(PACKAGE_NAME vosk)

vcpkg_install_copyright(FILE_LIST ${SOURCE_PATH}/COPYING)

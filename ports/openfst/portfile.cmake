vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO alphacep/openfst
    REF 18e94e63870ebcf79ebb42b7035cd3cb626ec090
    SHA512 abebdb3d8136c8eea2073ae1a7caa4dc5162a8b1556b7b62a8679693e47e6ddbcd9c00fdfb7a42ab42407ca27dba398a094535e631d066eb267e3b633c0b1f13
    HEAD_REF master
    PATCHES
        0000-add-cmakelists.patch
)

string(COMPARE EQUAL "${VCPKG_LIBRARY_LINKAGE}" "dynamic" BUILD_SHARED)

vcpkg_cmake_configure(
    SOURCE_PATH ${SOURCE_PATH}
    OPTIONS
        -DBUILD_SHARED_LIBS=${BUILD_SHARED}
        -DOPENFST_BUILD_BIN=OFF
        -DOPENFST_HAS_ABSL=ON
)

vcpkg_cmake_install()
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")
vcpkg_cmake_config_fixup(PACKAGE_NAME openfst)

vcpkg_install_copyright(FILE_LIST ${SOURCE_PATH}/COPYING)

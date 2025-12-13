vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO alphacep/kaldi
    REF bc5baf14231660bd50b7d05788865b4ac6c34481
    SHA512 936402c3070a417cb32c774f1dc628f80b8bda39d029d266e0d2a212b475a35a030d5fa8ae3bdba90f28d594309c6bf76489e8e54e2a34e47a23612e46704931
    HEAD_REF vosk
    PATCHES
        0000-fix-for-vcpkg.patch
)

string(COMPARE EQUAL "${VCPKG_LIBRARY_LINKAGE}" "dynamic" BUILD_SHARED)

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        -DBUILD_SHARED_LIBS=${BUILD_SHARED}
        -DKALDI_BUILD_EXE=OFF
        -DKALDI_BUILD_TEST=OFF
)

vcpkg_cmake_install()
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")
vcpkg_cmake_config_fixup()

vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/COPYING")

vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO google/ruy
    REF 21a85fef159f9942f636a43b14c64b481c2a05b2
    SHA512 e7ca114318d2dd0d46e542b2daea0da7f7ce9b6cce574dc99097c97f22a665b0b88c1add9146b015977a82765fbaa8bc0db7cbb3add98e4d76ffecfd2248a870
    HEAD_REF master
)

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        -DRUY_FIND_CPUINFO=ON
        -DRUY_MINIMAL_BUILD=ON
)

vcpkg_cmake_install()
vcpkg_copy_pdbs()
vcpkg_cmake_config_fixup(CONFIG_PATH "lib/cmake/${PORT}")
vcpkg_fixup_pkgconfig()

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")

vcpkg_install_copyright(FILE_LIST ${SOURCE_PATH}/LICENSE)

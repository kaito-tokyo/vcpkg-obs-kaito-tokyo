vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO ml-explore/mlx
    REF 68cf2fddd8de5edd8ab3d926391772b2e2cedad8
    SHA512 be975fc0489e2f72b963bc92f3b4568f02a1aedb6537074a75d5ef68cd1acac63f44d6a0ca9a98353bd2a02b7b4b8d443c78d3d414e8264b6eb077fd0bbee703
    HEAD_REF master
)

vcpkg_download_distfile(
    JSON_ARCHIVE
    URLS https://github.com/nlohmann/json/archive/refs/tags/v3.11.3.tar.gz
    FILENAME json-v3.11.3.tar.gz
    SHA512 7df19b621de34f08d5d5c0a25e8225975980841ef2e48536abcf22526ed7fb99f88ad954a2cb823115db59ccc88d1dbe74fe6c281b5644b976b33fb78db9d717
)

vcpkg_download_distfile(
    METAL_CPP_ARCHIVE
    URLS https://developer.apple.com/metal/cpp/files/metal-cpp_26.zip
    FILENAME metal-cpp_26.zip
    SHA512 d153f8d26dac38867b49d6ef8f98417191a7cb753908f4798c12c7110ed706e8bc5b72d4d94b9f237ceb36c42b795ae260dc9f3fff03ebf118c5d6e4efc53abe
)

vcpkg_download_distfile(
    GGUFLIB_ARCHIVE
    URLS https://github.com/antirez/gguf-tools/archive/8fa6eb65236618e28fd7710a0fba565f7faa1848.tar.gz
    FILENAME gguflib-8fa6eb65236618e28fd7710a0fba565f7faa1848.tar.gz
    SHA512 201ea3ec67c44fb512d8b02e07b118f51a3dcbf4e43888fa8cdca08e560c6c2d8dfd2fe812bfc0016e196ed813c89dd0d0aad58ac9758dd3070e55ed1c3a83c6
)

vcpkg_extract_source_archive(
    JSON_SOURCE_PATH
    ARCHIVE ${JSON_ARCHIVE}
)

vcpkg_extract_source_archive(
    METAL_CPP_SOURCE_PATH
    ARCHIVE ${METAL_CPP_ARCHIVE}
)

vcpkg_extract_source_archive(
    GGUFLIB_SOURCE_PATH
    ARCHIVE ${GGUFLIB_ARCHIVE}
)

vcpkg_cmake_configure(
    SOURCE_PATH ${SOURCE_PATH}
    OPTIONS
        -DFETCHCONTENT_SOURCE_DIR_GGUFLIB=${GGUFLIB_SOURCE_PATH}
        -DFETCHCONTENT_SOURCE_DIR_JSON=${JSON_SOURCE_PATH}
        -DFETCHCONTENT_SOURCE_DIR_METAL_CPP=${METAL_CPP_SOURCE_PATH}
        -DMLX_BUILD_TESTS=OFF
        -DUSE_SYSTEM_FMT=ON
)

vcpkg_cmake_install()

vcpkg_cmake_config_fixup(
  PACKAGE_NAME MLX
  CONFIG_PATH share/cmake/MLX
)

vcpkg_cmake_config_fixup(
    PACKAGE_NAME jaccl
    CONFIG_PATH lib/cmake/jaccl
)

file(
  REMOVE_RECURSE
  "${CURRENT_PACKAGES_DIR}/debug/include"
  "${CURRENT_PACKAGES_DIR}/debug/share"
  "${CURRENT_PACKAGES_DIR}/include/mlx/backend/cuda/binary"
  "${CURRENT_PACKAGES_DIR}/include/mlx/backend/cuda/copy"
  "${CURRENT_PACKAGES_DIR}/include/mlx/backend/cuda/reduce"
  "${CURRENT_PACKAGES_DIR}/include/mlx/backend/cuda/steel"
  "${CURRENT_PACKAGES_DIR}/include/mlx/backend/cuda/unary"
  "${CURRENT_PACKAGES_DIR}/include/mlx/backend/no_cpu"
  "${CURRENT_PACKAGES_DIR}/include/mlx/distributed/jaccl/lib/examples"
)

vcpkg_install_copyright(FILE_LIST ${SOURCE_PATH}/LICENSE)

#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Kaito Udagawa <umireon@kaito.tokyo>
#
# SPDX-License-Identifier: Apache-2.0

# file: scripts/build_ort_macos.sh
# description: Self-contained script to build ONNX Runtime for macOS.
# author: Kaito Udagawa <umireon@kaito.tokyo>
# version: 1.0.0
# date: 2026-04-01

set -euo pipefail
shopt -s nullglob

ORT_VERSION="${ORT_VERSION:-v1.24.1}"
OSX_DEPLOY_TARGET="${OSX_DEPLOY_TARGET:-12.0}"

cd "$(dirname "${BASH_SOURCE[0]}")/.."

ORT_COMPONENTS=(
  onnxruntime_session
  onnxruntime_optimizer
  onnxruntime_providers
  onnxruntime_lora
  onnxruntime_framework
  onnxruntime_graph
  onnxruntime_util
  onnxruntime_mlas
  onnxruntime_common
  onnxruntime_flatbuffers
  onnxruntime_providers_coreml
  coreml_proto
)

BUILD_PY="./.deps_vendor/onnxruntime/tools/ci_build/build.py"

BUILD_PY_ARGS=(
  --apple_deploy_target "${OSX_DEPLOY_TARGET}"
  --compile_no_warning_as_error
  --config Release
  --disable_rtti
  --parallel
  --skip_submodule_sync
  --skip_tests
  --use_coreml
  --use_vcpkg

  --cmake_extra_defines
  "CMAKE_OSX_DEPLOYMENT_TARGET=${OSX_DEPLOY_TARGET}"
  "CMAKE_PROJECT_INCLUDE_BEFORE=$(pwd)/scripts/no_install.cmake"
  CMAKE_POLICY_VERSION_MINIMUM=3.5

  --targets "${ORT_COMPONENTS[@]}" cpuinfo kleidiai
)

if [[ -f "./src/required_operators_and_types.with_runtime_opt.config" ]]; then
  BUILD_PY_ARGS+=(
    --include_ops_by_config "$(pwd)/src/required_operators_and_types.with_runtime_opt.config"
    --enable_reduced_operator_type_support
  )
fi

clone() {
	local -r ORT_SRC_DIR="./.deps_vendor/onnxruntime"
  if ! [[ -d "${ORT_SRC_DIR}" ]]; then
    git clone --filter "blob:none" --branch "${ORT_VERSION}" https://github.com/microsoft/onnxruntime.git "${ORT_SRC_DIR}"
  fi
	(
		cd "${ORT_SRC_DIR}"
		git checkout "${ORT_VERSION}"
		git submodule update --init --recursive --depth 1
	)
}

ensure_ort_src() {
	if ! [[ -d "./.deps_vendor/onnxruntime" ]]; then
		echo "ERROR: ONNX Runtime tree is not found." >&2
		exit 1
	fi
}

configure_arm64() {
	ensure_ort_src
  python3 "${BUILD_PY}" --update --build_dir "./.deps_vendor/ort_arm64" --osx_arch arm64 "${BUILD_PY_ARGS[@]}"
}

build_arm64() {
	ensure_ort_src
  python3 "${BUILD_PY}" --build --build_dir "./.deps_vendor/ort_arm64" --osx_arch arm64 "${BUILD_PY_ARGS[@]}"
}

configure_x86_64() {
	ensure_ort_src
  python3 "${BUILD_PY}" --update --build_dir "./.deps_vendor/ort_x86_64" --osx_arch x86_64 "${BUILD_PY_ARGS[@]}"
}

build_x86_64() {
	ensure_ort_src
  python3 "${BUILD_PY}" --build --build_dir "./.deps_vendor/ort_x86_64" --osx_arch x86_64 "${BUILD_PY_ARGS[@]}"
}

lipo_vcpkg() {
  local -r VCPKG_INSTALLED_ARM64="$1"
  local -r VCPKG_INSTALLED_X86_64="$2"
  local VCPKG_INSTALLED_UNIVERSAL="$3"

  rm -rf "${VCPKG_INSTALLED_UNIVERSAL}"
  mkdir -p "${VCPKG_INSTALLED_UNIVERSAL}"/{debug/lib/pkgconfig,include,lib/pkgconfig,share}

  cp -a "${VCPKG_INSTALLED_ARM64}/include/." "${VCPKG_INSTALLED_UNIVERSAL}/include/"
  cp -a "${VCPKG_INSTALLED_ARM64}/lib/pkgconfig/." "${VCPKG_INSTALLED_UNIVERSAL}/lib/pkgconfig/"
  cp -a "${VCPKG_INSTALLED_ARM64}/share/." "${VCPKG_INSTALLED_UNIVERSAL}/share/"

  local lib
  for lib in "${VCPKG_INSTALLED_ARM64}/lib/"*.a; do
    local name="${lib##*/}"

		if ! [[ -f "${VCPKG_INSTALLED_X86_64}/lib/${name}" ]]; then
		  echo "ERROR: ${name} does not exist for x86_64." >&2
			exit 1
		fi

    lipo \
      "${VCPKG_INSTALLED_ARM64}/lib/${name}" \
      "${VCPKG_INSTALLED_X86_64}/lib/${name}" \
      -create \
      -output "${VCPKG_INSTALLED_UNIVERSAL}/lib/${name}"
  done

  if [[ -d "${VCPKG_INSTALLED_ARM64}/debug" ]]; then
    cp -a "${VCPKG_INSTALLED_ARM64}/debug/lib/pkgconfig/." "${VCPKG_INSTALLED_UNIVERSAL}/debug/lib/pkgconfig/"

    local lib
    for lib in "${VCPKG_INSTALLED_ARM64}/debug/lib/"*.a; do
      local name="${lib##*/}"

			if ! [[ -f "${VCPKG_INSTALLED_X86_64}/debug/lib/${name}" ]]; then
				echo "ERROR: ${name} does not exist for x86_64." >&2
				exit 1
			fi

      lipo \
        "${VCPKG_INSTALLED_ARM64}/debug/lib/$name" \
        "${VCPKG_INSTALLED_X86_64}/debug/lib/$name" \
        -create \
        -output "${VCPKG_INSTALLED_UNIVERSAL}/debug/lib/$name"
    done
  fi

  if [[ -d "${VCPKG_INSTALLED_ARM64}/tools" ]]; then
    mkdir -p "${VCPKG_INSTALLED_UNIVERSAL}/tools"
    cp -a "${VCPKG_INSTALLED_ARM64}/tools/." "${VCPKG_INSTALLED_UNIVERSAL}/tools/"
  fi
}

lipo_ort_vcpkg() {
  lipo_vcpkg \
    "./.deps_vendor/ort_arm64/vcpkg_installed/osx-arm64" \
    "./.deps_vendor/ort_x86_64/vcpkg_installed/osx-x86_64" \
    "./.deps_vendor/ort_vcpkg_installed/osx-universal"
}

lipo_ort() {
  local -r ORT_ARM64_DIR="./.deps_vendor/ort_arm64/Release"
  local -r ORT_X86_64_DIR="./.deps_vendor/ort_x86_64/Release"
  local -r LIB_DIR="./.deps_vendor/lib"

  rm -rf "${LIB_DIR}"
  mkdir -p "${LIB_DIR}"

  local name
  for name in "${ORT_COMPONENTS[@]}"; do
    lipo -create \
      "${ORT_ARM64_DIR}/lib$name.a" \
      "${ORT_X86_64_DIR}/lib$name.a" \
      -output "${LIB_DIR}/lib$name.a"
  done

  lipo -create \
    "${ORT_ARM64_DIR}/_deps/pytorch_cpuinfo-build/libcpuinfo.a" \
    "${ORT_X86_64_DIR}/_deps/pytorch_cpuinfo-build/libcpuinfo.a" \
    -output "${LIB_DIR}/libcpuinfo.a"

  echo 'void __attribute__((visibility("hidden"))) __dummy__(){}' |
    clang -x c -arch x86_64 -c -o "${ORT_X86_64_DIR}/dummy.o" -mmacosx-version-min="${OSX_DEPLOY_TARGET}" -

  libtool -static -o "${ORT_X86_64_DIR}/dummy.a" "${ORT_X86_64_DIR}/dummy.o"

  lipo -create \
    "${ORT_ARM64_DIR}/_deps/kleidiai-build/libkleidiai.a" \
    "${ORT_X86_64_DIR}/dummy.a" \
    -output "${LIB_DIR}/libkleidiai.a"
}

if [[ "$#" -eq 0 ]]; then
  clone
  configure_arm64
  build_arm64
  configure_x86_64
  build_x86_64
  lipo_ort_vcpkg
  lipo_ort
else
  "$@"
fi

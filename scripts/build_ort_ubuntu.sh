#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Kaito Udagawa <umireon@kaito.tokyo>
#
# SPDX-License-Identifier: Apache-2.0

# file: scripts/build_ort_ubuntu.sh
# description: Self-contained script to build ONNX Runtime for Ubuntu.
# author: Kaito Udagawa <umireon@kaito.tokyo>
# version: 1.0.1
# date: 2026-04-01

set -euo pipefail
shopt -s nullglob

ORT_VERSION="${ORT_VERSION:-v1.24.4}"

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
)

BUILD_PY="./.deps_vendor/onnxruntime/tools/ci_build/build.py"

BUILD_PY_ARGS=(
  --compile_no_warning_as_error
  --config Release
  --disable_rtti
  --parallel
  --skip_submodule_sync
  --skip_tests
  --use_vcpkg

  --cmake_extra_defines
  CMAKE_POLICY_VERSION_MINIMUM=3.5
  "CMAKE_PROJECT_INCLUDE_BEFORE=$(pwd)/scripts/no_install.cmake"

  --targets "${ORT_COMPONENTS[@]}"
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
    git clone --filter "blob:none" --depth 1 --branch "${ORT_VERSION}" https://github.com/microsoft/onnxruntime.git "${ORT_SRC_DIR}"
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

enable_ccache() {
  BUILD_PY_ARGS+=(--use_ccache)
}

configure_x86_64() {
  ensure_ort_src
  [[ -n "${CCACHE_DIR:-}" ]] && enable_ccache
  python3 "${BUILD_PY}" --update --build_dir "./.deps_vendor/ort_x86_64" "${BUILD_PY_ARGS[@]}"
}

build_x86_64() {
  ensure_ort_src
  [[ -n "${CCACHE_DIR:-}" ]] && enable_ccache
  python3 "${BUILD_PY}" --build --build_dir "./.deps_vendor/ort_x86_64" "${BUILD_PY_ARGS[@]}"
}

install_ort_vcpkg_x86_64() {
  local -r ORT_VCPKG_INSTALLED_DIR="./.deps_vendor/ort_vcpkg_installed/x64-linux"

  rm -rf "${ORT_VCPKG_INSTALLED_DIR}"
  mkdir -p "${ORT_VCPKG_INSTALLED_DIR}"

  cp -a "./.deps_vendor/ort_x86_64/Release/vcpkg_installed/x64-linux/." "${ORT_VCPKG_INSTALLED_DIR}/"
}

install_ort_x86_64() {
  local -r ORT_LIB_DIR="./.deps_vendor/ort_lib"

  rm -rf "${ORT_LIB_DIR}"
  mkdir -p "${ORT_LIB_DIR}"

  for name in "${ORT_COMPONENTS[@]}"; do
    cp -a "./.deps_vendor/ort_x86_64/Release/lib$name.a" "${ORT_LIB_DIR}/"
  done
}

if [[ "$#" -eq 0 ]]; then
  bash "${BASH_SOURCE[0]}" clone
  bash "${BASH_SOURCE[0]}" configure_x86_64
  bash "${BASH_SOURCE[0]}" build_x86_64
  bash "${BASH_SOURCE[0]}" install_ort_vcpkg_x86_64
  bash "${BASH_SOURCE[0]}" install_ort_x86_64
else
  "$@"
fi

#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Kaito Udagawa <umireon@kaito.tokyo>
#
# SPDX-License-Identifier: Apache-2.0

# file: scripts/build_ort_ubuntu.sh
# description: Self-contained script to build ONNX Runtime for Ubuntu.
# author: Kaito Udagawa <umireon@kaito.tokyo>
# version: 1.0.1
# date: 2026-04-02

set -euo pipefail
shopt -s nullglob

ORT_VERSION="${ORT_VERSION:-v1.24.4}"
PYTHON="${PYTHON:-python3}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORT_SRC_DIR="${ROOT_DIR}/.deps_vendor/onnxruntime"
BUILD_PY="${ORT_SRC_DIR}/tools/ci_build/build.py"
REDUCED_OPS_CONFIG="${ROOT_DIR}/src/required_operators_and_types.with_runtime_opt.config"
ORT_X86_64_BUILD_DIR="${ROOT_DIR}/.deps_vendor/ort_x86_64"
ORT_X86_64_VCPKG_INSTALLED_DIR="${ROOT_DIR}/.deps_vendor/ort_vcpkg_installed/x64-linux"
ORT_X86_64_LIB_DIR="${ROOT_DIR}/.deps_vendor/ort_lib_x86_64"

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

BUILD_PY_ARGS=(
  --compile_no_warning_as_error
  --config Release
  --disable_rtti
  --parallel
  --skip_submodule_sync
  --skip_tests
  --use_vcpkg
)

if [[ -f "${REDUCED_OPS_CONFIG}" ]]; then
  BUILD_PY_ARGS+=(
    --include_ops_by_config "${REDUCED_OPS_CONFIG}"
    --enable_reduced_operator_type_support
  )
fi

BUILD_PY_CMAKE_EXTRA_DEFINES=(
  "CMAKE_POLICY_VERSION_MINIMUM=3.5"
  "CMAKE_PROJECT_INCLUDE_BEFORE=${ROOT_DIR}/scripts/no_install.cmake"
)

BUILD_PY_ARGS_CCACHE=()

clone() {
  if ! [[ -d "${ORT_SRC_DIR}" ]]; then
    git clone --filter 'blob:none' --depth 1 --branch "${ORT_VERSION}" https://github.com/microsoft/onnxruntime.git "${ORT_SRC_DIR}"
  fi
  (
    cd "${ORT_SRC_DIR}"
    git checkout "${ORT_VERSION}"
    git submodule update --init --recursive --filter 'blob:none' --depth 1
  )
}

ensure_ort_src() {
  if ! [[ -d "${ORT_SRC_DIR}" ]]; then
    echo "ERROR: ONNX Runtime tree is not found." >&2
    exit 1
  fi
}

enable_ccache() {
  BUILD_PY_ARGS_CCACHE=(--use_cache)
}

configure_x86_64() {
  ensure_ort_src

  if [[ -n "${CCACHE_DIR:-}" ]]; then
    enable_ccache
  fi

  local cmd=(
    "${PYTHON}"
    "${BUILD_PY}"
    --update
    --build_dir "${ORT_X86_64_BUILD_DIR}"
    "${BUILD_PY_ARGS[@]}"
    --cmake_extra_defines "${BUILD_PY_CMAKE_EXTRA_DEFINES[@]}"
    --targets "${ORT_COMPONENTS[@]}"
  )

  if [[ "${#BUILD_PY_ARGS_CCACHE[@]}" -gt 0 ]]; then
    cmd+=("${BUILD_PY_ARGS_CCACHE[@]}")
  fi

  "${cmd[@]}"
}

build_x86_64() {
  ensure_ort_src

  if [[ -n "${CCACHE_DIR:-}" ]]; then
    enable_ccache
  fi

  local cmd=(
    "${PYTHON}"
    "${BUILD_PY}"
    --build
    --build_dir "${ORT_X86_64_BUILD_DIR}"
    "${BUILD_PY_ARGS[@]}"
    --cmake_extra_defines "${BUILD_PY_CMAKE_EXTRA_DEFINES[@]}"
    --targets "${ORT_COMPONENTS[@]}"
  )

  if [[ "${#BUILD_PY_ARGS_CCACHE[@]}" -gt 0 ]]; then
    cmd+=("${BUILD_PY_ARGS_CCACHE[@]}")
  fi

  "${cmd[@]}"
}

install_ort_vcpkg_x86_64() {
  rm -rf "${ORT_X86_64_VCPKG_INSTALLED_DIR}"
  mkdir -p "${ORT_X86_64_VCPKG_INSTALLED_DIR}"

  cp -a "${ORT_X86_64_BUILD_DIR}/Release/vcpkg_installed/x64-linux/." "${ORT_X86_64_VCPKG_INSTALLED_DIR}/"
}

install_ort_x86_64() {
  rm -rf "${ORT_X86_64_LIB_DIR}"
  mkdir -p "${ORT_X86_64_LIB_DIR}"

  local name
  for name in "${ORT_COMPONENTS[@]}"; do
    cp -a "${ORT_X86_64_BUILD_DIR}/Release/lib$name.a" "${ORT_X86_64_LIB_DIR}/"
  done
}

if [[ "$#" -eq 0 ]]; then
  clone
  configure_x86_64
  build_x86_64
  install_ort_vcpkg_x86_64
  install_ort_x86_64
else
  "$@"
fi

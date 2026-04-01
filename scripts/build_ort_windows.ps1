# SPDX-FileCopyrightText: 2026 Kaito Udagawa <umireon@kaito.tokyo>
#
# SPDX-License-Identifier: Apache-2.0

# file: scripts/build_ort_windows.ps1
# description: Self-contained script to build ONNX Runtime for Windows x64.
# author: Kaito Udagawa <umireon@kaito.tokyo>
# version: 1.0.1
# date: 2026-04-01

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$PSNativeCommandUseErrorActionPreference = $true

$ORT_VERSION = if ($env:ORT_VERSION) { $env:ORT_VERSION } else { 'v1.24.4' }

Push-Location (Split-Path -Path $PSScriptRoot -Parent)

$ORT_COMPONENTS = @(
  'onnxruntime_session',
  'onnxruntime_optimizer',
  'onnxruntime_providers',
  'onnxruntime_lora',
  'onnxruntime_framework',
  'onnxruntime_graph',
  'onnxruntime_util',
  'onnxruntime_mlas',
  'onnxruntime_common',
  'onnxruntime_flatbuffers'
)

$BUILD_PY = '.deps_vendor/onnxruntime/tools/ci_build/build.py'

$BUILD_PY_ARGS = @(
  '--config', 'Release',
  '--parallel',
  '--compile_no_warning_as_error',
  '--disable_rtti',
  '--skip_submodule_sync',
  '--skip_tests',
  '--use_vcpkg',

  '--cmake_extra_defines',
  "CMAKE_PROJECT_INCLUDE_BEFORE=$((Get-Location).Path)/scripts/no_install.cmake",
  "CMAKE_POLICY_VERSION_MINIMUM=3.5",

  '--targets'
)

$BUILD_PY_ARGS += $ORT_COMPONENTS

if (Test-Path 'src/required_operators_and_types.with_runtime_opt.config') {
  $BUILD_PY_ARGS += @(
    '--include_ops_by_config', 'src/required_operators_and_types.with_runtime_opt.config',
    '--enable_reduced_operator_type_support'
  )
}

function clone() {
  $ORT_SRC_DIR = '.deps_vendor/onnxruntime'

  if (!(Test-Path $ORT_SRC_DIR)) {
    git clone --filter 'blob:none' --depth 1 --branch "$ORT_VERSION" https://github.com/microsoft/onnxruntime.git "$ORT_SRC_DIR"
  }

  Push-Location $ORT_SRC_DIR
  try {
    git checkout "$ORT_VERSION"
    git submodule update --init --recursive --depth 1
  }
  catch {
    throw
  }
  finally {
    Pop-Location
  }
}
function ensure_ort_src() {
  if (!(Test-Path -Path '.deps_vendor/onnxruntime' -PathType Container)) {
    Write-Error 'ERROR: ONNX Runtime tree is not found.'
    exit 1
  }
}

function enable_ccache() {
  $WRAPPER_DIR = './.deps_vendor/wrapper'

  if (!(Test-Path $WRAPPER_DIR)) {
    New-Item -ItemType Directory -Path $WRAPPER_DIR
  }

  $WRAPPER_CL_EXE = Join-Path $WRAPPER_DIR 'cl.exe'

  $ccacheCommand = Get-Command ccache.exe -ErrorAction SilentlyContinue
  if (-not $ccacheCommand) {
    Write-Error 'ERROR: ccache.exe was not found.'
    exit 1
  }
  $CCACHE_PROGRAM_PATH = $ccacheCommand.Source

  if (Test-Path $WRAPPER_CL_EXE) {
    Remove-Item -Path $WRAPPER_CL_EXE -Force -ErrorAction SilentlyContinue
  }

  Copy-Item -Path $CCACHE_PROGRAM_PATH -Destination $WRAPPER_CL_EXE -Force

  $script:BUILD_PY_ARGS += @(
    '--use_ccache',
    '--cmake_extra_defines',
    "CMAKE_VS_GLOBALS=UseMultiToolTask=true;EnforceProcessCountAcrossBuilds=true;TrackFileAccess=false;CLToolExe=cl.exe;CLToolPath=$(Join-Path (Get-Location) '.deps_vendor/wrapper')"
  )
}

function configure_x64() {
  ensure_ort_src
  if ($env:CCACHE_DIR) { enable_ccache }
  python "$BUILD_PY" --update --build_dir .deps_vendor/ort_x64 @BUILD_PY_ARGS
}

function build_x64() {
  ensure_ort_src
  if ($env:CCACHE_DIR) { enable_ccache }
  python "$BUILD_PY" --build --build_dir .deps_vendor/ort_x64 @BUILD_PY_ARGS
}

function install_ort_vcpkg_x64() {
  $ORT_VCPKG_INSTALLED_DIR = '.deps_vendor/ort_vcpkg_installed/x64-windows-static-md'

  Remove-Item -Path $ORT_VCPKG_INSTALLED_DIR -Recurse -Force -ErrorAction SilentlyContinue
  New-Item -ItemType Directory -Path $ORT_VCPKG_INSTALLED_DIR -Force

  Copy-Item -Path ./.deps_vendor/ort_x64/Release/vcpkg_installed/x64-windows-static-md/* -Destination $ORT_VCPKG_INSTALLED_DIR -Recurse -Force
}

function install_ort_x64() {
  $ORT_LIB_DIR = '.deps_vendor/ort_lib'

  Remove-Item -Path $ORT_LIB_DIR -Recurse -Force -ErrorAction SilentlyContinue
  New-Item -ItemType Directory -Path $ORT_LIB_DIR -Force

  foreach ($name in $ORT_COMPONENTS) {
    Copy-Item -Path ".deps_vendor/ort_x64/Release/Release/$name.lib" -Destination $ORT_LIB_DIR -Force
  }
}

try {
  if ($args.Count -eq 0) {
    & $PSCommandPath clone
    & $PSCommandPath configure_x64
    & $PSCommandPath build_x64
    & $PSCommandPath install_ort_vcpkg_x64
    & $PSCommandPath install_ort_x64
  } else {
    & $args[0]
  }
} finally {
  Pop-Location
}

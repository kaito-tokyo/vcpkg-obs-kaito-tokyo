# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
set(VCPKG_TARGET_ARCHITECTURE arm64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)
set(VCPKG_C_FLAGS "/MP /DWIN32 /D_WINDOWS")
set(VCPKG_CXX_FLAGS "/MP /DWIN32 /D_WINDOWS /Zc:__cplusplus /EHsc /GR- /we4541")
list(APPEND VCPKG_CMAKE_CONFIGURE_OPTIONS --compile-no-warning-as-error -DCMAKE_CXX_STANDARD=17)
set(VCPKG_BUILD_TYPE release)
if(PORT MATCHES "benchmark")
    list(APPEND VCPKG_CMAKE_CONFIGURE_OPTIONS
        "-DBENCHMARK_ENABLE_WERROR=OFF"
    )

endif()  # benchmark
if(PORT MATCHES "date")
    list(APPEND VCPKG_CMAKE_CONFIGURE_OPTIONS
        "-DENABLE_DATE_TESTING=OFF"
        "-DBUILD_TZ_LIB=OFF"
        "-DUSE_SYSTEM_TZ_DB=ON"
    )
endif()
if(PORT MATCHES "onnx")
    list(APPEND VCPKG_CMAKE_CONFIGURE_OPTIONS
        "-DONNX_DISABLE_STATIC_REGISTRATION=ON"
    )
    
    list(APPEND VCPKG_CMAKE_CONFIGURE_OPTIONS
        "-DONNX_USE_LITE_PROTO=ON"
    )
endif() # End ONNX-specific block

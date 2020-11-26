cmake_minimum_required (VERSION 2.8)
project (Ariolinux84)

include (TargetArch.cmake)

target_architecture (ARCH)
MESSAGE( STATUS "Target architecture is: " ${ARCH} )

SET(CMAKE_SKIP_BUILD_RPATH FALSE)
SET(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
SET(CMAKE_INSTALL_RPATH "./")
SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

set(SOURCE
        http/http.cpp http/http.h
        http/client.cpp http/client.h
        http/civetweb/civetweb.c http/civetweb/CivetServer.cpp
        http/simplejson/json.h
        linux84/linux84.cpp linux84/linux84.h
        proxy/proxy.cpp proxy/proxy.h
        app/main.cpp
        http/http_parser/http_parser.c http/http_parser/http_parser.h
        linux84/mini-gmp/mini-gmp.h linux84/mini-gmp/mini-gmp.c
        autotune/autotune.cpp autotune/autotune.h
        app/runner.h
        linux84/linux84_api.cpp linux84/linux84_api.h http/pool_settings_provider.cpp http/pool_settings_provider.h http/simplejson/json.cpp proxy/proxy_server.cpp proxy/proxy_server.h http/node_api.cpp http/node_api.h)
set(SOURCE_COMMON app/arguments.cpp app/arguments.h common/common.h common/common.cpp common/dllimport.h common/dllexport.h
        crypt/sha512.cpp crypt/sha512.h crypt/base64.cpp crypt/base64.h crypt/random_generator.cpp crypt/random_generator.h
        common/cfgpath.h)
set(SOURCE_linux8474 linux8474/linux8474.cpp linux8474/linux8474.h linux8474/argon2/argon2.cpp linux8474/argon2/argon2.h
        linux8474/argon2/defs.h linux8474/argon2/blake2/blake2b.c linux8474/argon2/blake2/blake2.h linux8474/argon2/blake2/blake2b-round.h
        linux8474/argon2/blake2/blake2b-load-sse41.h linux8474/argon2/blake2/blake2b-load-sse2.h linux8474/argon2/blake2/blake2-config.h
        linux8474/argon2/argon2profile_4_4_16384.c linux8474/argon2/argon2profile_1_1_524288.c)
set(SOURCE_CPU_linux8474 linux8474/cpu/cpu_linux8474.cpp linux8474/cpu/cpu_linux8474.h)
set(SOURCE_OPENCL_linux8474 linux8474/gpu/opencl/opencl_linux8474.cpp linux8474/gpu/opencl/opencl_linux8474.h
        linux8474/gpu/opencl/opencl_kernel.cpp linux8474/gpu/opencl/opencl_kernel.h)
set(SOURCE_CUDA_linux8474 linux8474/gpu/cuda/cuda_linux8474.cpp linux8474/gpu/cuda/cuda_linux8474.h
        linux8474/gpu/cuda/cuda_kernel.cu)
set(SOURCE_AMDGCN_linux8474 linux8474/gpu/amdgcn/amdgcn_linux8474.cpp linux8474/gpu/amdgcn/amdgcn_linux8474.h
        linux8474/gpu/amdgcn/amdgcn_kernel.cpp linux8474/gpu/amdgcn/amdgcn_kernel.h)
set(ARGON2_FILL_BLOCKS_SRC
        linux8474/cpu/argon2_opt/implementation.c
        linux8474/cpu/argon2_opt/blamka-round-opt.h
        linux8474/cpu/argon2_opt/blamka-round-ref.h
        linux8474/argon2/defs.h
        linux8474/argon2/blake2/blake2-impl.h)

set (CMAKE_CXX_STANDARD 11)
set (Ariolinux84_VERSION_MAJOR 0)
set (Ariolinux84_VERSION_MINOR 2)
set (Ariolinux84_VERSION_REVISION 0)

set (CMAKE_MACOSX_RPATH 0)

configure_file (
        "${PROJECT_SOURCE_DIR}/config.h.in"
        "${PROJECT_BINARY_DIR}/config.h"
)

include_directories("${PROJECT_BINARY_DIR}")
include_directories(linux8474/cpu/cpu_features/include)
if(WIN32)
    include_directories(win64/include)
    list(APPEND SOURCE_COMMON win64/src/dlfcn.c win64/src/win64.c)
endif()

find_package(Threads)

add_subdirectory(linux8474/cpu/cpu_features)
set_property(TARGET cpu_features PROPERTY POSITION_INDEPENDENT_CODE ON)

add_executable(ariolinux84 ${SOURCE})
add_library(common SHARED ${SOURCE_COMMON})
add_library(linux8474 SHARED ${SOURCE_linux8474})
target_link_libraries(linux8474 common ${CMAKE_DL_LIBS} ${CMAKE_THREAD_LIBS_INIT})
if(WIN32)
    target_link_libraries(common Psapi.lib)
endif()
add_library(cpu_linux8474 MODULE ${SOURCE_CPU_linux8474})
set_target_properties(cpu_linux8474
        PROPERTIES
        PREFIX ""
        SUFFIX ".hsh"
        LIBRARY_OUTPUT_DIRECTORY modules
        )
target_link_libraries(cpu_linux8474 linux8474 cpu_features)
add_dependencies(ariolinux84 cpu_linux8474)

if(NOT WITHOUT_CUDA)
    add_definitions(-DWITH_CUDA)
    if(NOT WIN32)
        add_definitions(-DPARALLEL_CUDA)
    endif()
    find_package(CUDA REQUIRED)
    set(
            CUDA_NVCC_FLAGS
            ${CUDA_NVCC_FLAGS};
            -O3 -arch=compute_35 -std=c++11
    )
    cuda_add_library(cuda_linux8474 MODULE ${SOURCE_CUDA_linux8474})
    set_target_properties(cuda_linux8474
            PROPERTIES
            PREFIX ""
            SUFFIX ".hsh"
            LIBRARY_OUTPUT_DIRECTORY modules
            )
    target_link_libraries(cuda_linux8474 linux8474)
    add_dependencies(ariolinux84 cuda_linux8474)
endif()

if(NOT WITHOUT_OPENCL)
    add_definitions(-DWITH_OPENCL)
    find_package(OpenCL REQUIRED)
    include_directories(${OpenCL_INCLUDE_DIR})
    add_library(opencl_linux8474 MODULE ${SOURCE_OPENCL_linux8474})
    set_target_properties(opencl_linux8474
            PROPERTIES
            PREFIX ""
            SUFFIX ".hsh"
            LIBRARY_OUTPUT_DIRECTORY modules
            )
    target_link_libraries(opencl_linux8474 linux8474 ${OpenCL_LIBRARY})
    add_dependencies(ariolinux84 opencl_linux8474)

    if(NOT WITHOUT_AMDGCN)
        add_definitions(-DWITH_AMDGCN)
        list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/linux8474/gpu/amdgcn/CLRX/cmake")
        add_subdirectory("linux8474/gpu/amdgcn/CLRX")
        include_directories("linux8474/gpu/amdgcn/CLRX")
        include_directories("${PROJECT_BINARY_DIR}/linux8474/gpu/amdgcn/CLRX/")

        add_library(amdgcn_linux8474 MODULE ${SOURCE_AMDGCN_linux8474})
        set_target_properties(amdgcn_linux8474
                PROPERTIES
                PREFIX ""
                SUFFIX ".hsh"
                LIBRARY_OUTPUT_DIRECTORY modules
                )
        target_link_libraries(amdgcn_linux8474 linux8474 CLRXCLHelperStatic CLRXAmdAsmStatic
                CLRXAmdBinStatic CLRXUtilsStatic ${OpenCL_LIBRARY})
        add_dependencies(ariolinux84 amdgcn_linux8474)
    endif()
endif()

target_link_libraries(ariolinux84 common linux8474)
if(WIN32)
    target_link_libraries(ariolinux84 ws2_32.lib)
endif()
if(APPLE)
    set_target_properties(ariolinux84 PROPERTIES LINK_FLAGS "-framework CoreServices")
endif()

add_library(argon2_fill_blocks_REF MODULE ${ARGON2_FILL_BLOCKS_SRC})
set_target_properties(argon2_fill_blocks_REF
        PROPERTIES
        PREFIX ""
        SUFFIX ".opt"
        LIBRARY_OUTPUT_DIRECTORY modules
        )
target_compile_definitions(argon2_fill_blocks_REF PRIVATE BUILD_REF=1)
add_dependencies(ariolinux84 argon2_fill_blocks_REF)

if(ARCH STREQUAL "x86_64")
    add_library(argon2_fill_blocks_SSE2 MODULE ${ARGON2_FILL_BLOCKS_SRC})
    add_library(argon2_fill_blocks_SSSE3 MODULE ${ARGON2_FILL_BLOCKS_SRC})
    add_library(argon2_fill_blocks_AVX MODULE ${ARGON2_FILL_BLOCKS_SRC})
    add_library(argon2_fill_blocks_AVX2 MODULE ${ARGON2_FILL_BLOCKS_SRC})
    add_library(argon2_fill_blocks_AVX512F MODULE ${ARGON2_FILL_BLOCKS_SRC})
    set_target_properties(argon2_fill_blocks_REF argon2_fill_blocks_SSE2 argon2_fill_blocks_SSSE3 argon2_fill_blocks_AVX argon2_fill_blocks_AVX2 argon2_fill_blocks_AVX512F
            PROPERTIES
            PREFIX ""
            SUFFIX ".opt"
            LIBRARY_OUTPUT_DIRECTORY modules
            )
    target_compile_options(argon2_fill_blocks_SSE2 PRIVATE -msse2)
    target_compile_options(argon2_fill_blocks_SSSE3 PRIVATE -mssse3)
    target_compile_options(argon2_fill_blocks_AVX PRIVATE -mavx)
    target_compile_options(argon2_fill_blocks_AVX2 PRIVATE -mavx2)
    target_compile_options(argon2_fill_blocks_AVX512F PRIVATE -mavx512f)
    add_dependencies(ariolinux84 argon2_fill_blocks_SSE2 argon2_fill_blocks_SSSE3 argon2_fill_blocks_AVX argon2_fill_blocks_AVX2 argon2_fill_blocks_AVX512F)
endif(ARCH STREQUAL "x86_64")

if(ARCH STREQUAL "arm" OR ARCH STREQUAL "aarch64")
    add_library(argon2_fill_blocks_NEON MODULE ${ARGON2_FILL_BLOCKS_SRC})
    set_target_properties(argon2_fill_blocks_NEON
            PROPERTIES
            PREFIX ""
            SUFFIX ".opt"
            LIBRARY_OUTPUT_DIRECTORY modules
            )
    target_compile_options(common PRIVATE -D__NEON__)
    if(ARCH STREQUAL "arm")
       target_compile_options(argon2_fill_blocks_NEON PRIVATE -D__NEON__ -mfpu=neon -funsafe-math-optimizations)
    else()
       target_compile_options(argon2_fill_blocks_NEON PRIVATE -D__NEON__)
    endif(ARCH STREQUAL "arm")

    add_dependencies(ariolinux84 argon2_fill_blocks_NEON)
endif(ARCH STREQUAL "arm" OR ARCH STREQUAL "aarch64")

if(WIN32)
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /D_CRT_SECURE_NO_WARNINGS=1")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /D_CRT_SECURE_NO_WARNINGS=1")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /D_CRT_SECURE_NO_WARNINGS=1")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /D_CRT_SECURE_NO_WARNINGS=1")
endif()

add_custom_target(copy-reporting-files ALL
        COMMAND cmake -E copy_directory "${CMAKE_SOURCE_DIR}/proxy/reporting/dist" "${CMAKE_BINARY_DIR}/reporting")

add_dependencies(ariolinux84 copy-reporting-files)

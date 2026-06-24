vcpkg_check_linkage(ONLY_STATIC_LIBRARY)

# R-B12(a): pin the libyuv source by SHA512 of a deterministic capture, not a bare git REF
# (gitiles `+archive` is NON-reproducible; R-R1 forbids vendoring). online-fetch.sh's
# stage_vcpkg_distfiles writes a reproducible `git archive | gzip -n` of the pinned commit into
# ./online and this consumes it, SHA512-verified (scripts/pins.env: SHA512_LIBYUV); the full git
# commit SHA-1 is the upstream content anchor. Hosts without the ./online capture (Windows golden
# VM) fall back to the git-SHA-1 commit pin (git verifies the tree on checkout) — see aom portfile.
set(_libyuv_archive "/online/libyuv-0faf8dd0e004520a61a603a4d2996d5ecc80dc3f.tar.gz")
if(EXISTS "${_libyuv_archive}")
    vcpkg_download_distfile(_libyuv_tgz
        URLS "file://${_libyuv_archive}"
        FILENAME "libyuv-0faf8dd0.tar.gz"
        SHA512 be6b343ab6c62e8f2d1571fedf25f5facbf7cd7fe8e1cc4949dab7549ad15f962c91ea43bf567785e54382d7689514f6b66d61bd56b3f38ba54ef51c5fd0da9b
    )
    vcpkg_extract_source_archive(SOURCE_PATH
        ARCHIVE "${_libyuv_tgz}"
        NO_REMOVE_ONE_LEVEL
        PATCHES
            fix-cmakelists.patch
    )
else()
    vcpkg_from_git(
        OUT_SOURCE_PATH SOURCE_PATH
        URL https://chromium.googlesource.com/libyuv/libyuv
        REF 0faf8dd0e004520a61a603a4d2996d5ecc80dc3f
        # Check https://chromium.googlesource.com/libyuv/libyuv/+/refs/heads/main/include/libyuv/version.h for a version!
        PATCHES
            fix-cmakelists.patch
    )
endif()

vcpkg_cmake_get_vars(cmake_vars_file)
include("${cmake_vars_file}")
if (VCPKG_DETECTED_CMAKE_CXX_COMPILER_ID STREQUAL "MSVC" AND NOT VCPKG_TARGET_IS_UWP)
    # Most of libyuv accelerated features need to be compiled by clang/gcc, so force use clang-cl, otherwise the performance is too poor.
    # Manually build the port with clang-cl when using MSVC as compiler

    message(STATUS "Set compiler to clang-cl when using MSVC")

    # https://github.com/microsoft/vcpkg/pull/10398
    set(VCPKG_POLICY_SKIP_ARCHITECTURE_CHECK enabled)

    vcpkg_find_acquire_program(CLANG)
    if (CLANG MATCHES "-NOTFOUND")
        message(FATAL_ERROR "Clang is required.")
    endif ()
    get_filename_component(CLANG "${CLANG}" DIRECTORY)

    if(VCPKG_TARGET_ARCHITECTURE STREQUAL "arm")
        set(CLANG_TARGET "arm")
    elseif(VCPKG_TARGET_ARCHITECTURE STREQUAL "arm64")
        set(CLANG_TARGET "aarch64")
    elseif(VCPKG_TARGET_ARCHITECTURE STREQUAL "x86")
        set(CLANG_TARGET "i686")
    elseif(VCPKG_TARGET_ARCHITECTURE STREQUAL "x64")
        set(CLANG_TARGET "x86_64")
    else()
        message(FATAL_ERROR "Unsupported target architecture")
    endif()

    set(CLANG_TARGET "${CLANG_TARGET}-pc-windows-msvc")

    message(STATUS "Using clang target ${CLANG_TARGET}")
    string(APPEND VCPKG_DETECTED_CMAKE_CXX_FLAGS --target=${CLANG_TARGET})
    string(APPEND VCPKG_DETECTED_CMAKE_C_FLAGS --target=${CLANG_TARGET})

    set(BUILD_OPTIONS
            -DCMAKE_CXX_COMPILER=${CLANG}/clang-cl.exe
            -DCMAKE_C_COMPILER=${CLANG}/clang-cl.exe
            -DCMAKE_CXX_FLAGS=${VCPKG_DETECTED_CMAKE_CXX_FLAGS}
            -DCMAKE_C_FLAGS=${VCPKG_DETECTED_CMAKE_C_FLAGS})
endif ()

vcpkg_cmake_configure(
    SOURCE_PATH ${SOURCE_PATH}
    DISABLE_PARALLEL_CONFIGURE
    OPTIONS
        ${BUILD_OPTIONS}
    OPTIONS_DEBUG
        -DCMAKE_DEBUG_POSTFIX=d
)

vcpkg_cmake_install()
vcpkg_copy_pdbs()

vcpkg_cmake_config_fixup(CONFIG_PATH share/cmake/libyuv)

file(REMOVE_RECURSE ${CURRENT_PACKAGES_DIR}/debug/include)
file(REMOVE_RECURSE ${CURRENT_PACKAGES_DIR}/debug/share)

configure_file(${CMAKE_CURRENT_LIST_DIR}/libyuv-config.cmake ${CURRENT_PACKAGES_DIR}/share/${PORT} COPYONLY)
file(INSTALL ${SOURCE_PATH}/LICENSE DESTINATION ${CURRENT_PACKAGES_DIR}/share/${PORT} RENAME copyright)

vcpkg_cmake_get_vars(cmake_vars_file)
include("${cmake_vars_file}")
if (VCPKG_DETECTED_CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    message(WARNING "Use MSVC to compile libyuv results in a very slow library. (https://github.com/microsoft/vcpkg/issues/28446)")
    file(INSTALL "${CMAKE_CURRENT_LIST_DIR}/usage-msvc" DESTINATION "${CURRENT_PACKAGES_DIR}/share/${PORT}" RENAME "usage")
else ()
    file(INSTALL "${CMAKE_CURRENT_LIST_DIR}/usage" DESTINATION "${CURRENT_PACKAGES_DIR}/share/${PORT}")
endif ()

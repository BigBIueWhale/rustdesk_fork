# NASM is required to build AOM
vcpkg_find_acquire_program(NASM)
get_filename_component(NASM_EXE_PATH ${NASM} DIRECTORY)
vcpkg_add_to_path(${NASM_EXE_PATH})

# Perl is required to build AOM
vcpkg_find_acquire_program(PERL)
get_filename_component(PERL_PATH ${PERL} DIRECTORY)
vcpkg_add_to_path(${PERL_PATH})

if(DEFINED ENV{USE_AOM_391})
    vcpkg_from_git(
        OUT_SOURCE_PATH SOURCE_PATH
        URL "https://aomedia.googlesource.com/aom"
        REF 8ad484f8a18ed1853c094e7d3a4e023b2a92df28 # 3.9.1
        PATCHES
            aom-uninitialized-pointer.diff
            aom-avx2.diff
            aom-install.diff
    )
else()
    # R-B12(a): pin the aom 3.12.1 source by SHA512 of a deterministic capture, not a bare git
    # REF. gitiles `+archive` is empirically NON-reproducible (even the decompressed tar differs
    # between two fetches), so the tarball URL cannot be SHA-pinned; R-R1 forbids vendoring. So
    # online-fetch.sh's stage_vcpkg_distfiles writes a reproducible `git archive | gzip -n` of the
    # pinned commit into ./online and this consumes it, SHA512-verified. The full git commit SHA-1
    # is the upstream content anchor; SHA512 (scripts/pins.env: SHA512_AOM_3_12_1) binds the exact
    # captured bytes. Hosts without the ./online capture (e.g. the Windows golden VM) fall back to
    # the git-SHA-1 commit pin below (git verifies the tree on checkout) — the documented residual.
    set(_aom_archive "/online/aom-10aece4157eb79315da205f39e19bf6ab3ee30d0.tar.gz")
    if(EXISTS "${_aom_archive}")
        vcpkg_download_distfile(_aom_tgz
            URLS "file://${_aom_archive}"
            FILENAME "aom-10aece41-3.12.1.tar.gz"
            SHA512 59c3e3f3fbf649857fcba1af63593a06336377fed554f9696c1965580b95778ded76ac409b40589e1f44a94b9fea6df777b7c58760b7c3df6f8274b968b83a05
        )
        vcpkg_extract_source_archive(SOURCE_PATH
            ARCHIVE "${_aom_tgz}"
            NO_REMOVE_ONE_LEVEL
            PATCHES
                aom-uninitialized-pointer.diff
                aom-install.diff
        )
    else()
        vcpkg_from_git(
            OUT_SOURCE_PATH SOURCE_PATH
            URL "https://aomedia.googlesource.com/aom"
            REF 10aece4157eb79315da205f39e19bf6ab3ee30d0 # 3.12.1
            PATCHES
                aom-uninitialized-pointer.diff
                # aom-avx2.diff
                # Can be dropped when https://bugs.chromium.org/p/aomedia/issues/detail?id=3029 is merged into the upstream
                aom-install.diff
        )
    endif()
endif()

set(aom_target_cpu "")
if(VCPKG_TARGET_IS_UWP OR (VCPKG_TARGET_IS_WINDOWS AND VCPKG_TARGET_ARCHITECTURE MATCHES "^arm"))
    # UWP + aom's assembler files result in weirdness and build failures
    # Also, disable assembly on ARM and ARM64 Windows to fix compilation issues.
    set(aom_target_cpu "-DAOM_TARGET_CPU=generic")
endif()

if(VCPKG_TARGET_ARCHITECTURE STREQUAL "arm" AND VCPKG_TARGET_IS_LINUX)
  set(aom_target_cpu "-DENABLE_NEON=OFF")
endif()

vcpkg_cmake_configure(
    SOURCE_PATH ${SOURCE_PATH}
    OPTIONS
        ${aom_target_cpu}
        -DENABLE_DOCS=OFF
        -DENABLE_EXAMPLES=OFF
        -DENABLE_TESTDATA=OFF
        -DENABLE_TESTS=OFF
        -DENABLE_TOOLS=OFF
)

vcpkg_cmake_install()

vcpkg_copy_pdbs()

vcpkg_fixup_pkgconfig()

if(VCPKG_TARGET_IS_WINDOWS)
  vcpkg_replace_string("${CURRENT_PACKAGES_DIR}/lib/pkgconfig/aom.pc" " -lm" "")
  if(NOT VCPKG_BUILD_TYPE)
    vcpkg_replace_string("${CURRENT_PACKAGES_DIR}/debug/lib/pkgconfig/aom.pc" " -lm" "")
  endif()
endif()

# Move cmake configs
vcpkg_cmake_config_fixup(CONFIG_PATH lib/cmake/${PORT})

# Remove duplicate files
file(REMOVE_RECURSE ${CURRENT_PACKAGES_DIR}/debug/include
                    ${CURRENT_PACKAGES_DIR}/debug/share)

# Handle copyright
file(INSTALL ${SOURCE_PATH}/LICENSE DESTINATION ${CURRENT_PACKAGES_DIR}/share/${PORT} RENAME copyright)

vcpkg_fixup_pkgconfig()

cmake_minimum_required(VERSION 3.21)
project(emp-sh2pc VERSION 1.0.0 LANGUAGES CXX)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
    message(FATAL_ERROR
        "In-source builds are not allowed. Use a separate build directory:\n"
        "  cmake -B build && cmake --build build")
endif()

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
        Debug Release RelWithDebInfo MinSizeRel)
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# ---------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------
option(EMP_SH2PC_BUILD_TESTS "Build emp-sh2pc tests"            ${PROJECT_IS_TOP_LEVEL})
option(EMP_SH2PC_INSTALL     "Generate install / export rules"  ${PROJECT_IS_TOP_LEVEL})
option(ENABLE_FLOAT          "Build the Float test"             ON)

# ---------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------
# Local-dev tip: point at sibling build trees with
#   -Demp-tool_DIR=/path/to/emp-tool/build
#   -Demp-ot_DIR=/path/to/emp-ot/build
# emp-ot's package config already pulls in emp-tool::emp-tool transitively.
find_package(emp-ot 1.0 REQUIRED)

# ---------------------------------------------------------------------
# Library target (header-only)
# ---------------------------------------------------------------------
add_library(emp-sh2pc INTERFACE)
add_library(emp-sh2pc::emp-sh2pc ALIAS emp-sh2pc)

# sh2pc_session.h publicly includes the C++20 BooleanContext surface
# (emp-tool/circuits/{context,typed}.h), so consumers must build as C++20.
target_compile_features(emp-sh2pc INTERFACE cxx_std_20)

target_include_directories(emp-sh2pc INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

target_link_libraries(emp-sh2pc INTERFACE emp-ot::emp-ot)

# ---------------------------------------------------------------------
# Install + export
# ---------------------------------------------------------------------
if(EMP_SH2PC_INSTALL)
    set(_cmake_install_dir ${CMAKE_INSTALL_LIBDIR}/cmake/emp-sh2pc)

    install(TARGETS emp-sh2pc EXPORT emp-sh2pcTargets)

    install(DIRECTORY emp-sh2pc
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        FILES_MATCHING
            PATTERN "*.h")

    install(EXPORT emp-sh2pcTargets
        NAMESPACE   emp-sh2pc::
        DESTINATION ${_cmake_install_dir}
        FILE        emp-sh2pcTargets.cmake)

    configure_package_config_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/emp-sh2pc-config.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/emp-sh2pc-config.cmake
        INSTALL_DESTINATION ${_cmake_install_dir})

    write_basic_package_version_file(
        ${CMAKE_CURRENT_BINARY_DIR}/emp-sh2pc-config-version.cmake
        VERSION       ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion)

    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/emp-sh2pc-config.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/emp-sh2pc-config-version.cmake
        DESTINATION ${_cmake_install_dir})
endif()

# Build-tree export so siblings can consume without `make install`. Use the
# export(TARGETS ...) form (not export(EXPORT ...)) so it works regardless of
# whether install rules registered an export set (EMP_SH2PC_INSTALL=OFF).
export(TARGETS emp-sh2pc
       NAMESPACE emp-sh2pc::
       FILE      ${CMAKE_CURRENT_BINARY_DIR}/emp-sh2pcTargets.cmake)

# ---------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------
if(EMP_SH2PC_BUILD_TESTS)
    include(CTest)
    add_subdirectory(test)
endif()

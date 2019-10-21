CMAKE_MINIMUM_REQUIRED(VERSION 3.10)
PROJECT(libtins)

OPTION(LIBTINS_BUILD_EXAMPLES "Build examples" ON)
OPTION(LIBTINS_BUILD_TESTS "Build tests" ON)
OPTION(LIBTINS_ENABLE_BENCH "Build benchmark" OFF)
OPTION(LIBTINS_ENABLE_STATIC "Enable static analysis" ON)

# Compile in release mode by default
IF(NOT CMAKE_BUILD_TYPE)
    MESSAGE(STATUS "Setting build type to 'RelWithDebInfo' as none was specified.")
    SET(CMAKE_BUILD_TYPE RelWithDebInfo)
ELSE(NOT CMAKE_BUILD_TYPE)
    MESSAGE(STATUS "Using specified '${CMAKE_BUILD_TYPE}' build type.")
ENDIF(NOT CMAKE_BUILD_TYPE)

# Build output checks
OPTION(LIBTINS_BUILD_SHARED "Build libtins as a shared library." ON)
IF(LIBTINS_BUILD_SHARED)
    MESSAGE(
        STATUS
        "Build will generate a shared library. "
        "Use LIBTINS_BUILD_SHARED=0 to perform a static build"
    )
    SET(LIBTINS_TYPE SHARED)
ELSE(LIBTINS_BUILD_SHARED)
    MESSAGE(STATUS "Build will generate a static library.")
    SET(LIBTINS_TYPE STATIC)
    ADD_DEFINITIONS("-DTINS_STATIC=1")
ENDIF(LIBTINS_BUILD_SHARED)

# The version number.
SET(TINS_VERSION_MAJOR 4)
SET(TINS_VERSION_MINOR 3)
SET(TINS_VERSION_PATCH 0)
SET(LIBTINS_VERSION "${TINS_VERSION_MAJOR}.${TINS_VERSION_MINOR}")

# Required Packages
SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules/")

# Allow disabling packet capture mechanism
OPTION(LIBTINS_ENABLE_PCAP "Enable capturing packets via libpcap" ON)

# Look for libpcap
IF(LIBTINS_ENABLE_PCAP)
    FIND_PACKAGE(PCAP REQUIRED)
    SET(TINS_HAVE_PCAP ON)
ENDIF()

INCLUDE(ExternalProject)

# *******************
# Compilation options
# *******************

IF(HAS_GCC_BUILTIN_SWAP)
    SET(TINS_HAVE_GCC_BUILTIN_SWAP ON)
ENDIF()

# C++17 support
MESSAGE(STATUS "Enabling C++17 features")
SET(CXX_STANDARD 17)

# IEEE 802.11 and WPA2 decryption support
OPTION(LIBTINS_ENABLE_DOT11 "Compile libtins with IEEE 802.11 support" ON)
OPTION(LIBTINS_ENABLE_WPA2 "Compile libtins with WPA2 decryption features (requires OpenSSL)" ON)
IF(LIBTINS_ENABLE_DOT11)
    SET(TINS_HAVE_DOT11 ON)
    MESSAGE(STATUS "Enabling IEEE 802.11 support.")
    IF(LIBTINS_ENABLE_WPA2)
        FIND_PACKAGE(OpenSSL)
        IF(OPENSSL_FOUND)
            SET(TINS_HAVE_WPA2_DECRYPTION ON)
            MESSAGE(STATUS "Enabling WPA2 decryption support.")
        ELSE()
            MESSAGE(WARNING "Disabling WPA2 decryption support since OpenSSL was not found")
            # Default this to empty strings
            SET(OPENSSL_INCLUDE_DIR "")
            SET(OPENSSL_LIBRARIES "")
        ENDIF()
    ELSE(LIBTINS_ENABLE_WPA2)
        MESSAGE(STATUS "Disabling WPA2 decryption support.")
    ENDIF(LIBTINS_ENABLE_WPA2)
ENDIF(LIBTINS_ENABLE_DOT11)

# Optionally enable TCPIP classes (on by default)
OPTION(LIBTINS_ENABLE_TCPIP "Enable TCPIP classes" ON)
IF(LIBTINS_ENABLE_TCPIP)
    SET(TINS_HAVE_TCPIP ON)
    MESSAGE(STATUS "Enabling TCPIP classes")
ELSE()
    SET(TINS_HAVE_TCPIP OFF)
    MESSAGE(STATUS "Disabling TCPIP classes")
ENDIF()

# Search for libboost
FIND_PACKAGE(Boost)

# Optionally enable the ACK tracker (on by default)
OPTION(LIBTINS_ENABLE_ACK_TRACKER "Enable TCP ACK tracking support" ON)
IF(LIBTINS_ENABLE_ACK_TRACKER)
    IF (Boost_FOUND)
        MESSAGE(STATUS "Enabling TCP ACK tracking support.")
        INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIRS})
        SET(TINS_HAVE_ACK_TRACKER ON)
    ELSE()
        MESSAGE(WARNING "Disabling ACK tracking support as boost.icl was not found")
        SET(TINS_HAVE_ACK_TRACKER OFF)
    ENDIF()
ELSE()
    SET(TINS_HAVE_ACK_TRACKER OFF)
    MESSAGE(STATUS "Disabling ACK tracking support")
ENDIF()

# Optionally enable the TCP stream custom data (on by default)
OPTION(LIBTINS_ENABLE_TCP_STREAM_CUSTOM_DATA "Enable TCP stream custom data support" ON)
IF(LIBTINS_ENABLE_TCP_STREAM_CUSTOM_DATA)
    IF (Boost_FOUND)
        MESSAGE(STATUS "Enabling TCP stream custom data support.")
        INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIRS})
        SET(TINS_HAVE_TCP_STREAM_CUSTOM_DATA ON)
    ELSE()
        MESSAGE(WARNING "Disabling TCP stream custom data support as boost.any was not found")
        SET(TINS_HAVE_TCP_STREAM_CUSTOM_DATA OFF)
    ENDIF()
ELSE()
    SET(TINS_HAVE_TCP_STREAM_CUSTOM_DATA OFF)
    MESSAGE(STATUS "Disabling TCP stream custom data support")
ENDIF()

OPTION(LIBTINS_ENABLE_WPA2_CALLBACKS "Enable WPA2 callback interface" ON)
IF(LIBTINS_ENABLE_WPA2_CALLBACKS AND TINS_HAVEs_WPA2_DECRYPTION)
    SET(STATUS "Enabling WPA2 callback interface")
    SET(TINS_HAVE_WPA2_CALLBACKS ON)
ENDIF()

# Add a target to generate API documentation using Doxygen
FIND_PACKAGE(Doxygen QUIET)
IF(DOXYGEN_FOUND)
    CONFIGURE_FILE(
        ${CMAKE_CURRENT_SOURCE_DIR}/docs/Doxyfile.in
        ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
        @ONLY
    )
    ADD_CUSTOM_TARGET(
        docs
        ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Generating API documentation with Doxygen" VERBATIM
    )
ENDIF(DOXYGEN_FOUND)

# Configuration file
CONFIGURE_FILE(
  "${PROJECT_SOURCE_DIR}/include/tins/config.h.in"
  "${PROJECT_SOURCE_DIR}/include/tins/config.h"
)

IF (NOT CMAKE_INSTALL_LIBDIR)
    SET(CMAKE_INSTALL_LIBDIR lib)
ENDIF()
IF (NOT CMAKE_INSTALL_BINDIR)
    SET(CMAKE_INSTALL_BINDIR bin)
ENDIF()
# The library output directory
SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR})
SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR})
# Support for pkg-config
SET(pkgconfig_prefix      ${CMAKE_INSTALL_PREFIX})
SET(pkgconfig_exec_prefix ${CMAKE_INSTALL_PREFIX})
SET(pkgconfig_libdir      ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})
SET(pkgconfig_version     ${LIBTINS_VERSION})
CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/libtins.pc.in
                ${CMAKE_CURRENT_BINARY_DIR}/libtins.pc @ONLY)

INSTALL(
    FILES
    ${CMAKE_CURRENT_BINARY_DIR}/libtins.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)

# Confiugure the uninstall script
CONFIGURE_FILE(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY
)

# Add uninstall target
ADD_CUSTOM_TARGET(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)

IF(LIBTINS_ENABLE_STATIC)
    find_program(CMAKE_CXX_CPPCHECK NAMES cppcheck)

    if (CMAKE_CXX_CPPCHECK)
        message(STATUS "Enable Cppcheck " ${CMAKE_CXX_CPPCHECK})
        list(
            APPEND CMAKE_CXX_CPPCHECK 
                "--quiet"
                "--template={file}:{line}:{column}: warning: {message} {id}"
                "--enable=all"
                "--inline-suppr"
                "--std=c++17"
                "--suppress=duplInheritedMember:*"
                "--suppress=noExplicitConstructor:*"
                "--suppress=unusedFunction:*"
                "--suppress=missingIncludeSystem:*"
                "--suppress=*:googlebenchmark/*"
                "--suppress=*:googletest/*"
                "--suppress=*:tests/*"
        )
    else()
        message(WARNING "Cppcheck not found")
        set(CMAKE_CXX_CPPCHECK "")
    endif()
ELSE()
    set(CMAKE_CXX_CPPCHECK "")
ENDIF()

# ******************
# Add subdirectories
# ******************
ADD_SUBDIRECTORY(src)

IF(LIBTINS_BUILD_EXAMPLES)
    IF(LIBTINS_ENABLE_PCAP)
        ADD_SUBDIRECTORY(examples)
    ELSE()
        MESSAGE(STATUS "Not building examples as pcap support is disabled")
    ENDIF()
ENDIF()

IF(LIBTINS_BUILD_TESTS)
    # Only include googletest if the git submodule has been fetched
    IF(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/googletest/CMakeLists.txt")
        # Enable tests and add the test directory
        MESSAGE(STATUS "Tests have been enabled")
        SET(GOOGLETEST_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/googletest)
        SET(GOOGLETEST_INCLUDE ${GOOGLETEST_ROOT}/googletest/include)
        SET(GOOGLETEST_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/googletest)
        SET(GOOGLETEST_LIBRARY ${GOOGLETEST_BINARY_DIR}/googletest)

        ExternalProject_Add(
            googletest
            DOWNLOAD_COMMAND ""
            SOURCE_DIR ${GOOGLETEST_ROOT}
            BINARY_DIR ${GOOGLETEST_BINARY_DIR}
            CMAKE_CACHE_ARGS "-DBUILD_GTEST:bool=ON" "-DBUILD_GMOCK:bool=OFF"
                            "-Dgtest_force_shared_crt:bool=ON"
                            "-DCMAKE_CXX_COMPILER:path=${CMAKE_CXX_COMPILER}"
            INSTALL_COMMAND ""
        )
        # Make sure we build googletest before anything else
        ADD_DEPENDENCIES(tins googletest)
        ENABLE_TESTING()
        ADD_SUBDIRECTORY(tests)
    ELSE()
        MESSAGE(STATUS "googletest git submodule is absent. Run `git submodule init && git submodule update` to get it")
    ENDIF()
ENDIF()

IF(LIBTINS_ENABLE_BENCH)
  MESSAGE(STATUS "Build Benchmarks")

  # build google benchmark
  SET(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "Suppressing benchmark's tests" FORCE)
  add_subdirectory(googlebenchmark)

  # build LibMVC benchmarks
  add_subdirectory(bench)
ENDIF()

# **********************************
# CMake project configuration export
# **********************************

if(UNIX)
    set(CONF_CMAKE_INSTALL_DIR lib/cmake/libtins)
else()
    set(CONF_CMAKE_INSTALL_DIR CMake)
endif()

# Add all targets to the build-tree export set
EXPORT(
    TARGETS tins
    FILE "${PROJECT_BINARY_DIR}/libtinsTargets.cmake"
)

# Export the package for use from the build-tree
# (this registers the build-tree with a global CMake-registry)
EXPORT(PACKAGE libtins)

# Create the libtinsConfig.cmake and libtinsConfigVersion.cmake files
# for the build tree
SET(CONF_INCLUDE_DIRS "${PROJECT_SOURCE_DIR}/include")
CONFIGURE_FILE(
    cmake/libtinsConfig.cmake.in
    "${PROJECT_BINARY_DIR}/libtinsConfig.cmake" @ONLY
)
CONFIGURE_FILE(
    cmake/libtinsConfigVersion.cmake.in
    "${PROJECT_BINARY_DIR}/libtinsConfigVersion.cmake" @ONLY
)
# Install the libtinsConfig.cmake and libtinsConfigVersion.cmake
INSTALL(
    FILES
    "${PROJECT_BINARY_DIR}/libtinsConfig.cmake"
    "${PROJECT_BINARY_DIR}/libtinsConfigVersion.cmake"
    DESTINATION ${CONF_CMAKE_INSTALL_DIR}
    COMPONENT dev
)

# Install the export set for use with the install-tree
INSTALL(
    EXPORT libtinsTargets
    DESTINATION ${CONF_CMAKE_INSTALL_DIR}
    COMPONENT dev
)

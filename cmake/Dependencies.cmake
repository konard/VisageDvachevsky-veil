include(FetchContent)
include(ExternalProject)

set(FETCHCONTENT_UPDATES_DISCONNECTED ON)

set(FMT_DOC OFF CACHE BOOL "" FORCE)
set(FMT_TEST OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
  fmt
  URL https://github.com/fmtlib/fmt/archive/refs/tags/10.2.1.tar.gz
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(fmt)

set(SPDLOG_FMT_EXTERNAL ON CACHE BOOL "" FORCE)
set(SPDLOG_FMT_EXTERNAL_HO OFF CACHE BOOL "" FORCE)
set(SPDLOG_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(SPDLOG_ENABLE_PCH OFF CACHE BOOL "" FORCE)
set(SPDLOG_BUILD_EXAMPLE OFF CACHE BOOL "" FORCE)
set(SPDLOG_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(SPDLOG_BUILD_BENCH OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
  spdlog
  URL https://github.com/gabime/spdlog/archive/refs/tags/v1.13.0.tar.gz
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(spdlog)

set(CLI11_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(CLI11_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CLI11_BUILD_DOCS OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
  CLI11
  URL https://github.com/CLIUtils/CLI11/archive/refs/tags/v2.4.2.tar.gz
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(CLI11)

# nlohmann/json for IPC message serialization
set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
set(JSON_Install OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
  nlohmann_json
  URL https://github.com/nlohmann/json/archive/refs/tags/v3.11.3.tar.gz
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(nlohmann_json)

set(VEIL_SODIUM_VERSION 1.0.19)

function(veil_try_system_sodium out_found)
  set(${out_found} FALSE PARENT_SCOPE)
  find_package(PkgConfig QUIET)
  if(PKG_CONFIG_FOUND)
    pkg_check_modules(SODIUM QUIET libsodium)
  endif()
  find_library(SODIUM_LIBRARY NAMES sodium)
  find_path(SODIUM_INCLUDE_DIR NAMES sodium.h)
  if(SODIUM_LIBRARY AND SODIUM_INCLUDE_DIR)
    add_library(Sodium::Sodium UNKNOWN IMPORTED)
    set_target_properties(Sodium::Sodium PROPERTIES
      IMPORTED_LOCATION "${SODIUM_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES "${SODIUM_INCLUDE_DIR}"
    )
    set(${out_found} TRUE PARENT_SCOPE)
  endif()
endfunction()

set(VEIL_SODIUM_FOUND FALSE)
if(VEIL_USE_SYSTEM_SODIUM)
  veil_try_system_sodium(VEIL_SODIUM_FOUND)
  if(NOT VEIL_SODIUM_FOUND)
    message(FATAL_ERROR "VEIL_USE_SYSTEM_SODIUM=ON but libsodium not found")
  endif()
else()
  veil_try_system_sodium(VEIL_SODIUM_FOUND)
endif()

if(NOT VEIL_SODIUM_FOUND)
  set(SODIUM_PREFIX ${CMAKE_BINARY_DIR}/external/sodium)
  ExternalProject_Add(sodium_ep
    PREFIX ${SODIUM_PREFIX}
    URL https://download.libsodium.org/libsodium/releases/libsodium-${VEIL_SODIUM_VERSION}.tar.gz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    CONFIGURE_COMMAND <SOURCE_DIR>/configure --prefix=<INSTALL_DIR> --enable-minimal
    BUILD_COMMAND make
    INSTALL_COMMAND make install
    BUILD_IN_SOURCE ON
    UPDATE_COMMAND ""
    BUILD_BYPRODUCTS ${SODIUM_PREFIX}/lib/libsodium.a
  )
  file(MAKE_DIRECTORY ${SODIUM_PREFIX}/include)
  file(MAKE_DIRECTORY ${SODIUM_PREFIX}/lib)
  add_library(Sodium::Sodium UNKNOWN IMPORTED)
  add_dependencies(Sodium::Sodium sodium_ep)
  set_target_properties(Sodium::Sodium PROPERTIES
    IMPORTED_LOCATION ${SODIUM_PREFIX}/lib/libsodium.a
    INTERFACE_INCLUDE_DIRECTORIES ${SODIUM_PREFIX}/include
  )
endif()

if(VEIL_BUILD_TESTS)
  set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
  set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
  set(gtest_disable_pthreads OFF CACHE BOOL "" FORCE)
  FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.tar.gz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
  )
  FetchContent_MakeAvailable(googletest)
endif()

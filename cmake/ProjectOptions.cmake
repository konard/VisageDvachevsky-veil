option(VEIL_ENABLE_LTO "Enable interprocedural optimization" OFF)
option(VEIL_ENABLE_WARNINGS_AS_ERRORS "Treat warnings as errors" ON)
option(VEIL_ENABLE_SANITIZERS "Enable Address/Undefined sanitizers" ON)
option(VEIL_ENABLE_CLANG_TIDY "Run clang-tidy during build if available" ON)
option(VEIL_USE_SYSTEM_SODIUM "Prefer system-provided libsodium" OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(VEIL_ENABLE_LTO)
  include(CheckIPOSupported)
  check_ipo_supported(RESULT ipo_supported OUTPUT ipo_error)
  if(ipo_supported)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
  else()
    message(WARNING "IPO/LTO not supported: ${ipo_error}")
  endif()
endif()

if(VEIL_ENABLE_SANITIZERS)
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  endif()
endif()

if(VEIL_ENABLE_CLANG_TIDY)
  find_program(CLANG_TIDY_EXE NAMES clang-tidy)
  if(CLANG_TIDY_EXE)
    # Store the clang-tidy executable path but don't set CMAKE_CXX_CLANG_TIDY
    # globally, as that would apply to external dependencies too.
    # Instead, we'll apply it per-target using veil_set_warnings().
    set(VEIL_CLANG_TIDY_COMMAND "${CLANG_TIDY_EXE}" CACHE STRING "")
  else()
    message(WARNING "clang-tidy requested but not found")
  endif()
endif()

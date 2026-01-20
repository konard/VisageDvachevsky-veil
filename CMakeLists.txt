cmake_minimum_required(VERSION 3.20)

project(VEIL VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(VEIL_BUILD_TESTS "Build unit and integration tests" ON)

include(cmake/ProjectOptions.cmake)
include(cmake/Warnings.cmake)
include(cmake/Dependencies.cmake)

option(VEIL_BUILD_TOOLS "Build tools and utilities" ON)

if(VEIL_BUILD_TESTS)
  enable_testing()
endif()

add_subdirectory(src)

if(VEIL_BUILD_TESTS)
  add_subdirectory(tests)
endif()

if(VEIL_BUILD_TOOLS)
  add_subdirectory(src/tools)
endif()

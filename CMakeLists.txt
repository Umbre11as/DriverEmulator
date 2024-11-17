cmake_minimum_required(VERSION 3.26)
include("${CMAKE_CURRENT_LIST_DIR}/cmake/flags.cmake")
project(DriverEmulator)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

add_subdirectory(emulated/ntoskrnl)
add_subdirectory(emulated/fltmgr)

add_compile_options("/FI${CMAKE_CURRENT_LIST_DIR}/vshacks.h")

file(GLOB_RECURSE SOURCES "src/*.cpp")

add_executable(DriverEmulator ${SOURCES})

include("../cmake/flags.cmake")
project(fltmgr)

list(APPEND CMAKE_MODULE_PATH "../cmake")

file(GLOB_RECURSE SOURCES "src/*.c")

add_library(fltmgr SHARED ${SOURCES})

target_link_libraries(fltmgr PUBLIC ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/Release/ntoskrnl.lib)

include("${CMAKE_CURRENT_LIST_DIR}/cmake/flags.cmake")
project(ntoskrnl)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

file(GLOB_RECURSE SOURCES "src/*.c")

add_library(ntoskrnl SHARED ${SOURCES})

target_link_libraries(ntoskrnl PUBLIC ucrt.lib)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/dist")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/dist")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/dist")

add_compile_options("/Od")
add_compile_options("/Oi")
add_compile_options("/GS-")
add_compile_options("/GL-")

add_link_options("/WX:NO")
add_link_options("/OPT:REF")
add_link_options("/OPT:ICF")

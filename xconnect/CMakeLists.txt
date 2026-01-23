# Set the minimum required version of CMake
cmake_minimum_required(VERSION 3.0)

project(pv-xconnect VERSION 0.1)

# Find libevent
find_library(LIBEVENT_LIB event)
find_library(PICOHTTPPARSER_LIB picohttpparser)
find_library(THTTP_LIB thttp)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_CURRENT_SOURCE_DIR}/../utils
)

# Set the source files for the binary
add_executable(pv-xconnect
    main.c
    plumbing.c
    plugins/unix.c
    plugins/rest.c
    plugins/drm.c
    plugins/wayland.c
    plugins/dbus.c
    ../utils/json.c
    ../utils/str.c
)

target_link_libraries(pv-xconnect
    ${LIBEVENT_LIB}
    ${PICOHTTPPARSER_LIB}
    ${THTTP_LIB}
    dl
)

install(TARGETS pv-xconnect
        DESTINATION bin/
)

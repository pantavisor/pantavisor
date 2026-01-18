# Set the minimum required version of CMake
cmake_minimum_required(VERSION 3.0)

project(pv-xconnect VERSION 0.1)

# Find libevent
find_library(LIBEVENT_LIB event)
find_library(LIBEVENT_PTHREADS_LIB event_pthreads)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/..
)

# Set the source files for the binary
add_executable(pv-xconnect
    main.c
    plumbing.c
    plugins/unix.c
    plugins/rest.c
    plugins/drm.c
    plugins/wayland.c
)

target_link_libraries(pv-xconnect
    ${LIBEVENT_LIB}
    ${LIBEVENT_PTHREADS_LIB}
    dl
)

install(TARGETS pv-xconnect
        DESTINATION bin/
)

# Set the minimum required version of CMake
cmake_minimum_required(VERSION 3.0)

# Set the project name and version
project(pv_lxc VERSION 019)

# Find the shared library
find_library(LXC_LIB lxc)

# Set the source files for the binary
add_library(pv_lxc MODULE
    pv_lxc.c
    pv_lxc.h
)

get_filename_component(PARENT_DIR ../ ABSOLUTE)
target_include_directories(pv_lxc PRIVATE ${PARENT_DIR})
SET_TARGET_PROPERTIES(pv_lxc PROPERTIES PREFIX "")
target_link_libraries(pv_lxc ${LXC_LIB})

install(TARGETS pv_lxc
	DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR}/${CMAKE_PROJECT_NAME}
)

# pv_lxccli plugin - CLI-based LXC plugin (no liblxc dependency)
add_library(pv_lxccli MODULE
    pv_lxccli.c
    pv_lxccli.h
)

target_include_directories(pv_lxccli PRIVATE ${PARENT_DIR})
SET_TARGET_PROPERTIES(pv_lxccli PROPERTIES PREFIX "")

# openpty is in libutil on glibc, but in libc on musl
# Check if we need to link libutil
include(CheckFunctionExists)
check_function_exists(openpty HAVE_OPENPTY_IN_LIBC)
if(NOT HAVE_OPENPTY_IN_LIBC)
    find_library(UTIL_LIB util)
    if(UTIL_LIB)
        target_link_libraries(pv_lxccli ${UTIL_LIB})
    endif()
endif()

install(TARGETS pv_lxccli
	DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR}/${CMAKE_PROJECT_NAME}
)


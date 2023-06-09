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
include_directories(${PARENT_DIR})

SET_TARGET_PROPERTIES(pv_lxc PROPERTIES PREFIX "")

target_link_libraries(pv_lxc ${LXC_LIB})

install(TARGETS pv_lxc
	DESTINATION /lib/
)

# Set the minimum required version of CMake
cmake_minimum_required(VERSION 3.0)

# Set the project name and version
project(pv_lxc VERSION 019)

get_filename_component(PARENT_DIR ../ ABSOLUTE)

# Find the shared library
find_library(LXC_LIB lxc)

# Set the source files for the binary
add_library(pv_lxc MODULE
    pv_lxc.c
    pv_lxc.h
)

target_include_directories(pv_lxc PRIVATE ${PARENT_DIR})
SET_TARGET_PROPERTIES(pv_lxc PROPERTIES PREFIX "")
target_link_libraries(pv_lxc ${LXC_LIB})

install(TARGETS pv_lxc
	DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR}/${CMAKE_PROJECT_NAME}
)

# Set the source files for the binary
add_library(pv_runc MODULE
    pv_runc.c
    pv_runc.h
    pv_runc_container_status.c
    pv_runc_container_status.h
)

target_include_directories(pv_runc PRIVATE ${PARENT_DIR})
SET_TARGET_PROPERTIES(pv_runc PROPERTIES PREFIX "")

install(TARGETS pv_runc
	DESTINATION /lib/
)


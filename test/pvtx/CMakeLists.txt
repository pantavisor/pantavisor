# CMakeLists.txt for pvtx unit tests
#
# These tests exercise the pvtx transaction tool in isolation and do NOT
# require a running Pantavisor instance.  Dependencies: pvtx binary, jq,
# xxd, bc, xargs, sed in PATH.
#
# Usage (after building pantavisor with -DPANTAVISOR_PVTX=ON):
#
#   # From the top-level build directory:
#   ctest -R pvtx -V
#
#   # Verbose output for all tests:
#   PVTX_TEST_PRINT_ALL=1 ctest -R pvtx -V
#
# The tests are also registered from the top-level CMakeLists.txt via
# enable_testing() / add_test().  This file exists so that the test
# directory can be used as a cmake subdirectory in downstream projects.

cmake_minimum_required(VERSION 3.0)

if(PANTAVISOR_PVTX)
    add_test(
        NAME pvtx
        COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/pvtx.sh
                ${CMAKE_CURRENT_SOURCE_DIR}/../..
                ${CMAKE_CURRENT_BINARY_DIR}/../..
    )
endif()

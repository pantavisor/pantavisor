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
# enable_testing() / add_subdirectory().  This file exists so that the test
# directory can be used as a cmake subdirectory in downstream projects.

cmake_minimum_required(VERSION 3.0)

if(PANTAVISOR_PVTX)
    set(PVTX_TESTS
        test_create_empty_transaction
        test_process_json_keys_with_spaces
        test_signature_removal
        test_signature_removal2
        test_signature_removal3
        test_removal_config_pkg
        test_package_update
        test_add_package_from_tar
        test_add_new_package
        test_add_new_package_from_cat
        test_update_bsp
        test_update_bsp_with_groups
        test_install_from_tgz
        test_two_package_signing_same_files
        test_two_package_signing_same_files_with_globs
        test_removal_of_signed_config
        test_queue_new
        test_queue_actions
        test_queue_process
        test_queue_process_with_remove
        test_deploy
        test_process_queue_without_begin
        test_local_transaction
        test_empty_transaction_has_spec
        test_show_is_idempotent
        test_spec_preserved_after_remove
        test_add_state_roundtrip
        test_double_add_is_idempotent
        test_abort_clears_transaction
    )

    foreach(PVTX_TEST ${PVTX_TESTS})
        add_test(
            NAME pvtx::${PVTX_TEST}
            COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/pvtx.sh
                    ${CMAKE_CURRENT_SOURCE_DIR}/../..
                    ${CMAKE_CURRENT_BINARY_DIR}/../..
                    ${PVTX_TEST}
        )
    endforeach()
endif()

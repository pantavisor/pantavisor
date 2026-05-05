cmake_minimum_required(VERSION 3.16)

if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    project(pvtx C)
    include(GNUInstallDirs)
    set(PANTAVISOR_PVTX ON CACHE BOOL "build pantavisor pvtx")
    set(PANTAVISOR_PVTX_STATIC OFF CACHE BOOL "build pantavisor pvtx static")
endif()

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Werror -Wextra)

set(LIB_SRC
    src/pvtx_buffer.c
    src/pvtx_ctrl.c
    src/pvtx_error.c
    src/pvtx_jsmn_utils.c
    src/pvtx_state.c
    src/pvtx_tar.c
    src/pvtx_tar_formats.c
    src/pvtx_txn.c
    src/pvtx_utils/base64.c
    src/pvtx_utils/jsmn.c
    src/pvtx_utils/sha256-internal.c
    ../utils/fs.c
    ../utils/tsh.c
    ../utils/pvsignals.c
)

set(EXEC_SRC src/pvtx.c)

if(PANTAVISOR_PVTX)
    find_library(PANTAVISOR_PVTX_ZLIB z)
    add_library(pvtx_shared SHARED ${LIB_SRC})
    add_executable(pvtx ${EXEC_SRC})

    target_compile_definitions(pvtx_shared PUBLIC DISABLE_LOGSERVER)
    target_include_directories(pvtx_shared PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/..
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_include_directories(pvtx PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/..
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )

    set_target_properties(pvtx_shared PROPERTIES OUTPUT_NAME "pvtx")

    target_link_libraries(pvtx pvtx_shared ${PANTAVISOR_PVTX_ZLIB})
    install(TARGETS pvtx DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(PANTAVISOR_PVTX_STATIC)
    set(_saved_lib_suffixes ${CMAKE_FIND_LIBRARY_SUFFIXES})
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    find_library(PANTAVISOR_PVTX_STATIC_ZLIB z)
    set(CMAKE_FIND_LIBRARY_SUFFIXES ${_saved_lib_suffixes})

    add_library(pvtx_static STATIC ${LIB_SRC})
    add_executable(pvtx-static ${EXEC_SRC})

    target_compile_definitions(pvtx_static PUBLIC DISABLE_LOGSERVER)
    target_include_directories(pvtx_static PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/..
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_include_directories(pvtx-static PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/..
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )

    set_target_properties(pvtx_static PROPERTIES OUTPUT_NAME "pvtx")

    target_link_libraries(pvtx-static pvtx_static ${PANTAVISOR_PVTX_STATIC_ZLIB})
    target_link_options(pvtx-static PRIVATE
        LINKER:-static
        -static
        -static-libgcc
    )

    set_target_properties(pvtx-static PROPERTIES LINK_SEARCH_END_STATIC 1)
    install(TARGETS pvtx-static DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

enable_testing()
add_subdirectory(../test/pvtx pvtx-test)

cmake_minimum_required(VERSION 3.0)
project(pvcm-proxy VERSION 1)

add_executable(pvcm-proxy
    main.c
)

target_include_directories(pvcm-proxy PRIVATE ${CMAKE_SOURCE_DIR})

install(TARGETS pvcm-proxy
    DESTINATION ${CMAKE_INSTALL_FULL_BINDIR}
)

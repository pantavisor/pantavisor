cmake_minimum_required(VERSION 3.0)
project(pvcm-proxy VERSION 1)

find_package(PkgConfig REQUIRED)
pkg_check_modules(DBUS REQUIRED dbus-1)

add_executable(pvcm-proxy
    main.c
    pvcm_config.c
    pvcm_transport_uart.c
    pvcm_transport_rpmsg.c
    pvcm_protocol.c
    pvcm_bridge.c
    pvcm_dbus_bridge.c
)

target_include_directories(pvcm-proxy PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${DBUS_INCLUDE_DIRS}
)

target_link_libraries(pvcm-proxy
    ${DBUS_LIBRARIES}
    pthread
)

install(TARGETS pvcm-proxy
    DESTINATION ${CMAKE_INSTALL_FULL_BINDIR}
)

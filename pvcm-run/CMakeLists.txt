cmake_minimum_required(VERSION 3.0)
project(pvcm-run VERSION 1)

find_package(PkgConfig REQUIRED)
pkg_check_modules(DBUS REQUIRED dbus-1)

find_library(LIBEVENT event)
find_path(LIBEVENT_INCLUDE event2/event.h)

add_executable(pvcm-run
    main.c
    pvcm_config.c
    pvcm_transport_uart.c
    pvcm_transport_rpmsg.c
    pvcm_protocol.c
    pvcm_bridge.c
    pvcm_dbus_bridge.c
    pvcm_fs_bridge.c
    pvcm_sendq.c
)

target_include_directories(pvcm-run PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${DBUS_INCLUDE_DIRS}
    ${LIBEVENT_INCLUDE}
)

target_link_libraries(pvcm-run
    ${DBUS_LIBRARIES}
    ${LIBEVENT}
)

install(TARGETS pvcm-run
    DESTINATION ${CMAKE_INSTALL_FULL_BINDIR}
)

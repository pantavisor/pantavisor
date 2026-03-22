if(CONFIG_PANTAVISOR)

zephyr_include_directories(include)

zephyr_library_named(pantavisor)

# mandatory modules
zephyr_library_sources(
  src/pvcm_server.c
  src/pvcm_state.c
  src/pvcm_heartbeat.c
)

zephyr_library_sources_ifdef(CONFIG_PANTAVISOR_LOG_BACKEND
  src/pvcm_log_backend.c
)

# transport
zephyr_library_sources_ifdef(CONFIG_PANTAVISOR_TRANSPORT_UART
  src/pvcm_transport_uart.c
)

zephyr_library_sources_ifdef(CONFIG_PANTAVISOR_TRANSPORT_RPMSG
  src/pvcm_transport_rpmsg.c
)

# optional modules
zephyr_library_sources_ifdef(CONFIG_PANTAVISOR_BRIDGE
  src/pvcm_client.c
)

zephyr_library_sources_ifdef(CONFIG_PANTAVISOR_DBUS
  src/pvcm_dbus.c
)

zephyr_library_sources_ifdef(CONFIG_PANTAVISOR_SHELL
  src/pvcm_shell.c
)

endif()

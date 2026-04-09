---
nav_order: 13
---
# Watchdog

Pantavisor also offers some [configurable](../../../reference/legacy/pantavisor-configuration.md#summary) convenience to set up and ping the [Linux Kernel watchdog](https://www.kernel.org/doc/html/v6.1/watchdog/watchdog-api.html).

## Mode

The watchdog mode will determine when the watchdog is pinged by Pantavisor.

### Disabled

In this mode, Pantavisor will never ping the watchdog.

### Shutdown

This is the default mode. Pantavisor will start pinging the watchdog when a reboot or poweroff order is issued. This way, we make sure the device reboots in a shutdown freeze event.

### Startup

This mode combines Pantavisor pinging the watchdog during initialization and shutdown. As the watchdog is activated with a ping, it is expected that a container will take that role during the device regular operation.

### Always

In this mode, Pantavisor will ping the watchdog during all the device operation.

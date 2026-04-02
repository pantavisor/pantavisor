/*
 * pvcm-run D-Bus bridge
 *
 * Bridges PVCM D-Bus frames to the Linux system D-Bus.
 * MCU firmware calls D-Bus methods and subscribes to signals
 * via DBUS_CALL/SUBSCRIBE frames; the bridge forwards them
 * to the real D-Bus daemon via libdbus-1.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef PVCM_DBUS_BRIDGE_H
#define PVCM_DBUS_BRIDGE_H

#include "pvcm_transport.h"
#include "../protocol/pvcm_protocol.h"
#include <stddef.h>
#include <event2/event.h>

/* Initialize D-Bus bridge with event loop. Connects to the bus at
 * socket_path. The dbus_fd is registered with the event_base for
 * async signal delivery. Pass NULL socket_path to skip D-Bus. */
int pvcm_dbus_bridge_init(struct event_base *base,
			   struct pvcm_transport *t,
			   const char *socket_path);

/* Handle incoming D-Bus frames from MCU */
int pvcm_dbus_bridge_on_call(struct pvcm_transport *t,
			     const uint8_t *buf, int len);
int pvcm_dbus_bridge_on_data(struct pvcm_transport *t,
			     const uint8_t *buf, int len);
int pvcm_dbus_bridge_on_subscribe(struct pvcm_transport *t,
				  const uint8_t *buf, int len);
int pvcm_dbus_bridge_on_unsubscribe(struct pvcm_transport *t,
				    const uint8_t *buf, int len);

/* Clean up D-Bus connection and events */
void pvcm_dbus_bridge_cleanup(void);

#endif /* PVCM_DBUS_BRIDGE_H */

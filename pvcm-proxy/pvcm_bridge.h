/*
 * pvcm-proxy HTTP bridge
 * SPDX-License-Identifier: MIT
 */

#ifndef PVCM_BRIDGE_H
#define PVCM_BRIDGE_H

#include "pvcm_transport.h"
#include "../protocol/pvcm_protocol.h"

#include <stddef.h>
#include <event2/event.h>

/* Route entry: maps a hostname to a backend (unix socket or TCP) */
struct http_route {
	char name[64];         /* hostname without .pvlocal suffix */
	char unix_path[256];   /* unix socket path (if non-empty, use AF_UNIX) */
	char tcp_host[64];     /* TCP host (if unix_path empty) */
	int  tcp_port;         /* TCP port */
};

#define PVCM_MAX_ROUTES 16

/* Add a route. spec format: "name=unix:/path" or "name=tcp:host:port" */
int pvcm_bridge_add_route(const char *spec);

/* Initialize the HTTP bridge */
int pvcm_bridge_init(struct pvcm_transport *t);

/* Handle incoming HTTP frames from MCU (outbound requests) */
int pvcm_bridge_on_http_req(struct pvcm_transport *t,
			    const uint8_t *buf, int len);
int pvcm_bridge_on_http_data(struct pvcm_transport *t,
			     const uint8_t *buf, int len);
int pvcm_bridge_on_http_end(struct pvcm_transport *t,
			    const uint8_t *buf, int len);

/* Start evhttp listener for inbound requests to MCU */
int pvcm_bridge_start_listener(struct event_base *base,
			       struct pvcm_transport *t, int port);

/* Handle REPLY frames from MCU (responses to inbound requests) */
int pvcm_bridge_on_reply_req(struct pvcm_transport *t,
			     const uint8_t *buf, int len);
int pvcm_bridge_on_reply_data(struct pvcm_transport *t,
			      const uint8_t *buf, int len);
int pvcm_bridge_on_reply_end(struct pvcm_transport *t,
			     const uint8_t *buf, int len);

#endif

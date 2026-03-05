/*
 * Copyright (c) 2026 Pantacor Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef PV_AGENT_TUNNEL_H
#define PV_AGENT_TUNNEL_H

#include <event2/event.h>

/*
 * Initialize the tunnel client with device identity.
 * Connects to the tunnel server via WebSocket over either a Unix socket
 * or TCP, depending on the target format:
 *
 *   Unix socket: target starts with "/" (e.g. "/run/tunnel.sock")
 *   TCP:         target is "host:port" (e.g. "10.0.3.10:8080")
 *
 * After WebSocket upgrade, performs challenge-response authentication:
 *   Hub sends auth_challenge with random hex
 *   Client signs with ethsign, sends auth_response
 *   Hub verifies on-chain and sends auth_result
 *
 * key_path: path to device private key file (e.g. "/var/lib/devicepass/device.key")
 * address:  device Ethereum address (e.g. "0x...")
 *
 * Receives JSON commands, dispatches through agent_op_dispatch(), and
 * sends JSON results back over the WebSocket.
 *
 * Reconnects automatically on disconnect (5s interval).
 *
 * Returns 0 on success (connection initiated), -1 on failure.
 */
int tunnel_init(struct event_base *base, const char *target,
		const char *key_path, const char *address);

/*
 * Shut down the tunnel client and free resources.
 */
void tunnel_shutdown(void);

/*
 * Get the guardian address learned during authentication.
 * Returns NULL if not yet authenticated.
 */
const char *tunnel_get_guardian(void);

#endif /* PV_AGENT_TUNNEL_H */

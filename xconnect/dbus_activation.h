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
#ifndef PV_XCONNECT_DBUS_ACTIVATION_H
#define PV_XCONNECT_DBUS_ACTIVATION_H

#include <stdbool.h>

// On-demand D-Bus service activation for the hosted system bus. This tracks the
// set of activatable well-known names (from the pv-ctrl graph), watches name
// ownership via a single persistent monitor connection to the bus, and lets the
// dbus proxy hold a cold method_call until its target name gains an owner (see
// xconnect/XCONNECT.md, "D-Bus Service Activation").

// Exactly one of these fires per successful pvx_act_hold() registration.
typedef void (*pvx_act_ready_cb)(void *ctx); // name gained an owner
typedef void (*pvx_act_fail_cb)(
	void *ctx, const char *dbus_error,
	const char *message); // timeout / activation error

// Rebuild the activatable-name set from a graph reconcile pass:
//   begin() starts a fresh pending set;
//   add()  registers one activatable name and the host bus socket the monitor
//          connects to (all hosted-bus names share the same socket);
//   end()  swaps the pending set in and (re)starts the ownership monitor.
void pvx_act_reconcile_begin(void);
void pvx_act_reconcile_add(const char *name, const char *bus_socket);
void pvx_act_reconcile_end(void);

// Is `name` an on-demand activatable well-known name?
bool pvx_act_is_activatable(const char *name);

// Does `name` currently have an owner on the bus (per the monitor)? Unknown
// names and a not-yet-connected monitor report false (treated as cold).
bool pvx_act_name_has_owner(const char *name);

// Register a waiter for `name` and trigger its activation via pv-ctrl. When the
// name gains an owner, ready(ctx) fires; on timeout or a failed activation,
// fail(ctx, dbus_error, message) fires. Returns 0 if a wait was registered
// (a callback is guaranteed later), <0 if it could not be set up at all.
int pvx_act_hold(const char *name, pvx_act_ready_cb ready, pvx_act_fail_cb fail,
		 void *ctx);

// Cancel and free any pending waiter registered with `ctx` without firing a
// callback (e.g. the client connection was torn down).
void pvx_act_cancel(void *ctx);

#endif /* PV_XCONNECT_DBUS_ACTIVATION_H */

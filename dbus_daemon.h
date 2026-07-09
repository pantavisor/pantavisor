/*
 * Copyright (c) 2025 Pantacor Ltd.
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

#ifndef PV_DBUS_DAEMON_H
#define PV_DBUS_DAEMON_H

#ifdef PANTAVISOR_XCONNECT_DBUS_SYSTEMBUS

struct pv_state;

// Hosted dbus system bus: the well-known service name containers require, the
// managed daemon name, and the runtime paths it lives under in /run/pv/dbus.
#define PV_DBUS_SYSTEMBUS_NAME "system-bus"
#define PV_DBUS_SYSTEMBUS_DAEMON "pv-dbus"
#define PV_DBUS_SYSTEMBUS_DIR "/run/pv/dbus"
#define PV_DBUS_SYSTEMBUS_SOCKET PV_DBUS_SYSTEMBUS_DIR "/system_bus_socket"
#define PV_DBUS_SYSTEMBUS_CONF PV_DBUS_SYSTEMBUS_DIR "/system.conf"
#define PV_DBUS_SYSTEMBUS_POLICYDIR PV_DBUS_SYSTEMBUS_DIR "/policy.d"

// Private passwd bind-mounted over /etc/passwd in the daemon's mount jail so it
// can resolve the per-role masquerade uids that the generated policy keys on,
// without touching the rootfs /etc/passwd. See pv_dbus_daemon_generate().
#define PV_DBUS_SYSTEMBUS_PASSWD PV_DBUS_SYSTEMBUS_DIR "/passwd"

// Per-role bus identity: roles masquerade (SASL EXTERNAL) to a stable uid in a
// reserved range, resolvable in the daemon's private passwd as "<prefix><role>".
#define PV_DBUS_ROLE_NAME_PREFIX "pv-dbus-"

// Allocate-or-return the stable numeric uid for `role`, persisted so a role
// keeps its uid across reboots and revisions. Returns the uid (>= base reserved
// range) or -1 on bad input.
int pv_dbus_daemon_role_uid(const char *role);

// Reject states that would shadow the builtin host export or double-own a
// well-known name. Returns -1 to reject the revision (rollback during an
// update), 0 otherwise.
int pv_dbus_daemon_validate(struct pv_state *s);

// Resolve the platform that owns well-known `name` on the hosted system bus and
// declares on-demand activation, or NULL. The (bus,owns)->owner index used by
// the activate endpoint to start a passive owner on first use.
struct pv_platform;
struct pv_platform *pv_dbus_daemon_activatable_owner(struct pv_state *s,
						     const char *name);

// Lay down the runtime dir, base config and seed passwd before the managed
// dbus-daemon is spawned. Disables the daemon when the feature is off in config.
void pv_dbus_daemon_prepare(void);

// Regenerate the per-name policy fragments and the role passwd from the current
// state, then reload the running daemon. Called after a state is validated and
// applied; the two files are written from the same role->uid map so they cannot
// drift.
void pv_dbus_daemon_generate(struct pv_state *s);

#endif /* PANTAVISOR_XCONNECT_DBUS_SYSTEMBUS */
#endif /* PV_DBUS_DAEMON_H */

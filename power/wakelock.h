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
#ifndef PV_WAKELOCK_H
#define PV_WAKELOCK_H

#include <stdbool.h>

// Suspend-blocking scopes. Each scope acquires/releases the single shared
// kernel wakelock through a userspace reference count; a scope owns a guard so
// it performs exactly one acquire and one release no matter how often its code
// path runs.
enum wl_scope {
	WL_BOOT,
	WL_UPDATE,
	WL_UPDATE_CHECK,
	WL_SHUTDOWN,
	WL_DEVMETA,
	WL_USRMETA,
	// held while a debug/serial shell session is open, so an operator always
	// has time to intervene (e.g. roll back to a good revision) over serial
	// without the device suspending out from under them
	WL_DEBUG_SHELL,
	// managed mode: held for the duration of a timed wake window so the device
	// stays awake long enough for the network (wifi/tailscale) to re-associate
	// after deep suspend and for at least one full poll round to complete
	WL_POLL,
	WL_SCOPE_MAX
};

int pv_wakelock_init(void);
// Re-evaluate power.mode once config levels that load after pv_wakelock_init()
// (e.g. pantahub.config on /storage) are available, and start managed-mode
// facilities if we transitioned into managed.
void pv_wakelock_apply_config(void);

// Called once the FSM first reaches steady state (RUN -> WAIT). In managed mode
// this is where opportunistic suspend (autosleep) is turned on; enabling it
// earlier races the boot lock and can suspend the device mid-boot. No-op unless
// mode is managed. Idempotent.
void pv_wakelock_managed_ready(void);

void pv_wakelock_deinit(void);

void pv_wakelock_acquire(enum wl_scope scope);
void pv_wakelock_release(enum wl_scope scope);

// The devmeta scope is dirty-gated: it is held from a local pv-ctrl mutation
// until the change syncs to Hub (or a bound elapses). These helpers drive that
// lifecycle on top of the shared refcount using a generation counter.
//
// dirty:  a real pv-ctrl mutation happened while authed (bump gen, acquire)
// sent:   a devmeta PUT was queued (snapshot the sent generation)
// acked:  a devmeta PUT completed (ok=200: release if caught up, keep if a
//         newer change landed mid-flight; ok=false: release, retried later)
// deauth: the PH client left the reporting state (release if held)
void pv_wakelock_devmeta_dirty(void);
void pv_wakelock_devmeta_sent(void);
void pv_wakelock_devmeta_acked(bool ok);
void pv_wakelock_devmeta_deauth(void);

// managed mode: the update-check poll roundtrip finished. reached_hub is true
// when the request actually round-tripped to Hub (network up), false on a
// connection failure. Drives the per-wake awake window: a failed round is
// retried (staying awake) until one succeeds or the max-awake bound elapses.
void pv_wakelock_poll_round_done(bool reached_hub);

// Read-only state for the GET /wakelocks control endpoint. Caller frees.
char *pv_wakelock_get_json(void);

#endif // PV_WAKELOCK_H

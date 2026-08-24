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

// Suspend-blocking scopes, refcounted onto the one shared kernel wakelock. Each
// scope is guarded, so it contributes exactly one acquire and one release
// however often its code path runs.
enum wl_scope {
	WL_BOOT,
	WL_UPDATE,
	WL_UPDATE_CHECK,
	WL_SHUTDOWN,
	WL_DEVMETA,
	WL_USRMETA,
	// so the device never suspends out from under an operator on serial
	WL_DEBUG_SHELL,
	// managed: spans a timed wake window, long enough for the network to
	// re-associate after deep suspend and one poll round to complete
	WL_POLL,
	WL_SCOPE_MAX
};

int pv_wakelock_init(void);
// Re-evaluate power.mode once config levels that load after pv_wakelock_init()
// (e.g. pantahub.config on /storage) are available.
void pv_wakelock_apply_config(void);

// Called once the FSM first reaches steady state (RUN -> WAIT); turns on
// autosleep after a settle delay. Managed only, idempotent.
void pv_wakelock_managed_ready(void);

void pv_wakelock_deinit(void);

void pv_wakelock_acquire(enum wl_scope scope);
void pv_wakelock_release(enum wl_scope scope);

// The devmeta scope is dirty-gated: held from a local pv-ctrl mutation until it
// syncs to Hub or power.devmeta.max_held elapses. A generation counter keeps a
// change that lands mid-flight from releasing early.
void pv_wakelock_devmeta_dirty(void);
void pv_wakelock_devmeta_sent(void);
void pv_wakelock_devmeta_acked(bool ok);
void pv_wakelock_devmeta_deauth(void);
// true while a local mutation is still waiting to reach Hub
bool pv_wakelock_devmeta_is_pending(void);

// Drives the per-wake window: a round that did not reach Hub is retried while
// staying awake, until one succeeds or max-awake elapses.
void pv_wakelock_poll_round_done(bool reached_hub);

// An update finished; poll again before sleeping so a queued revision applies
// in this wake. Call while the update still holds WL_UPDATE.
void pv_wakelock_update_finished(void);

// Read-only state for the GET /wakelocks control endpoint. Caller frees.
char *pv_wakelock_get_json(void);

#endif // PV_WAKELOCK_H

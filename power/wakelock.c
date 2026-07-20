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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#include <pthread.h>

#include <sys/timerfd.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>

#include <linux/limits.h>
#include <linux/rtc.h>

#include "power/wakelock.h"

#include "config.h"
#include "event/event.h"
#include "pantahub/pantahub_proto.h"

#include "utils/json.h"

#define MODULE_NAME "wakelock"
#define pv_log(level, msg, ...)                                                \
	vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__,       \
	     ##__VA_ARGS__)
#include "log.h"

// single kernel wakelock name, guarded by the userspace refcount below
#define WL_NAME "pantavisor"

#define WL_SYSFS_LOCK "wake_lock"
#define WL_SYSFS_UNLOCK "wake_unlock"
#define WL_SYSFS_AUTOSLEEP "autosleep"

// RTC char device (rtc0). Managed mode wakes from autosleep via a blocking read
// on this fd (see _alarm_thread_fn): the read returns in-kernel still under the
// wakeup-event hold, so the worker thread can grab the wakelock inline before
// the autosleep loop re-suspends — a timerfd + event-loop callback loses that
// race.
#define WL_RTC_DEV "/dev/rtc0"

static struct pv_wakelock {
	bool init;
	bool degraded;
	power_mode_t mode;
	// shared reference count; a sysfs write happens only on the 0->1 and
	// 1->0 edges. Single-threaded libevent process, so a plain int is safe.
	int count;
	// per-scope guard: at most one acquire / one release contributes to the
	// count for each scope
	bool held[WL_SCOPE_MAX];
	// held sysfs fds, opened once at init (modeled on wdt.c)
	int lock_fd;
	int unlock_fd;
	// managed mode: opportunistic suspend (/sys/power/autosleep) is enabled
	bool autosleep;
	int alarm_fd; // /dev/rtc0, kept open; the worker thread blocks reading it
	struct event *alarm_ev;
	// The RTC wake handoff needs a BLOCKING read on alarm_fd with the kernel
	// wakelock grabbed inline in the same thread; an event-loop callback loses
	// the autosleep re-suspend race. The thread parks in read(/dev/rtc0), grabs
	// the wakelock via its own fd on wake, then kicks the event loop.
	pthread_t alarm_thread;
	bool alarm_thread_started;
	volatile bool alarm_thread_run;
	int alarm_wl_fd; // thread's own /sys/power/wake_lock fd
	int alarm_notify_fd; // eventfd: thread -> event loop
	// managed settle: keep autosleep OFF for a delay after ready so we do not
	// suspend mid-boot (containers/drivers still initializing). Kernel timerfd
	// so it is exact across the FSM path.
	bool settle_pending;
	int settle_fd;
	struct event *settle_ev;
	// managed wake window: each timed wake holds WL_POLL until the network
	// re-associates and one poll round reaches Hub (min/max awake bounds).
	bool poll_active;
	bool poll_round_ok;
	bool poll_min_elapsed;
	struct event *poll_min_ev;
	struct event *poll_max_ev;
	struct event *poll_retry_ev;
	// devmeta dirty-gate: WL_DEVMETA held while there is un-acked devmeta;
	// generation counters avoid clearing a change that landed mid-flight
	unsigned int dm_pending_gen;
	unsigned int dm_sent_gen;
	struct event *dm_backstop_ev;
} wl = {
	.lock_fd = -1,
	.unlock_fd = -1,
	.alarm_fd = -1,
	.alarm_wl_fd = -1,
	.alarm_notify_fd = -1,
	.settle_fd = -1,
};

static const char *_mode_str(power_mode_t m)
{
	switch (m) {
	case PWR_DISABLED:
		return "disabled";
	case PWR_LOCKS:
		return "locks";
	case PWR_MANAGED:
		return "managed";
	default:
		return "unknown";
	}
}

static const char *_scope_str(enum wl_scope scope)
{
	switch (scope) {
	case WL_BOOT:
		return "boot";
	case WL_UPDATE:
		return "update";
	case WL_UPDATE_CHECK:
		return "update_check";
	case WL_SHUTDOWN:
		return "shutdown";
	case WL_DEVMETA:
		return "devmeta";
	case WL_USRMETA:
		return "usrmeta";
	case WL_DEBUG_SHELL:
		return "debug_shell";
	case WL_POLL:
		return "poll";
	default:
		return "unknown";
	}
}

static void _sysfs_path(char *out, size_t len, const char *attr)
{
	snprintf(out, len, "%s/%s", pv_config_get_str(PV_POWER_SYSFS_DIR),
		 attr);
}

static int _sysfs_write(int fd, const char *buf)
{
	if (fd < 0)
		return -1;

	if (write(fd, buf, strlen(buf)) < 0) {
		pv_log(WARN, "wakelock: sysfs write '%s' failed: %s", buf,
		       strerror(errno));
		return -1;
	}

	return 0;
}

// Latch the module disabled. A wakelock failure must never fail an update, so
// from here every acquire/release is bookkept but touches no sysfs.
static void _set_degraded(void)
{
	if (!wl.degraded) {
		wl.degraded = true;
		pv_log(WARN, "wakelock: degraded (no CONFIG_PM_WAKELOCKS)");
	}

	if (wl.lock_fd >= 0) {
		close(wl.lock_fd);
		wl.lock_fd = -1;
	}
	if (wl.unlock_fd >= 0) {
		close(wl.unlock_fd);
		wl.unlock_fd = -1;
	}
}

static void _count_inc(void)
{
	wl.count++;

	if (wl.count == 1 && !wl.degraded) {
		if (_sysfs_write(wl.lock_fd, WL_NAME) == 0)
			pv_log(DEBUG, "wakelock: wake_lock/%s", WL_NAME);
	}
}

static void _count_dec(void)
{
	if (wl.count <= 0)
		return;

	wl.count--;

	if (wl.count == 0 && !wl.degraded) {
		if (_sysfs_write(wl.unlock_fd, WL_NAME) == 0)
			pv_log(DEBUG, "wakelock: wake_unlock/%s", WL_NAME);
	}
}

void pv_wakelock_acquire(enum wl_scope scope)
{
	if (!wl.init || wl.mode == PWR_DISABLED)
		return;
	if (scope < 0 || scope >= WL_SCOPE_MAX)
		return;
	if (wl.held[scope])
		return;

	wl.held[scope] = true;
	_count_inc();

	pv_log(DEBUG, "wakelock: ACQUIRE scope=%s count=%d", _scope_str(scope),
	       wl.count);
}

void pv_wakelock_release(enum wl_scope scope)
{
	if (!wl.init || wl.mode == PWR_DISABLED)
		return;
	if (scope < 0 || scope >= WL_SCOPE_MAX)
		return;
	if (!wl.held[scope])
		return;

	wl.held[scope] = false;
	_count_dec();

	pv_log(DEBUG, "wakelock: RELEASE scope=%s count=%d", _scope_str(scope),
	       wl.count);
}

// devmeta dirty-gated scope ---------------------------------------------------

static void _devmeta_backstop_cb(evutil_socket_t fd, short events, void *arg)
{
	pv_log(WARN, "wakelock: devmeta max-hold backstop elapsed; releasing");

	pv_wakelock_release(WL_DEVMETA);

	// one-shot timer already fired; free it here (safe from own callback)
	if (wl.dm_backstop_ev) {
		event_free(wl.dm_backstop_ev);
		wl.dm_backstop_ev = NULL;
	}
}

static void _devmeta_backstop_cancel(void)
{
	if (!wl.dm_backstop_ev)
		return;

	event_del(wl.dm_backstop_ev);
	event_free(wl.dm_backstop_ev);
	wl.dm_backstop_ev = NULL;
}

// Hard bound for the case where the Hub is offline and no PUT ever round-trips,
// so an unreachable Hub cannot pin the device awake forever.
static void _devmeta_backstop_arm(void)
{
	struct event_base *base = pv_event_get_base();
	if (!base)
		return;

	int max_hold = pv_config_get_int(PV_POWER_DEVMETA_MAX_HELD);
	if (max_hold <= 0)
		return;

	_devmeta_backstop_cancel();

	wl.dm_backstop_ev = evtimer_new(base, _devmeta_backstop_cb, NULL);
	if (!wl.dm_backstop_ev) {
		pv_log(ERROR,
		       "wakelock: could not create devmeta backstop timer");
		return;
	}

	struct timeval tv = { max_hold, 0 };
	event_add(wl.dm_backstop_ev, &tv);
}

static void _devmeta_release(void)
{
	_devmeta_backstop_cancel();
	pv_wakelock_release(WL_DEVMETA);
}

void pv_wakelock_devmeta_dirty(void)
{
	if (!wl.init || wl.mode == PWR_DISABLED)
		return;

	wl.dm_pending_gen++;

	if (!wl.held[WL_DEVMETA]) {
		pv_wakelock_acquire(WL_DEVMETA);
		_devmeta_backstop_arm();
	}

	// optionally push out-of-band right away rather than waiting up to a
	// full devmeta interval, minimizing awake time
	if (pv_config_get_bool(PV_POWER_DEVMETA_EAGER_PUSH))
		pv_pantahub_proto_set_devmeta();
}

void pv_wakelock_devmeta_sent(void)
{
	if (!wl.init || wl.mode == PWR_DISABLED)
		return;

	wl.dm_sent_gen = wl.dm_pending_gen;
}

void pv_wakelock_devmeta_acked(bool ok)
{
	if (!wl.init || wl.mode == PWR_DISABLED)
		return;
	if (!wl.held[WL_DEVMETA])
		return;

	if (!ok) {
		// failed attempt: change is buffered on disk and retried later;
		// a new change re-arms the scope
		_devmeta_release();
		return;
	}

	// 200: caught up only if no newer change landed while in flight
	if (wl.dm_pending_gen == wl.dm_sent_gen)
		_devmeta_release();
	// else keep held; the next push flushes the newer change
}

void pv_wakelock_devmeta_deauth(void)
{
	if (!wl.init || wl.mode == PWR_DISABLED)
		return;

	if (wl.held[WL_DEVMETA])
		_devmeta_release();
}

// managed mode: timed wake-and-poll ------------------------------------------

// delay between poll-round attempts while the network is still coming back up
#define WL_POLL_RETRY_S 3

// Fire one full poll round: check Hub for pending steps and sync metadata. Each
// call acquires its own in-flight scope; the outer WL_POLL window keeps us
// awake across retries and the min-awake floor.
static void _poll_fire_requests(void)
{
	pv_pantahub_proto_get_pending_steps();
	pv_pantahub_proto_set_devmeta();
	pv_pantahub_proto_get_usrmeta();
}

// Close the wake window: cancel its timers, drop WL_POLL. Idempotent.
static void _poll_window_close(const char *why)
{
	if (!wl.poll_active)
		return;
	wl.poll_active = false;

	if (wl.poll_min_ev) {
		event_del(wl.poll_min_ev);
		event_free(wl.poll_min_ev);
		wl.poll_min_ev = NULL;
	}
	if (wl.poll_max_ev) {
		event_del(wl.poll_max_ev);
		event_free(wl.poll_max_ev);
		wl.poll_max_ev = NULL;
	}
	if (wl.poll_retry_ev) {
		event_del(wl.poll_retry_ev);
		event_free(wl.poll_retry_ev);
		wl.poll_retry_ev = NULL;
	}

	pv_wakelock_release(WL_POLL);
	pv_log(DEBUG, "wakelock: wake window closed (%s)", why);
}

// Close only once BOTH the min-awake floor elapsed AND a full round reached Hub,
// so we neither re-suspend before the network recovers nor linger past a done
// round.
static void _poll_window_maybe_close(void)
{
	if (wl.poll_round_ok && wl.poll_min_elapsed)
		_poll_window_close("round complete");
}

static void _poll_retry_cb(evutil_socket_t fd, short events, void *arg)
{
	if (!wl.poll_active || wl.poll_round_ok)
		return;
	pv_log(DEBUG, "wakelock: retrying poll round (network not up yet)");
	_poll_fire_requests();
}

static void _poll_min_cb(evutil_socket_t fd, short events, void *arg)
{
	wl.poll_min_elapsed = true;
	_poll_window_maybe_close();
}

static void _poll_max_cb(evutil_socket_t fd, short events, void *arg)
{
	pv_log(INFO,
	       "wakelock: wake window max-awake reached; giving up this round");
	_poll_window_close("max-awake");
}

// (re)arm the one-shot retry timer; the device stays awake via WL_POLL meanwhile
static void _poll_arm_retry(void)
{
	struct event_base *base = pv_event_get_base();
	if (!base)
		return;

	if (wl.poll_retry_ev) {
		event_del(wl.poll_retry_ev);
		event_free(wl.poll_retry_ev);
		wl.poll_retry_ev = NULL;
	}

	wl.poll_retry_ev = evtimer_new(base, _poll_retry_cb, NULL);
	if (!wl.poll_retry_ev)
		return;

	struct timeval tv = { WL_POLL_RETRY_S, 0 };
	event_add(wl.poll_retry_ev, &tv);
}

// Open a wake window: hold the device awake for at least min-awake seconds (so
// wifi/tailscale re-associate after deep suspend) and until one full poll round
// reaches Hub, bounded by max-awake seconds. All three timers run while WL_POLL
// is held, so plain libevent timers are exact here.
static void _poll_window_open(void)
{
	struct event_base *base = pv_event_get_base();
	int min_awake = pv_config_get_int(PV_POWER_WAKE_MIN_AWAKE);
	int max_awake = pv_config_get_int(PV_POWER_WAKE_MAX_AWAKE);

	// feature disabled (no max bound) or no event loop: fall back to the
	// legacy single-shot behaviour (fire once; the per-request scopes govern
	// awake time)
	if (max_awake <= 0 || !base) {
		_poll_fire_requests();
		return;
	}

	// max-awake backstop: an offline Hub can never pin the device awake. This
	// is the safety bound, so if it cannot be armed we must NOT open a window
	// (which could otherwise stay awake forever) — fall back to single-shot.
	wl.poll_max_ev = evtimer_new(base, _poll_max_cb, NULL);
	if (!wl.poll_max_ev) {
		pv_log(WARN,
		       "wakelock: could not arm wake-window max-awake timer; single-shot poll");
		_poll_fire_requests();
		return;
	}

	pv_wakelock_acquire(WL_POLL);
	wl.poll_active = true;
	wl.poll_round_ok = false;
	wl.poll_min_elapsed = (min_awake <= 0);

	struct timeval tv_max = { max_awake, 0 };
	event_add(wl.poll_max_ev, &tv_max);

	// min-awake floor: keep awake at least this long even once a round
	// succeeds, so the link finishes re-associating
	if (min_awake > 0) {
		wl.poll_min_ev = evtimer_new(base, _poll_min_cb, NULL);
		if (wl.poll_min_ev) {
			struct timeval tv = { min_awake, 0 };
			event_add(wl.poll_min_ev, &tv);
		}
	}

	pv_log(DEBUG,
	       "wakelock: wake window opened (min_awake=%ds max_awake=%ds)",
	       min_awake, max_awake);

	_poll_fire_requests();
}

// Arm the RTC wake alarm for now + interval seconds via the /dev/rtc char
// device. The RTC alarm is one-shot, so this is called both to arm the first
// wake and to re-arm each cycle from _alarm_cb.
static int _managed_rtc_arm(int fd, int interval)
{
	struct rtc_time now;
	if (ioctl(fd, RTC_RD_TIME, &now) < 0) {
		pv_log(WARN, "wakelock: RTC_RD_TIME failed: %s",
		       strerror(errno));
		return -1;
	}

	struct tm tm = {
		.tm_sec = now.tm_sec,
		.tm_min = now.tm_min,
		.tm_hour = now.tm_hour,
		.tm_mday = now.tm_mday,
		.tm_mon = now.tm_mon,
		.tm_year = now.tm_year,
		.tm_isdst = -1,
	};
	time_t t = timegm(&tm);
	if (t == (time_t)-1)
		return -1;
	t += interval;

	struct tm out;
	gmtime_r(&t, &out);

	struct rtc_wkalrm alm;
	memset(&alm, 0, sizeof(alm));
	alm.enabled = 1; // arm + enable the alarm IRQ so read() gets the event
	alm.time.tm_sec = out.tm_sec;
	alm.time.tm_min = out.tm_min;
	alm.time.tm_hour = out.tm_hour;
	alm.time.tm_mday = out.tm_mday;
	alm.time.tm_mon = out.tm_mon;
	alm.time.tm_year = out.tm_year;
	if (ioctl(fd, RTC_WKALM_SET, &alm) < 0) {
		pv_log(WARN, "wakelock: RTC_WKALM_SET failed: %s",
		       strerror(errno));
		return -1;
	}
	return 0;
}

// Worker thread: park in a BLOCKING read on the RTC char device. When the alarm
// fires (the device is woken from autosleep) grab the kernel wakelock the
// instant the read returns — in this same thread, before anything else — so the
// kernel's post-read wakeup hold covers us before the autosleep loop can
// re-suspend (~197us, faster than any event-loop callback could react). Then
// kick the event loop via an eventfd to do the poll-window work, which is not
// latency-critical because the wakelock is already held. The thread must not
// call pv_log or any other Pantavisor code — only raw syscalls — to stay
// thread-safe against the single-threaded event loop.
static void *_alarm_thread_fn(void *arg)
{
	(void)arg;
	while (wl.alarm_thread_run) {
		unsigned long data = 0;
		ssize_t r = read(wl.alarm_fd, &data, sizeof(data)); // BLOCKS

		// grab the kernel wakelock IMMEDIATELY, before anything else
		if (wl.alarm_wl_fd >= 0) {
			ssize_t w =
				write(wl.alarm_wl_fd, WL_NAME, strlen(WL_NAME));
			(void)w;
		}

		if (!wl.alarm_thread_run)
			break;
		if (r < 0 && errno == EINTR)
			continue;
		if (r < 0)
			break; // fd closed / fatal — stop the thread

		// hand off to the event loop (re-arm + open the poll window there)
		uint64_t one = 1;
		if (wl.alarm_notify_fd >= 0) {
			ssize_t w =
				write(wl.alarm_notify_fd, &one, sizeof(one));
			(void)w;
		}
	}
	return NULL;
}

// Event-loop side of a managed wake: the worker thread has already grabbed the
// kernel wakelock, so nothing here is latency-critical. Adopt that grab into the
// WL_POLL refcount, re-arm the next RTC wake, and open the poll window.
static void _alarm_notify_cb(evutil_socket_t fd, short events, void *arg)
{
	uint64_t v = 0;
	if (read(fd, &v, sizeof(v)) < 0 && errno != EAGAIN)
		pv_log(WARN, "wakelock: alarm notify read failed: %s",
		       strerror(errno));

	bool had_window = wl.poll_active;

	// adopt the thread's raw kernel-wakelock grab into the refcount (idempotent
	// at the kernel level: same WL_NAME); the normal release path now owns it
	pv_wakelock_acquire(WL_POLL);

	// the RTC alarm is one-shot; re-arm the next wake now, while WL_POLL holds
	// the device awake, so a future wake is always armed before we can sleep
	int interval = pv_config_get_int(PV_POWER_WAKE_INTERVAL);
	if (interval <= 0)
		interval = 1;
	_managed_rtc_arm(wl.alarm_fd, interval);

	pv_log(DEBUG, "wakelock: managed wake");

	// a window from a previous alarm is still open: it already owns WL_POLL,
	// so leave our (no-op) acquire in place and don't stack another window
	if (had_window) {
		pv_log(DEBUG,
		       "wakelock: wake alarm fired while window still open; skipping");
		return;
	}

	// not authed: nothing to poll — drop the lock we just took and let the
	// device go back to sleep
	if (!pv_pantahub_proto_is_auth()) {
		pv_wakelock_release(WL_POLL);
		return;
	}

	// _poll_window_open takes ownership of the WL_POLL we are already holding
	_poll_window_open();
}

// Called from the update-check response path. A round that round-tripped to Hub
// completes the window (after the min-awake floor); a connection failure retries
// within the max-awake budget instead of letting the device re-suspend.
void pv_wakelock_poll_round_done(bool reached_hub)
{
	if (!wl.init || wl.mode != PWR_MANAGED || !wl.poll_active)
		return;

	if (reached_hub) {
		wl.poll_round_ok = true;
		pv_log(DEBUG, "wakelock: poll round reached Hub");
		_poll_window_maybe_close();
		return;
	}

	pv_log(DEBUG, "wakelock: poll round did not reach Hub; retrying in %ds",
	       WL_POLL_RETRY_S);
	_poll_arm_retry();
}

// Enable opportunistic suspend (write "mem" to /sys/power/autosleep). From here
// the kernel suspends whenever the wakelock refcount is zero, so this must only
// run once the device is ready (boot lock released, platforms up) — see
// pv_wakelock_managed_ready(). The RTC worker thread (see _managed_arm_alarm)
// wakes us back up on schedule. Idempotent.
static void _managed_enable_autosleep(void)
{
	char path[PATH_MAX];
	int fd;

	if (wl.autosleep)
		return;

	_sysfs_path(path, sizeof(path), WL_SYSFS_AUTOSLEEP);
	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		pv_log(WARN, "wakelock: could not open '%s': %s", path,
		       strerror(errno));
		return;
	}
	if (write(fd, "mem", strlen("mem")) < 0) {
		pv_log(WARN, "wakelock: could not enable autosleep: %s",
		       strerror(errno));
	} else {
		wl.autosleep = true;
		pv_log(INFO, "wakelock: autosleep enabled");
	}
	close(fd);
}

// Arm the wake alarm via the RTC char device and start the worker thread that
// parks in a blocking read on it (the RTC alarm survives suspend, so the device
// can wake itself on a schedule to poll). Keeping the fd open and reading it
// blocking-in-a-thread is deliberate — see WL_RTC_DEV / _alarm_thread_fn. Safe
// to call at init: arming the alarm does not itself suspend the device.
// Idempotent (wl.alarm_ev guards re-entry).
static void _managed_arm_alarm(void)
{
	struct event_base *base = pv_event_get_base();
	if (!base)
		return;

	if (wl.alarm_ev)
		return;

	int interval = pv_config_get_int(PV_POWER_WAKE_INTERVAL);
	if (interval <= 0)
		interval = 1;

	// Open the RTC char device BLOCKING and keep it open for the life of managed
	// mode: the worker thread parks in read() here and grabs the wakelock inline
	// on return — that inline grab is what beats the autosleep re-suspend race.
	wl.alarm_fd = open(WL_RTC_DEV, O_RDONLY | O_CLOEXEC);
	if (wl.alarm_fd < 0) {
		pv_log(WARN, "wakelock: could not open %s: %s", WL_RTC_DEV,
		       strerror(errno));
		return;
	}

	// the thread grabs the kernel wakelock through its own fd so it never races
	// the event-loop-owned lock_fd
	char lpath[PATH_MAX];
	_sysfs_path(lpath, sizeof(lpath), WL_SYSFS_LOCK);
	wl.alarm_wl_fd = open(lpath, O_WRONLY | O_CLOEXEC);
	if (wl.alarm_wl_fd < 0) {
		pv_log(WARN, "wakelock: could not open %s for alarm thread: %s",
		       lpath, strerror(errno));
		goto err_rtc;
	}

	// eventfd: worker thread -> event loop
	wl.alarm_notify_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (wl.alarm_notify_fd < 0) {
		pv_log(WARN, "wakelock: eventfd failed: %s", strerror(errno));
		goto err_wl;
	}

	if (_managed_rtc_arm(wl.alarm_fd, interval) < 0)
		goto err_notify;

	wl.alarm_ev = event_new(base, wl.alarm_notify_fd, EV_READ | EV_PERSIST,
				_alarm_notify_cb, NULL);
	if (!wl.alarm_ev) {
		pv_log(ERROR, "wakelock: could not create alarm notify event");
		goto err_notify;
	}
	event_add(wl.alarm_ev, NULL);

	wl.alarm_thread_run = true;
	if (pthread_create(&wl.alarm_thread, NULL, _alarm_thread_fn, NULL) !=
	    0) {
		pv_log(ERROR, "wakelock: could not start alarm thread: %s",
		       strerror(errno));
		wl.alarm_thread_run = false;
		event_del(wl.alarm_ev);
		event_free(wl.alarm_ev);
		wl.alarm_ev = NULL;
		goto err_notify;
	}
	wl.alarm_thread_started = true;

	pv_log(INFO,
	       "wakelock: managed wake alarm armed via %s at %ds (blocking-read thread)",
	       WL_RTC_DEV, interval);
	return;

err_notify:
	close(wl.alarm_notify_fd);
	wl.alarm_notify_fd = -1;
err_wl:
	close(wl.alarm_wl_fd);
	wl.alarm_wl_fd = -1;
err_rtc:
	close(wl.alarm_fd);
	wl.alarm_fd = -1;
}

// End the settle window: cancel the backstop timer and finally enable
// opportunistic suspend. Idempotent, safe to call from the timer callback or
// the update-check release path.
static void _managed_settle_done(const char *why)
{
	if (!wl.settle_pending)
		return;

	wl.settle_pending = false;
	if (wl.settle_ev) {
		event_del(wl.settle_ev);
		event_free(wl.settle_ev);
		wl.settle_ev = NULL;
	}
	if (wl.settle_fd >= 0) {
		close(wl.settle_fd);
		wl.settle_fd = -1;
	}

	pv_log(INFO,
	       "wakelock: managed settle complete (%s); enabling autosleep",
	       why);
	_managed_enable_autosleep();
}

// Backstop: if the device never reaches the Hub (offline), settle anyway after
// a bounded delay so managed mode still eventually suspends. Driven by a kernel
// timerfd (fires when the fd becomes readable), so the delay is exact and not
// subject to libevent's cached-time skew.
static void _managed_settle_cb(evutil_socket_t fd, short events, void *arg)
{
	uint64_t expirations = 0;
	if (read(fd, &expirations, sizeof(expirations)) < 0 && errno != EAGAIN)
		pv_log(WARN, "wakelock: settle timerfd read failed: %s",
		       strerror(errno));

	_managed_settle_done("timeout");
}

// Called once the top-level FSM first reaches steady state (boot lock released,
// platforms started). In managed mode we arm the wake alarm here, but do NOT
// enable autosleep yet: at this point containers are typically still mounting
// (loop/dm/EXT4 recovery) and out-of-tree drivers (e.g. the NXP moal wifi) are
// still initializing, so suspending now hangs the freeze and the watchdog
// resets the board. Instead we hold autosleep off for a fixed settle delay
// (PV_POWER_AUTOSLEEP_SETTLE) to let the system go quiescent first.
void pv_wakelock_managed_ready(void)
{
	if (!wl.init || wl.degraded)
		return;
	if (wl.mode != PWR_MANAGED)
		return;

	_managed_arm_alarm();

	// already settled (e.g. runtime transition already enabled autosleep)
	if (wl.autosleep || wl.settle_pending)
		return;

	int settle = pv_config_get_int(PV_POWER_AUTOSLEEP_SETTLE);
	if (settle <= 0) {
		// settle disabled: keep the legacy behaviour (suspend at ready)
		_managed_enable_autosleep();
		return;
	}

	struct event_base *base = pv_event_get_base();
	if (!base) {
		// no event loop yet: fall back to immediate enable rather than
		// pinning awake forever
		_managed_enable_autosleep();
		return;
	}

	// kernel timerfd one-shot at +settle seconds; watched for readability so
	// the fire time is exact regardless of libevent's time cache
	wl.settle_fd =
		timerfd_create(CLOCK_BOOTTIME, TFD_CLOEXEC | TFD_NONBLOCK);
	if (wl.settle_fd < 0) {
		pv_log(WARN,
		       "wakelock: settle timerfd_create failed (%s); enabling autosleep now",
		       strerror(errno));
		_managed_enable_autosleep();
		return;
	}

	struct itimerspec its = { 0 };
	its.it_value.tv_sec = settle;
	if (timerfd_settime(wl.settle_fd, 0, &its, NULL) < 0) {
		pv_log(WARN,
		       "wakelock: settle timerfd_settime failed (%s); enabling autosleep now",
		       strerror(errno));
		close(wl.settle_fd);
		wl.settle_fd = -1;
		_managed_enable_autosleep();
		return;
	}

	wl.settle_ev = event_new(base, wl.settle_fd, EV_READ | EV_PERSIST,
				 _managed_settle_cb, NULL);
	if (!wl.settle_ev) {
		pv_log(WARN,
		       "wakelock: settle event_new failed; enabling autosleep now");
		close(wl.settle_fd);
		wl.settle_fd = -1;
		_managed_enable_autosleep();
		return;
	}
	event_add(wl.settle_ev, NULL);

	wl.settle_pending = true;
	pv_log(INFO,
	       "wakelock: managed settle armed; deferring autosleep %ds to let the system settle (containers up, drivers initialized)",
	       settle);
}

// init / deinit --------------------------------------------------------------

int pv_wakelock_init(void)
{
	char path[PATH_MAX];

	if (wl.init)
		return 0;

	wl.mode = pv_config_get_power_mode();
	wl.init = true;

	pv_log(INFO, "wakelock: mode=%s", pv_config_get_power_mode_str());

	if (wl.mode == PWR_DISABLED)
		return 0;

	_sysfs_path(path, sizeof(path), WL_SYSFS_LOCK);
	wl.lock_fd = open(path, O_WRONLY | O_CLOEXEC);
	if (wl.lock_fd < 0) {
		_set_degraded();
		return 0;
	}

	_sysfs_path(path, sizeof(path), WL_SYSFS_UNLOCK);
	wl.unlock_fd = open(path, O_WRONLY | O_CLOEXEC);
	if (wl.unlock_fd < 0) {
		_set_degraded();
		return 0;
	}

	// best-effort: clear a stale lock left by a prior crash (a no-op after a
	// clean reboot, since kernel wakelock state is fresh)
	_sysfs_write(wl.unlock_fd, WL_NAME);

	// Managed mode: arm the wake alarm now, but defer enabling autosleep to
	// pv_wakelock_managed_ready() (first RUN->WAIT) so we never suspend before
	// the boot lock is held and platforms are up.
	if (wl.mode == PWR_MANAGED)
		_managed_arm_alarm();

	return 0;
}

void pv_wakelock_apply_config(void)
{
	if (!wl.init || wl.degraded)
		return;

	power_mode_t m = pv_config_get_power_mode();
	if (m == wl.mode)
		return;

	pv_log(INFO, "wakelock: mode %s -> %s (config applied)",
	       _mode_str(wl.mode), _mode_str(m));
	wl.mode = m;

	// only-forward transition we act on: entering managed at runtime (after
	// boot) arms the wake alarm and enables autosleep. This path is post-ready
	// by construction, so enabling autosleep immediately is safe. Other
	// transitions just change how acquire/release behave via wl.mode.
	if (m == PWR_MANAGED) {
		_managed_arm_alarm();
		_managed_enable_autosleep();
	}
}

void pv_wakelock_deinit(void)
{
	if (!wl.init)
		return;

	_devmeta_backstop_cancel();

	if (wl.settle_ev) {
		event_del(wl.settle_ev);
		event_free(wl.settle_ev);
		wl.settle_ev = NULL;
	}
	if (wl.settle_fd >= 0) {
		close(wl.settle_fd);
		wl.settle_fd = -1;
	}
	wl.settle_pending = false;

	if (wl.poll_min_ev) {
		event_del(wl.poll_min_ev);
		event_free(wl.poll_min_ev);
		wl.poll_min_ev = NULL;
	}
	if (wl.poll_max_ev) {
		event_del(wl.poll_max_ev);
		event_free(wl.poll_max_ev);
		wl.poll_max_ev = NULL;
	}
	if (wl.poll_retry_ev) {
		event_del(wl.poll_retry_ev);
		event_free(wl.poll_retry_ev);
		wl.poll_retry_ev = NULL;
	}
	wl.poll_active = false;

	// stop the RTC blocking-read worker thread before tearing down its fds
	// (pthread_cancel interrupts the blocking read, which is a cancellation
	// point)
	if (wl.alarm_thread_started) {
		wl.alarm_thread_run = false;
		pthread_cancel(wl.alarm_thread);
		pthread_join(wl.alarm_thread, NULL);
		wl.alarm_thread_started = false;
	}

	if (wl.alarm_ev) {
		event_del(wl.alarm_ev);
		event_free(wl.alarm_ev);
		wl.alarm_ev = NULL;
	}
	if (wl.alarm_fd >= 0) {
		close(wl.alarm_fd);
		wl.alarm_fd = -1;
	}
	if (wl.alarm_wl_fd >= 0) {
		close(wl.alarm_wl_fd);
		wl.alarm_wl_fd = -1;
	}
	if (wl.alarm_notify_fd >= 0) {
		close(wl.alarm_notify_fd);
		wl.alarm_notify_fd = -1;
	}
	if (wl.lock_fd >= 0) {
		close(wl.lock_fd);
		wl.lock_fd = -1;
	}
	if (wl.unlock_fd >= 0) {
		close(wl.unlock_fd);
		wl.unlock_fd = -1;
	}

	wl.init = false;
}

// observability --------------------------------------------------------------

char *pv_wakelock_get_json(void)
{
	struct pv_json_ser js;

	pv_json_ser_init(&js, 512);

	pv_json_ser_object(&js);
	{
		pv_json_ser_key(&js, "mode");
		// report the ACTIVE captured mode, not the live config (which may
		// differ until pv_wakelock_apply_config() runs)
		pv_json_ser_string(&js, _mode_str(wl.mode));

		pv_json_ser_key(&js, "count");
		pv_json_ser_number(&js, wl.count);

		pv_json_ser_key(&js, "degraded");
		pv_json_ser_bool(&js, wl.degraded);

		pv_json_ser_key(&js, "autosleep");
		pv_json_ser_bool(&js, wl.autosleep);

		pv_json_ser_key(&js, "settling");
		pv_json_ser_bool(&js, wl.settle_pending);

		// managed wake window: true while awake for a timed poll round
		pv_json_ser_key(&js, "polling");
		pv_json_ser_bool(&js, wl.poll_active);

		pv_json_ser_key(&js, "held");
		pv_json_ser_object(&js);
		{
			pv_json_ser_key(&js, "boot");
			pv_json_ser_bool(&js, wl.held[WL_BOOT]);
			pv_json_ser_key(&js, "update");
			pv_json_ser_bool(&js, wl.held[WL_UPDATE]);
			pv_json_ser_key(&js, "update_check");
			pv_json_ser_bool(&js, wl.held[WL_UPDATE_CHECK]);
			pv_json_ser_key(&js, "devmeta");
			pv_json_ser_bool(&js, wl.held[WL_DEVMETA]);
			pv_json_ser_key(&js, "usrmeta");
			pv_json_ser_bool(&js, wl.held[WL_USRMETA]);
			pv_json_ser_key(&js, "shutdown");
			pv_json_ser_bool(&js, wl.held[WL_SHUTDOWN]);
			pv_json_ser_key(&js, "debug_shell");
			pv_json_ser_bool(&js, wl.held[WL_DEBUG_SHELL]);
			pv_json_ser_key(&js, "poll");
			pv_json_ser_bool(&js, wl.held[WL_POLL]);

			pv_json_ser_object_pop(&js);
		}

		pv_json_ser_object_pop(&js);
	}

	return pv_json_ser_str(&js);
}

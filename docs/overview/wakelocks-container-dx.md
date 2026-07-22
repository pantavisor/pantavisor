# Wakelocks for Containers — Developer Experience Design (DRAFT)

> Status: design proposal, 2026-07-21. Builds on the wakelocks feature
> ([wakelocks.md](wakelocks.md), branch `feature/wakelock-managed`,
> pantavisor PR #768). Phase 0 (§2.0) is implemented and validated
> on-device; phases 1+ (§7) are not started yet.

The wakelocks feature gives *Pantavisor itself* suspend-safety: internal
scopes (boot, update, hub roundtrips, shutdown, …) hold a refcounted kernel
wakelock, and `managed` mode adds autosleep plus an RTC-timed wake to poll
the Hub. Containers, however, have **no power API at all**: they cannot
block suspend, cannot schedule a wake, cannot learn why the device woke, and
cannot even read `GET /wakelocks` (it is mgmt-only). This document designs
the container-facing layer — with the explicit goal that **most software
should benefit without being modified**.

## 1. Adoption ladder — overview

| Level | Who changes what | Covers |
|---|---|---|
| 0 | nothing — defaults per group | unmodified containers get explicit run windows |
| 1 | one `power` section in the container manifest | periodic / event-driven apps, unmodified binaries |
| 2 | standard Linux APIs bridged (logind inhibitors) | stock system software (NetworkManager, ModemManager, …) |
| 3 | native pv-ctrl API | purpose-built Pantavisor apps |

All levels are implemented on one internal broker: per-owner wakelock
accounting + a wake-alarm queue + per-container run-window state machines
(the managed poll window logic, generalized).

### 1.1 Naming, units and inheritance — the scheme

Every key in this topic — the base wakelocks feature and all phases below
— follows one scheme:

**Vocabulary.** The same words at every layer (config, manifest, ctrl
API, logs): *wake* (any resume; the periodic one is the device
**heartbeat**), *window* (run time granted to containers), *lock* (a
held wakelock or lease), *alarm* (a scheduled future wake), *freeze*,
*wakeup* (wake sources). Held-time bounds are always `max_held`.

**Durations.** No `_s`-suffixed names anywhere. All durations are
`DURATION` config values parsed by one `pv_parse_duration()`: a bare
number is seconds (`3600`), or a single-unit literal — `30s`, `10min`,
`1h`, `1d` (the syntax `backoff_policy` already speaks). In JSON
(manifest and ctrl API): number = seconds, string = duration literal.

**Namespace.** No mode prefixes (`managed.` does not appear in key paths
— mode gating is behavior, documented per key). The base feature's keys:

| key | default | meaning |
|---|---|---|
| `power.mode` | `locks` | `disabled` / `locks` / `managed` |
| `power.sysfs_dir` | `/sys/power` | base dir of the wakelock/autosleep sysfs nodes |
| `power.wake.interval` | `1h` | the heartbeat: time between timed wakes |
| `power.wake.min_awake` | `10s` | minimum awake time per wake |
| `power.wake.max_awake` | `1min` | hard cap on awake time per wake |
| `power.wake.run_window` | `0` (off) | shared container run window after the wake's payloads (phase 0) |
| `power.autosleep.settle` | `90s` | delay after ready before autosleep is enabled |
| `power.devmeta.eager_push` | `false` | push devmeta to the Hub immediately on dirty instead of waiting an interval |
| `power.devmeta.max_held` | `5min` | backstop on the devmeta lock awaiting a Hub ack |

Env vars derive mechanically (`PV_POWER_WAKE_INTERVAL`,
`PV_POWER_DEVMETA_MAX_HELD`, …). Planned subtrees: `power.container.*`
— the **global scope of the manifest `power` section, field-for-field**
(§3); `power.limit.*` — system clamps, always in the battery-protective
direction (ceilings on awake/held time, floors on intervals);
`power.freeze.*` and `power.wakeup.*` (phases 5/6).

**Inheritance (per-container policy fields).** Two orthogonal stacks.
The existing config-level stack (`RUN > OEM > PV`) resolves every
`power.*` config key as usual. The scope stack resolves each manifest
field `F` independently, per field:

`run.json power.F` → group's `power.F` (groups.json) →
config `power.container.F` → built-in default.

Rules, for every present and future field: **absent = inherit; explicit
`0`/`"off"` = disabled at that scope** and stops inheritance (a group
can enable, a single container can opt out). After resolution, values
are clamped against `power.limit.*` with a log warning and devmeta
visibility — never a validation failure. Shape errors (`align` without
`interval`, `min_awake > max_awake`, a `power` section on a
`MOUNTED`-goal container) are warn-and-ignore. Note this is a
**per-field merge** — deliberately finer than `auto_recovery`'s
all-or-nothing group inheritance; the reference doc must state the
divergence explicitly.

## 2. Level 0 — run windows (no declarations)

### 2.0 Phase 0: the basic run window, built from what already exists

The managed cycle already *is* a shared container run window: on every RTC
wake the whole system runs until the poll window closes (`round_ok` +
`min_awake`, capped by `max_awake`), and during suspend the PM freezer
stops every container anyway — no cgroup freezing involved, no new
mechanism. Phase 0 just turns that side effect into a stated, guaranteed
contract with **one new knob**:

| key | default | meaning |
|---|---|---|
| `power.wake.run_window` | `0` (off) | after the hub roundtrip completes, stay awake this much longer as the containers' guaranteed run window |

- **Why not just raise `min_awake`?** `power.wake.min_awake` is anchored
  at the wake and *includes* the roundtrip — a slow hub eats the
  containers' time. `run_window` starts when the round is done, so the
  container guarantee is independent of hub latency. Implementation is one
  more close condition in the existing `_poll_window_maybe_close()`: close
  when round done AND min elapsed AND `run_window` elapsed since round
  completion — or at the `power.wake.max_awake` hard cap, unchanged.
- **Cadence** is `power.wake.interval` — already configurable.
- **Safety is already in place**: `power.wake.max_awake` bounds the whole
  window, so a chatty container can at worst push the duty cycle to
  `max_awake / interval` — bounded misbehavior, no freezer needed.
  Because it caps the *whole* wake, `min_awake + run_window > max_awake`
  is a misconfiguration — warned at startup.
- Observability: `wakelock: run window open/close` log markers; `polling`
  in `GET /wakelocks` already covers the window state.

**Local management (no Hub) — the wake is a device heartbeat, not a hub
side effect.** On a local-management device (unclaimed / no Pantahub) the
hub roundtrip never happens, yet the wake cadence must still be honored and
containers still need their run window — there, the window is the *only*
purpose of the wake. Phase 0 therefore reframes the RTC wake as the device
heartbeat with two optional payloads (hub roundtrip; container run window):

- **Close-condition fix (required)**: today the window closes on
  `poll_round_ok`, which is set by the Hub client — on an unauthed device
  it never fires and every wake would burn to the `max_awake` backstop.
  Rule: with no Hub configured/authed, the round is considered complete at
  window open, so the window is `run_window` anchored at the wake.
- **Arming rule**: no Hub *and* `run_window=0` → nothing to wake for →
  do not arm the periodic RTC alarm at all (pure external-wake device).
  Either payload present → arm at `power.wake.interval`.
- **Key naming**: the interval lives at `power.wake.interval` because it
  governs the heartbeat whether or not a Hub is configured (§1.1; the
  original `update_check.*` naming was dropped pre-release).

What phase 0 consciously does **not** give: separation (containers also run
during the roundtrip — harmless), per-container accounting, quiescence
close (the window is timer-closed only), and any per-container scheduling.
The stated contract for unmodified software is simply: *"your container
runs at least `run_window` every `wake.interval`, wall-clock timers catch
up on each wake"* — and it holds identically on Hub-managed and
local-management devices.

### 2.1 Hardened run windows via freeze/thaw (deferred — later phase)

The rest of §2 describes the freeze/thaw hardening that makes windows
*exclusive* rather than shared. It is **deferred out of phase 0**: the v1
freezer has known sharp edges, the v2-freeze-in-hybrid question is
unverified on-device, and the dependency rules (never freeze the
network-owner, mgmt, xconnect providers) need the group/role policy work.
Entry gate for this phase: the §8 cgroup-v2 on-device check.

#### The problem with "awake = everybody runs"

Without container freezing, every wake — including Pantavisor's own cloud
roundtrip — implicitly runs *all* containers. Consequences: the poll window
cannot close on quiescence (any chatty container keeps the device awake),
per-container accounting is meaningless, and container work rides an
undeclared, cadence-of-the-poll schedule nobody chose.

#### Design: freeze app containers, thaw them in explicit run windows

In `managed` mode, containers in freezable groups are **cgroup-frozen** in
steady state and **thawed only during explicit run windows**:

- **Pantavisor's poll wake stays private.** RTC wake → poll roundtrip →
  re-suspend, with app containers frozen throughout. The poll window's
  close condition is back to what is already implemented (round done + min
  awake) — no app can distort it.
- **App run windows are scheduled**, not incidental: a window is opened by
  the broker (default cadence per group; Level 1 refines per container),
  the container(s) are thawed, the window closes on floor-met + quiescence
  (bounded by a max), the containers are re-frozen, the lock is released,
  the device may sleep.
- Windows **coalesce**: by default the app window is scheduled adjacent to
  a poll wake (one resume serves both), but it is a *separate, explicit*
  window with its own accounting — adjacency is an optimization, not a
  semantic.

#### Mechanism — what exists today (verified in source)

- Pantavisor itself constructs the cgroup layout in embedded/standalone
  mode (`cgroup.c:271-299`): tmpfs root, named `systemd`/`pantavisor` v1
  hierarchies, the v1 resource controllers **including `freezer`**
  (`cgroup.c:291`), and a cgroup2 mount at `/sys/fs/cgroup/unified`
  (`nsdelegate`). Appengine mode follows the host (all versions supported).
- Containers are started in a forked child via `lxc_container_new()`; no
  liblxc handle is retained in the Pantavisor process. Freeze/thaw should
  therefore be **direct cgroup filesystem writes** by the broker, not
  liblxc calls:
  - cgroup2: write `1`/`0` to the container cgroup's `cgroup.freeze`;
    completion signaled via `cgroup.events` (`frozen 1`).
  - cgroup1: write `FROZEN`/`THAWED` to `freezer.state`; poll
    `freezer.state` until it leaves `FREEZING`.
- One write freezes the container's whole cgroup subtree — "full
  hierarchy" freeze is the default and only sensible unit.

#### Is it trivial and stable? Mostly — with these known edges

**The good freezer vs. the flaky one.** cgroup2 `cgroup.freeze`
(kernel ≥ 5.2) is a *core* cgroup2 interface, not a controller — it exists
on any cgroup2 mount, **including the hybrid `unified` mount Pantavisor
already creates**. It is the one to prefer: frozen tasks land in a
signal-stop-like state, remain **killable**, and freezing cannot wedge.
The v1 `freezer` controller works (it is what `lxc-freeze` has used for a
decade) but has kernel-documented sharp edges: tasks in uninterruptible
sleep (NFS, fuse, some drivers) can stall the transition in `FREEZING`,
and **frozen tasks do not receive signals — not even SIGKILL — until
thawed**.

Rules that follow:

1. **Prefer v2 `cgroup.freeze` via the unified mount** when per-container
   cgroups exist there (LXC manages the unified hierarchy in hybrid mode —
   verify on-device); fall back to v1 `freezer.state` otherwise.
2. **Always thaw before stop/signal/update** (mandatory on v1, harmless on
   v2). The update path thaws everything first; container teardown thaws
   before kill.
3. **Debug entry auto-thaws**: `pventer`/exec into a frozen container must
   thaw it under a debug lease, or the shell just hangs — same spirit as
   the existing `debug_shell` scope.

**Interaction with suspend: orthogonal and compatible.** The PM freezer
handles already-cgroup-frozen tasks fine; if anything, suspend entry gets
cheaper because most tasks are already stopped. Freezing is *not* suspend:
while the device is awake, `CLOCK_MONOTONIC` keeps advancing for frozen
tasks and the kernel still ACKs their TCP connections (data queues up to
the receive buffer; the peer sees a zero window, the connection survives).
Both are useful properties: monotonic periodic timers of a frozen container
accrue across other containers' windows and fire immediately on thaw
("catch-up on thaw"), and freeze-while-awake is strictly gentler on network
software than suspend.

**What thaw means, precisely:** at thaw, everything deferred fires at once
— expired wall-clock timers (cron minutes, `CLOCK_REALTIME` timerfds),
elapsed monotonic timers, buffered socket data, queued fd events. The run
window's floor/quiescence/max machinery is exactly the right container for
this thundering herd: the app drains its backlog, goes quiet, gets frozen
again.

**The one real hazard: cross-container dependencies.** A frozen container
cannot serve anyone:

- **Never freeze the container that owns the uplink** (network manager) —
  Pantavisor's own cloud roundtrip depends on it. Same for mgmt containers
  and any xconnect *provider* whose consumer may run while it is frozen; a
  frozen fuse server hangs every accessor of its mount.
- Freeze policy is therefore **group/role-aware, deny-by-default for
  service-like groups**: only "app-like" groups are freezable (e.g. the
  `app` group frozen, `root`/`platform` groups exempt), refinable per
  container in the Level-1 manifest. The xconnect dependency graph gives a
  validation hook: reject or warn on a state where a freezable provider
  has a non-freezable consumer — same pattern as today's collision
  validation.

**Verdict:** the mechanism is near-trivial (one sysfs write per edge, no
new dependencies) and stable within known, manageable rules — prefer v2
freeze, thaw-before-kill, role-aware policy. It is the right Level-0
foundation precisely because it makes run windows *explicit*: Pantavisor's
poll window and app windows are separate schedulable, accountable objects
instead of an accident of being awake at the same time.

#### Freeze-phase knobs — deliberately minimal (two)

The freeze phase adds exactly **one further config key** on top of phase
0's `run_window` (`PV | OEM | RUN`, like the other `power.*` keys);
everything else is fixed behavior:

| key | default | meaning |
|---|---|---|
| `power.freeze.groups` | `` (off) | comma-separated groups frozen in managed steady state; empty string keeps phase-0 behavior (no freezing) |

The window itself stays phase 0's: the app window piggybacks on the managed
poll wake, `run_window` long. What freezing changes is *exclusivity*:
RTC wake → lock held → poll roundtrip (apps frozen) → thaw `freeze.groups`
→ `run_window` scope for its duration → freeze → release → autosleep.
Boot: containers start thawed and run through ready + settle as today;
first freeze happens when autosleep is enabled.

Fixed behaviors (not knobs): thaw-everything before update/teardown/stop;
auto-thaw on debug entry (`pventer`); `GET /wakelocks` reports the frozen
groups and a `held.run_window` flag; `wakelock: FREEZE group=…` /
`wakelock: THAW group=…` log markers for the testplan.

Still deferred beyond this phase: quiescence sensing, CPU floors,
per-container cadence/windows, `align`/`exec`, wake-source routing — all
Level 1+. A fixed-length window is trivially predictable and testable; the
smarter close conditions only make sense once per-container declarations
exist.

- `disabled`/`locks` modes: no freezing (feature inert, exactly like
  autosleep today).

## 3. Level 1 — the declarative `power` manifest section

A `power` section in the platform manifest (same layer as roles and restart
policy), handled entirely by Pantavisor. The section itself — and its
container > group > system inheritance — is born in phase 1 with the
declarative cadence fields below; later phases only ever add fields to it
(phase 3 adds `max_held`, §5 health integration). Field names, duration
syntax and the scope-resolution rules are the §1.1 scheme: the same
fields exist identically in `run.json`, in the group definition, and as
`power.container.*` config keys (the global scope).

**Phase 1 (locked): declarative cadence.** Fields added:

```json
"power": {
  "interval": "1h",     // open my run window at least once an hour
  "min_awake": "10s",   // cold-start grace before quiescence sensing is trusted
  "max_awake": "2min",  // hard cap on my window — THE guarantee
  "align": "1h"         // anchor due-times to wall clock (stock cron works)
}
```

Phase-1 semantics, as locked:

- **Scheduling — minimal earliest-deadline arming, not a queue.** The RTC
  is armed for `min(heartbeat, earliest container due-time)` via the
  existing `_managed_rtc_arm()` — a `min()` over containers. Phase 4
  generalizes this into the real named-alarm queue; this is its embryo.
- **Coalescing**: any wake (whatever its reason) opens every window whose
  due-time falls within a tolerance of now — v1: 25 % of that container's
  `interval` — and the container's next due reschedules from the actual
  open. Ten hourly containers must not mean ten wakes.
- **Pre-freeze semantics — holds, not slots.** Until phase 5, a
  per-container window is a *refcounted hold* (scope
  `window:<platform>`) keeping the device awake until close; it is NOT an
  exclusive run slot — every container runs whenever the device is awake.
  Exclusivity is exactly what phase 5's freezing adds.
- **No CPU floor — opportunity, not consumption.** An idle container must
  not pin its window (a consumption floor `min_cpu_ms` would hang every
  idle window to the max cap — removed). Instead, **quiescence is
  PSI-informed**: quiescent = cgroup CPU usage ≈ 0 AND CPU stall
  (`cpu.pressure`, time runnable-but-denied) ≈ 0 over a settle period.
  This separates the three cases correctly: idle-by-choice closes early
  (it had its opportunity), working stays open, and *starved* stays open
  too — stall counts as activity, which is what the CPU floor was for.
  `min_awake` survives only as a small cold-start grace (default ~10 s:
  caught-up timers need a moment to begin showing activity).
  Availability ladder: per-cgroup `cpu.pressure` (unified mount +
  `CONFIG_PSI`) → global `/proc/pressure/cpu` as a conservative
  correction + per-cgroup usage → usage-only threshold (no PSI). Build
  item: `CONFIG_PSI=y` joins the wakelock kernel fragment (watch
  `CONFIG_PSI_DEFAULT_DISABLED` → needs `psi=1` cmdline).
- **Bounded against busy-loopers.** Quiescence only ever closes a window
  *early*; `max_awake` is the guarantee. A spinning container runs to
  the cap and closes anyway; worst-case duty cycle is
  `max_awake / interval`, and system limits (below) bound that
  fleet-wide regardless of declarations.
- **Clamp + warn, never validation-fail.** Declared values are clamped
  against the system limits (`power.limit.max_awake` ceiling,
  `power.limit.interval` floor, …) with a log warning and devmeta
  visibility. Unlike xconnect name collisions (correctness conflicts,
  rightly fatal), power values are quantitative — a greedy `interval`
  must not WONTGO an update. The global `power.wake.max_awake`
  stays wake-scope-only.
- **`align`** anchors due-times to wall-clock boundaries: its value is a
  duration, and due-times snap to multiples of it from UTC midnight —
  `"1h"` = on the hour, `"15min"`, `"1d"` = midnight (pure due-time
  computation on the same min()-arming — no alarm queue needed). This is
  deliberately *in* phase 1: without it, unmodified wall-clock software
  (stock cron) only fires if a window happens to cover the scheduled
  minute, and monotonic-timer loops (`sleep 3600`) need 3600 s of
  cumulative awake time — the adoption payoff of declared cadences lives
  in `align`.
- **Stats are a first-class deliverable — decisions are made on them.**
  Per container, surfaced in the mgmt `GET /wakelocks` view and exported
  via devmeta: windows opened; closes by reason (`quiesce` vs `max`);
  consecutive max-closes (the busy-looper signal — bound first, make the
  pathology visible); cumulative window time; cumulative lease held-time
  (phase 2). These are the calibration inputs for `run_window`,
  quiescence thresholds, and phase-3 `max_held` values — thresholds get
  measured, not guessed. Log markers:
  `wakelock: WINDOW open platform=<p>` /
  `wakelock: WINDOW close platform=<p> reason=quiesce|max`.

**Later-phase fields** (same section, added when their machinery lands):

- ~~`exec`~~ — **dropped.** In-container exec-on-window was the wrong
  marriage (attach machinery, uid, output capture bolted onto a
  long-running container). Its use case — "make any CLI tool
  suspend-aware" — is served by the phase-8 **job container type**: the
  scheduler *starts* a one-shot container (its existing init-cmd is the
  tool) and its exit closes the window.
- **`wakeup`** (phase 6) — declare interest in wake sources; Pantavisor
  computes the union, enables the matching `/sys/class/wakeup` nodes, and
  guarantees the declaring container a window when a wake is attributed
  to its source (its event is already queued on its fds; stock event-loop
  software just runs).
- **`freeze`** (phase 5) — per-container override of the group freeze
  policy.

## 4. Level 2 — standard APIs bridged (no custom code)

**logind inhibitor bridge.** Stock system software (NetworkManager,
ModemManager, upower, …) already speaks systemd-logind's power protocol:
`org.freedesktop.login1.Manager.Inhibit()` returns an **fd whose closure
releases the inhibitor** — inherently crash-safe, exactly the lease model —
plus `PrepareForSleep(true/false)` signals that NetworkManager uses to
down/up connections across suspend. Pantavisor already hosts a shared D-Bus
system bus (xconnect); a small `login1` façade on that bus maps Inhibit fds
to broker locks and emits `PrepareForSleep` around autosleep edges. Stock
network stacks become suspend-aware with **zero code changes**. Caveat to
resolve on-device: autosleep has no clean "about to suspend" edge, so
delay-inhibitors get a bounded grace anchored at refcount-reaches-zero —
whether that satisfies stock NetworkManager needs an experiment.

(A FUSE-backed fake `/sys/power/wake_lock` for Android-heritage software is
possible and cheap to describe, niche in practice — noted, not planned.)

## 5. Level 3 — native pv-ctrl API

For purpose-built apps. Transport is the **local pv-ctrl socket** — every
container already has it bind-mounted rw, and `ctrl_caller` resolves
SO_PEERCRED → platform, giving unforgeable attribution and lifecycle-tied
cleanup for free. (Pantahub's role is policy and fleet observability —
caps via config, per-container battery-blame stats via devmeta — never the
data path.)

- **Wakelocks as leases — two forms, one table.** Caller identity always
  comes from SO_PEERCRED → platform; every acquisition carries a mandatory,
  capped `timeout`; everything auto-releases when the container leaves
  RUNNING; all forms feed the single kernel lock's refcount.
  - **Anonymous, refcounted** (the zero-coordination default):
    `POST /wakelocks {"timeout": "30s"}` pushes one reference on the
    caller's *container default lock*; `DELETE /wakelocks` pops one.
    Multiple processes/scripts inside one container stack references
    without inventing names or coordinating — kernel-wakelock-style
    semantics, and what `pv-with-wakelock <cmd>` uses. Each reference
    keeps its **own lease**, so a leaked reference expires alone instead
    of being kept alive by innocent re-acquirers; `DELETE` pops the
    longest-remaining reference (conservative: short backstops survive).
    Popping at count 0 is an explicit error (409), so double-release bugs
    surface.
  - **Named, idempotent** (the state-guard form):
    `POST /wakelocks/{name} {"timeout": "1min"}` is held-or-renew — re-POST
    *renews* (resets the lease to `timeout` from now, absolute not
    additive), never stacks, so a renew loop (UI "user-active") cannot
    leak counts. `DELETE /wakelocks/{name}` releases. Named locks are for
    renewable long holds, distinct timeout policies, and introspection.
  - `GET /wakelocks` becomes readable by every container: own locks with
    per-reference counts and expiries; mgmt sees all owners + cumulative
    held-time stats. Log markers distinguish the forms and the exit paths:
    `wakelock: ACQUIRE scope=ctrl:<platform> count=…` (anonymous),
    `…scope=ctrl:<platform>/<name>` (named), `RELEASE` vs `EXPIRE`.
- **Alarms are brokered (phase 4, locked)** — necessarily, for two hard
  reasons: `RTC_WKALM_SET` has one slot, and the ~197 µs autosleep
  re-suspend race means a container-side `CLOCK_BOOTTIME_ALARM` timerfd
  fires without the container ever being scheduled. The phase-4 **deadline
  queue** generalizes phase 1's `min()` arming and serves everything —
  API alarms, phase-1 cadence windows (system-owned entries), and the
  managed poll (just another entry). One scheduler.
  - API: `POST /alarms/{name}` with `at` (epoch) | `in`, plus
    `period`, `persistent`, `window`, `grace`; `GET /alarms` (own),
    `DELETE /alarms/{name}`. Named per container like named locks.
    Duration fields follow §1.1 (number = seconds, string = literal).
  - **`window` — inexact placement**: fire anywhere in
    `[at, at+window]`, preferring an already-scheduled wake (reuses the
    phase-1 coalescing logic). The telemetry persona's field.
  - **Past-due fires immediately** (including `persistent` alarms found
    past-due at boot after power-off); `period` realigns forward from
    now. The only robust behavior on RTC-from-1970 boards (§8 clock
    caveat remains for wall-clock-anchored alarms).
  - **Persistence**: `persistent: true` survives container restart *and*
    reboot (stored per-platform under `/storage`, re-armed at
    managed-init). Non-persistent alarms die with the container,
    consistent with lock auto-release.
  - **Delivery — handoff is takeover-not-ack**: the RTC thread grabs the
    kernel lock inline; the broker holds a **handoff lease** for the
    target container, released when the container acquires *any* lock of
    its own (the natural "I've taken over") or at `grace` expiry
    (default `10s`, ceiling `30s`). No explicit ack verb — acquiring a
    lease is already the documented wake pattern.
  - **Caps** (clamp-and-warn, phase-1 style):
    `power.limit.alarm_interval` (`1min` floor), `power.limit.alarms`
    (8 per container), `power.limit.alarm_grace` (`30s` ceiling).
- **Power events (phase 4, locked)** — long-poll
  `GET /power/events?timeout=N` on pv-ctrl.
  - **Per-container bounded event queue** (16 deep, at-least-once): a
    long-poll is not always parked (re-poll gaps), so events queue and a
    re-poll drains immediately; overflow drops oldest and counts a stat.
  - v1 event types: `alarm` and `mode` only. `resume {reason}` joins in
    phase 6, when the generic resume detector exists — likely a
    `/sys/power/wakeup_count`-handshake thread in the same
    blocking-read-then-lock pattern that solved the RTC race, with
    best-effort attribution from `pm_wakeup_irq` /
    `/sys/class/wakeup` event-count diffs.
  - Implementation note: this is the first non-request-response ctrl
    endpoint (parked evhttp connections, delayed replies via
    `evhttp_send_reply_start`) — spike this plumbing first, the rest of
    the phase stacks on it.
  - **Stats** (decisions-on-stats, per container): alarms fired /
    delivered; **handoff outcomes split takeover vs. grace-expiry**
    (grace-expiry = "slept through its own alarm" — the alarm-side
    busy-looper analogue, a future health input); event-queue overflows;
    coalesced-vs-exact placements (proves `window` earns its keep).
- **Caps & grants**: per-container `power` grant with limits
  (max lease, min alarm interval, infinite-lock privilege). Default:
  allow with tight caps; OEM config tightens or grants more.
- **Health integration — the quiescence contract (phase 3, its own phase
  after Locks v1 — phase 2).** Leases bound *leaks*,
  but not a buggy container that renews forever: a wedged state machine
  re-POSTing on schedule looks alive to the lease layer while pinning the
  battery indefinitely. So wakelock behavior becomes part of the container
  health contract: if a container's aggregate refcount does not return to
  **zero** within its resolved `max_held` (measured
  since the count last left zero; renewals do *not* reset it), the
  container is deemed broken and **recycled via its existing restart
  policy** — which already encodes the blast radius (container restart
  vs. system-level reboot), so no new remediation machinery or decision
  logic is introduced.

  **The threshold is layered policy, not a global cap** — configured at
  the same levels where restart policy already lives:

  | level | where | meaning |
  |---|---|---|
  | system | config `power.container.max_held` | fleet/device-wide default; `0` (default) = check disabled |
  | group | `"power": {"max_held": "30min"}` in the group definition | applies to all containers in the group |
  | container | `"power": {"max_held": "30min"}` in the container manifest | per-container tuning |

  Precedence and sentinels are exactly the §1.1 scope stack: container >
  group > system; **absent = inherit**, explicit `0` = disabled at that
  level (so a group can enable the check and one known-long-holder
  container can opt out). The check is therefore **off unless some policy
  level enables it** — it is an opt-in health contract, and enabling it
  per group (e.g. "all `app`-group containers must quiesce within
  `30min`") is the expected common shape.

  Schema note: `max_held` joins the `power` section that phase 1's
  declarative cadence layer (§3) already established — born there with
  `interval`/`min_awake`/`max_awake`/`align` and its
  group/container/inheritance plumbing. This phase only ever adds the one
  duration field to that existing shape, never a second one.

  Sequence on trip: log `wakelock: FORFEIT platform=<p> held=<n>s` +
  drop all the container's locks + apply restart policy; trip counts
  surface in `GET /wakelocks` stats and devmeta (fleet visibility of
  misbehaving apps). Thresholds should be generous (order of an hour) —
  this is a broken-container detector, not a scheduling tool. Same
  philosophy as the internal `power.devmeta.max_held` backstop and the
  watchdog: every hold is bounded, and sustained failure to quiesce is a
  health signal, not a power state.
- **Tooling**: `pvcontrol wakelock acquire|release|ls`,
  `pvcontrol alarm set|ls|rm`, `pvcontrol power events`, plus a
  `pv-with-wakelock <cmd>` wrapper.

## 6. Personas (who needs what)

- **Network manager**: Level 2 (logind bridge) for suspend transitions;
  never freezable; owns WoWLAN/driver wake config; declares `wlan` wakeup.
  Persistent connections do not survive suspend — wake-on-packet hardware
  or poll redesign; no API papers over this.
- **UI**: renewable lease = idle timeout (renew on input, expiry sleeps);
  wake on input/GPIO source; panel power is the container's, suspend
  policy is Pantavisor's.
- **Machine/appliance logic**: persistent exact alarms for scheduled
  cycles; OEM-granted long leases for physical machine cycles (leases must
  exceed restart latency so a crashed controller re-acquires); no "sticky"
  lock class — that reintroduces unbounded holds.
- **BT onboarding**: button wake → routed window (later: wake-activation
  starts the container) → bounded pairing lease → release.
- **Telemetry/uploaders**: inexact `window` work coalesced onto wakes
  that happen anyway — without this, managed mode's savings evaporate.
- **Debug/maintenance**: renewable debug lease; SSH into a container on a
  managed device today can suspend (or, with Level 0, freeze) mid-session
  — auto-thaw + lease on debug entry is the fix and the cheapest first
  consumer of the lock API.
- **Wake-source catalogue** for `resume.reason`: rtc, network, gpio,
  ble, usb, uart, modem (SMS/ring), pmic (charger/battery), sensor
  (motion), can.

## 7. Phasing

- **Phase 0 — basic run window** (§2.0): `power.wake.run_window`,
  one close condition added to the existing poll-window machinery, log
  markers. No freezing, no new API surface; testable with the existing
  wakelocks testplan approach.
- **Phase 1 — Declarative cadence v1**: `interval`/`min_awake`/
  `max_awake`/`align` in a new `power` manifest section — born here,
  with container/group/system inheritance plumbing; later phases only
  ever add fields to it, never a second shape. Minimal earliest-deadline
  RTC arming; coalescing (25 % tolerance); PSI-informed quiescence close
  (no CPU floor); clamp-and-warn against system ceilings; per-container
  window/close-reason stats in mgmt GET + devmeta (the calibration and
  busy-looper signals). Windows are refcounted holds until phase 5 adds
  exclusivity. Purely declarative — no ctrl API, no container code
  changes, so it ships independently of Locks v1 (reordered ahead of it:
  bigger adoption payoff for less surface, and nothing here depends on
  the ctrl-API mechanism phase 2 builds).
- **Phase 2 — Locks v1**: pv-ctrl leases (anonymous refcounted + named
  idempotent) + global caps + auto-release + per-caller GET + pvcontrol
  subcommands. Pure ctrl + wakelock code; no policy parsing. Shares the
  underlying keyed wakelock table with phase 1 but is otherwise
  independent of it (imperative container-initiated leases vs.
  phase 1's declarative, pantavisor-initiated windows).
- **Phase 3 — Lock health check**: the quiescence contract (FORFEIT →
  restart policy) for phase 2's leases specifically — a wedged container
  that renews a lease forever looks alive to the lease layer while
  pinning the battery, so this catches it. Enabled and tuned via layered
  policy (system config → group → container; see §5). Adds `max_held`
  to the `power` section phase 1 already established. Thresholds
  calibrated from real phase-2 lease telemetry.
- **Phase 4 — Alarms + events**: deadline queue, long-poll
  `/power/events`, handoff leases, `persistent`/`period`/`window`.
  Alarms are pure delivery to running containers — no exec (see phase 8).
- **Phase 5 — Freeze/thaw hardening of run windows** (§2.1): group-aware
  freeze policy, direct cgroup writes (v2 `cgroup.freeze` preferred, v1
  fallback), thaw-before-stop discipline, exclusive app windows. Entry
  gate: the §8 cgroup-v2-in-hybrid on-device check.
- **Phase 6 — Wake reasons + wakeup-source config**: resume detector —
  the open engineering item — plus `power.wakeup.sources` and
  per-container `wakeup`; `resume {reason}` events join `/power/events`.
- **Phase 7 — logind inhibitor bridge** on the hosted D-Bus bus.
- **Phase 8 — Job containers + wake-activation**: a scheduled one-shot
  container *type* (declares a schedule; the phase-4 queue *starts* the
  container; **exit is the close condition** — exact, no quiescence
  heuristics; exit code feeds restart policy; logs via normal container
  capture). This supersedes the dropped `exec` field: the container's
  existing init-cmd (`lxc.init.cmd`) makes any CLI tool a job with one
  manifest entry. Wake-activation generalizes it to event-triggered
  starts (wake reason → start container). Plus whatever coalescing/stat
  refinements the field data asks for.

## 8. Open questions

- Do LXC containers get per-container cgroups on the hybrid `unified`
  mount in our embedded layout? This single on-device check now gates
  *two* features: v2 `cgroup.freeze` (phase 5) and per-cgroup
  `cpu.pressure` PSI for quiescence sensing (phase 1) — answer it early.
- Quiescence calibration: settle-period length and the "≈ 0" thresholds
  for usage and stall — to be measured from phase-1 window stats on a
  real device, not guessed.
- `PrepareForSleep` grace semantics under autosleep — stock-NetworkManager
  experiment.
- Resume-detection mechanism for non-RTC wakes (`wakeup_count` handshake
  vs. suspend_stats watcher) — needs the same empirical on-device
  treatment the RTC race got.
- Persistent alarms across *reboot* (re-armed at managed-init from
  /storage) vs. container-restart only; clock-validity on RTC-from-1970
  boards.
- Default-allow caps vs. OEM `grant-only` switch for the Level-3 API.
- Fleet-level `align` thundering herd: aligned due-times synchronize
  whole fleets onto the same wall-clock instant — deterministic
  per-device jitter within the coalescing tolerance?

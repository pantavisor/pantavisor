---
title: "pvtest List"
sidebar_position: 9
description: "Test to do list."
---
# pvtest List

Every pvtest, by scope and category, with implementation status. Keep this in sync with the
tree: when a pvtest is added, modified or removed, update the table below (and `TODO.md`) and
mark completed tests `✓`.

Test data lives in this repo under `pvtest/suites/{local,remote}/`. See
[authoring.md](authoring.md) for how to add or update one.

## local — local experience tests

Local experience tests exercise Pantavisor features that operate without any cloud connectivity. These tests cover the ctrl server's unix socket API, container lifecycle, runtime behavior, security policies, and local services.

### core

*Core Pantavisor initialization: config loading, config validation, namespace setup.*

| Test | Description | Done |
|------|-------------|------|
| `local/core/legacy-config-overload` | Legacy configuration overload | ✓ |
| `local/core/modern-config-overload` | Modern configuration overload (Env/Cmdline) | ✓ |
| `local/core/invalid-config-values` | Invalid Configuration Values Handling | |
| `local/core/rootfs-namespace` | Rootfs namespace (mounts, symlinks, etc.) | |

### lifecycle

*Container and revision lifecycle: updates (reboot/non-reboot), rollback, auto-recovery, power-loss safety.*

| Test | Description | Done |
|------|-------------|------|
| `local/lifecycle/reboot-nonreboot-rollback` | Reboot, non-reboot and rollback updates | ✓ |
| `local/lifecycle/seq-non-reboot-updates` | Sequential non-reboot updates | ✓ |
| `local/lifecycle/power-loss-during-update` | Power Loss During Update | |
| `local/lifecycle/shared-object-restart-policies` | Shared object update with distinct restart policies | |
| `local/lifecycle/auto-recovery-restart` | Auto-recovery restart on failure | |
| `local/lifecycle/auto-recovery-retries-rollback` | Auto-recovery retries exhaustion during TESTING triggers rollback | |
| `local/lifecycle/auto-recovery-stable-timeout` | Auto-recovery stable timeout holds commit | |
| `local/lifecycle/auto-recovery-never-stops` | Auto-recovery policy never stops container after retries | |
| `local/lifecycle/auto-recovery-stabilize` | Stabilize pattern: container fails N times then becomes stable | |
| `local/lifecycle/auto-recovery-always-restart` | Always-restart policy on any exit code | |
| `local/lifecycle/auto-recovery-group-inheritance` | Group-level auto-recovery policy inherited by containers | |
| `local/lifecycle/auto-recovery-container-override` | Container auto-recovery overrides group (all-or-nothing) | |
| `local/lifecycle/auto-recovery-backoff-duration` | Backoff duration resets retry cycle after exhaustion | |

### runtime

*Container runtime behavior: state JSON handling, groups, storage persistence, exports, remount policies.*

| Test | Description | Done |
|------|-------------|------|
| `local/runtime/invalid-state-json` | Invalid State JSON | |
| `local/runtime/large-state-json` | Large State JSON (100+ containers) | |
| `local/runtime/container-groups-startup` | Container Groups and Startup Order | |
| `local/runtime/container-storage-persistence` | Container Storage Persistence | |
| `local/runtime/config-overlay` | Configuration Overlay | |
| `local/runtime/resource-constraints` | Resource Constraints (CPU/Mem) | |
| `local/runtime/status-goal-success-failure` | Status Goal Success and Failure | ✓ |
| `local/runtime/forward-compat-parse` | Forward compatibility: unknown status_goal/restart_policy values, an unknown extra key, and a prefix-sharing key never reject a revision | ✓ |
| `local/runtime/container-exports` | Container Exports to Host | |
| `local/runtime/remount-policies` | Remount Policies (PV_REMOUNT_POLICY) | |
| `local/runtime/objects-crud` | Object store put/get/verify (pv-ctrl) | ✓ |
| `local/runtime/steps-rw` | Step read + local revision put (pv-ctrl) | ✓ |
| `local/runtime/ctrl-empty-object-put` | Bodyless object PUT replies, no hang (pv-ctrl) | ✓ |
| `local/runtime/cgroup-devices-allow-all` | A container with only `lxc.cgroup.devices.allow = a` starts on cgroup v2 and the log warns the line is not needed | ✓ |
| `local/runtime/cgroup-v1-devices-refused` | A container with only an `lxc.cgroup` device whitelist is refused on cgroup v2 and the update rolls back | ✓ |
| `local/runtime/cgroup-v1-and-v2-lines` | A container with `lxc.cgroup` and `lxc.cgroup2` lines starts on cgroup v2 with the `lxc.cgroup` lines left out | ✓ |
| `local/runtime/cgroup-v2-devices-enforced` | Containers with `lxc.cgroup2` device and pids lines run on cgroup v2, reach only the listed devices and get `pids.max = 64` | ✓ |
| `local/runtime/cgroup-v1-only-refused` | A container with only `lxc.cgroup` device and pids lines is refused on cgroup v2 and the update rolls back | ✓ |
| `local/runtime/invalid-signal-handling` | Invalid Signal Handling | |
| `local/runtime/devmode-refused` | Devmode revisions are refused while `PV_DEVMODE_ALLOWED` is false, also when it is set through user-meta; mgmt containers have no `/pantavisor/devmode` | ✓ |
| `local/runtime/devmode-create` | Enable devmode in `pantavisor.config`, create a devmode revision from the running one, list its inlays; the committed revision does not change; create again while it runs changes nothing; a devmode or unknown base is refused | ✓ |
| `local/runtime/devmode-create-resume` | `devmode create --resume` keeps the files in the inlays of the earlier devmode revision | ✓ |
| `local/runtime/devmode-create-plain` | A plain `devmode create` removes the files in the inlays of the earlier devmode revision | ✓ |
| `local/runtime/devmode-create-base` | `devmode create` with the committed revision as an explicit base | ✓ |
| `local/runtime/devmode-inlay-files` | A file put into an inlay with `pvcontrol devmode files put` shows up after a restart, survives another one and is gone after a reset | ✓ |
| `local/runtime/devmode-overlay` | `/pantavisor/devmode/<container>` lists the image files and is read-only; removing a file or recreating a directory through `pvcontrol devmode files` hides it in the container after a restart; a reset brings both back; a file the container wrote itself shows read-only under `/pantavisor/devmode/.container-layer/<container>` | ✓ |
| `local/runtime/exec-refused` | Running a command in a container is refused while devmode is not allowed and for a container without the mgmt role; `PV_DEVMODE_ALLOWED` is `0` | ✓ |
| `local/runtime/exec-devmode` | Run commands in containers in devmode: exit code, stdout and stderr, stdin, timeout, output limit, arguments without a shell, namespaces, cgroup and capabilities of the container, mgmt and non-mgmt callers, `_pv_`, unknown and stopped containers, at most 4 at once; `PV_DEVMODE_ALLOWED` is `1` | ✓ |
| `local/runtime/devmode-files` | `pvcontrol devmode files` puts a file from standard input or a file, with a mode and new directories, replaces it, lists the changes with their sha256, gets a file, removes a file of the image (listed as deleted) and a directory with `--recursive`; refuses `..`, keeps a symlink inside the container, refuses it outside devmode and for a container without the mgmt role, works from a mgmt container; the container sees the files after a restart | ✓ |
| `local/runtime/devmode-files-tar` | `pvcontrol devmode files get --tar` returns the whole container, a folder or a file as a tar: names relative to the container root, modes with setuid and setgid, owners, a symlink, a name over 100 bytes, a file changed in devmode and an image file with the same content and mtime as in the container; a missing path, `..` and an unknown container are refused | ✓ |
| `local/runtime/devmode-apply-container` | `devmode apply` restarts a container with the `container` restart policy without a reboot of the device, and the container sees the file put into its inlay | ✓ |
| `local/runtime/devmode-fallback` | After a crash in devmode the device runs the committed revision again and the devmode revision shows `ERROR` | ✓ |
| `local/runtime/devmode-rerun` | A devmode revision rolled back by a crash runs again by name, with the file in its inlay | ✓ |
| `local/runtime/devmode-put` | `steps put` over the running devmode revision is refused; over a stopped one it keeps the inlay | ✓ |
| `local/runtime/devmode-leave` | Running the committed revision leaves devmode and no container keeps an inlay | ✓ |
| `local/runtime/devmode-remove` | `pvcontrol steps rm` refuses the running devmode revision and a revision that is not a devmode revision; it removes a devmode revision that does not run and a second remove is refused | ✓ |

### control

*Tests that target the pv-ctrl unix socket API in a general way. Other categories may also use pv-ctrl, but for a specific subsystem rather than the API surface itself.*

| Test | Description | Done |
|------|-------------|------|
| `local/control/basic-endpoints` | Basic Endpoints (Containers, Objects, etc.) | ✓ |
| `local/control/basic-endpoints-curl` | Basic Endpoints via cURL | ✓ |
| `local/control/container-status-fields` | `pid`, `started_at` (device uptime in seconds) and `restarts` of a container in `GET /containers`, and their absence after a stop | ✓ |
| `local/control/pvcurl-slow-answer` | pvcurl waits for an answer that takes 7 seconds when given `--max-time`, and exits with 28 when the default 5 seconds run out | ✓ |
| `local/control/status-codes` | HTTP status-code contract (commands, signals, drivers, buildinfo) | ✓ |
| `local/control/staged-start` | STAGED via MOUNTED + lifecycle_goal: stage, API start/stop/start, reject start on plain MOUNTED, unknown lifecycle_goal falls back | ✓ |
| `local/control/cmd-rejections` | Commands are rejected in local mode, with remote control disabled by config and while an update is ongoing | |
| `local/control/pvcontrol-responsiveness` | pvcontrol responds normally during a time-consuming local operation (e.g. object transfer, sequential update) | |

### xconnect

*xconnect service mesh: proxying, identity headers, D-Bus mediation, DRM, and Wayland isolation.*

| Test | Description | Done |
|------|-------------|------|
| `local/xconnect/unix-sockets` | Unix Sockets (UDS proxying) | |
| `local/xconnect/rest-over-uds` | REST-over-UDS (Identity headers) | |
| `local/xconnect/dbus` | D-Bus (Policy mediation) | |
| `local/xconnect/drm` | DRM (Graphics node injection) | |
| `local/xconnect/wayland` | Wayland (Isolated UI rendering) | |

### security

*Security policies: secure boot, OEM key validation, container roles, object checksum verification, encrypted storage.*

| Test | Description | Done |
|------|-------------|------|
| `local/security/strict-secure-boot` | Strict Secure Boot (Unsigned rejection) | ✓ |
| `local/security/container-roles` | Container Roles (mgmt vs nobody access) | ✓ |
| `local/security/oem-secureboot` | OEM Secureboot (OEM key validation) | ✓ |
| `local/security/object-checksum` | Object Checksum Validation (dm-verity data objects skipped only when the handler is on) | ✓ |
| `local/security/lenient-secure-boot` | Lenient Secure Boot | |
| `local/security/encrypted-storage` | Encrypted Storage (LUKS/dm-crypt) | |
| `local/security/secureboot-sig-0x30` | Secure Boot when signature starts with 0x30 | |

### services

*On-device services: garbage collection, SSH, metadata manipulation, tsh daemon, IPAM, and other auxiliary features.*

| Test | Description | Done |
|------|-------------|------|
| `local/services/console-alerts` | Container status changes reach `/dev/console` as WALL alerts; `PV_LOG_CONSOLE_ALERTS=0` set at runtime silences them | |
| `local/services/console-alerts-dedup` | Console alert skipped when a stdout output shows it | |
| `local/services/on-demand-gc` | On-Demand Garbage Collection | ✓ |
| `local/services/sync-gc` | Synchronous Garbage Collection (/storage/gc) | ✓ |
| `local/services/daemons` | Daemon list/stop/start (pv-ctrl) | ✓ |
| `local/services/metadata-crud` | Device/user metadata CRUD (pv-ctrl) | ✓ |
| `local/services/tsh-daemon` | tsh daemon management & log capture | |
| `local/services/ssh-override` | SSH Override | |
| `local/services/metadata-manipulation` | Metadata Manipulation | |
| `local/services/ipam-single-pool` | Single IPAM pool — container gets IP from pool | |
| `local/services/ipam-multi-pool` | Two IPAM pools — correct address assignment | |
| `local/services/ipam-collision` | Conflicting pool addresses detected and rejected | |
| `local/services/ipam-invalid` | Invalid IPAM config rejected gracefully | |
| `local/services/ipam-lxcbr` | IPAM with lxcbr bridge networking | |

### logserver

*The log server: protocols and sockets, platform attribution, fd subscriptions, outputs, timestamps, capture switches, per-revision directories and rotation. Its config is read once at boot, so every test sets it in `setup.config.env`.*

| Test | Description | Done |
|------|-------------|------|
| `local/logserver/devlog` | Per-container /dev/log with `PV_LOG_AUTO_DEVLOG=1`: capture, attribution, src sanitization, socket create/remove on stop/start, `dev-log` unset/true/false, a name too long for its log socket | ✓ |
| `local/logserver/devlog-override` | Per-container `dev-log: true`/`false` in run.json with `PV_LOG_AUTO_DEVLOG=0` | ✓ |
| `local/logserver/ingest` | Every protocol on a container's /dev/log and pv-ctrl-log, platform attribution, malformed input dropped without killing the log server | ✓ |
| `local/logserver/fd-lifecycle` | pv-fd-log console capture across restart/stop/start: no leaked fds, no spin on a closed fd | ✓ |
| `local/logserver/capture-off` | `PV_LOG_CAPTURE=0`, `PV_LOG_LOGGERS=0`, `PV_LOG_CAPTURE_DMESG=0` | ✓ |
| `local/logserver/capture-revision` | `PV_LOG_CAPTURE`/`PV_LOG_CAPTURE_DMESG` from OEM config follow non-reboot updates, off then on, log server not restarted | ✓ |
| `local/logserver/filetree-singlefile` | `PV_LOG_LEVEL=2`, filetree+singlefile, golang/strftime timestamps, absolute tsec, dmesg and loggers on | ✓ |
| `local/logserver/dmesg-overrun` | `/dev/kmsg` ring buffer overrun: dmesg stays subscribed, overrun line once per 10 s window with a count | ✓ |
| `local/logserver/stdout` | `PV_LOG_LEVEL=6`, filetree with `stdout.pantavisor`, invalid timestamp format, relative tsec, dmesg skipped | ✓ |
| `local/logserver/heartbeat` | INFO `alive:` line at the `PV_LOG_HEARTBEAT_INTERVAL` pace, run-time change through user meta, `0` stops it, no `hub:` line in local mode | ✓ |
| `local/logserver/nullsink` | `PV_LOG_SERVER_OUTPUTS=nullsink`: every source accepted, nothing written | ✓ |
| `local/logserver/rotation-and-revisions` | Log directories across update and rollback, update output, rotation and cleanup under a small `PV_LOG_DIR_MAXSIZE` | ✓ |

---

## remote — remote experience tests

Remote experience tests require an active Pantacor Hub connection and exercise the device-cloud communication layer: initial claiming, revision delivery, cloud status reporting, and remote services.

### core

*Core remote initialization: pantahub.config parsing (encrypted and unencrypted), Hub TLS certificate verification, Hub proxies.*

| Test | Description | Done |
|------|-------------|------|
| `remote/core/encrypted-pantahub-config` | Encrypted `pantahub.config` handling | ✓ |
| `remote/core/unencrypted-pantahub-config` | Unencrypted `pantahub.config` handling | |
| `remote/core/hub-certificate-verification` | Hub TLS certificate verification | ✓ |
| `remote/core/hub-certificate-denylist` | A certificate of the Hub chain in the denylist file blocks the Hub connection | ✓ |
| `remote/core/hub-proxy-forward` | Hub traffic through a forward proxy (HTTP CONNECT) | ✓ |
| `remote/core/hub-proxy-reverse` | Hub traffic through a reverse proxy (TLS to the proxy) | ✓ |

### lifecycle

*Cloud-driven revision lifecycle: simultaneous updates, disk-space handling, cloud rollback status, retry logic.*

| Test | Description | Done |
|------|-------------|------|
| `remote/lifecycle/simultaneous-updates` | Successful Multiple Simultaneous Remote Updates | ✓ |
| `remote/lifecycle/insufficient-disk-space` | Update with Insufficient Disk Space | ✓ |
| `remote/lifecycle/rollback-cloud-status` | Trigger rollback and verify cloud status | ✓ |
| `remote/lifecycle/update-retries-pv-crash` | Update retries when PV crashes | ✓ |
| `remote/lifecycle/update-retries-gc-pressure` | Update retries when PV crashes with GC pressure | ✓ |
| `remote/lifecycle/claim-after-local-updates` | Claim after local updates with random artifacts | ✓ |
| `remote/lifecycle/download-cancel-mid-transfer` | Owner cancel from the Hub aborts an update mid-download and keeps the partial object | ✓ |
| `remote/lifecycle/download-resume-on-timeout` | Object download resumes via Range after a mid-transfer crash | ✓ |
| `remote/lifecycle/download-progress-continuous` | Download progress reported continuously mid-object | ✓ |

### control

*Tests that target Pantacor Hub communication in a general way. Other categories also use hub communication, but for their specific purpose (revision delivery, log push, etc.).*

| Test | Description | Done |
|------|-------------|------|
| `remote/control/manual-claim` | Manual Device Claim | ✓ |
| `remote/control/auto-claim` | Automatic Device Claim | ✓ |
| `remote/control/cmd-reset-identity` | With PV_CONTROL_REMOTE_ALWAYS=0, identity reset is rejected unless on a DONE local revision, wipes the credentials in local mode and after go-remote, then re-claim reprocesses revision 1 under a new Hub id | |
| `remote/control/hint-reset-identity` | With PV_CONTROL_REMOTE_ALWAYS=0, Hub identity-reset-requested hint on a Hub revision transitions to locals/identity-reset, which stays remote across reboots, wipes the credentials, registers naming the old Hub id as parent, confirms the reset after the autotok re-claim and processes revision 1 under each Hub id | |
| `remote/control/hint-reset-identity-go-remote` | With PV_CONTROL_REMOTE_ALWAYS=0, Hub identity-reset-requested hint on a go-remote local revision transitions to locals/identity-reset, which stays remote across reboots, wipes the credentials, registers naming the old Hub id as parent, confirms the reset after the autotok re-claim and processes revision 1 under the new Hub id | |
| `remote/control/always-remote-disabled` | Always Remote Disabled | ✓ |
| `remote/control/always-remote-enabled` | Always Remote Enabled | ✓ |
| `remote/control/pvcontrol-responsiveness` | pvcontrol responds normally during a Pantahub download or other expensive remote operation | |

### services

*Cloud-integrated services: log push, metadata exchange, and other hub-backed features.*

| Test | Description | Done |
|------|-------------|------|
| `remote/services/ph-logger-cloud-push` | `ph-logger` cloud push | ✓ |
| `remote/services/hub-summary` | DEBUG `hub:` summary at the `PH_LOG_SUMMARY_INTERVAL` pace with request and failure counts; run-time change through Hub user meta, `0` stops it, back on counts only from the restart | ✓ |
| `remote/control/device-user-metadata` | Device/User Metadata Exchange | ✓ |


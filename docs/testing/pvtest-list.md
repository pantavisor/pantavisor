---
title: "pvtest List"
sidebar_position: 5
description: "Test to do list."
---
# pvtest List

Every pvtest, by scope and category, with implementation status. Keep this in sync with the
tree: when a pvtest is added, modified or removed, update the table below (and `TODO.md`) and
mark completed tests `✓`.

Test data lives in this repo under `pvtest/suites/{local,remote}/`. See
[appengine.md](appengine.md) for how to add or update one.

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
| `local/runtime/container-exports` | Container Exports to Host | |
| `local/runtime/remount-policies` | Remount Policies (PV_REMOUNT_POLICY) | |
| `local/runtime/objects-crud` | Object store put/get/verify (pv-ctrl) | ✓ |
| `local/runtime/steps-rw` | Step read + local revision put (pv-ctrl) | ✓ |
| `local/runtime/ctrl-empty-object-put` | Bodyless object PUT replies, no hang (pv-ctrl) | ✓ |
| `local/runtime/invalid-signal-handling` | Invalid Signal Handling | |

### control

*Tests that target the pv-ctrl unix socket API in a general way. Other categories may also use pv-ctrl, but for a specific subsystem rather than the API surface itself.*

| Test | Description | Done |
|------|-------------|------|
| `local/control/basic-endpoints` | Basic Endpoints (Containers, Objects, etc.) | ✓ |
| `local/control/basic-endpoints-curl` | Basic Endpoints via cURL | ✓ |
| `local/control/status-codes` | HTTP status-code contract (commands, signals, drivers, buildinfo) | ✓ |
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
| `local/security/object-checksum` | Object Checksum Validation | ✓ |
| `local/security/lenient-secure-boot` | Lenient Secure Boot | |
| `local/security/encrypted-storage` | Encrypted Storage (LUKS/dm-crypt) | |
| `local/security/secureboot-sig-0x30` | Secure Boot when signature starts with 0x30 | |

### services

*On-device services: garbage collection, logging, SSH, metadata manipulation, tsh daemon, IPAM, and other auxiliary features.*

| Test | Description | Done |
|------|-------------|------|
| `local/services/log-output-formats` | Log Output Formats (filetree/singlefile) | |
| `local/services/on-demand-gc` | On-Demand Garbage Collection | ✓ |
| `local/services/sync-gc` | Synchronous Garbage Collection (/storage/gc) | ✓ |
| `local/services/daemons` | Daemon list/stop/start (pv-ctrl) | ✓ |
| `local/services/metadata-crud` | Device/user metadata CRUD (pv-ctrl) | ✓ |
| `local/services/tsh-daemon` | tsh daemon management & log capture | |
| `local/services/log-rotation` | Log rotation functionality | |
| `local/services/ssh-override` | SSH Override | |
| `local/services/metadata-manipulation` | Metadata Manipulation | |
| `local/services/ipam-single-pool` | Single IPAM pool — container gets IP from pool | |
| `local/services/ipam-multi-pool` | Two IPAM pools — correct address assignment | |
| `local/services/ipam-collision` | Conflicting pool addresses detected and rejected | |
| `local/services/ipam-invalid` | Invalid IPAM config rejected gracefully | |
| `local/services/ipam-lxcbr` | IPAM with lxcbr bridge networking | |

---

## remote — remote experience tests

Remote experience tests require an active Pantacor Hub connection and exercise the device-cloud communication layer: initial claiming, revision delivery, cloud status reporting, and remote services.

### core

*Core remote initialization: pantahub.config parsing (encrypted and unencrypted).*

| Test | Description | Done |
|------|-------------|------|
| `remote/core/encrypted-pantahub-config` | Encrypted `pantahub.config` handling | ✓ |
| `remote/core/unencrypted-pantahub-config` | Unencrypted `pantahub.config` handling | |

### lifecycle

*Cloud-driven revision lifecycle: simultaneous updates, disk-space handling, cloud rollback status, retry logic.*

| Test | Description | Done |
|------|-------------|------|
| `remote/lifecycle/simultaneous-updates` | Successful Multiple Simultaneous Remote Updates | ✓ |
| `remote/lifecycle/insufficient-disk-space` | Update with Insufficient Disk Space | ✓ |
| `remote/lifecycle/rollback-cloud-status` | Trigger rollback and verify cloud status | ✓ |
| `remote/lifecycle/update-retries-pv-crash` | Update retries when PV crashes | ✓ |
| `remote/lifecycle/update-retries-gc-pressure` | Update retries when PV crashes with GC pressure | ✓ |
| `remote/lifecycle/claim-after-local-updates` | Claim after local updates with random artifacts | |
| `remote/lifecycle/download-cancel-mid-transfer` | Owner cancel from the Hub aborts an update mid-download and keeps the partial object | ✓ |
| `remote/lifecycle/download-resume-on-timeout` | Object download resumes via Range after a mid-transfer crash | ✓ |
| `remote/lifecycle/download-progress-continuous` | Download progress reported continuously mid-object | ✓ |

### control

*Tests that target Pantacor Hub communication in a general way. Other categories also use hub communication, but for their specific purpose (revision delivery, log push, etc.).*

| Test | Description | Done |
|------|-------------|------|
| `remote/control/manual-claim` | Manual Device Claim | ✓ |
| `remote/control/auto-claim` | Automatic Device Claim | ✓ |
| `remote/control/always-remote-disabled` | Always Remote Disabled | ✓ |
| `remote/control/always-remote-enabled` | Always Remote Enabled | ✓ |
| `remote/control/pvcontrol-responsiveness` | pvcontrol responds normally during a Pantahub download or other expensive remote operation | |

### services

*Cloud-integrated services: log push, metadata exchange, and other hub-backed features.*

| Test | Description | Done |
|------|-------------|------|
| `remote/services/ph-logger-cloud-push` | `ph-logger` cloud push | ✓ |
| `remote/control/device-user-metadata` | Device/User Metadata Exchange | ✓ |


# Platform: Container Runtime Features

This document describes implemented and in-progress container runtime features in Pantavisor.

---

## 1. Container Lifecycle Control

**Status:** ✅ Implemented (PR #612)

### API

```bash
# Stop a container
curl -X PUT --unix-socket /run/pv/pv-ctrl \
  http://localhost/containers/myapp -d '{"action": "stop"}'

# Start a stopped container
curl -X PUT --unix-socket /run/pv/pv-ctrl \
  http://localhost/containers/myapp -d '{"action": "start"}'

# Restart (atomic stop + start)
curl -X PUT --unix-socket /run/pv/pv-ctrl \
  http://localhost/containers/myapp -d '{"action": "restart"}'
```

### Constraints
- Only containers with `restart_policy: container` can be controlled
- Containers with `restart_policy: system` are protected (require reboot)

---

## 2. Auto-Recovery

**Status:** ✅ Implemented (PR #610)

Containers can define recovery policies for automatic restart on failure.

### Configuration (`run.json`)

```json
{
    "name": "my-app",
    "auto_recovery": {
        "type": "on-failure",
        "maximum_retry_count": 5,
        "retry_delay": 1,
        "backoff_factor": 2.0,
        "reset_window": 300
    }
}
```

### Policy Types

| Type | Behavior |
|------|----------|
| `no` | Default. Exit = Stop. |
| `always` | Restart on any exit (including exit 0) |
| `on-failure` | Restart only on non-zero exit |
| `unless-stopped` | Restart unless stopped via API |

### Backoff

Exponential backoff prevents crash loops:
- First retry: `retry_delay` seconds
- Subsequent: `delay * backoff_factor`
- After `maximum_retry_count`: container stops, enters FAILED state
- If running longer than `reset_window`: retry counter resets

---

## 3. Dynamic Networking (IPAM)

**Status:** 🔲 In Development

### 3.1 Overview

Pantavisor manages container networking through IP pools defined at the device level. Containers request interfaces from pools and receive dynamically allocated IPs.

**Design Principles:**
- Names are identity; IPs are ephemeral
- Sticky IPs within boot session (restart keeps same IP)
- Fresh allocation on device reboot (no persistence)
- Backward compatible with static `lxc.container.conf`

### 3.2 Pool Definition (`device.json`)

BSP/integrator defines available networks:

```json
{
    "network": {
        "pools": {
            "internal": {
                "type": "bridge",
                "bridge": "br0",
                "subnet": "10.0.3.0/24",
                "gateway": "10.0.3.1",
                "nat": true
            }
        }
    }
}
```

| Field | Description |
|-------|-------------|
| `type` | `bridge` (veth pair to bridge) or `macvlan` (direct to parent) |
| `bridge` | Bridge interface name (for type=bridge) |
| `parent` | Parent interface (for type=macvlan) |
| `subnet` | IP subnet in CIDR notation |
| `gateway` | Gateway IP (assigned to bridge) |
| `nat` | Enable NAT for outbound traffic |

### 3.3 Interface Request (`run.json`)

Containers request a single interface from a pool:

```json
{
    "name": "webserver",
    "network": {
        "pool": "internal",
        "hostname": "webserver"
    }
}
```

Or explicit host networking (bypass IPAM):

```json
{
    "name": "legacy-app",
    "network": {
        "mode": "host"
    }
}
```

**Default:** No `network` section = use static `lxc.container.conf` (backward compatible)

### 3.4 IP Allocation

In-memory lease tracking:

```
Container start → Allocate next IP from pool → Create lease
Container restart → Reuse existing lease (same IP)
Container stop → Lease retained (for restart)
Container removed → Release lease
Device reboot → All leases cleared
```

IPs are allocated sequentially starting from `gateway + 1`.

### 3.5 Static Config Validation

Containers with static IPs in `lxc.container.conf` are validated against pools:

| Static Config | run.json | Result |
|--------------|----------|--------|
| IP on br0, in subnet | Pool uses br0 | ✅ Honor static, reserve in pool |
| IP on br1 | Pool uses br0 | ❌ Bridge mismatch → refuse, rollback |
| IP outside subnet | Pool defined | ❌ IP conflict → refuse, rollback |
| Any static config | No network section | ✅ Legacy mode, no validation |

### 3.6 Bridge Setup

On boot, Pantavisor:
1. Creates bridge interface (e.g., `br0`)
2. Assigns gateway IP to bridge
3. Sets up NAT rules (iptables or nftables, whichever available)
4. Enables IP forwarding

### 3.7 LXC Integration

For containers with pool networking, Pantavisor injects LXC config:

```
lxc.net.0.type = veth
lxc.net.0.link = br0
lxc.net.0.name = eth0
lxc.net.0.ipv4.address = 10.0.3.2/24
lxc.net.0.ipv4.gateway = 10.0.3.1
lxc.net.0.flags = up
```

This overrides any static network config in `lxc.container.conf`.

### 3.8 Name Resolution

Container IPs are exposed via API:

```bash
curl --unix-socket /run/pv/pv-ctrl http://localhost/containers | jq .
```

Response includes `ipv4_address` for each container. Use pv-xconnect or query API for name→IP resolution.

### 3.9 MAC Address Generation

MAC addresses are generated deterministically from container name:
```
02:pv:XX:XX:XX:XX  (XX = hash of container name)
```

This ensures same MAC on restart (helps with ARP caches, debugging).

---

## 4. Container Status API

**Status:** ✅ Implemented (PR #612)

### GET /containers

Returns detailed runtime status:

```json
[{
    "name": "my-container",
    "status": "STARTED",
    "status_goal": "STARTED",
    "pid": 1234,
    "uptime_secs": 3600,
    "restart_policy": "container",
    "auto_recovery": {
        "type": "on-failure",
        "max_retries": 5,
        "current_retries": 0
    },
    "provides": [
        {"name": "my-api", "type": "rest", "socket": "/run/my.sock"}
    ],
    "consumes": [
        {"name": "db", "type": "unix", "requirement": "required", "role": "client"}
    ]
}]
```

---

## 5. Try-Boot and Rollback

Pantavisor implements atomic updates with automatic rollback. When an update is installed, the device enters "try-boot" mode. If the new revision fails to reach a stable state, the system automatically rolls back to the previous working revision.

### 5.1 Overview

The try-boot mechanism ensures devices remain operational even if an update is faulty:

1. **Install**: New revision is written, `pv_try` is set
2. **Reboot**: Device boots into new revision (try-boot mode)
3. **Validate**: Pantavisor waits for system stability
4. **Commit or Rollback**:
   - Success → commit new revision as `pv_done`
   - Failure → reboot returns to previous `pv_done`

**Key principle**: Any reboot before commit is a rollback. Whether it's a controlled reboot triggered by pantavisor due to failure, or an unexpected kernel panic, the bootloader will return to the last known good revision.

### 5.2 Bootloader Variables

Four variables control update state:

| Variable | Storage | Purpose |
|----------|---------|---------|
| `pv_rev` | Kernel cmdline | Currently booted revision |
| `pv_try` | Persistent (uboot.txt/rpiab.txt) | Revision to try |
| `pv_done` | Persistent | Last committed revision |
| `pv_trying` | Persistent (pv.env) | Latch to detect rollback |

**State relationships:**

```
Normal operation:     pv_rev == pv_done, pv_try empty
Installing update:    pv_try = new_rev, pv_rev == pv_done
Trying update:        pv_rev == pv_try (booted into new revision)
After commit:         pv_rev == pv_done == new_rev, pv_try cleared
After rollback:       pv_rev == pv_done (old revision), pv_try cleared
```

### 5.3 Bootloader Logic

The bootloader (U-Boot) uses `pv_trying` as a latch to detect rollback:

```
if pv_try is set:
    if pv_trying == pv_try:
        # Already tried this revision and rebooted → ROLLBACK
        boot pv_rev (previous stable)
    else:
        # First attempt → try the new revision
        set pv_trying = pv_try
        boot pv_try
else:
    # Normal boot
    boot pv_rev
```

Reference implementation: `meta-pantavisor/recipes-bsp/u-boot/files/boot.cmd.pvgeneric`

### 5.4 Boot Success Criteria

For pantavisor to commit a try-boot revision, ALL of the following must be true:

1. **All containers started** - No container startup failures
2. **Essential mounts succeeded** - All required disks/volumes mounted
3. **Readiness signals received** - Containers with `status_goal: ready` signaled via pv-ctrl
4. **Stability period passed** - System stable for `PV_UPDATER_COMMIT_DELAY` seconds
5. **Network connected** (remote devices) - Pantahub communication working

Only after all criteria are met does pantavisor commit: `pv_done = pv_rev`, clear `pv_try`.

### 5.5 Rollback Triggers

Any of these conditions trigger rollback (reboot to previous revision):

| Trigger | Description |
|---------|-------------|
| Container crash | Any container exits unexpectedly during startup |
| Container start failure | Container fails to start (bad config, missing deps) |
| Essential mount failure | Required disk/volume fails to mount |
| Network config error | Invalid IPAM configuration (IP outside subnet, etc.) |
| Goals timeout | Containers don't reach `status_goal` within `PV_UPDATER_GOALS_TIMEOUT` |
| Network timeout | Can't reach Pantahub within `PH_UPDATER_NETWORK_TIMEOUT` (remote devices) |
| Kernel panic | Unexpected crash causes reboot |
| Watchdog timeout | System hangs, hardware watchdog triggers reboot |

### 5.6 Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `PV_UPDATER_COMMIT_DELAY` | 25s | Stability period before commit |
| `PV_UPDATER_GOALS_TIMEOUT` | 120s | Max time for containers to reach ready state |
| `PH_UPDATER_NETWORK_TIMEOUT` | 120s | Max time to establish Pantahub connection |
| `PV_REVISION_RETRIES` | 10 | Retry attempts before permanent rollback |

See [CONFIGURATION.md](CONFIGURATION.md) for the complete configuration reference and layered precedence model.

### 5.7 Container Readiness

Containers can declare a `status_goal` in their configuration:

```json
{
    "name": "my-app",
    "status_goal": "ready"
}
```

**Status goals:**

| Goal | Meaning |
|------|---------|
| `started` | Container process running (default) |
| `ready` | Container must signal readiness via pv-ctrl |

**Signaling readiness:**

```bash
# From inside container
curl -X PUT --unix-socket /pv/pv-ctrl/ctrl \
  http://localhost/containers/my-app -d '{"status": "ready"}'
```

If a container with `status_goal: ready` doesn't signal within `PV_UPDATER_GOALS_TIMEOUT`, the system rolls back.

### 5.8 Network Configuration Validation

IPAM validates network configuration at container start. Invalid configuration prevents container startup, triggering rollback during try-boot:

| Validation | Error | Result |
|------------|-------|--------|
| Static IP outside pool subnet | IP 10.0.5.200 not in 10.0.3.0/24 | Container start refused |
| Static IP already in use | IP collision with another container | Container start refused |
| Pool doesn't exist | Reference to undefined pool | Container start refused |

**Example invalid configuration:**

```json
{
    "network": {
        "pools": {
            "internal": {
                "subnet": "10.0.3.0/24",
                "gateway": "10.0.3.1"
            }
        }
    }
}
```

```json
{
    "name": "my-app",
    "network": {
        "pool": "internal",
        "static_ip": "192.168.1.100"  // ERROR: outside 10.0.3.0/24
    }
}
```

This container will fail to start. During try-boot, this triggers rollback to the previous working revision.

### 5.9 Rollback Detection

When pantavisor boots after a rollback, it detects the situation:

```
pv_rev != pv_try (but pv_try was set)
```

Pantavisor logs the rollback event and clears `pv_try`. The system continues operating on the stable `pv_done` revision.

### 5.10 Bootloader Customization

The reference bootloader script (`boot.cmd.pvgeneric`) supports several customization mechanisms for tweaking kernel command line during development and production.

#### Environment Files

| File | Location | Purpose |
|------|----------|---------|
| `oemEnv.txt` | Boot partition | OEM environment overrides, loaded early |
| `uboot.txt` | `/boot/` on data partition | Pantavisor state (pv_rev, pv_try) |
| `pv.env` | Boot partition | Try-boot latch (pv_trying) |

#### Command Line Variables

The kernel command line is assembled from multiple sources:

```
${pv_platargs} ${pv_baseargs} pv_try=${pv_try} pv_rev=${boot_rev} panic=2 pv_quickboot ${fdtbootargs} ${configargs} ${oemargs} ${localargs}
```

| Variable | Source | Purpose |
|----------|--------|---------|
| `pv_platargs` | U-Boot env / oemEnv.txt | Platform-specific args (default: `earlyprintk`) |
| `pv_baseargs` | Hardcoded | Core boot args: `panic=3 root=/dev/ram rootfstype=ramfs rdinit=/usr/bin/pantavisor` |
| `fdtbootargs` | Device tree `/chosen/bootargs` | Args from DTB (display, memory config) |
| `configargs` | U-Boot env | BSP configuration args |
| `oemargs` | U-Boot env / oemEnv.txt | OEM-specific production args |
| `localargs` | U-Boot env | Local development/debug args |

#### Development Customization

**Method 1: oemEnv.txt on boot partition**

Create `oemEnv.txt` with U-Boot environment format:
```
localargs=loglevel=7
configargs=cma=128M
```

**Method 2: U-Boot environment**

Set variables in U-Boot before boot:
```
setenv localargs "loglevel=7"
saveenv
```

**Method 3: Runtime via pv.env**

The `pv.env` file on boot partition can store persistent variables that survive across boots.

#### Kernel Cmdline Configuration

Only specific pantavisor settings can be configured via kernel command line:

| Config Key | Cmdline | Description |
|------------|---------|-------------|
| `PV_STORAGE_DEVICE` | Yes | Storage device path (mandatory) |
| `PV_STORAGE_FSTYPE` | Yes | Filesystem type: `ext4`, `ubifs`, `jffs2` (mandatory) |
| `PV_STORAGE_MNTPOINT` | Yes | Storage mount point (mandatory) |
| `PV_SYSTEM_INIT_MODE` | Yes | Mode: `embedded`, `standalone`, `appengine` |

Most pantavisor configuration is done via config files, not kernel cmdline. See [Pantavisor Configuration](https://docs.pantahub.com/pantavisor-configuration/) for the full reference.

#### Common Customizations

| Use Case | Variable | Example |
|----------|----------|---------|
| Kernel debug | `localargs` | `loglevel=7 debug` |
| Serial console | `pv_platargs` | `console=ttyS0,115200 earlyprintk` |
| Memory config | `configargs` | `cma=256M` |
| Display config | `fdtbootargs` | (set in DTB) |
| Production tweaks | `oemargs` | `quiet` |
| Init mode | `localargs` | `PV_SYSTEM_INIT_MODE=appengine` |
| Storage | `localargs` | `PV_STORAGE_DEVICE=/dev/mmcblk0p2 PV_STORAGE_FSTYPE=ext4` |

#### Precedence

Variables are concatenated in order, so later variables can override earlier ones for some kernel parameters. Platform-specific (`pv_platargs`) comes first, development (`localargs`) comes last.

### 5.11 Sequence Diagram

```
                    INSTALL UPDATE
                          │
                          ▼
              ┌─────────────────────┐
              │  Set pv_try = new   │
              │  Write boot image   │
              └─────────────────────┘
                          │
                          ▼
                       REBOOT
                          │
                          ▼
              ┌─────────────────────┐
              │  Bootloader checks  │
              │  pv_try vs pv_trying│
              └─────────────────────┘
                          │
            ┌─────────────┴─────────────┐
            │                           │
     First attempt              Already tried
            │                           │
            ▼                           ▼
    Boot pv_try                 Boot pv_rev
    Set pv_trying               (ROLLBACK)
            │
            ▼
    ┌───────────────┐
    │  Pantavisor   │
    │  validates    │
    └───────────────┘
            │
  ┌─────────┴─────────┐
  │                   │
Success            Failure
  │                   │
  ▼                   ▼
COMMIT              REBOOT
pv_done=new         (triggers
pv_try=∅            rollback)
```

---

## 6. Implementation Status

| Feature | Status | PR |
|---------|--------|-----|
| Container stop/start/restart | ✅ Done | #612 |
| Enhanced status API | ✅ Done | #612 |
| Auto-recovery policies | ✅ Done | #610 |
| IPAM core (pools, leases) | ✅ Done | - |
| Bridge/NAT setup | ✅ Done | - |
| LXC network injection | ✅ Done | - |
| Static IP validation | 🔲 In Progress | - |
| Network config rollback | 🔲 In Progress | - |

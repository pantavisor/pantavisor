# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with the Pantavisor source code.

## Overview

Pantavisor is the core runtime for managing containerized embedded Linux devices. Written in C, it acts as the init system (PID 1) that orchestrates containerized building blocks for firmware and applications. It provides atomic state management, over-the-air updates, and integration with Pantahub cloud services.

Key characteristics:
- Single binary design (~1MB compressed) for low-spec embedded devices
- Uses LXC for container management
- Atomic state transitions with rollback support
- JSON-based declarative state format

## Build System

### CMake Build

```bash
mkdir build && cd build
cmake .. [OPTIONS]
make
make install
```

### Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `PANTAVISOR_RUNTIME` | ON | Build main pantavisor binary |
| `PANTAVISOR_PVTX` | ON | Build pvtx transaction tool |
| `PANTAVISOR_PVTX_STATIC` | OFF | Build statically-linked pvtx |
| `PANTAVISOR_DM_VERITY` | OFF | dm-verity for read-only squash volumes |
| `PANTAVISOR_DM_CRYPT` | OFF | dm-crypt encrypted disk support |
| `PANTAVISOR_DEBUG` | OFF | Enable debug features |
| `PANTAVISOR_APPENGINE` | OFF | Build for Docker-based appengine mode |
| `PANTAVISOR_E2FSGROW_ENABLE` | ON | Partition autogrow feature |
| `PANTAVISOR_PVTEST` | OFF | Build test components |
| `PANTAVISOR_CLANG_FORMAT_CHECK` | OFF | Enforce clang-format on build |
| `PANTAVISOR_DISTRO_NAME` | "" | Distro name in version string |
| `PANTAVISOR_DISTRO_VERSION` | "" | Distro version in version string |

### Build Targets

- `pantavisor` - Main runtime binary (installed as `/usr/bin/pantavisor`, symlinked to `/init`)
- `pvtx` - Transaction management CLI tool
- `pvtx-static` - Statically-linked pvtx for environments without shared libs
- `remount` - Container mount/remount utility

### Dependencies

- **thttp** - HTTP server library
- **mbedtls** - TLS/crypto (mbedtls, mbedx509, mbedcrypto)
- **lxc** - Container library (liblxc)
- **libevent** - Asynchronous I/O with mbedtls support
- **picohttpparser** - HTTP parsing
- **zlib** - Compression

## Directory Structure

```
pantavisor/
├── ctrl/           # HTTP control server and REST API endpoints
├── disk/           # Storage management (dm-crypt, swap, volumes, zram)
├── event/          # libevent-based async event handling
├── logserver/      # Distributed logging with multiple backends
├── pantahub/       # Cloud platform integration
├── parser/         # State JSON parsing (multi1, system1 formats)
├── plugins/        # Loadable plugin system (pv_lxc)
├── pvtx/           # Transaction management
├── remount/        # Container remount utility
├── update/         # Update lifecycle and progress
├── utils/          # Core utilities (json, lists, base64, fs, etc.)
├── scripts/        # Helper scripts (hooks, mounts, crash handling)
├── tools/          # Utilities (pventer, fallbear-cmd)
├── defaults/       # Default configuration files
├── policies/       # AppArmor and security policies
├── ssh/            # SSH configuration
├── skel/           # Filesystem skeleton
├── pvs/            # Secure boot trust store
├── appengine/      # Appengine build mode configs
├── embedded/       # Embedded build mode configs
└── pvtest/         # Testing framework
```

## Core Architecture

### Main Data Structures

**`struct pantavisor`** (pantavisor.h) - Central state holder containing:
- `pv_state *state` - Current device state
- `pv_update *update` - Active update information
- `pv_ctrl_cmd *cmd` - Pending control command
- Connection, metadata, and remote trail information

**`struct pv_state`** (state.h) - Device state containing:
- `spec_t spec` - State format (SPEC_MULTI1, SPEC_SYSTEM1)
- `revision` - State revision number
- BSP configuration, platforms list, volumes, disks, addons, objects

**`struct pv_platform`** (platforms.h) - Container with:
- Status: INSTALLED, MOUNTED, BLOCKED, STARTING, STARTED, READY, STOPPING, STOPPED
- LXC configuration, volumes, drivers
- Group membership, restart policies

### State Machine

The main state machine in `pantavisor.c` defines these states:

- `INIT` - System initialization
- `RUN` - Normal operation, platforms running
- `WAIT` - Idle, waiting for commands/updates
- `COMMAND` - Processing control command
- `ROLLBACK` - Rolling back to previous state
- `REBOOT` / `POWEROFF` - System shutdown
- `ERROR` - Error state
- `EXIT` - Clean exit

State flow:
```
INIT -> RUN -> WAIT <-> COMMAND
                 |
                 v
             ROLLBACK <- ERROR
                 |
                 v
         REBOOT / POWEROFF / EXIT
```

### Entry Point

`init.c:main()` initializes the system:
1. Early mounts (/proc, /sys, /dev)
2. Signal handling setup
3. Configuration loading
4. Storage initialization
5. Starts main loop via `pantavisor.c`

## Key Components

### Control Server (ctrl/)

HTTP REST API for device management via Unix socket at `/run/pantavisor/pv/pv-ctrl`.

**Endpoints:**
- `/buildinfo` - Build version information
- `/commands` - Device commands (reboot, poweroff, etc.)
- `/config` - Runtime configuration
- `/containers` - Container status and lifecycle control
- `/daemons` - Managed daemon control (pv-xconnect, etc.)
- `/devmeta` - Device metadata
- `/drivers` - Driver management
- `/groups` - Container group management
- `/objects` - Object store operations
- `/signals` - Signal handling
- `/steps` - Update step tracking
- `/usrmeta` - User metadata
- `/xconnect-graph` - Service mesh topology

#### Container Control API (`ctrl/ctrl_containers_ep.c`)

**GET /containers**
Returns JSON array of all containers with their status:
```json
[{
  "name": "my-container",
  "group": "root",
  "status": "STARTED",
  "status_goal": "STARTED",
  "restart_policy": "container",
  "roles": ["mgmt"]
}]
```

**PUT /containers/{name}**
Performs lifecycle actions on a container. Only containers with `restart_policy: "container"` can be controlled; containers with `restart_policy: "system"` are protected.

Request body:
```json
{"action": "stop"}   // Stop container, disable auto-recovery
{"action": "start"}  // Start a stopped container
{"action": "restart"}  // Stop and immediately restart
```

Response: HTTP 200 OK on success, HTTP 400/404 on error.

**Implementation notes:**
- `stop`: Sets status goal to STOPPED, disables auto-recovery, calls `pv_platform_force_stop()`
- `start`: Restores group default status goal, calls `pv_platform_start()`
- `restart`: Combines stop and start in a single operation

#### Daemon Control API (`ctrl/ctrl_daemons_ep.c`)

**GET /daemons**
Returns JSON array of managed daemons:
```json
[{
  "name": "pv-xconnect",
  "pid": 1234,
  "respawn": true
}]
```

**PUT /daemons/{name}**
Controls daemon lifecycle:
```json
{"action": "stop"}   // Disable respawn and kill daemon
{"action": "start"}  // Enable respawn and start if not running
```

**Commands** (defined in `ctrl_cmd.h`):
- `UPDATE_METADATA` - Update device metadata
- `REBOOT_DEVICE` - Trigger device reboot
- `POWEROFF_DEVICE` - Trigger device poweroff
- `LOCAL_RUN` - Run local state
- `LOCAL_RUN_COMMIT` - Commit local state run
- `MAKE_FACTORY` - Reset to factory state
- `ENABLE_SSH` / `DISABLE_SSH` - SSH control
- `GO_REMOTE` - Switch to remote management
- `RUN_GC` - Run garbage collection
- `DEFER_REBOOT` - Defer pending reboot
- `TRY_ONCE` - Try state once without commit

### State Parsers (parser/)

Two state format versions:
- `parser_system1.c` - Current format with platforms, groups, volumes, disks
- `parser_multi1.c` - Legacy format

Entry point: `pv_parser_get_state()`

### Update System (update/)

**Remote updates:**
1. Download state from Pantahub
2. Install objects (containers, configs)
3. Validate signatures/checksums
4. Test new state
5. Commit or rollback

**Local updates:**
1. Pre-install hooks
2. Apply state changes
3. Run tests
4. Post-install hooks

**Update states:** queued, downloading, inprogress, testing, done, failed, final

### Storage Management (disk/, storage.c)

**Disk types:**
- `DIR` - Directory mount
- `DM_CRYPT_*` - Encrypted disk
- `SWAP` - Swap space
- `VOLUME` - Mounted volume
- `ZRAM` - Compressed RAM disk

**Volume types:**
- `LOOPIMG` - Loop-mounted image
- `PERMANENT` - Persistent storage
- `REVISION` - Per-revision storage
- `BOOT` - Boot partition

**Storage layout:**
```
/storage/
├── trails/{rev}/.pvr/json  # State JSON
├── trails/{rev}/.pv/       # Platform state
├── boot/                   # Boot files
├── config/                 # Configuration
├── disks/                  # Disk definitions
└── objects/                # Cached objects
```

### Pantahub Integration (pantahub/)

Cloud platform communication:
- Device registration and authentication
- State synchronization
- Progress reporting for updates
- Device token management (Pantahub-Devices-Auto-Token-V1)

### Logging System (logserver/)

Multiple backends available:
- `stdout` - Console output
- `singlefile` - Single log file
- `filetree` - Per-platform log files
- `null` - Discard logs
- `out` - Generic output
- `update` - Update-specific logging
- `timestamp` - Timestamped logging

### Event System (event/)

Built on libevent2:
- `pv_event_base_init()` - Initialize event loop
- `pv_event_base_loop()` - Run main loop
- HTTP server integration via thttp
- Socket listeners, periodic timers

### PVTX Transaction System (pvtx/)

CLI tool for local state transactions:

```bash
# Start a new transaction
pvtx begin

# Add a file to the transaction
pvtx add <file>

# Remove a file from the transaction
pvtx remove <path>

# Apply the transaction
pvtx commit

# Cancel the transaction
pvtx abort

# Show current transaction state
pvtx show

# Deploy a transaction archive
pvtx deploy <archive.tgz>
```

Transactions are tar-based with checksums and state serialization.

### Configuration (config.h)

Over 130 configuration options organized by category:

**Network settings:**
- Pantahub connection parameters
- Proxy configuration
- Interface settings

**Storage configuration:**
- Disk encryption settings
- Volume mount options
- Garbage collection policies

**Security options:**
- Signature verification
- AppArmor policies
- SSH access control

**Bootloader settings:**
- `BL_UBOOT_PLAIN` - Standard U-Boot
- `BL_UBOOT_PVK` - U-Boot with PVK
- `BL_UBOOT_AB` - U-Boot A/B boot
- `BL_GRUB` - GRUB bootloader
- `BL_RPIAB` - Raspberry Pi A/B boot

**Debug options:**
- Log levels
- Crash dump settings
- Development features

**Updater settings:**
- Retry policies
- Timeout configuration
- Rollback behavior

### Plugin System (plugins/)

The plugin system provides modular container runtime support. Plugins are dynamically loaded shared libraries that implement the container lifecycle interface.

#### Plugin Architecture

**Loading Mechanism (platforms.c):**
1. At startup, `pv_platforms_init_ctrl()` iterates through registered container types
2. For each type, attempts to load `pv_<type>.so` from `${SYSTEM_LIBDIR}/pv_<type>.so`
3. Uses `dlopen()` with `RTLD_NOW` for immediate symbol resolution
4. Resolves required function symbols via `dlsym()`
5. Injects callback functions for paths, logging, and pantavisor instance access

**Plugin Location:**
- Default: `/lib/pantavisor/pv_<type>.so`
- Controlled by `PV_SYSTEM_LIBDIR` configuration

#### Container Controller Interface

Defined in `platforms.c`:

```c
struct pv_cont_ctrl {
    char *type;                     // Container type name (e.g., "lxc")
    void (*set_loglevel)(int);      // Set plugin log level
    void (*set_capture)(bool);      // Enable/disable log capture
    int (*start)(struct pv_platform *p, const char *rev,
                 char *conf_file, int logfd, int pipefd);
    void (*stop)(struct pv_platform *p, char *conf_file);
    int (*get_console_fd)(struct pv_platform *p,
                          struct pv_platform_log *log);
};
```

**Registered Types:**
```c
enum {
    PV_CONT_LXC,        // LXC containers
    // PV_CONT_DOCKER,  // Future: Docker support
    PV_CONT_MAX
};
```

#### Required Plugin Exports

Every plugin must export these symbols:

| Symbol | Signature | Purpose |
|--------|-----------|---------|
| `pv_start_container` | `int (pv_platform*, const char*, char*, int, int)` | Start a container |
| `pv_stop_container` | `void (pv_platform*, char*)` | Stop a container |
| `pv_set_pv_instance_fn` | `void (void*)` | Receive pantavisor instance getter |
| `pv_set_pv_paths_fn` | `void (void*, ...)` | Receive path helper functions |

**Optional exports:**

| Symbol | Signature | Purpose |
|--------|-----------|---------|
| `pv_set_pv_conf_loglevel_fn` | `void (int)` | Configure log level |
| `pv_set_pv_conf_capture_fn` | `void (bool)` | Enable log capture |
| `pv_console_log_getfd` | `int (pv_platform*, pv_platform_log*)` | Get console file descriptor |

#### pv_lxc Plugin (plugins/pv_lxc.c)

The primary container runtime plugin providing LXC integration.

**Dependencies:**
- liblxc (LXC container library)
- Pantavisor's custom LXC fork (lxc-pv) with `pv_export.h` extensions

**Key Functions:**

```c
// Start an LXC container
int pv_start_container(struct pv_platform *p, const char *rev,
                       char *conf_file, int logfd, int pipefd);

// Stop an LXC container
void pv_stop_container(struct pv_platform *p, char *conf_file);

// Get console PTY file descriptor for logging
int pv_console_log_getfd(struct pv_platform *p, struct pv_platform_log *log);
```

**Container Setup (`pv_setup_lxc_container`):**

1. **Basic Configuration:**
   - Sets `lxc.rootfs.mount` for container filesystem
   - Sets `lxc.uts.name` (hostname) to platform name
   - Configures log level from pantavisor settings

2. **Config Overlay:**
   - Injects platform-specific config directory into rootfs path
   - Supports overlayfs-style configuration layering

3. **Cgroup Configuration:**
   - Handles cgroup v1/v2 differences
   - Removes legacy `lxc.cgroup.devices.allow/deny` for cgroup2
   - Sets `lxc.cgroup2.devices.allow = a` for unified cgroup

4. **Role-based Mounts:**

   For `PLAT_ROLE_MGMT` (management platforms):
   - Mounts `.pv/` directory read-only at `/pv`
   - Mounts logs directory read-only at `/pv/logs`
   - Mounts user metadata at `/pv/user-meta`
   - Mounts device metadata at `/pv/device-meta`

   For regular platforms:
   - Mounts log control socket at `/pv/pv-ctrl/log`
   - Mounts pvcontrol socket at `/pv/pv-ctrl/ctrl`
   - Mounts platform-specific logs at `/pv/logs`
   - Mounts platform user/device metadata

5. **Auto Module/Firmware Mounting:**
   - If `automodfw` enabled, binds `/lib/firmware`
   - Mounts kernel modules squashfs for current kernel version

6. **Cmdline Filtering:**
   - Strips `console=` parameters from kernel cmdline
   - Passes filtered cmdline to container

7. **Mount Hooks:**
   - Enables hooks from `/lib/pantavisor/pv/hooks_lxc-mount.d/`
   - Optionally includes `export.sh` hook if export enabled

**Container Startup Process:**

```
pv_start_container()
    │
    ├── Fork child process (pv-platform-<name>)
    │
    └── Child:
        ├── Block SIGCHLD
        ├── Initialize LXC logging
        ├── Create lxc_container object
        ├── Load config from conf_file
        ├── Apply pv_setup_lxc_container() modifications
        ├── Set custom init command if p->exec specified
        ├── Save modified config
        ├── Start container (daemonized)
        ├── Write init_pid to pipefd
        └── Exit child process

    Parent:
        └── Return success (init_pid communicated via pipe)
```

**Logging Setup:**
- Supports LXC log file (`lxc.log.file`)
- Supports console log (`lxc.console.logfile`)
- Automatic pvlogger process spawning for external log files
- Default truncate size: 2MB

#### Creating New Plugins

**CMakeLists.txt Template:**
```cmake
cmake_minimum_required(VERSION 3.0)
project(pv_myruntime VERSION 019)

find_library(MYRUNTIME_LIB myruntime)

add_library(pv_myruntime MODULE
    pv_myruntime.c
    pv_myruntime.h
)

get_filename_component(PARENT_DIR ../ ABSOLUTE)
target_include_directories(pv_myruntime PRIVATE ${PARENT_DIR})
SET_TARGET_PROPERTIES(pv_myruntime PROPERTIES PREFIX "")
target_link_libraries(pv_myruntime ${MYRUNTIME_LIB})

install(TARGETS pv_myruntime
    DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR}/${CMAKE_PROJECT_NAME}
)
```

**Header Template (pv_myruntime.h):**
```c
#ifndef PV_MYRUNTIME_H
#define PV_MYRUNTIME_H

#include "../config.h"
#include "../platforms.h"

// Required: Receive pantavisor instance getter
void pv_set_pv_instance_fn(void *fn_pv_get_instance);

// Required: Receive path helper functions
void pv_set_pv_paths_fn(void *fn_vlog, void *fn_pv_paths_pv_file, ...);

// Optional: Configure log level
void pv_set_pv_conf_loglevel_fn(int loglevel);

// Optional: Enable/disable log capture
void pv_set_pv_conf_capture_fn(bool capture);

// Required: Start container, return 0 on success
int pv_start_container(struct pv_platform *p, const char *rev,
                       char *conf_file, int logfd, int pipefd);

// Required: Stop container
void pv_stop_container(struct pv_platform *p, char *conf_file);

// Optional: Get console file descriptor
int pv_console_log_getfd(struct pv_platform *p, struct pv_platform_log *log);

#endif
```

**Registering New Plugin Type:**

Add to `platforms.c`:
```c
enum {
    PV_CONT_LXC,
    PV_CONT_MYRUNTIME,  // Add new type
    PV_CONT_MAX
};

struct pv_cont_ctrl cont_ctrl[PV_CONT_MAX] = {
    { "lxc", NULL, NULL, NULL, NULL, NULL },
    { "myruntime", NULL, NULL, NULL, NULL, NULL },  // Add entry
};
```

#### Experimental Plugins (In Development)

Based on backup files in the plugins directory:

**pv_runc (OCI Runtime):**
- Provides runc/OCI container support
- Similar interface to pv_lxc
- Would enable running standard OCI container images

**pv_wasmedge (WebAssembly):**
- WasmEdge runtime integration
- Would enable running WebAssembly workloads as "containers"
- Lightweight alternative for edge computing

#### Plugin Files

| File | Purpose |
|------|---------|
| `plugins/CMakeLists.txt` | Build configuration for plugins |
| `plugins/pv_lxc.c` | LXC plugin implementation (~670 lines) |
| `plugins/pv_lxc.h` | LXC plugin interface |
| `plugins/pv_runc.c~` | (WIP) runc plugin |
| `plugins/pv_wasmedge.c~` | (WIP) WasmEdge plugin |

## Bootloader Subsystem

The bootloader subsystem manages atomic updates across reboots using a set of state variables and bootloader-specific implementations.

### Core Variables

Three key variables control the update state machine:

| Variable | Storage | Purpose |
|----------|---------|---------|
| `pv_rev` | Runtime + cmdline/env | Currently running revision (set at boot time) |
| `pv_try` | Persistent storage | Revision being tested (set when installing update) |
| `pv_done` | Persistent storage | Last committed/stable revision |

**Variable relationships:**

```
Normal operation:     pv_rev == pv_done, pv_try is empty
Installing update:    pv_try set to new revision, pv_rev == pv_done
Trying update:        pv_rev == pv_try (booted into new revision)
After commit:         pv_rev == pv_done == committed rev, pv_try cleared
After rollback:       pv_rev == pv_done (old revision), pv_try cleared
```

### State Detection Logic (bootloader.c)

```c
pv_bootloader_update_in_progress()  // pv_try is set and non-empty
pv_bootloader_trying_update()       // pv_try is set AND pv_rev == pv_try
```

### Update Flow

1. **Install Update** (`pv_bootloader_install_update(rev)`):
   - Calls bootloader-specific `install_update()` hook
   - Sets `pv_try = rev` in persistent storage

2. **Reboot** - Device boots with new revision

3. **On Success - Commit** (`pv_bootloader_pre_commit_update()` + `post_commit_update()`):
   - Sets `pv_rev = rev` (the new revision)
   - Clears `pv_try`
   - Calls bootloader-specific `commit_update()` hook

4. **On Failure - Rollback** (`pv_bootloader_fail_update()`):
   - Clears `pv_try`
   - Next reboot returns to `pv_done` revision

### Bootloader Operations Interface (bootloader.h)

```c
struct bl_ops {
    void (*free)(void);
    int (*init)(void);

    // Key-value storage primitives
    int (*set_env_key)(char *key, char *value);
    int (*unset_env_key)(char *key);
    char *(*get_env_key)(char *key);
    int (*flush_env)(void);

    // Update lifecycle hooks
    int (*install_update)(char *rev);
    int (*commit_update)();
    int (*fail_update)();

    // Boot state validation (optional)
    int (*validate_state)(const char *pv_try, const char *pv_done,
                          char **pv_rev_out);
};
```

### Bootloader Implementations

#### U-Boot Plain/PVK (uboot.c)

**Type:** `BL_UBOOT_PLAIN`, `BL_UBOOT_PVK`

**Storage:**
- Primary: `uboot.txt` file in `/storage/boot/`
- Optional: MTD partition named `pv-env` for atomic writes

**Format:** Null-terminated key=value pairs:
```
pv_rev=5\0pv_try=6\0\0
```

**Behavior:**
- Reads `pv_rev` from environment variable or kernel cmdline at boot
- Stores `pv_rev`, `pv_try` in uboot.txt (or MTD if `mtd_only` config set)
- `flush_env()` erases MTD partition to clean dirty flags
- No install/commit hooks - relies on storage layer for image management

**Configuration:**
- `PV_BOOTLOADER_MTD_ONLY` - Use only MTD partition (no uboot.txt)
- `PV_BOOTLOADER_MTD_ENV` - MTD partition name (default: "pv-env")

#### U-Boot A/B (ubootab.c)

**Type:** `BL_UBOOT_AB`

**Storage:**
- U-Boot environment via `fw_printenv`/`fw_setenv` commands
- Two MTD partitions for A/B kernel images

**Features:**
- Manages active/inactive MTD partitions for FIT images
- Each partition has a 4KB header with `fit_rev=<revision>`
- Smart update: compares FIT image signatures, skips write if unchanged
- Writes FIT image to inactive partition during install

**Update Flow:**
1. `install_update(rev)`: Write kernel to inactive partition with version header
2. On reboot: U-Boot selects partition based on environment
3. `commit_update()`: (not implemented - relies on env update)

**Configuration:**
- `PV_BOOTLOADER_UBOOTAB_A_NAME` - Partition A name
- `PV_BOOTLOADER_UBOOTAB_B_NAME` - Partition B name
- `PV_BOOTLOADER_UBOOTAB_ENV_NAME` - Environment partition
- `PV_BOOTLOADER_UBOOTAB_ENV_BAK_NAME` - Backup environment partition
- `PV_BOOTLOADER_UBOOTAB_ENV_OFFSET` - Environment offset in partition
- `PV_BOOTLOADER_UBOOTAB_ENV_SIZE` - Environment size

#### Raspberry Pi A/B (rpiab.c)

**Type:** `BL_RPIAB`

**Storage:**
- `rpiab.txt` in `/storage/boot/` - stores pv_rev, pv_try (like uboot.txt)
- `autoboot.txt` on partition 1 - controls A/B boot selection
- `pv_rev.txt` on each boot partition - identifies installed revision

**Partition Layout:**
```
Partition 1: bootsel   - Contains autoboot.txt (selector)
Partition 2: boot_a    - Boot image A with kernels, DTBs, initramfs
Partition 3: boot_b    - Boot image B (alternate)
```

**Boot State Detection:**
Reads from device tree at boot:
- `/proc/device-tree/chosen/bootloader/tryboot` - Is this a tryboot? (0 or 1)
- `/proc/device-tree/chosen/bootloader/partition` - Which partition booted
- `/proc/device-tree/chosen/bootloader/boot-mode` - SD card (1) or USB (4)

**autoboot.txt Format:**
```ini
[all]
tryboot_a_b=1
boot_partition=2

[tryboot]
boot_partition=3
```

**Update Flow:**

1. **Install** (`install_update(rev)`):
   - Writes `rpiboot.img` (or `.gz`) to try partition
   - Writes `pv_rev.txt` containing revision to try partition

2. **Arm Tryboot** (in `set_env_key("pv_try", rev)`):
   - After pv_try is stored in rpiab.txt
   - Sets tryboot flag via RPi mailbox API (`RPI_FIRMWARE_SET_REBOOT_FLAGS`)
   - This is the commit point - next reboot will boot try partition

3. **On Reboot**:
   - RPi bootloader checks tryboot flag
   - If set, boots from `[tryboot]` partition (e.g., partition 3)
   - Tryboot flag is automatically cleared by bootloader

4. **Validate State** (`validate_state()`):
   - Reads `pv_rev.txt` from booted partition
   - Verifies it matches expected revision (pv_try or pv_done)
   - Detects early rollback if tryboot=0 but pv_try was set

5. **Commit** (`commit_update()`):
   - Swaps boot_partition and tryboot_partition in autoboot.txt
   - New revision becomes the default boot

**Early Rollback Detection:**
If device boots normally (not tryboot) but pv_try is set, this indicates:
- Power loss before tryboot flag was armed
- Very early crash causing RPi auto-rollback
Pantavisor logs a warning and continues with pv_done revision.

#### GRUB (grub.c)

**Type:** `BL_GRUB`

**Storage:**
- `grubenv` file in `/storage/boot/` (standard GRUB environment block)

**Format:** Standard 1024-byte GRUB environment:
```
# GRUB Environment Block
pv_rev=5
pv_try=6
###########################... (padding with #)
```

**Behavior:**
- Reads/writes standard GRUB environment format
- Creates/initializes grubenv if missing or invalid
- No install/commit hooks - GRUB script handles boot selection
- Expects GRUB configuration to read pv_rev/pv_try and select appropriate boot entry

### Initialization Sequence (bootloader.c)

```c
pv_bl_early_init():
    1. Initialize pv_rev to "0" (factory default)
    2. Initialize bootloader ops based on config type
    3. Read pv_try from storage (ops->get_env_key("pv_try"))
    4. Read pv_done from storage (ops->get_env_key("pv_rev"))
    5. Get pv_rev from environment variable or kernel cmdline
    6. If validate_state() hook exists, call it to verify/override pv_rev
```

### Storage Files Summary

| Bootloader | State File | Boot Image Management |
|------------|------------|----------------------|
| uboot | `/storage/boot/uboot.txt` | External (storage layer) |
| ubootab | U-Boot env (fw_printenv) | MTD partitions A/B |
| rpiab | `/storage/boot/rpiab.txt` | FAT partitions 2/3 |
| grub | `/storage/boot/grubenv` | External (GRUB config) |

## Utilities (utils/)

| Utility | Purpose |
|---------|---------|
| `json.c` | JSON parsing/building with json-build |
| `list.h` | Doubly-linked list operations |
| `base64.c` | Base64 encoding/decoding |
| `fs.c` | Filesystem operations |
| `str.c` | String manipulation |
| `tsh.c` | Task shell - command execution |
| `timer.c` | Timer abstractions |
| `pvsignals.c` | Signal handling |
| `pvzlib.c` | Zlib compression wrapper |
| `socket.c` | Socket utilities |
| `mtd.c` | MTD device handling |
| `fitimg.c` | FIT image support |
| `buildinfo.c` | Build information |

## Container Lifecycle

1. **Installation** - Create volumes, prepare mounts
2. **Mounting** - Set up LXC configuration
3. **Starting** - Launch container init process
4. **Monitoring** - Track status goals
5. **Stopping** - Graceful shutdown or force kill
6. **Cleanup** - Remove mounts, release resources

## Platform Status Flow

```
INSTALLED -> MOUNTED -> STARTING -> STARTED -> READY
                                       |
                                       v
                                   STOPPING -> STOPPED
```

## Runlevels

Platforms are started in runlevel order:
1. `RUNLEVEL_DATA` - Data/storage platforms
2. `RUNLEVEL_ROOT` - Root filesystem
3. `RUNLEVEL_PLATFORM` - Core platform services
4. `RUNLEVEL_APP` - Application containers

## Testing

### Running Tests

```bash
# Build with tests enabled
cmake -DPANTAVISOR_TESTS=ON ..
make

# Run all tests via CTest
ctest

# Run pvtx test suite
./test/pvtx/pvtx.sh <source_dir> <build_dir>
```

### Test Binaries

When `PANTAVISOR_TESTS=ON`:
- `test-pv-json` - JSON utility tests
- `test-pv-tsh` - Task shell tests
- `test-pv-zram` - ZRAM utility tests

## Code Style

### Compiler Settings

- All warnings treated as errors (`-Werror` flag)
- C standard as defined by CMake defaults

### Formatting

The project uses clang-format for code formatting.

**Check formatting (fails build if incorrect):**
```bash
cmake -DPANTAVISOR_CLANG_FORMAT_CHECK=ON ..
make
```

**Auto-format all source files:**
```bash
cmake -DPANTAVISOR_CLANG_FORMAT_CHECK=ON ..
make format
```

The project uses a `.clang-format` file in the root directory for style configuration.

## Installation Paths

| Path | Contents |
|------|----------|
| `/usr/bin/pantavisor` | Main binary |
| `/init` | Symlink to pantavisor (embedded mode) |
| `/usr/bin/pvtx` | Transaction tool |
| `/usr/bin/pventer` | Container entry utility |
| `/usr/bin/fallbear-cmd` | SSH command handler |
| `/lib/pantavisor/pv/` | Plugins and scripts |
| `/lib/pantavisor/pv/hooks_lxc-mount.d/` | LXC mount hooks |
| `/lib/pantavisor/pvtx.d/` | PVTX scripts |
| `/lib/pantavisor/skel/` | Filesystem skeleton |
| `/etc/pantavisor/` | Configuration directory |
| `/etc/pantavisor/defaults/` | Default settings |
| `/etc/pantavisor/policies/` | Security policies |
| `/etc/pantavisor/ssh/` | SSH configuration |
| `/etc/pantavisor/pvs/` | Secure boot trust store |
| `/storage/` | Runtime storage (embedded mode) |

## Key Files Reference

| File | Purpose |
|------|---------|
| `init.c` | Entry point, early initialization |
| `pantavisor.c` | Core state machine |
| `state.c` | State lifecycle management |
| `platforms.c` | Container management |
| `storage.c` | Revision and object storage |
| `config.c` | Configuration handling |
| `ctrl/ctrl.c` | REST API server |
| `update/update.c` | Update coordination |
| `pantahub/pantahub.c` | Cloud integration |
| `parser/parser_system1.c` | State JSON parsing (42KB, comprehensive) |
| `event/event.c` | Event loop |
| `disk/disk.c` | Storage management |
| `logserver/logserver.c` | Logging system |
| `pvtx/pvtx_txn.c` | Transaction handling |

## External Resources

- [Pantavisor Documentation](https://docs.pantahub.com/pantavisor-architecture/)
- [Community Forum](https://community.pantavisor.io)
- [Getting Started Guide](https://docs.pantahub.com/before-you-begin/)
- [FAQ](https://pantavisor.io/guides/faq/)

## Architecture Documentation

For deep-dives into specific subsystems, refer to the following documents:

- **[SYSTEM_STATE.md](SYSTEM_STATE.md)**: Defines the Pantavisor System State architecture (BSP, Device Config, Containers, Storage, Signatures).
- **[xconnect/XCONNECT.md](xconnect/XCONNECT.md)**: Specification for the pv-xconnect service mesh (D-Bus, Unix, REST mediation).
- **[PLATFORM-FUTURE.md](PLATFORM-FUTURE.md)**: Design roadmap for future container engine features (Auto-recovery, IPAM).
# Pantavisor Configuration System

This document describes the Pantavisor configuration system, including all available options, the layered precedence model, and configuration sources.

---

## 1. Configuration Layers

Pantavisor uses a layered configuration system where higher-precedence sources override lower ones. Each configuration key specifies which layers are allowed to set it.

### 1.1 Layer Precedence (Low to High)

| Level | Source | Description |
|-------|--------|-------------|
| `default` | Code | Built-in defaults compiled into pantavisor |
| `args` | Binary args | Command-line arguments to pantavisor binary |
| `pv conf file` | `pantavisor.config` | Main configuration file in `/etc/pantavisor/` |
| `ph conf file` | `pantahub.config` | Pantahub credentials file |
| `policy` | Policy file | Named policy in `/etc/pantavisor/policies/` |
| `oem config` | OEM container | Configuration from OEM container's config file |
| `pv cmdline` | Kernel cmdline | `pv_*` parameters on kernel command line |
| `ph cmdline` | Kernel cmdline | `ph_*` parameters on kernel command line |
| `env` | Environment | Environment variables |
| `metadata` | User metadata | Runtime overrides via device metadata |
| `command` | API command | Runtime overrides via pv-ctrl API |

**Higher levels override lower levels.** For example, a value set via kernel cmdline (`pv cmdline`) overrides the same value set in `pantavisor.config` (`pv conf file`).

### 1.2 Configuration Loading Sequence

```
1. Initialize defaults from code
   │
2. Parse kernel cmdline (pv_* and ph_* prefixes)
   │
3. Parse environment variables
   │
4. Load /etc/pantavisor/pantavisor.config
   │   └─ Apply values at 'pv conf file' level
   │
5. Determine policy name (from cmdline → env → config)
   │   └─ Load /etc/pantavisor/policies/<policy>.config
   │      └─ Apply values at 'policy' level
   │
6. Apply kernel cmdline values at 'pv cmdline' level
   │
7. Apply environment values at 'env' level
   │
8. [At runtime] Load OEM container config
   │   └─ Apply values at 'oem config' level
   │
9. [At runtime] Load pantahub.config (credentials)
   │   └─ Apply values at 'ph conf file' level
   │
10. [At runtime] Apply metadata overrides
    └─ Apply values at 'metadata' level
```

### 1.3 Key Naming Conventions

Configuration keys use two formats:

**Canonical format** (preferred):
```
PV_SECTION_SUBSECTION_NAME
PH_SECTION_SUBSECTION_NAME
```

**Legacy format** (deprecated, still supported):
```
section.subsection.name
```

Examples:
- `PV_LOG_LEVEL` (canonical) = `log.level` (legacy)
- `PH_CREDS_HOST` (canonical) = `creds.host` (legacy)

On kernel cmdline, use lowercase with underscores:
```
pv_log_level=4 pv_storage_device=/dev/mmcblk0p2
```

---

## 2. Configuration Files

### 2.1 pantavisor.config

Main configuration file, typically at `/etc/pantavisor/pantavisor.config`.

**Format:** Key-value pairs, one per line:
```
PV_LOG_LEVEL=4
PV_BOOTLOADER_TYPE=rpiab
PV_STORAGE_DEVICE=/dev/mmcblk0p2
PV_STORAGE_FSTYPE=ext4
```

### 2.2 pantahub.config

Pantahub credentials and connection settings, at `/pv/phconfig/pantahub.config`.

```
PH_CREDS_HOST=api.pantahub.com
PH_CREDS_PORT=443
PH_CREDS_ID=<device-id>
PH_CREDS_SECRET=<device-secret>
PH_CREDS_PRN=<device-prn>
```

### 2.3 Policy Files

Named policies in `/etc/pantavisor/policies/<name>.config`:

```
# /etc/pantavisor/policies/debug.config
PV_LOG_LEVEL=5
PV_DEBUG_SHELL=1
PV_DEBUG_SSH=1
```

Select policy via:
- Kernel cmdline: `pv_policy=debug`
- Config file: `PV_POLICY=debug`

### 2.4 OEM Container Config

OEM containers can provide configuration overrides in `<policy>.config`:

```
/storage/trails/<rev>/<oem-container>/<policy>.config
```

The OEM container is identified by `PV_OEM_NAME` configuration.

---

## 3. Configuration Reference

### 3.1 Pantahub Connection (PH_*)

| Key | Type | Default | Levels | Description |
|-----|------|---------|--------|-------------|
| `PH_CREDS_HOST` | string | `api.pantahub.com` | ph, oem | Pantahub API server hostname |
| `PH_CREDS_ID` | string | - | ph, oem | Device identifier |
| `PH_CREDS_PORT` | int | `443` | ph, oem | Pantahub API port |
| `PH_CREDS_PROXY_HOST` | string | - | ph, oem | HTTP proxy hostname |
| `PH_CREDS_PROXY_NOPROXYCONNECT` | int | `0` | ph, oem | Disable CONNECT for proxy (0/1) |
| `PH_CREDS_PROXY_PORT` | int | `3218` | ph, oem | HTTP proxy port |
| `PH_CREDS_PRN` | string | - | ph, oem | Device PRN (Pantahub Resource Name) |
| `PH_CREDS_SECRET` | string | - | ph, oem | Device authentication secret |
| `PH_CREDS_TYPE` | string | `builtin` | ph, oem | Credentials type |
| `PH_FACTORY_AUTOTOK` | string | - | ph, oem | Factory auto-claim token |
| `PH_LIBEVENT_HTTP_TIMEOUT` | int | `60` | ph, oem, run | HTTP request timeout (seconds) |
| `PH_LIBEVENT_HTTP_RETRIES` | int | `1` | ph, oem, run | HTTP request retry count |
| `PH_METADATA_DEVMETA_INTERVAL` | int | `10` | ph, oem, run | Device metadata push interval (seconds) |
| `PH_METADATA_USRMETA_INTERVAL` | int | `5` | ph, oem, run | User metadata refresh interval (seconds) |
| `PH_ONLINE_REQUEST_THRESHOLD` | int | `0` | ph, oem, run | Failed requests before going offline |
| `PH_UPDATER_INTERVAL` | int | `60` | ph, oem, run | Update check interval (seconds) |
| `PH_UPDATER_NETWORK_TIMEOUT` | int | `120` | ph, oem, run | Network timeout before rollback (seconds) |
| `PH_UPDATER_TRANSFER_MAX_COUNT` | int | `5` | ph, oem, run | Max concurrent object transfers |

### 3.2 Bootloader (PV_BOOTLOADER_*)

| Key | Type | Default | Levels | Description |
|-----|------|---------|--------|-------------|
| `PV_BOOTLOADER_TYPE` | enum | `uboot` | pv | Bootloader type: `uboot`, `uboot-pvk`, `uboot-ab`, `grub`, `rpiab` |
| `PV_BOOTLOADER_FITCONFIG` | string | - | pv | FIT image configuration name |
| `PV_BOOTLOADER_MTD_ENV` | string | - | pv | MTD partition for bootloader environment |
| `PV_BOOTLOADER_MTD_ONLY` | bool | `0` | pv | Use only MTD for env storage (no file) |
| `PV_BOOTLOADER_UBOOTAB_A_NAME` | string | `fitA` | pv | U-Boot A/B: partition A name |
| `PV_BOOTLOADER_UBOOTAB_B_NAME` | string | `fitB` | pv | U-Boot A/B: partition B name |
| `PV_BOOTLOADER_UBOOTAB_ENV_NAME` | string | - | pv | U-Boot A/B: environment partition |
| `PV_BOOTLOADER_UBOOTAB_ENV_BAK_NAME` | string | - | pv | U-Boot A/B: backup environment partition |
| `PV_BOOTLOADER_UBOOTAB_ENV_OFFSET` | int | `0` | pv | U-Boot A/B: environment offset (bytes) |
| `PV_BOOTLOADER_UBOOTAB_ENV_SIZE` | int | `0` | pv | U-Boot A/B: environment size (bytes) |

### 3.3 Storage (PV_STORAGE_*)

| Key | Type | Default | Levels | Description |
|-----|------|---------|--------|-------------|
| `PV_STORAGE_DEVICE` | string | - | pv, **cmdline** | Storage device path (e.g., `/dev/mmcblk0p2`) |
| `PV_STORAGE_FSTYPE` | string | - | pv, **cmdline** | Filesystem type: `ext4`, `ubifs`, `jffs2` |
| `PV_STORAGE_MNTPOINT` | string | - | pv, **cmdline** | Storage mount point |
| `PV_STORAGE_MNTTYPE` | string | - | pv | Mount type override |
| `PV_STORAGE_WAIT` | int | `5` | pv | Wait for storage device (seconds) |
| `PV_STORAGE_LOGTEMPSIZE` | string | - | pv | In-memory log tmpfs size |
| `PV_STORAGE_GC_KEEP_FACTORY` | bool | `0` | pv, oem, run | Protect factory revision from GC |
| `PV_STORAGE_GC_RESERVED` | int | `5` | pv, oem, run | Disk space reservation (%) |
| `PV_STORAGE_GC_THRESHOLD` | int | `0` | pv, oem, run | GC trigger threshold (%) |
| `PV_STORAGE_GC_THRESHOLD_DEFERTIME` | int | `600` | pv, oem, run | GC deferral time (seconds) |
| `PV_STORAGE_PHCONFIG_VOL` | bool | `0` | pv | Use volume for Pantahub config |

### 3.4 Logging (PV_LOG_*)

| Key | Type | Default | Levels | Description |
|-----|------|---------|--------|-------------|
| `PV_LOG_LEVEL` | int | `0` | pv, oem, run | Log level: 0=FATAL, 1=ERROR, 2=WARN, 3=INFO, 4=DEBUG, 5=ALL |
| `PV_LOG_DIR` | string | `/storage/logs/` | pv | Log storage directory |
| `PV_LOG_MAXSIZE` | int | `2097152` | pv, oem, run | Max log file size before rotation (bytes) |
| `PV_LOG_BUF_NITEMS` | int | `128` | pv, oem | In-memory log buffer size (KB) |
| `PV_LOG_CAPTURE` | bool | `1` | pv, oem | Enable log capture |
| `PV_LOG_CAPTURE_DMESG` | bool | `1` | pv, oem | Capture kernel messages |
| `PV_LOG_LOGGERS` | bool | `1` | pv, oem | Enable container loggers |
| `PV_LOG_PUSH` | bool | `1` | pv, oem, run | Push logs to Pantahub |
| `PV_LOG_SERVER_OUTPUTS` | mask | `filetree` | pv, oem, run | Output backends (comma-separated) |
| `PV_LOG_FILETREE_TIMESTAMP_FORMAT` | string | - | pv, oem, run | Timestamp format for filetree output |
| `PV_LOG_SINGLEFILE_TIMESTAMP_FORMAT` | string | - | pv, oem, run | Timestamp format for singlefile output |
| `PV_LOG_STDOUT_TIMESTAMP_FORMAT` | string | - | pv, oem, run | Timestamp format for stdout output |
| `PV_LXC_LOG_LEVEL` | int | `2` | pv, oem | LXC log level: 0=TRACE to 8=FATAL |
| `PV_LIBTHTTP_LOG_LEVEL` | int | `3` | pv, oem, run | HTTP library log level |

**Log server outputs:** `nullsink`, `singlefile`, `filetree`, `stdout`, `stdout_direct`, `stdout.containers`, `stdout.pantavisor`

### 3.5 Debug (PV_DEBUG_*)

| Key | Type | Default | Levels | Description |
|-----|------|---------|--------|-------------|
| `PV_DEBUG_SHELL` | bool | `1` | pv | Enable debug shell on console |
| `PV_DEBUG_SHELL_AUTOLOGIN` | bool | `0` | pv | Auto-login to debug shell |
| `PV_DEBUG_SHELL_TIMEOUT` | int | `60` | pv | Shell access timeout (seconds) |
| `PV_DEBUG_SSH` | bool | `1` | pv, oem, run | Enable SSH server |
| `PV_DEBUG_SSH_AUTHORIZED_KEYS` | string | - | pv, oem, run | SSH authorized_keys file |

### 3.6 System (PV_SYSTEM_*)

| Key | Type | Default | Levels | Description |
|-----|------|---------|--------|-------------|
| `PV_SYSTEM_INIT_MODE` | enum | `embedded` | pv, **cmdline** | Init mode: `embedded`, `standalone`, `appengine` |
| `PV_SYSTEM_RUNDIR` | string | `/run/pantavisor/pv` | pv | Runtime directory |
| `PV_SYSTEM_CONFDIR` | string | `/configs` | pv | Configuration directory |
| `PV_SYSTEM_ETCDIR` | string | `/etc` | pv | Etc directory |
| `PV_SYSTEM_ETCPANTAVISORDIR` | string | `/etc/pantavisor` | pv | Pantavisor etc directory |
| `PV_SYSTEM_LIBDIR` | string | `/lib` | pv | Library directory |
| `PV_SYSTEM_USRDIR` | string | `/usr` | pv | Usr directory |
| `PV_SYSTEM_MEDIADIR` | string | `/media` | pv | Media mount directory |
| `PV_SYSTEM_APPARMOR_PROFILES` | string | - | pv | AppArmor profiles to load |
| `PV_SYSTEM_MOUNT_SECURITYFS` | bool | `0` | pv | Mount security filesystem |
| `PV_SYSTEM_DRIVERS_LOAD_EARLY_AUTO` | bool | `0` | pv | Auto-load drivers at startup |

### 3.7 Network (PV_NET_*)

| Key | Type | Default | Levels | Description |
|-----|------|---------|--------|-------------|
| `PV_NET_BRDEV` | string | `lxcbr0` | pv, oem | Default bridge device |
| `PV_NET_BRADDRESS4` | string | `10.0.3.1` | pv, oem | Bridge IPv4 address |
| `PV_NET_BRMASK4` | string | `255.255.255.0` | pv, oem | Bridge IPv4 netmask |

### 3.8 Updater (PV_UPDATER_*)

| Key | Type | Default | Levels | Description |
|-----|------|---------|--------|-------------|
| `PV_UPDATER_COMMIT_DELAY` | int | `25` | pv, oem, run | Stability wait before commit (seconds) |
| `PV_UPDATER_GOALS_TIMEOUT` | int | `120` | pv, oem, run | Container readiness timeout (seconds) |
| `PV_UPDATER_USE_TMP_OBJECTS` | bool | `0` | pv, oem, run | Store objects in tmpfs during download |
| `PV_REVISION_RETRIES` | int | `10` | pv, oem, run | Update retry attempts before rollback |

### 3.9 Secure Boot (PV_SECUREBOOT_*)

| Key | Type | Default | Levels | Description |
|-----|------|---------|--------|-------------|
| `PV_SECUREBOOT_MODE` | enum | `lenient` | pv | Mode: `disabled`, `audit`, `lenient`, `strict` |
| `PV_SECUREBOOT_CHECKSUM` | bool | `1` | pv | Validate artifact checksums |
| `PV_SECUREBOOT_HANDLERS` | bool | `1` | pv | Enable checksum handlers |
| `PV_SECUREBOOT_TRUSTSTORE` | string | `ca-certificates` | pv | Default certificate store |
| `PV_SECUREBOOT_OEM_TRUSTSTORE` | string | `ca-oem-certificates` | pv | OEM certificate store |

### 3.10 Watchdog (PV_WDT_*)

| Key | Type | Default | Levels | Description |
|-----|------|---------|--------|-------------|
| `PV_WDT_MODE` | enum | `shutdown` | pv | Mode: `disabled`, `shutdown`, `startup`, `always` |
| `PV_WDT_TIMEOUT` | int | `15` | pv | Watchdog timeout (seconds) |

### 3.11 Control (PV_CONTROL_*)

| Key | Type | Default | Levels | Description |
|-----|------|---------|--------|-------------|
| `PV_CONTROL_REMOTE` | bool | `1` | pv, oem | Enable Pantahub communication |
| `PV_CONTROL_REMOTE_ALWAYS` | bool | `0` | pv, oem | Maintain connection in local mode |

### 3.12 Disk (PV_DISK_*)

| Key | Type | Default | Levels | Description |
|-----|------|---------|--------|-------------|
| `PV_DISK_EXPORTSDIR` | string | `/exports` | pv | Exports directory |
| `PV_DISK_VOLDIR` | string | `/volumes` | pv | Volumes directory |
| `PV_DISK_WRITABLEDIR` | string | `/writable` | pv | Writable overlay directory |

### 3.13 Cache (PV_CACHE_*)

| Key | Type | Default | Levels | Description |
|-----|------|---------|--------|-------------|
| `PV_CACHE_DEVMETADIR` | string | `/storage/cache/devmeta` | pv | Device metadata cache |
| `PV_CACHE_USRMETADIR` | string | `/storage/cache/meta` | pv | User metadata cache |

### 3.14 Other

| Key | Type | Default | Levels | Description |
|-----|------|---------|--------|-------------|
| `PV_OEM_NAME` | string | - | pv | OEM container name for config overlay |
| `PV_POLICY` | string | - | pv | Active policy name |
| `PV_DROPBEAR_CACHE_DIR` | string | `/storage/cache/dropbear` | pv | SSH server cache |
| `PV_LIBTHTTP_CERTSDIR` | string | `/certs` | pv | TLS certificates directory |
| `PV_LIBEVENT_DEBUG_MODE` | bool | `0` | pv, oem | Enable libevent debugging |
| `PV_VOLMOUNT_DM_EXTRA_ARGS` | string | - | pv, oem | Extra dm-verity mount options |

---

## 4. Kernel Command Line

Only specific settings can be configured via kernel command line:

| Key | Cmdline Parameter | Required |
|-----|-------------------|----------|
| `PV_STORAGE_DEVICE` | `pv_storage_device` | Yes (embedded mode) |
| `PV_STORAGE_FSTYPE` | `pv_storage_fstype` | Yes (embedded mode) |
| `PV_STORAGE_MNTPOINT` | `pv_storage_mntpoint` | Yes (embedded mode) |
| `PV_SYSTEM_INIT_MODE` | `pv_system_init_mode` | No |

Example kernel cmdline:
```
pv_storage_device=/dev/mmcblk0p2 pv_storage_fstype=ext4 pv_storage_mntpoint=/storage pv_system_init_mode=embedded
```

For Pantahub settings, use `ph_` prefix:
```
ph_creds_host=custom.pantahub.com ph_updater_interval=120
```

---

## 5. Sysctl Configuration

Keys prefixed with `PV_SYSCTL_` are written to `/proc/sys/` paths:

```
PV_SYSCTL_KERNEL_CORE_PATTERN=|/lib/pv/pvcrash --skip
```

Translates to:
```
/proc/sys/kernel/core_pattern = |/lib/pv/pvcrash --skip
```

The key path uses underscores where the sysctl path uses slashes/dots.

---

## 6. Runtime Configuration API

### 6.1 Query Configuration

```bash
curl --unix-socket /run/pantavisor/pv/pv-ctrl http://localhost/config
```

Returns JSON array with all config entries:
```json
[
  {"key": "PV_LOG_LEVEL", "value": "3", "modified": "pv conf file"},
  {"key": "PV_BOOTLOADER_TYPE", "value": "rpiab", "modified": "default"},
  ...
]
```

### 6.2 Runtime Overrides via Metadata

Configuration can be overridden at runtime through device user-meta:

```bash
# Set via Pantahub API or local metadata
curl -X PUT --unix-socket /run/pantavisor/pv/pv-ctrl \
  http://localhost/usrmeta/PV_LOG_LEVEL -d '4'
```

Only keys with `run` (META | CMD) in their allowed levels support runtime override.

---

## 7. Example Configurations

### 7.1 Minimal Embedded Configuration

```
# /etc/pantavisor/pantavisor.config
PV_STORAGE_DEVICE=/dev/mmcblk0p2
PV_STORAGE_FSTYPE=ext4
PV_BOOTLOADER_TYPE=uboot
```

### 7.2 Raspberry Pi Configuration

```
# /etc/pantavisor/pantavisor.config
PV_STORAGE_DEVICE=/dev/mmcblk0p4
PV_STORAGE_FSTYPE=ext4
PV_BOOTLOADER_TYPE=rpiab
PV_LOG_LEVEL=3
```

### 7.3 Debug Policy

```
# /etc/pantavisor/policies/debug.config
PV_LOG_LEVEL=5
PV_DEBUG_SHELL=1
PV_DEBUG_SHELL_AUTOLOGIN=1
PV_DEBUG_SSH=1
PV_LXC_LOG_LEVEL=0
```

### 7.4 Production Policy

```
# /etc/pantavisor/policies/production.config
PV_LOG_LEVEL=1
PV_DEBUG_SHELL=0
PV_DEBUG_SSH=0
PV_SECUREBOOT_MODE=strict
PV_WDT_MODE=always
```

---

## 8. Legacy Key Migration

The following legacy keys are deprecated. Migrate to canonical format:

| Legacy Key | Canonical Key |
|------------|---------------|
| `log.level` | `PV_LOG_LEVEL` |
| `bootloader.type` | `PV_BOOTLOADER_TYPE` |
| `storage.device` | `PV_STORAGE_DEVICE` |
| `creds.host` | `PH_CREDS_HOST` |
| `updater.interval` | `PH_UPDATER_INTERVAL` |
| `control.remote` | `PV_CONTROL_REMOTE` |
| `debug.shell` | `PV_DEBUG_SHELL` |
| `debug.ssh` | `PV_DEBUG_SSH` |
| `wdt.mode` | `PV_WDT_MODE` |
| `secureboot.mode` | `PV_SECUREBOOT_MODE` |

See source code `config.c` for complete alias table.

---

## 9. Related Documentation

- [PLATFORM.md](PLATFORM.md) - Container runtime features and try-boot mechanism
- [Pantavisor Configuration](https://docs.pantahub.com/pantavisor-configuration/) - Online reference

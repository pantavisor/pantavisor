---
hide:
  - toc
---

# Pantavisor Configuration

!!! Note
    This reference page presents the newly unified configuration key syntax. To get to the deprecated but still supported previous format, you will have to go [here](../legacy/pantavisor-configuration-legacy.md).

## Summary

!!! Note
    The key syntax is the same for all [configuration levels](#levels).

!!! Note
    All keys are case insensitive.

!!! Note
    Syntax and behavior of keys tagged with (experimental) might change and break backwards compatibility.

This table contains the currently supported list of configuration keys, sorted alphabetically.

| Key | Value | Default | Description |
|-----|-------|---------|-------------|
| `PH_CREDS_HOST` | IP or hostname | `api.pantahub.com` | set [Pantacor Hub](../../pantavisor-src/docs/overview/remote-control.md#pantacor-hub) address |
| `PH_CREDS_ID` | string | empty | set [Pantacor Hub](../../pantavisor-src/docs/overview/remote-control.md#pantacor-hub) device ID |
| `PH_CREDS_PORT` | port | `443` | set port for communication with [Pantacor Hub](../../pantavisor-src/docs/overview/remote-control.md#pantacor-hub) |
| `PH_CREDS_PROXY_HOST` | IP or hostname | empty | set [Pantacor Hub](../../pantavisor-src/docs/overview/remote-control.md#pantacor-hub) proxy address |
| `PH_CREDS_PROXY_NOPROXYCONNECT` | `0` or `1` | `0` | disable proxy communication with [Pantacor Hub](../../pantavisor-src/docs/overview/remote-control.md#pantacor-hub) |
| `PH_CREDS_PROXY_PORT` | port | `3218` | set port for proxy communication with [Pantacor Hub](../../pantavisor-src/docs/overview/remote-control.md#pantacor-hub) |
| `PH_CREDS_PRN` | string | empty | set [Pantacor Hub](../../pantavisor-src/docs/overview/remote-control.md#pantacor-hub) device PRN |
| `PH_CREDS_SECRET` | string | empty | set [Pantacor Hub](../../pantavisor-src/docs/overview/remote-control.md#pantacor-hub) credentials secret |
| `PH_CREDS_TYPE` | `builtin` | `builtin` | set [Pantacor Hub](../../pantavisor-src/docs/overview/remote-control.md#pantacor-hub) credentials type |
| `PH_FACTORY_AUTOTOK` | token | empty | set [factory auto token](https://docs.pantahub.com/pantahub-base/devices/#auto-assign-devices-to-owners) for communication with [Pantacor Hub](../../pantavisor-src/docs/overview/remote-control.md#pantacor-hub) |
| `PH_LIBEVENT_HTTP_RETRIES` | number of retries | `1` | set HTTP request number of retries for communication with [Pantacor Hub](../../pantavisor-src/docs/overview/remote-control.md#pantacor-hub) |
| `PH_LIBEVENT_HTTP_TIMEOUT` | time (in seconds) | `60` | set HTTP request timeout for communication with [Pantacor Hub](../../pantavisor-src/docs/overview/remote-control.md#pantacor-hub) |
| `PH_METADATA_DEVMETA_INTERVAL` | time (in seconds) | `10` | set push interval for [device metadata](../../pantavisor-src/docs/overview/storage.md#device-metadata) to [Pantacor Hub](../../pantavisor-src/docs/overview/remote-control.md#pantacor-hub) |
| `PH_METADATA_USRMETA_INTERVAL` | time (in seconds) | `5` | set refresh interval for [user metadata](../../pantavisor-src/docs/overview/storage.md#user-metadata) from [Pantacor Hub](../../pantavisor-src/docs/overview/remote-control.md#pantacor-hub) |
| `PH_ONLINE_REQUEST_THRESHOLD` | number of failures | `0` | number of failed requests to [Pantacor Hub](../../pantavisor-src/docs/overview/remote-control.md#pantacor-hub) allowed to still consider device online |
| `PH_UPDATER_INTERVAL` | time (in seconds) | `60` | set time between [Pantacor Hub](../../pantavisor-src/docs/overview/remote-control.md#pantacor-hub) [update](../../pantavisor-src/docs/overview/updates.md) requests |
| `PH_UPDATER_NETWORK_TIMEOUT` | time (in seconds) | `120` | set time before [rollback](../../pantavisor-src/docs/overview/updates.md#error) if device cannot communicate with [Pantacor Hub](../../pantavisor-src/docs/overview/remote-control.md#pantacor-hub) |
| `PH_UPDATER_TRANSFER_MAX_COUNT` | number of transfers | `5` | set maximum number of object transfers to and from [Pantacor Hub](../../pantavisor-src/docs/overview/remote-control.md#pantacor-hub) during [updates](../../pantavisor-src/docs/overview/updates.md) |
| `PV_BOOTLOADER_FITCONFIG` | string | empty | set FIT configuration name |
| `PV_BOOTLOADER_MTD_ENV` | string | empty | set MTD name for bootloader env |
| `PV_BOOTLOADER_MTD_ONLY` | `0` or `1` | `0` | enable MTD for bootloader env |
| `PV_BOOTLOADER_TYPE` | `uboot`, `uboot-ab`, `uboot-pvk`, `rpiab` or `grub` | `uboot` | set [bootloader](../../pantavisor-src/docs/overview/bsp.md#bootloader) type |
| `PV_BOOTLOADER_UBOOTAB_A_NAME` | string | `fitA` | name of the partition to use as "A" in uboot-ab mode |
| `PV_BOOTLOADER_UBOOTAB_B_NAME` | string | `fitB` | name of the partition to use as "B" in uboot-ab mode |
| `PV_BOOTLOADER_UBOOTAB_ENV_BAK_NAME` | string | empty | name of the partition where the uboot environment is backed up |
| `PV_BOOTLOADER_UBOOTAB_ENV_NAME` | string | empty | name  of the partition where the uboot environment is stored |
| `PV_BOOTLOADER_UBOOTAB_ENV_OFFSET` | offset in bytes | `0` | environment offset from the beginning of the partition |
| `PV_BOOTLOADER_UBOOTAB_ENV_SIZE` | size in bytes | `0` | size of the uboot environment |
| `PV_CACHE_DEVMETADIR` | path | `/storage/cache/devmeta` | set persistent [device metadata](../legacy/pantavisor-metadata.md#device-metadata) dir |
| `PV_CACHE_USRMETADIR` | path | `/storage/cache/meta` | set persistent [user metadata](../legacy/pantavisor-metadata.md#user-metadata) dir |
| `PV_CONTROL_REMOTE` | `0` or `1` | `1` | allow remote control from [Pantacor Hub](../../pantavisor-src/docs/overview/remote-control.md#pantacor-hub) |
| `PV_CONTROL_REMOTE_ALWAYS` | `0` or `1` | `0` | keep [communication with Pantacor Hub](../../pantavisor-src/docs/overview/remote-control.md#pantacor-hub) even when a [local revision](../../pantavisor-src/docs/overview/local-control.md) is running |
| `PV_DEBUG_SHELL` | `0` or `1` | `1` | enable local debug shell |
| `PV_DEBUG_SHELL_AUTOLOGIN` | `0` or `1` | `0` | enable autologin for debug shell |
| `PV_DEBUG_SHELL_TIMEOUT` | time (in seconds) | `60` | time that Pantavisor waits before rebooting if [debug shell console](../../inspect-device.md#tty) is opened |
| `PV_DEBUG_SSH` | `0` or `1` | `1` | enable SSH debug access |
| `PV_DEBUG_SSH_AUTHORIZED_KEYS` | string | empty | set authorized keys for SSH debug access |
| `PV_DISK_EXPORTSDIR` | path | `/exports` | set exports directory |
| `PV_DISK_VOLDIR` | path | `/volumes` | set volumes directory |
| `PV_DISK_WRITABLEDIR` | path | `/writable` | set writable directory |
| `PV_DROPBEAR_CACHE_DIR` | path | `/storage/cache/dropbear` | set [debug ssh server](../../inspect-device.md#ssh) cache directory |
| `PV_LIBEVENT_DEBUG_MODE` | `0` or `1` | `0` | enable event loop debug logs |
| `PV_LIBTHTTP_CERTSDIR` | path | `/certs` | set certificates directory for libthttp |
| `PV_LIBTHTTP_LOG_LEVEL` | `0` to `5` | `3` | set libthttp log verbosity level |
| `PV_LOG_BUF_NITEMS` | integer | `128` | set in-memory [logs](../../pantavisor-src/docs/overview/storage.md#logs) buffer size |
| `PV_LOG_EVENTS` | `0` or `1` | `1` | enable [event journaling](../../pantavisor-src/docs/overview/event-journal.md) in progress payload |
| `PV_LOG_CAPTURE` | `0` or `1` | `1` | capture logs from containers |
| `PV_LOG_CAPTURE_DMESG` | `0` or `1` | `1` | capture dmesg logs |
| `PV_LOG_DIR` | path | `/storage/logs/` | set [logs](../../pantavisor-src/docs/overview/storage.md#logs) directory |
| `PV_LOG_DIR_MAXSIZE` | integer with optional suffix `B`(default),`K`,`KB`,`M`,`MB`,`G`,`GB`,`T`,`TB`,`%`; `0` for auto 10% (100% if tmpfs) | `16777216` | max size of log directory |
| `PV_LOG_FILETREE_TIMESTAMP_FORMAT` | format string | empty | timestamp format for filetree logs |
| `PV_LOG_HYSTERESIS_FACTOR` | positive integer | `4` | controls the gap between high and low watermarks for [log directory cleanup](../../pantavisor-src/docs/overview/storage.md#log-directory-size-management) |
| `PV_LOG_LEVEL` | `0` to `5` | `0` | set Pantavisor log level (0: FATAL to 5: ALL) |
| `PV_LOG_LOGGERS` | `0` or `1` | `1` | enable loggers for containers |
| `PV_LOG_PUSH` | `0` or `1` | `1` | push logs to [Pantacor Hub](../../pantavisor-src/docs/overview/remote-control.md#pantacor-hub) |
| `PV_LOG_ROTATE_FACTOR` | integer | `5` | determines per-file rotation threshold for [log directory cleanup](../../pantavisor-src/docs/overview/storage.md#log-directory-size-management) |
| `PV_LOG_SERVER_OUTPUTS` | string | `filetree` | set log server outputs (comma separated) |
| `PV_LOG_SINGLEFILE_TIMESTAMP_FORMAT` | format string | empty | timestamp format for single-file logs |
| `PV_LOG_STDOUT_TIMESTAMP_FORMAT` | format string | empty | timestamp format for stdout logs |
| `PV_LXC_LOG_LEVEL` | `0` to `5` | `2` | set LXC log level |
| `PV_NET_BRADDRESS4` | IP address | `10.0.3.1` | set bridge IPv4 address |
| `PV_NET_BRDEV` | interface name | `lxcbr0` | set bridge device name |
| `PV_NET_BRMASK4` | IP mask | `255.255.255.0` | set bridge IPv4 mask |
| `PV_OEM_NAME` | string | empty | set OEM name for configuration overrides |
| `PV_POLICY` | string | empty | set policy name for configuration |
| `PV_REMOUNT_POLICY` | string | empty | set remount policy name for filesystem remounting |
| `PV_REVISION_RETRIES` | integer | `10` | number of retries for revision transitions |
| `PV_SECUREBOOT_CHECKSUM` | `0` or `1` | `1` | enable artifact [checksum validation](../../pantavisor-src/docs/overview/storage.md#artifact-checksum) |
| `PV_SECUREBOOT_HANDLERS` | `0` or `1` | `1` | enable handlers verification |
| `PV_SECUREBOOT_MODE` | `disabled`, `audit`, `lenient` or `strict` | `lenient` | set secureboot mode |
| `PV_SECUREBOOT_OEM_TRUSTSTORE` | path | `/etc/pantavisor/certs/oem` | set path to OEM truststore |
| `PV_SECUREBOOT_TRUSTSTORE` | path | `/etc/pantavisor/certs` | set path to Pantavisor truststore |
| `PV_STORAGE_DEVICE` | string | empty | set storage device name |
| `PV_STORAGE_FSTYPE` | string | empty | set storage filesystem type |
| `PV_STORAGE_GC_KEEP_FACTORY` | `0` or `1` | `0` | keep factory revision during GC |
| `PV_STORAGE_GC_RESERVED` | percentage | `5` | reserved storage percentage for GC |
| `PV_STORAGE_GC_THRESHOLD` | percentage | `0` | storage GC threshold percentage |
| `PV_STORAGE_GC_THRESHOLD_DEFERTIME` | time (in seconds) | `600` | defer time for GC threshold |
| `PV_STORAGE_LOGTEMPSIZE` | size string | empty | set size for temporary log storage |
| `PV_STORAGE_MNTPOINT` | path | empty | set storage mount point |
| `PV_STORAGE_MNTTYPE` | string | empty | set storage mount type |
| `PV_STORAGE_PHCONFIG_VOL` | `0` or `1` | `0` | use volume for Pantahub configuration |
| `PV_STORAGE_WAIT` | time (in seconds) | `5` | time to wait for storage device |
| `PV_SYSCTL_*` | string | — | set any kernel sysctl at runtime; key maps to `/proc/sys/` (e.g. `PV_SYSCTL_KERNEL_CORE_PATTERN` → `/proc/sys/kernel/core_pattern`) |
| `PV_SYSCTL_KERNEL_CORE_PATTERN` | string | `\|/lib/pv/pvcrash --skip` | set kernel core dump pattern |
| `PV_SYSTEM_APPARMOR_PROFILES` | string | empty | AppArmor profiles to load |
| `PV_SYSTEM_CONFDIR` | path | `/configs` | set directory for system configurations |
| `PV_SYSTEM_DRIVERS_LOAD_EARLY_AUTO` | `0` or `1` | `0` | enable early auto-loading of drivers |
| `PV_SYSTEM_ETCDIR` | path | `/etc` | set system etc directory |
| `PV_SYSTEM_ETCPANTAVISORDIR` | path | `/etc/pantavisor` | set Pantavisor etc directory |
| `PV_SYSTEM_INIT_MODE` | `embedded`, `standalone` or `appengine` | `embedded` | set [system init mode](../../pantavisor-src/docs/overview/init-mode.md) |
| `PV_SYSTEM_LIBDIR` | path | `/lib` | set system library directory |
| `PV_SYSTEM_MEDIADIR` | path | `/media` | set system media directory |
| `PV_SYSTEM_MOUNT_SECURITYFS` | `0` or `1` | `0` | mount securityfs |
| `PV_SYSTEM_RUNDIR` | path | `/run/pantavisor/pv` | set system run directory |
| `PV_SYSTEM_USRDIR` | path | `/usr` | set system usr directory |
| `PV_UPDATER_COMMIT_DELAY` | time (in seconds) | `25` | delay before committing an update |
| `PV_UPDATER_GOALS_TIMEOUT` | time (in seconds) | `120` | timeout for reaching update goals |
| `PV_UPDATER_USE_TMP_OBJECTS` | `0` or `1` | `0` | use temporary objects during updates |
| `PV_VOLMOUNT_DM_EXTRA_ARGS` | string | empty | extra arguments for DM volume mounting |
| `PV_WDT_MODE` | `disabled`, `shutdown`, `startup` or `always` | `shutdown` | set [watchdog mode](../../pantavisor-src/docs/overview/watchdog.md) |
| `PV_WDT_TIMEOUT` | time (in seconds) | `15` | set watchdog timeout |

## Levels

This table shows the [configuration levels](../../pantavisor-src/docs/overview/pantavisor-configuration-levels.md) that are allowed for each [configuration key](#summary).

| Key | [pv.conf](../../pantavisor-src/docs/overview/pantavisor-configuration-levels.md#pantavisorconfig) | [ph.conf](../../pantavisor-src/docs/overview/pantavisor-configuration-levels.md#pantahubconfig) | [env,bootargs](../../pantavisor-src/docs/overview/pantavisor-configuration-levels.md#environment-variables) | [Policy](../../pantavisor-src/docs/overview/pantavisor-configuration-levels.md#policies) | [OEM](../../pantavisor-src/docs/overview/pantavisor-configuration-levels.md#oem) | [User meta](../../pantavisor-src/docs/overview/pantavisor-configuration-levels.md#user-metadata) | [Command](../../pantavisor-src/docs/overview/pantavisor-configuration-levels.md#commands) |
|-----|------------------------------------------------------------|------------------------------------------------------------|-----------------------------------------------------------------|-------------------------------------------------------|-----------------------------------------------|---------------------------------------------------------------|--------------------------------------------------------|
| `PH_CREDS_HOST`                      | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: | :material-close: |
| `PH_CREDS_ID`                        | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: | :material-close: |
| `PH_CREDS_PORT`                      | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: | :material-close: |
| `PH_CREDS_PROXY_HOST`                | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: | :material-close: |
| `PH_CREDS_PROXY_NOPROXYCONNECT`      | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: | :material-close: |
| `PH_CREDS_PROXY_PORT`                | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: | :material-close: |
| `PH_CREDS_PRN`                       | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: | :material-close: |
| `PH_CREDS_SECRET`                    | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: | :material-close: |
| `PH_CREDS_TYPE`                      | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: | :material-close: |
| `PH_FACTORY_AUTOTOK`                 | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: | :material-close: |
| `PH_LIBEVENT_HTTP_TIMEOUT`           | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: |
| `PH_LIBEVENT_HTTP_RETRIES`           | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: |
| `PH_METADATA_DEVMETA_INTERVAL`       | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: |
| `PH_METADATA_USRMETA_INTERVAL`       | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: |
| `PH_ONLINE_REQUEST_THRESHOLD`        | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: |
| `PH_UPDATER_INTERVAL`                | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: |
| `PH_UPDATER_NETWORK_TIMEOUT`         | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: |
| `PH_UPDATER_TRANSFER_MAX_COUNT`      | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: |
| `PV_BOOTLOADER_FITCONFIG`            | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_BOOTLOADER_MTD_ENV`              | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_BOOTLOADER_MTD_ONLY`             | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_BOOTLOADER_TYPE`                 | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_BOOTLOADER_UBOOTAB_A_NAME`       | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_BOOTLOADER_UBOOTAB_B_NAME`       | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_BOOTLOADER_UBOOTAB_ENV_NAME`     | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_BOOTLOADER_UBOOTAB_ENV_BAK_NAME` | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_BOOTLOADER_UBOOTAB_ENV_OFFSET`   | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_BOOTLOADER_UBOOTAB_ENV_SIZE`     | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_CACHE_DEVMETADIR`                | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_CACHE_USRMETADIR`                | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_CONTROL_REMOTE`                  | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: | :material-close: | :material-close: |
| `PV_CONTROL_REMOTE_ALWAYS`           | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: | :material-close: | :material-close: |
| `PV_DEBUG_SHELL`                     | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_DEBUG_SHELL_AUTOLOGIN`           | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_DEBUG_SHELL_TIMEOUT`             | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_DEBUG_SSH`                       | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-check: |
| `PV_DEBUG_SSH_AUTHORIZED_KEYS`       | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: |
| `PV_DISK_EXPORTSDIR`                 | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_DISK_VOLDIR`                     | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_DISK_WRITABLEDIR`                | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_DROPBEAR_CACHE_DIR`              | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_LIBEVENT_DEBUG_MODE`             | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: |
| `PV_LIBTHTTP_CERTSDIR`               | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_LIBTHTTP_LOG_LEVEL`              | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: |
| `PV_LOG_BUF_NITEMS`                  | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: | :material-close: | :material-close: |
| `PV_LOG_EVENTS`                      | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: | :material-close: | :material-check: |
| `PV_LOG_CAPTURE`                     | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: | :material-close: | :material-close: |
| `PV_LOG_CAPTURE_DMESG`               | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: | :material-close: | :material-close: |
| `PV_LOG_DIR`                         | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_LOG_DIR_MAXSIZE`                 | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: |
| `PV_LOG_FILETREE_TIMESTAMP_FORMAT`   | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: |
| `PV_LOG_HYSTERESIS_FACTOR`           | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: |
| `PV_LOG_LEVEL`                       | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: |
| `PV_LOG_LOGGERS`                     | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: | :material-close: | :material-close: |
| `PV_LOG_PUSH`                        | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: |
| `PV_LOG_ROTATE_FACTOR`               | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: |
| `PV_LOG_SERVER_OUTPUTS`              | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: |
| `PV_LOG_SINGLEFILE_TIMESTAMP_FORMAT` | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: |
| `PV_LOG_STDOUT_TIMESTAMP_FORMAT`     | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: |
| `PV_LXC_LOG_LEVEL`                   | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: | :material-close: | :material-close: |
| `PV_NET_BRADDRESS4`                  | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: | :material-close: | :material-close: |
| `PV_NET_BRDEV`                       | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: | :material-close: | :material-close: |
| `PV_NET_BRMASK4`                     | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: | :material-close: | :material-close: |
| `PV_OEM_NAME`                        | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_POLICY`                          | :material-check: | :material-close: | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: |
| `PV_REMOUNT_POLICY`                   | :material-close: | :material-close: | :material-check: | :material-close: | :material-close: | :material-close: | :material-close: |
| `PV_REVISION_RETRIES`                | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: |
| `PV_SECUREBOOT_CHECKSUM`             | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_SECUREBOOT_HANDLERS`             | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_SECUREBOOT_MODE`                 | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_SECUREBOOT_OEM_TRUSTSTORE`       | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_SECUREBOOT_TRUSTSTORE`           | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_STORAGE_DEVICE`                  | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_STORAGE_FSTYPE`                  | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_STORAGE_GC_KEEP_FACTORY`         | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: |
| `PV_STORAGE_GC_RESERVED`             | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: |
| `PV_STORAGE_GC_THRESHOLD_DEFERTIME`  | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: |
| `PV_STORAGE_GC_THRESHOLD`            | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: |
| `PV_STORAGE_LOGTEMPSIZE`             | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_STORAGE_MNTPOINT`                | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_STORAGE_MNTTYPE`                 | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_STORAGE_WAIT`                    | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_SYSCTL_*`                        | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: | :material-close: | :material-close: |
| `PV_SYSCTL_KERNEL_CORE_PATTERN`      | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: | :material-close: | :material-close: |
| `PV_SYSTEM_APPARMOR_PROFILES`        | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_SYSTEM_CONFDIR`                  | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_SYSTEM_DRIVERS_LOAD_EARLY_AUTO`  | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_SYSTEM_ETCDIR`                   | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_SYSTEM_INIT_MODE`                | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_SYSTEM_LIBDIR`                   | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_SYSTEM_MEDIADIR`                 | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_SYSTEM_MOUNT_SECURITYFS`         | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_SYSTEM_RUNDIR`                   | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_SYSTEM_USRDIR`                   | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_UPDATER_COMMIT_DELAY`            | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: |
| `PV_UPDATER_GOALS_TIMEOUT`           | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: |
| `PV_UPDATER_USE_TMP_OBJECTS`         | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: |
| `PV_VOLMOUNT_DM_EXTRA_ARGS`          | :material-check: | :material-close: | :material-check: | :material-check: | :material-check: | :material-close: | :material-close: |
| `PV_WDT_MODE`                        | :material-check: | :material-close: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |
| `PV_WDT_TIMEOUT`                     | :material-check: | :material-check: | :material-check: | :material-check: | :material-close: | :material-close: | :material-close: |

---
title: "Pantavisor Configuration"
sidebar_position: 2
description: "All pantavisor.json configuration keys, defaults, and allowed levels."
---

# Pantavisor Configuration

:::note
This reference page presents the newly unified configuration key syntax. To get to the deprecated but still supported previous format, you will have to go [here](https://github.com/pantavisor/docs.pantavisor/blob/master/archive/legacy/pantavisor-configuration-legacy.md).
:::

:::note
This page lists all configuration keys, their values, and the levels each one supports. For an explanation of what each level means and how they take precedence over one another, see [Configuration Levels](../overview/pantavisor-configuration-levels.md).
:::

## Summary

:::note
The key syntax is the same for all [configuration levels](#levels).
:::

:::note
All keys are case insensitive.
:::

:::note
Syntax and behavior of keys tagged with (experimental) might change and break backwards compatibility.
:::

This table contains the currently supported list of configuration keys, sorted alphabetically.

| Key | Value | Default | Description |
|-----|-------|---------|-------------|
| `PH_CREDS_HOST` | IP or hostname | `api.pantahub.com` | set [Pantacor Hub](../overview/remote-control.md#pantacor-hub) address |
| `PH_CREDS_ID` | string | empty | set [Pantacor Hub](../overview/remote-control.md#pantacor-hub) device ID |
| `PH_CREDS_PORT` | port | `443` | set port for communication with [Pantacor Hub](../overview/remote-control.md#pantacor-hub) |
| `PH_CREDS_PROXY_HOST` | IP or hostname | empty | set [Pantacor Hub](../overview/remote-control.md#pantacor-hub) proxy address |
| `PH_CREDS_PROXY_NOPROXYCONNECT` | `0` or `1` | `0` | disable proxy communication with [Pantacor Hub](../overview/remote-control.md#pantacor-hub) |
| `PH_CREDS_PROXY_PORT` | port | `3218` | set port for proxy communication with [Pantacor Hub](../overview/remote-control.md#pantacor-hub) |
| `PH_CREDS_PRN` | string | empty | set [Pantacor Hub](../overview/remote-control.md#pantacor-hub) device PRN |
| `PH_CREDS_SECRET` | string | empty | set [Pantacor Hub](../overview/remote-control.md#pantacor-hub) credentials secret |
| `PH_CREDS_TYPE` | `builtin` | `builtin` | set [Pantacor Hub](../overview/remote-control.md#pantacor-hub) credentials type |
| `PH_FACTORY_AUTOTOK` | token | empty | set [factory auto token](https://docs.pantahub.com/pantahub-base/devices/#auto-assign-devices-to-owners) for communication with [Pantacor Hub](../overview/remote-control.md#pantacor-hub) |
| `PH_LIBEVENT_HTTP_RETRIES` | number of retries | `1` | set HTTP request number of retries for communication with [Pantacor Hub](../overview/remote-control.md#pantacor-hub) |
| `PH_LIBEVENT_HTTP_TIMEOUT` | time (in seconds) | `60` | set HTTP request timeout for communication with [Pantacor Hub](../overview/remote-control.md#pantacor-hub) |
| `PH_METADATA_DEVMETA_INTERVAL` | time (in seconds) | `10` | set push interval for [device metadata](../overview/storage.md#device-metadata) to [Pantacor Hub](../overview/remote-control.md#pantacor-hub) |
| `PH_METADATA_USRMETA_INTERVAL` | time (in seconds) | `5` | set refresh interval for [user metadata](../overview/storage.md#user-metadata) from [Pantacor Hub](../overview/remote-control.md#pantacor-hub) |
| `PH_ONLINE_REQUEST_THRESHOLD` | number of failures | `0` | number of failed requests to [Pantacor Hub](../overview/remote-control.md#pantacor-hub) allowed to still consider device online |
| `PH_UPDATER_INTERVAL` | time (in seconds) | `60` | set time between [Pantacor Hub](../overview/remote-control.md#pantacor-hub) [update](../overview/updates.md) requests |
| `PH_UPDATER_NETWORK_TIMEOUT` | time (in seconds) | `120` | set time before [rollback](../overview/updates.md#error) if device cannot communicate with [Pantacor Hub](../overview/remote-control.md#pantacor-hub) |
| `PH_UPDATER_TRANSFER_MAX_COUNT` | number of transfers | `5` | set maximum number of object transfers to and from [Pantacor Hub](../overview/remote-control.md#pantacor-hub) during [updates](../overview/updates.md) |
| `PV_BOOTLOADER_FITCONFIG` | string | empty | set FIT configuration name |
| `PV_BOOTLOADER_MTD_ENV` | string | empty | set MTD name for bootloader env |
| `PV_BOOTLOADER_MTD_ONLY` | `0` or `1` | `0` | enable MTD for bootloader env |
| `PV_BOOTLOADER_TYPE` | `uboot`, `uboot-ab`, `uboot-pvk`, `rpiab` or `grub` | `uboot` | set [bootloader](../overview/bsp.md#bootloader) type |
| `PV_BOOTLOADER_UBOOTAB_A_NAME` | string | `fitA` | name of the partition to use as "A" in uboot-ab mode |
| `PV_BOOTLOADER_UBOOTAB_B_NAME` | string | `fitB` | name of the partition to use as "B" in uboot-ab mode |
| `PV_BOOTLOADER_UBOOTAB_ENV_BAK_NAME` | string | empty | name of the partition where the uboot environment is backed up |
| `PV_BOOTLOADER_UBOOTAB_ENV_NAME` | string | empty | name  of the partition where the uboot environment is stored |
| `PV_BOOTLOADER_UBOOTAB_ENV_OFFSET` | offset in bytes | `0` | environment offset from the beginning of the partition |
| `PV_BOOTLOADER_UBOOTAB_ENV_SIZE` | size in bytes | `0` | size of the uboot environment |
| `PV_CACHE_DEVMETADIR` | path | `/storage/cache/devmeta` | set persistent [device metadata](pantavisor-metadata.md#device-metadata) dir |
| `PV_CACHE_USRMETADIR` | path | `/storage/cache/meta` | set persistent [user metadata](pantavisor-metadata.md#user-metadata) dir |
| `PV_CONTROL_REMOTE` | `0` or `1` | `1` | allow remote control from [Pantacor Hub](../overview/remote-control.md#pantacor-hub) |
| `PV_CONTROL_REMOTE_ALWAYS` | `0` or `1` | `0` | keep [communication with Pantacor Hub](../overview/remote-control.md#pantacor-hub) even when a [local revision](../overview/local-control.md) is running |
| `PV_DEBUG_SHELL` | `0` or `1` | `1` | enable local debug shell |
| `PV_DEBUG_SHELL_AUTOLOGIN` | `0` or `1` | `0` | enable autologin for debug shell |
| `PV_DEBUG_SHELL_TIMEOUT` | time (in seconds) | `60` | time that Pantavisor waits before rebooting if [debug shell console](../../meta-pantavisor/getting-started/operate/device-access/serial-port.md) is opened |
| `PV_DEBUG_SSH` | `0` or `1` | `1` | enable SSH debug access |
| `PV_DEBUG_SSH_AUTHORIZED_KEYS` | string | empty | set authorized keys for SSH debug access |
| `PV_DISK_EXPORTSDIR` | path | `/exports` | set exports directory |
| `PV_DISK_VOLDIR` | path | `/volumes` | set volumes directory |
| `PV_DISK_WRITABLEDIR` | path | `/writable` | set writable directory |
| `PV_DROPBEAR_CACHE_DIR` | path | `/storage/cache/dropbear` | set [debug ssh server](../../meta-pantavisor/getting-started/operate/device-access/local-network.md) cache directory |
| `PV_LIBEVENT_DEBUG_MODE` | `0` or `1` | `0` | enable event loop debug logs |
| `PV_LIBTHTTP_CERTSDIR` | path | `/certs` | set certificates directory for libthttp |
| `PV_LIBTHTTP_LOG_LEVEL` | `0` to `5` | `3` | set libthttp log verbosity level |
| `PV_LOG_BUF_NITEMS` | integer | `128` | set in-memory [logs](../overview/storage.md#logs) buffer size |
| `PV_LOG_CAPTURE` | `0` or `1` | `1` | capture logs from containers |
| `PV_LOG_CAPTURE_DMESG` | `0` or `1` | `1` | capture dmesg logs |
| `PV_LOG_DIR` | path | `/storage/logs/` | set [logs](../overview/storage.md#logs) directory |
| `PV_LOG_DIR_MAXSIZE` | integer with optional suffix `B`(default),`K`,`KB`,`M`,`MB`,`G`,`GB`,`T`,`TB`,`%`; `0` for auto 10% (100% if tmpfs) | `16777216` | max size of log directory |
| `PV_LOG_FILETREE_TIMESTAMP_FORMAT` | format string | empty | timestamp format for filetree logs |
| `PV_LOG_HYSTERESIS_FACTOR` | positive integer | `4` | controls the gap between high and low watermarks for [log directory cleanup](../overview/storage.md#log-directory-size-management) |
| `PV_LOG_LEVEL` | `0` to `5` | `0` | set Pantavisor log level (0: FATAL to 5: ALL) |
| `PV_LOG_LOGGERS` | `0` or `1` | `1` | enable loggers for containers |
| `PV_LOG_PUSH` | `0` or `1` | `1` | push logs to [Pantacor Hub](../overview/remote-control.md#pantacor-hub) |
| `PV_LOG_ROTATE_FACTOR` | integer | `5` | determines per-file rotation threshold for [log directory cleanup](../overview/storage.md#log-directory-size-management) |
| `PV_LOG_SERVER_OUTPUTS` | string | `filetree` | set log server outputs (comma separated) |
| `PV_LOG_AUTO_DEVLOG` | `0` or `1` | `1` | globally enable or disable the [/dev/log](logserver-sockets.md#devlog) bind-mount into containers; can be overridden per-container with `dev-log` in `run.json` |
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
| `PV_SECUREBOOT_CHECKSUM` | `0` or `1` | `1` | enable artifact [checksum validation](../overview/storage.md#artifact-checksum) |
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
| `PV_STORAGE_FIRMWARE_VOL` | `0` or `1` | `0` | use bsp volume `pv--firmware` as alternate kernel firmware load path (written to `/sys/module/firmware_class/parameters/path`); requires the volume to be declared in `device.json` |
| `PV_STORAGE_PHCONFIG_VOL` | `0` or `1` | `0` | use volume for Pantahub configuration |
| `PV_STORAGE_WAIT` | time (in seconds) | `5` | time to wait for storage device |
| `PV_SYSCTL_*` | string | — | set any kernel sysctl at runtime; key maps to `/proc/sys/` (e.g. `PV_SYSCTL_KERNEL_CORE_PATTERN` → `/proc/sys/kernel/core_pattern`) |
| `PV_SYSCTL_KERNEL_CORE_PATTERN` | string | `\|/lib/pv/pvcrash --skip` | set kernel core dump pattern |
| `PV_SYSTEM_APPARMOR_PROFILES` | string | empty | AppArmor profiles to load |
| `PV_SYSTEM_CONFDIR` | path | `/configs` | set directory for system configurations |
| `PV_SYSTEM_DRIVERS_LOAD_EARLY_AUTO` | `0` or `1` | `0` | enable early auto-loading of drivers |
| `PV_SYSTEM_ETCDIR` | path | `/etc` | set system etc directory |
| `PV_SYSTEM_ETCPANTAVISORDIR` | path | `/etc/pantavisor` | set Pantavisor etc directory |
| `PV_SYSTEM_INIT_MODE` | `embedded`, `standalone` or `appengine` | `embedded` | set [system init mode](../overview/init-mode.md) |
| `PV_SYSTEM_LIBDIR` | path | `/lib` | set system library directory |
| `PV_SYSTEM_MEDIADIR` | path | `/media` | set system media directory |
| `PV_SYSTEM_MOUNT_SECURITYFS` | `0` or `1` | `0` | mount securityfs |
| `PV_SYSTEM_RUNDIR` | path | `/run/pantavisor/pv` | set system run directory |
| `PV_SYSTEM_USRDIR` | path | `/usr` | set system usr directory |
| `PV_UPDATER_COMMIT_DELAY` | time (in seconds) | `25` | delay before committing an update |
| `PV_UPDATER_GOALS_TIMEOUT` | time (in seconds) | `120` | timeout for reaching update goals |
| `PV_UPDATER_USE_TMP_OBJECTS` | `0` or `1` | `0` | use temporary objects during updates |
| `PV_VOLMOUNT_DM_EXTRA_ARGS` | string | empty | extra arguments for DM volume mounting |
| `PV_WDT_MODE` | `disabled`, `shutdown`, `startup` or `always` | `shutdown` | set [watchdog mode](../overview/watchdog.md) |
| `PV_WDT_TIMEOUT` | time (in seconds) | `15` | set watchdog timeout |
| `PV_XCONNECT_DBUS_SYSTEMBUS_ENABLED` | `0` or `1` | `1` | enable the [pantavisor-hosted D-Bus system bus](pantavisor-xconnect.md#pantavisor-hosted-system-bus) (also requires the `xconnect-dbus-systembus` build feature) |

## Levels

This table shows the [configuration levels](../overview/pantavisor-configuration-levels.md) that are allowed for each [configuration key](#summary).

| Key | [pv.conf](../overview/pantavisor-configuration-levels.md#pantavisorconfig) | [ph.conf](../overview/pantavisor-configuration-levels.md#pantahubconfig) | [env,bootargs](../overview/pantavisor-configuration-levels.md#environment-variables) | [Policy](../overview/pantavisor-configuration-levels.md#policies) | [OEM](../overview/pantavisor-configuration-levels.md#oem) | [User meta](../overview/pantavisor-configuration-levels.md#user-metadata) | [Command](../overview/pantavisor-configuration-levels.md#commands) |
|-----|------------------------------------------------------------|------------------------------------------------------------|-----------------------------------------------------------------|-------------------------------------------------------|-----------------------------------------------|---------------------------------------------------------------|--------------------------------------------------------|
| `PH_CREDS_HOST`                      | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ |
| `PH_CREDS_ID`                        | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ |
| `PH_CREDS_PORT`                      | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ |
| `PH_CREDS_PROXY_HOST`                | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ |
| `PH_CREDS_PROXY_NOPROXYCONNECT`      | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ |
| `PH_CREDS_PROXY_PORT`                | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ |
| `PH_CREDS_PRN`                       | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ |
| `PH_CREDS_SECRET`                    | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ |
| `PH_CREDS_TYPE`                      | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ |
| `PH_FACTORY_AUTOTOK`                 | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ |
| `PH_LIBEVENT_HTTP_TIMEOUT`           | ✗ | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ |
| `PH_LIBEVENT_HTTP_RETRIES`           | ✗ | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ |
| `PH_METADATA_DEVMETA_INTERVAL`       | ✗ | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ |
| `PH_METADATA_USRMETA_INTERVAL`       | ✗ | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ |
| `PH_ONLINE_REQUEST_THRESHOLD`        | ✗ | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ |
| `PH_UPDATER_INTERVAL`                | ✗ | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ |
| `PH_UPDATER_NETWORK_TIMEOUT`         | ✗ | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ |
| `PH_UPDATER_TRANSFER_MAX_COUNT`      | ✗ | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ |
| `PV_BOOTLOADER_FITCONFIG`            | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_BOOTLOADER_MTD_ENV`              | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_BOOTLOADER_MTD_ONLY`             | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_BOOTLOADER_TYPE`                 | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_BOOTLOADER_UBOOTAB_A_NAME`       | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_BOOTLOADER_UBOOTAB_B_NAME`       | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_BOOTLOADER_UBOOTAB_ENV_NAME`     | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_BOOTLOADER_UBOOTAB_ENV_BAK_NAME` | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_BOOTLOADER_UBOOTAB_ENV_OFFSET`   | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_BOOTLOADER_UBOOTAB_ENV_SIZE`     | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_CACHE_DEVMETADIR`                | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_CACHE_USRMETADIR`                | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_CONTROL_REMOTE`                  | ✓ | ✗ | ✓ | ✓ | ✓ | ✗ | ✗ |
| `PV_CONTROL_REMOTE_ALWAYS`           | ✓ | ✗ | ✓ | ✓ | ✓ | ✗ | ✗ |
| `PV_DEBUG_SHELL`                     | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_DEBUG_SHELL_AUTOLOGIN`           | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_DEBUG_SHELL_TIMEOUT`             | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_DEBUG_SSH`                       | ✓ | ✗ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `PV_DEBUG_SSH_AUTHORIZED_KEYS`       | ✓ | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ |
| `PV_DISK_EXPORTSDIR`                 | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_DISK_VOLDIR`                     | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_DISK_WRITABLEDIR`                | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_DROPBEAR_CACHE_DIR`              | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_LIBEVENT_DEBUG_MODE`             | ✓ | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ |
| `PV_LIBTHTTP_CERTSDIR`               | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_LIBTHTTP_LOG_LEVEL`              | ✓ | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ |
| `PV_LOG_BUF_NITEMS`                  | ✓ | ✗ | ✓ | ✓ | ✓ | ✗ | ✗ |
| `PV_LOG_CAPTURE`                     | ✓ | ✗ | ✓ | ✓ | ✓ | ✗ | ✗ |
| `PV_LOG_CAPTURE_DMESG`               | ✓ | ✗ | ✓ | ✓ | ✓ | ✗ | ✗ |
| `PV_LOG_DIR`                         | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_LOG_DIR_MAXSIZE`                 | ✓ | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ |
| `PV_LOG_FILETREE_TIMESTAMP_FORMAT`   | ✓ | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ |
| `PV_LOG_HYSTERESIS_FACTOR`           | ✓ | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ |
| `PV_LOG_LEVEL`                       | ✓ | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ |
| `PV_LOG_LOGGERS`                     | ✓ | ✗ | ✓ | ✓ | ✓ | ✗ | ✗ |
| `PV_LOG_PUSH`                        | ✓ | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ |
| `PV_LOG_ROTATE_FACTOR`               | ✓ | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ |
| `PV_LOG_SERVER_OUTPUTS`              | ✓ | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ |
| `PV_LOG_AUTO_DEVLOG`                 | ✓ | ✗ | ✓ | ✓ | ✓ | ✗ | ✗ |
| `PV_LOG_SINGLEFILE_TIMESTAMP_FORMAT` | ✓ | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ |
| `PV_LOG_STDOUT_TIMESTAMP_FORMAT`     | ✓ | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ |
| `PV_LXC_LOG_LEVEL`                   | ✓ | ✗ | ✓ | ✓ | ✓ | ✗ | ✗ |
| `PV_NET_BRADDRESS4`                  | ✓ | ✗ | ✓ | ✓ | ✓ | ✗ | ✗ |
| `PV_NET_BRDEV`                       | ✓ | ✗ | ✓ | ✓ | ✓ | ✗ | ✗ |
| `PV_NET_BRMASK4`                     | ✓ | ✗ | ✓ | ✓ | ✓ | ✗ | ✗ |
| `PV_OEM_NAME`                        | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_POLICY`                          | ✓ | ✗ | ✓ | ✗ | ✗ | ✗ | ✗ |
| `PV_REMOUNT_POLICY`                   | ✗ | ✗ | ✓ | ✗ | ✗ | ✗ | ✗ |
| `PV_REVISION_RETRIES`                | ✓ | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ |
| `PV_SECUREBOOT_CHECKSUM`             | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_SECUREBOOT_HANDLERS`             | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_SECUREBOOT_MODE`                 | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_SECUREBOOT_OEM_TRUSTSTORE`       | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_SECUREBOOT_TRUSTSTORE`           | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_STORAGE_DEVICE`                  | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_STORAGE_FSTYPE`                  | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_STORAGE_GC_KEEP_FACTORY`         | ✓ | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ |
| `PV_STORAGE_GC_RESERVED`             | ✓ | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ |
| `PV_STORAGE_GC_THRESHOLD_DEFERTIME`  | ✓ | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ |
| `PV_STORAGE_GC_THRESHOLD`            | ✓ | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ |
| `PV_STORAGE_LOGTEMPSIZE`             | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_STORAGE_MNTPOINT`                | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_STORAGE_MNTTYPE`                 | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_STORAGE_WAIT`                    | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_SYSCTL_*`                        | ✓ | ✗ | ✓ | ✓ | ✓ | ✗ | ✗ |
| `PV_SYSCTL_KERNEL_CORE_PATTERN`      | ✓ | ✗ | ✓ | ✓ | ✓ | ✗ | ✗ |
| `PV_SYSTEM_APPARMOR_PROFILES`        | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_SYSTEM_CONFDIR`                  | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_SYSTEM_DRIVERS_LOAD_EARLY_AUTO`  | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_SYSTEM_ETCDIR`                   | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_SYSTEM_INIT_MODE`                | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_SYSTEM_LIBDIR`                   | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_SYSTEM_MEDIADIR`                 | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_SYSTEM_MOUNT_SECURITYFS`         | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_SYSTEM_RUNDIR`                   | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_SYSTEM_USRDIR`                   | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_UPDATER_COMMIT_DELAY`            | ✓ | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ |
| `PV_UPDATER_GOALS_TIMEOUT`           | ✓ | ✗ | ✓ | ✓ | ✓ | ✗ | ✗ |
| `PV_UPDATER_USE_TMP_OBJECTS`         | ✓ | ✗ | ✓ | ✓ | ✓ | ✓ | ✗ |
| `PV_VOLMOUNT_DM_EXTRA_ARGS`          | ✓ | ✗ | ✓ | ✓ | ✓ | ✗ | ✗ |
| `PV_WDT_MODE`                        | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_WDT_TIMEOUT`                     | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ |
| `PV_XCONNECT_DBUS_SYSTEMBUS_ENABLED` | ✓ | ✗ | ✓ | ✓ | ✓ | ✗ | ✗ |

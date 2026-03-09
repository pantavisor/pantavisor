# Pantavisor Configuration (Legacy)

!!! Warning 
    This configuration format is **deprecated** but still supported for backwards compatibility. For the new unified configuration syntax, please refer to the [Pantavisor Configuration](pantavisor-configuration.md) page.

Pantavisor configuration can be modified at different stages: compile time, boot time, update time, or runtime. Each subsequent level overrides the previous ones in the hierarchy.

## At Compile Time

The default configuration is defined in `pantavisor.config` and `pantahub.config` files included during the build process.

### pantavisor.config

| Key | Value | Default | Description |
|-----|-------|---------|-------------|
| `policy` | string | empty | Set configuration [policy]() |
| `cache.usrmetadir` | path | `/storage/cache/meta` | Persistent user metadata directory |
| `cache.devmetadir` | path | `/storage/cache/devmeta` | Persistent device metadata directory |
| `system.apparmor.profiles` | string | empty | AppArmor profiles to load during init |
| `system.init.mode` | `embedded`, `standalone`, `appengine` | `embedded` | Pantavisor initialization mode |
| `system.libdir` | path | `/lib` | System library path |
| `system.etcdir` | path | `/etc` | System configuration path |
| `system.rundir` | path | `/pv` | Runtime state path |
| `system.mediadir` | path | `/media` | Media mount path |
| `system.confdir` | path | `/configs` | Platform configuration path |
| `system.drivers.load_early.auto` | `0` or `1` | `0` | Auto-load modules and firmware |
| `system.mount.securityfs` | `0` or `1` | `0` | Mount securityfs during early init |
| `debug.shell` | `0` or `1` | `1` | Enable local [debug shell](inspect-device.md#tty) |
| `debug.shell.autologin` | `0` or `1` | `0` | Enable autologin for debug shell |
| `debug.ssh` | `0` or `1` | `1` | Enable debug SSH server |
| `debug.ssh_authorized_keys` | path | `/pv/user-meta/pvr-sdk.authorized_keys` | Path to authorized SSH keys |
| `dropbear.cache.dir` | path | `/storage/cache/dropbear` | Dropbear cache directory |
| `bootloader.type` | `uboot`, `uboot-pvk`, `grub` | `uboot` | Type of bootloader |
| `bootloader.mtd_only` | `0` or `1` | `0` | Enable MTD for bootloader environment |
| `bootloader.mtd_env` | path | N/A | Path to MTD device |
| `libthttp.certsdir` | path | `"/certs"` | Path to THTTP certificates |
| `secureboot.mode` | `disabled`, `audit`, `lenient`, `strict` | `lenient` | Secureboot enforcement level |
| `secureboot.truststore` | string | `ca-certificates` | Truststore name for signature validation |
| `secureboot.checksum` | `0` or `1` | `1` | Enable artifact checksum validation |
| `secureboot.handlers` | `0` or `1` | `1` | Enable artifact volume handlers |
| `storage.device` | identifier | **mandatory** | Storage device (LABEL, UUID, or /dev path) |
| `storage.fstype` | `ext4`, `ubifs`, `jffs2` | **mandatory** | Storage filesystem type |
| `storage.mntpoint` | path | **mandatory** | Main storage mount point |
| `storage.mnttype` | `ext4` | `disabled` | Mount filesystem type |
| `storage.logtempsize` | size | `disabled` | Size of temporary log buffer in RAM |
| `storage.wait` | integer | `5` | Seconds to wait for storage device |
| `storage.gc.reserved` | percentage | `5` | Reserved disk percentage for GC |
| `storage.gc.keep_factory` | `0` or `1` | `0` | Prevent GC from deleting revision 0 |
| `storage.gc.threshold` | percentage | `0` | Usage percentage to trigger GC |
| `storage.gc.threshold.defertime` | seconds | `600` | Defer time for threshold-based GC |
| `disk.voldir` | path | `/volumes` | Container volumes path |
| `updater.goals.timeout` | seconds | `120` | Timeout for reaching container status goals |
| `updater.use_tmp_objects` | `0` or `1` | `0` | Use on-disk temporary storage for downloads |
| `updater.commit.delay` | seconds | `25` | Delay before committing a new revision |
| `revision.retries` | integer | `10` | Max revision transition retries |
| `wdt.mode` | `disabled`, `shutdown`, `startup`, `always` | `shutdown` | Watchdog behavior |
| `wdt.timeout` | seconds | `15` | Hardware watchdog timeout |
| `net.brdev` | string | `lxcbr0` | Container bridge interface name |
| `net.braddress4` | IP | `10.0.3.1` | Bridge IPv4 address |
| `net.brmask4` | mask | `255.255.255.0` | Bridge IPv4 network mask |
| `log.dir` | path | `/storage/logs/` | Persistent logs directory |
| `log.server.outputs` | comma-list | `filetree` | Active log server outputs |
| `log.maxsize` | bytes | `2097152` | Max size of individual log files |
| `log.level` | `0` to `5` | `0` | Pantavisor log verbosity level |
| `log.buf_nitems` | integer | `128` | In-memory log buffer size (KB) |
| `log.capture` | `0` or `1` | `1` | Enable log capture from containers |
| `log.capture.dmesg` | `0` or `1` | `0` | Capture kernel dmesg into logs |
| `log.loggers` | `0` or `1` | `1` | Enable/disable loggers |
| `control.remote` | `0` or `1` | `1` | Enable communication with Pantacor Hub |
| `control.remote.always` | `0` or `1` | `0` | Maintain Hub connection during local revisions |

### pantahub.config

| Key | Value | Default | Description |
|-----|-------|---------|-------------|
| `creds.type` | `builtin`, `ext-*` | `builtin` | Authentication method |
| `creds.host` | hostname | `192.168.53.1` | Pantacor Hub API address |
| `creds.port` | port | `12365` | Pantacor Hub API port |
| `creds.proxy.host` | hostname | `NULL` | Optional HTTP proxy address |
| `creds.proxy.port` | port | `3128` | HTTP proxy port |
| `creds.id` | string | unset | Hub-assigned device ID |
| `creds.secret` | string | unset | Hub-assigned device secret |
| `factory.autotok` | string | `disabled` | Token for automatic claiming |
| `updater.interval` | seconds | `60` | Interval for update checks |
| `log.push` | `0` or `1` | `1` | Push stored logs to the cloud |
| `metadata.devmeta.interval` | seconds | `10` | Interval for device metadata synchronization |
| `metadata.usrmeta.interval` | seconds | `5` | Interval for user metadata synchronization |

## At Boot Time

Configuration can be overridden via the kernel command line or system policies.

### Command Line Overrides

Append `pv_<key>=<value>` for `pantavisor.config` keys or `ph_<key>=<value>` for `pantahub.config` keys to the boot arguments.

**Example:**
```bash
pv_log.level=5 ph_log.push=0
```

### System Policies

Policies are configuration files stored in the revision that are applied during boot. All keys are allowed in policies except for system paths (`system.*`) and init mode.

## After an Update

Specific keys can be overridden in a new revision by including a configuration file and referencing it from `bsp/run.json`. This allows revisions to tune runtime behavior like GC thresholds or update intervals.

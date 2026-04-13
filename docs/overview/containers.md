---
nav_order: 4
---
# Containers

Pantavisor implements a lightweight container run-time with the help of Linux Containers (LXC). Each container, in its minimal form, is then comprised of a rootfs that will be run isolated in its own name-space and an LXC configuration file. All these, as well as more advanced configuration, are included in the [state JSON](../../../reference/legacy/pantavisor-state-format-v2.md#containerrunjson).

## Storage

### Rootfs

The most basic storage unit of any container is always the rootfs. 

### Volumes

In addition to the rootfs, a container may define more auxiliary [storage volumes](../../../reference/legacy/pantavisor-state-format-v2.md#storage). Pantavisor gives flexibility to configure the persistence of changes and encryption. 

There a three types of persistence options:

* permanent: changes are stored in a single writable location.
* revision: changes are stored in a writable location pegged to the revision.
* boot: a pure tmpfs storage that will throw away changes after a reset.

Storage can be linked to a [storage disk](storage.md#disks).

### Remount Policies

After mounting the rootfs and additional volumes, Pantavisor can perform one to many remount operations. These operations can be defined either at a [global level](../../../reference/legacy/pantavisor-state-format-v2.md#devicejson) or [per container](../../../reference/legacy/pantavisor-state-format-v2.md#containerrunjson).

Several policies can be defined, but only one will be run, depending on the `PV_REMOUNT_POLICY` key set in [configuration](../../../reference/legacy/pantavisor-configuration.md).

Each policy contains a list of remount directives that follows the [mount command](https://www.man7.org/linux/man-pages/man8/mount.8.html) format for path (can use wildcards) and mount options.

### Configuration Overlay

On top of that, [additional files](../../../reference/legacy/pantavisor-state-format-v2.md#_configcontainer) can be attached to a [revision](revisions.md) to create a new overlay that will overwrite whatever is in that location in the rootfs of the container, creating the directories or files if necessary.

Thanks to this, configuration files or scripts can be added or modified without having to do it in the rootfs itself when preparing a new revision. It is advisable to limit this fature to small text based files, as bigger files might make boot up slower.

Underneath the cover, these config overlay files will be attached using the multiple-lower-dir feature of Linux 'overlayfs'. The mount command that
sets up this multi lowerdir overlay mount for the pantavisor rootfs is akin to:

```
mount -t overlay overlay -olowerdir=/configs/container:/volumes/container/root.squashfs,upperdir=/volumes/container/lxc-overlay /path/to/rootfs/mountpoint
```

### Exports

Container rootfs directories can be mounted back into the host using the `exports` feature from [a container](../../../reference/legacy/pantavisor-state-format-v2.md#containerrunjson). Those will be mounted to `/exports/<container>` at a relative path equal to its absolute path in the container.

This opens the possibility to share directories between containers and Pantavisor itself.

## Groups

Containers can be [grouped](../../../reference/legacy/pantavisor-state-format-v2.md#containerrunjson).

Groups main function is to define the order in which containers are started. Groups are ordered and will not begin the mount and/or start up of their containers until all [status goals](#status-goal) from all the containers belonging to the previous group are achieved. The status goal of each container can be configured at group level as well as overloaded for each container. If not configured at container level, group also determines the [restart policy](#restart-policy) in a similar way as the status goal.

If groups are not [explicitly configured](../../../reference/legacy/pantavisor-state-format-v2.md#groupsjson), Pantavisor will create the default ones:

| name | default status goal | default restart policy | description | 
| ---- | ------------------- | ---------------------- | ----------- | 
| data | MOUNTED | system | containers which volumes we want to mount but not to be started |
| root | STARTED | system | container or containers that are in charge of setting network connectivity up for the board |
| platform | STARTED | system | middleware and utility containers |
| app | STARTED | container | application level containers |

When using the default groups and if a container is not linked to a group, it will be automatically set to _platform_, except if it is the first container in alphabetical order and no other container has been set to _root_, in which case it will be set to _root_. If not using the default groups and if a container is not linked to a group, the [revision](revisions.md) will [fail](updates.md#error).

## Roles

[Roles](../../../reference/legacy/pantavisor-state-format-v2.md#containerrun.json) can be set to a given container. Roles will determine the elements that Pantavisor will make available in the container rootfs. There is just two role supported for now: `mgmt` and `nobody`.

If no role or the role `nobody` is defined, Pantavisor just mounts these elements into the container under the /pantavisor path:

* [pv-ctrl socket](../../../reference/legacy/pantavisor-commands.md) with no privileges (only allows to report [signals](#signals) to alter the [status goal](#status-goal)).
* [pv-ctrl-log socket](../../../reference/legacy/logserver-sockets.md#pv-ctrl-log) to send logs at [Log Server](storage.md#logs).
* [pv-fd-log socket](../../../reference/legacy/logserver-sockets.md#pv-fd-log) to subscribe file descriptor at [Log Server](storage.md#logs).
* The [stored logs](storage.md#logs) for that container and revision.
* The stored [user metadata](storage.md#user-metadata) and [device metadata](storage.md#device-metadata) for that container.

In addition to this, `mgmt` containers get these elements in /pantavisor:

* [pv-ctrl socket](../../../reference/legacy/pantavisor-commands.md) with privileges (full request support) for [local control](local-control.md).
* [pv-ctrl-log socket](../../../reference/legacy/logserver-sockets.md#pv-ctrl-log) to send logs at [Log Server](storage.md#logs).
* [pv-fd-log socket](../../../reference/legacy/logserver-sockets.md#pv-fd-log) to subscribe file descriptor at [Log Server](storage.md#logs).
* Full [stored logs](storage.md#logs) for all containers and revisions.
* The stored [user metadata](storage.md#user-metadata) and [device metadata](storage.md#device-metadata) for all containers.
* Challenge and device-id information for [Pantacor Hub](remote-control.md#pantacor-hub).

## Restart Policy

[Restart policy](../../../reference/legacy/pantavisor-state-format-v2.md#containerrunjson) defines how Pantavisor is going to [transition](updates.md#inprogress) into a new revision. There are two types of policies:

* system: any update that modifies any object or JSON belonging to at least one of the containers with _system_ restart policy will result in a [reboot transition](updates.md#reboot-transition).
* container: any update that only modifies objects or JSONs belonging to containers with the _container_ restart policy will result in a [non-reboot transition](updates.md#non-reboot-transition)

If the restart policy is not [explicitly configured](../../../reference/legacy/pantavisor-state-format-v2.md#containerrunjson) in a container, it will be set according to its [group](#groups) default one.

## Status

After a new [revision](revisions.md) is [updated](updates.md), or after the board is booted up, the containers will try to start if they were not previously started (this could happen in case of a [non-reboot update](updates.md#non-reboot-transition)).

These are the different status containers can be at:

* INSTALLED: the container is installed and ready to go.
* MOUNTED: the container volumes are mounted, but not yet started.
* BLOCKED: any of the [status goals](#status-goal) from a container belonging to the previous group are not yet achieved.
* STARTING: container is starting.
* STARTED: container PID is running.
* READY: Pantavisor has received a readiness [signal](#signals) from the container.
* RECOVERING: container crashed and [auto-recovery](#auto-recovery) is waiting to restart it.
* STOPPING: container is stopping because of a [update transition](#updates.md).
* STOPPED: container has stopped.

This status is also stored at the [group](#groups) level. The status of a group is always READY, except if any of the containers that form the group has not yet achieved their [status goal](#status-goal). In that case, the status of a group is the same as the container with the lower status, not counting the containers that have reached its status goal. This group status can be consulted from our [local control interface](../../../reference/legacy/pantavisor-commands.md#groups) and is also registered at the [Pantavisor logs](storage.md#logs).

Same way as with the group status, a [revision](revisions.md) global status is also stored. The way to calculate this status is the same as with the group one, but taking all containers from the revision into account. The revision status is stored in [device metadata](../../../reference/legacy/pantavisor-metadata.md#device-metadata), can be consulted from our [local control interface](../../../reference/legacy/pantavisor-commands.md#device-meta) and changes are registered at the [Pantavisor logs](storage.md#logs).

### Status Goal

Status goal defines the [status](#status) that Pantavisor is going to aim for a container and, ultimately, this is going to affect how [groups](#groups) are activated.

These are the status goals currently supported:

* MOUNTED: for containers whose volumes we want to be mounted but not started.
* STARTED: rest of containers that we want mounted and started, but we only check if its PID is running.
* READY: same as STARTED, but a readiness [signal](#signals) coming from the container namespace is required.

If the status goal is not [explicitely configured](../../../reference/legacy/pantavisor-state-format-v2.md#containerrunjson) in a container, it will be set according to its [group](#groups) default one.

A [timeout](../../../reference/legacy/pantavisor-state-format-v2.md#device.json) can be configured so an [update](updates.md#testing) will [fail](updates.md#error) if the status goal is not achieved withing the defined time value. If the timeout occurs during a regular bootup, the status goal checking will be omited and the following [group](#groups) will be unlocked.

### Signals

Signals can be sent from the container namespace to Pantavisor using the [local control interface](../../../reference/legacy/pantavisor-commands.md#signal) in order to affect the container [status](#status).

For now, we only support the `ready` signal, which can be used to get to the [READY status goal](#status-goal) from a container.

## Auto-Recovery

Containers can be configured to automatically restart after a crash using the `auto_recovery` object in [run.json](pantavisor-state-format-v2.md#containerrunjson) or inherited from the container's [group](#groups).

### Recovery Policies

| Policy | Behavior |
| ------ | -------- |
| `no` | Never restart (default). |
| `on-failure` | Restart on exit. (Note: the current implementation does not distinguish exit codes — it behaves the same as `always`. A future revision will leave the container stopped if it exits with status 0.) |
| `always` | Restart on any exit. |
| `unless-stopped` | Restart on any exit unless the container was explicitly stopped via API. |

### Exponential Backoff

When a container crashes, Pantavisor waits `retry_delay` seconds before restarting. On each subsequent crash, the delay is multiplied by `backoff_factor` (e.g., 5s, 10s, 20s, 40s with factor 2.0). The `reset_window` resets the retry counter if the container has been running longer than the configured seconds since its last start.

### Stability Tracking

The `stable_timeout` field defines how many seconds a container must survive after reaching its [status goal](#status-goal) before being considered stable. This does **not** block [group](#groups) startup chaining — groups still gate on `status_goal` only. However, during [TESTING](updates.md#testing), the commit is held until all containers with a `stable_timeout` have proven stable. If a container crashes within its stability window, the timer resets on the next successful start.

### Backoff Policy

The `backoff_policy` field controls what happens after `max_retries` is exhausted:

| Value | Behavior |
| ----- | -------- |
| `reboot` | Reboot the system (default). |
| `never` | Leave the container stopped; system continues running. |
| Duration (e.g., `10min`) | Wait the specified duration, reset the retry counter, and restart the full recovery cycle. Supported units: `s` (seconds), `min` (minutes), `h` (hours). |

During [TESTING](updates.md#testing), `max_retries` exhaustion always triggers a [rollback](updates.md#error) regardless of the backoff policy.

### Group-Level Defaults

Groups in [device.json](pantavisor-state-format-v2.md#devicejson) can define a default `auto_recovery` object. Containers inherit this configuration **all-or-nothing**: if a container has its own `auto_recovery` in `run.json`, it is used entirely; otherwise the group's default applies. No field-level merging is performed. The default `app` group ships with an on-failure recovery policy.

## Lifecycle Control

Containers with `restart_policy: "container"` can be stopped, started, and restarted at runtime via the [control socket](../../../reference/legacy/pantavisor-commands.md#containers). Containers with `restart_policy: "system"` cannot be controlled this way — they require a system-level transition (reboot or update).

### Stop

Stopping a container via the API is fundamentally different from a crash. It sets the `user_stopped` flag on the container's auto-recovery state, which tells the recovery engine to leave the container stopped. No retry counters are consumed and no backoff policy is triggered — even for containers with `max_retries: 0` that would normally go to backoff on first crash.

When a container transitions to [STOPPED](#status), its volumes are unmounted. This ensures clean state for a subsequent start.

### Start

Starting a previously stopped container clears the `user_stopped` flag and transitions the container to INSTALLED, which triggers the normal engine lifecycle: volumes are mounted, drivers are loaded, and the container process is started. Auto-recovery is fully restored with its original configuration.

### Restart

Restart force-stops the container and resets the auto-recovery retry counter to zero. For containers with auto-recovery configured, the recovery engine picks up the stopped container and restarts it through the standard recovery path (respecting retry delays and backoff). For containers without auto-recovery, the restart transitions the container directly to INSTALLED for an immediate start.

!!! Note "Volume unmount on stop"
    TODO: The bulk volume unmount in `pv_state_stop_force` and `pv_state_stop_platforms` is now redundant for platform volumes, since volumes are unmounted individually when each platform transitions to STOPPED. The bulk unmount paths should be cleaned up to only handle BSP volumes (plat == NULL). Additionally, `pv_volume_unmount` should guard against double-unmount to avoid spurious error logs during shutdown.

## Drivers

Containers can [reference](../../../reference/legacy/pantavisor-state-format-v2.md#containerrunjson) the BSP [managed drivers](bsp.md#managed-drivers) as required, optional or manual.

* required: these drivers will be loaded as soon as container is [STARTED](#status). The [revision](revisions.md) will fail if the drivers are not enabled through BSP as managed drivers.
* optional: these drivers will be loaded as soon as container is [STARTED](#status) too. In this case the revision will not fail if the drivers are not defined in the BSP.
* manual: drivers can be loaded from within containers trough [local control](local-control.md). The success or failure of loading drivers using the REST API will not determine whether a revision fails or not, but the [calls](../../../reference/legacy/pantavisor-commands.md#drivers) will return an error response if necessary.

## Loggers

Containers, by default, will automatically direct these logs from the container to the [Log Server](storage.md#logs):

* syslog
* messages
* lxc log
* lxc console

This list can be expanded to other files using the [state JSON](../../../reference/legacy/pantavisor-state-format-v2.md#logger).

## Service Mesh

Containers can expose services to each other and consume services from other containers through [xconnect](xconnect.md), Pantavisor's built-in service mesh. Providers declare services in a `services.json` manifest; consumers declare requirements in their `run.json`. The `pv-xconnect` daemon handles mediation and resource injection at runtime, supporting Unix sockets, REST, D-Bus, DRM, and Wayland.

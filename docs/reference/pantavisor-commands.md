---
title: "Control Socket"
sidebar_position: 3
description: "pv-ctrl HTTP-over-Unix-socket endpoints."
---

# Pantavisor Control Socket

**Overview:** [Local Control](../overview/local-control.md) explains what the control socket is for and
who may use it.

The pv-ctrl socket enables communication between the containers and Pantavisor during runtime.

The following subsections describe the behaviour of the HTTP API for the different endpoints, which you can test either using any HTTP client or our [pvcontrol tool](https://gitlab.com/pantacor/pv-platforms/pvr-sdk/-/blob/master/files/usr/bin/pvcontrol) from the default [pvr-sdk container](https://gitlab.com/pantacor/pv-platforms/pvr-sdk).

:::note
The examples provided use cURL, but any HTTP client inside of your container should work.
:::

## /containers

This endpoint can be used to list and manage [containers](../overview/containers.md) in the current revision.

### List containers

Returns all containers with their [status](../overview/containers.md#status), [restart policy](../overview/containers.md#restart-policy), [auto-recovery](../overview/containers.md#auto-recovery) state, and service mesh information.

```
$ curl -X GET --unix-socket /pantavisor/pv-ctrl "http://localhost/containers"
```

Each container has these fields, among others. `pid`, `started_at` and `restarts` are only there once the container has been started in the running revision, and `pid` and `started_at` only while it is `STARTED` or `READY`:

| Field | Description |
|-------|-------------|
| `name` | container name |
| `status`, `status_goal` | see [status values](#status-values) |
| `pid` | process id of the container init, as seen by Pantavisor |
| `started_at` | start of the container, in seconds since 1970. On a device without a battery-backed clock this is the time of the moment, which can jump when the clock is set |
| `restarts` | how many times the container was started again since the revision started; `0` after the first start |

```
$ pvcontrol containers ls | jq '.[] | select(.name == "my-container") | {status, pid, started_at, restarts}'
{"status":"STARTED","pid":1234,"started_at":1761052800,"restarts":0}
```

#### Status values

The same values are reported per group by [`/groups`](#groups) and per revision in
[device metadata](pantavisor-metadata.md#device-metadata).

| Status | Meaning |
|--------|---------|
| `NONE` | No status yet assigned |
| `INSTALLED` | Installed and ready to go |
| `MOUNTED` | Volumes mounted, not started |
| `STAGED` | Mounted, drivers loaded, runnable — waiting to be [started on demand](#lifecycle-control) |
| `BLOCKED` | A container in an earlier [group](../overview/containers.md#groups) has not met its status goal |
| `STARTING` | Starting |
| `STARTED` | The container PID is running |
| `READY` | A readiness [signal](#signal) has been received from the container |
| `RECOVERING` | Crashed, and [auto-recovery](../overview/containers.md#auto-recovery) is waiting to restart it |
| `STOPPING` | Stopping because of an [update transition](../overview/updates.md) |
| `STOPPED` | Stopped |

`MOUNTED`, `STAGED`, `STARTED` and `READY` are also the four
[status goals](../overview/containers.md#status-goal) a container or group can be given.

### Lifecycle control

Containers with `restart_policy: "container"` can be stopped, started, and restarted via the API. Containers with `restart_policy: "system"` are protected and will return HTTP 403, except for `restart` during [devmode](#devmode).

To stop a container:

```
$ curl -X PUT --header "Content-Type: application/json" --data "{\"action\":\"stop\"}" --unix-socket /pantavisor/pv-ctrl "http://localhost/containers/my-container"
```

Stopping a container sets the `user_stopped` flag, which prevents [auto-recovery](../overview/containers.md#auto-recovery) from restarting it. The container's auto-recovery configuration is preserved — no retry counters are consumed and no backoff is triggered.

To start a previously stopped container:

```
$ curl -X PUT --header "Content-Type: application/json" --data "{\"action\":\"start\"}" --unix-socket /pantavisor/pv-ctrl "http://localhost/containers/my-container"
```

Starting clears the `user_stopped` flag and returns the container to the normal engine lifecycle. Auto-recovery is fully restored.

To restart a running container:

```
$ curl -X PUT --header "Content-Type: application/json" --data "{\"action\":\"restart\"}" --unix-socket /pantavisor/pv-ctrl "http://localhost/containers/my-container"
```

Restart force-stops the container and resets the retry counter to zero. For containers with auto-recovery configured, the recovery engine restarts it naturally through the standard path. For containers without auto-recovery (`RECOVERY_NO`), the container is restarted directly.

| Action | State change | Auto-recovery effect |
| ------ | ------------ | -------------------- |
| stop | Running → STOPPED | `user_stopped` set; recovery skipped |
| start | STOPPED → INSTALLED → start | `user_stopped` cleared; recovery restored |
| start (from STAGED) | STAGED → INSTALLED → start | unaffected (was never running) |
| restart (with recovery) | Running → STOPPED → recovery engine restarts | Retry counter reset to 0 |
| restart (no recovery) | Running → STOPPED → INSTALLED → start | Direct restart |

While a [devmode](../overview/devmode.md) revision runs, a `system` container answers `restart` with `409` (reboot needed). Add `?reboot=1` to reboot the device into the devmode revision instead:

```
$ curl -X PUT --header "Content-Type: application/json" --data "{\"action\":\"restart\"}" --unix-socket /pantavisor/pv-ctrl "http://localhost/containers/my-system-container?reboot=1"
```

`stop` and `start` of a `system` container stay `403`. The answer to a call with `?reboot=1` that is accepted has the body `{"reboot":true}`: the device reboots right after it.

### Run a command in a container

`POST /containers/{name}/exec` runs a command in a running container and answers when the command ended. It is only available to containers with the `mgmt` role, and only while a [devmode](../overview/devmode.md) revision runs.

```
$ curl -X POST --header "Content-Type: application/json" --data '{"argv":["cat","/etc/os-release"],"timeout_s":10}' --unix-socket /pantavisor/pv-ctrl "http://localhost/containers/my-container/exec"
{"exit_code":0,"signal":null,"timed_out":false,"stdout_b64":"UFJFVFRZ...","stderr_b64":"","truncated":{"stdout":false,"stderr":false},"duration_ms":41}
```

The request body must have a `Content-Length` and is at most 384 KiB:

| Field | Type | Description |
|-------|------|-------------|
| `argv` | array of strings | required, 1 to 256 entries of at most 4096 bytes each and 32 KiB together; run as given, without a shell. To use a shell write `["sh","-c","..."]`. `argv[0]` is looked up in the `PATH` of the container |
| `stdin_b64` | string | base64 of the standard input, at most 256 KiB |
| `timeout_s` | number | 1 to 600, 30 by default. The command gets `SIGTERM` then, and `SIGKILL` 2 seconds later |
| `max_output` | number | 1 to 1048576, 16384 by default: bytes kept of each of stdout and stderr. The command is still read to its end, so it never blocks on a full pipe |
| `cwd` | string | working directory in the container, `/` by default |
| `env` | object | up to 32 variables added to the environment of the container init |

The answer is `200` also when the command fails. `exit_code` is `null` when a signal ended the command, and `signal` holds the signal number. `stdout_b64` and `stderr_b64` are base64. A command that does not exist ends with `exit_code` `127` (not executable: `126`) and a message in stderr, as a shell would do.

| Status | Condition |
|--------|-----------|
| `400` | bad JSON, no `argv`, a limit exceeded or no `Content-Length` |
| `403` | the caller is not a `mgmt` container, or [`PV_DEVMODE_ALLOWED`](pantavisor-configuration.md#summary) is `false` |
| `404` | the container is not in the running revision, or is `_pv_` (Pantavisor itself is never a target) |
| `409` | the running revision is not a devmode revision, or the container is not running |
| `500` | the command could not be started, for example the container cannot be joined |
| `503` | 4 commands already run; the answer has a `Retry-After` header |

The command runs as root of the container with:

- the namespaces (mount, pid, network, uts, ipc and cgroup) and the cgroups of the container init, so it sees what the container sees and is limited as the container is;
- the capability bounding set of the container init, so it never has more capabilities than the container;
- the environment of the container init plus `env`;
- the AppArmor profile of the container init, when Pantavisor itself runs under a different one.

The seccomp filter of the container is not applied. Every call writes one line to `pantavisor.log` with the caller, the container, `argv[0]`, the exit code and the duration; arguments and output are not logged. Use it from a shell with `pvcontrol containers exec <name> -- <command>`, see [pvcontrol](../tools/pvcontrol.md#run-a-command-in-a-container).

## /devmode

This endpoint reports the state of [devmode](../overview/devmode.md) and manages the per-container inlay. It is only available to containers with the `mgmt` role.

To get the devmode state:

```
$ curl -X GET --unix-socket /pantavisor/pv-ctrl "http://localhost/devmode"
{"enabled":true,"active":true,"revision":"devmode/r/12","base":"12","containers":[{"name":"my-container","inlay":"/storage/disks/rev/devmode/r/12/my-container/_devmode","inlay_storage":"disks/rev/devmode/r/12/my-container/_devmode","container_layer":".container/my-container","container_layer_persistence":"boot"}]}
```

`inlay_storage`: the inlay relative to the storage root, which mgmt containers see at `/storage`.

`container_layer`: the files the running container wrote itself (its `lxc-overlay` upper layer), relative to the devmode folder. Mgmt containers see them read-only at `/pantavisor/devmode/<container_layer>`, for example `/pantavisor/devmode/.container/my-container`. `container_layer_persistence` is the `persistence` (`boot`, `revision` or `permanent`) of the container's `lxc-overlay` storage. Both are absent for a container without an overlay root filesystem or without an `lxc-overlay` volume.

`revision`, `base` and `containers` are only present when `active` is `true`, that is, when the running revision is a devmode revision.

To start a devmode session, copy a base revision into a devmode revision and run it. Both fields are optional:

```
$ curl -X POST --header "Content-Type: application/json" --data '{"base":"0","resume":false}' --unix-socket /pantavisor/pv-ctrl "http://localhost/devmode"
{"revision":"devmode/r/0","base":"0","resumed":false,"reboot":true}
```

| Field | Description |
|-------|-------------|
| `base` | revision number or `locals/<name>`; default: the committed revision, as `pantavisor.revision` in the device metadata reports it |
| `resume` | `true` keeps the files of an earlier devmode revision of the same base; the default removes that revision first, with its logs and inlays, so the session starts clean |

The answer is sent before the device changes revision. `reboot` is `true` when the device reboots to run it. If the devmode revision of that base is already running, nothing changes and the answer is `{"revision":"devmode/r/0","base":"0","resumed":true,"running":true}`.

To empty the inlay of one container:

```
$ curl -X DELETE --unix-socket /pantavisor/pv-ctrl "http://localhost/devmode/containers/my-container"
```

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/devmode` | devmode state: `enabled`, `active`, running devmode `revision`, its `base` and the inlay path of each container |
| `POST` | `/devmode` | start a devmode session: copy `base` into a devmode revision and run it |
| `DELETE` | `/devmode/containers/{name}` | remove all files from the inlay of a container |

| Status | Condition |
|--------|-----------|
| `400` | `POST`: `base` is a devmode revision ("a devmode revision cannot be the base of another one") or not a revision number or `locals/<name>` |
| `403` | [`PV_DEVMODE_ALLOWED`](pantavisor-configuration.md#summary) is `false` |
| `404` | `POST`: the base revision does not exist; `DELETE`: a container that is not in the running revision |
| `409` | `DELETE`: the running revision is not a devmode revision; `POST`: an update or command is in progress |
| `422` | `POST`: the state of the base does not verify |

## /daemons

This endpoint can be used to list and manage Pantavisor internal daemons.

To list all daemons and their current status:

```
$ curl -X GET --unix-socket /pantavisor/pv-ctrl "http://localhost/daemons"
```

To stop a specific daemon (e.g., `pv-xconnect`):

```
$ curl -X PUT --header "Content-Type: application/json" --data "{\"action\":\"stop\"}" --unix-socket /pantavisor/pv-ctrl "http://localhost/daemons/pv-xconnect"
```

To start a specific daemon:

```
$ curl -X PUT --header "Content-Type: application/json" --data "{\"action\":\"start\"}" --unix-socket /pantavisor/pv-ctrl "http://localhost/daemons/pv-xconnect"
```

## /groups

These requests can be used to list [groups](../overview/containers.md#groups).

To list all groups in the current revision:

```
$ curl -X GET --unix-socket /pantavisor/pv-ctrl "http://localhost/groups"
```

## /wakelocks

Returns the current power mode and wakelock state: mode, refcount, whether autosleep/settle/poll are active, and which scopes are held. See [`GET /wakelocks`](pantavisor-power.md#get-wakelocks) for the field-by-field semantics, and [Power and Wakelocks](../overview/wakelocks.md) for what the modes mean.

```
$ curl -X GET --unix-socket /pantavisor/pv-ctrl "http://localhost/wakelocks"
{
  "mode": "locks",
  "count": 0,
  "degraded": false,
  "autosleep": false,
  "settling": false,
  "polling": false,
  "run_window": false,
  "held": {
    "boot": false,
    "update": false,
    "update_check": false,
    "devmeta": false,
    "usrmeta": false,
    "shutdown": false,
    "debug_shell": false,
    "poll": false
  }
}
```

## /signal

This type of command can be issued to alter the container [status](../overview/containers.md#status) in Pantavisor.

To send the one-shot readiness signal:

```
$ curl -X POST --header "Content-Type: application/json" --data "{\"type\":\"ready\",\"payload\":\"\"}" --unix-socket /pantavisor/pv-ctrl http://localhost/signal
```

This request will fail if the [signal type](../overview/containers.md#signals) is not supported, or if that [status goal](../overview/containers.md#status-goal) is not expected.

## /commands

These commands can perform changes in Pantavisor [container engine](../overview/pantavisor-architecture.md#container-orchestration) itself, so the result will not be inmediate to the request.

An example of a command that tells Pantavisor to transition to revision 4:

```
$ curl -X POST --header "Content-Type: application/json" --data "{\"op\":\"LOCAL_RUN\",\"payload\":\"4\"}" --unix-socket /pantavisor/pv-ctrl http://localhost/commands
```

As you can see, the body of the request contains the command itself in JSON format.

These are the different commands that are supported. You can test them by substituting ```op``` and ```payload``` in the above command:

| op | payload | Description |
| -- | ------- | ----------- |
| UPDATE_METADATA | `{key, value}` | upload the json as a new pair of device metadata to Pantacor Hub |
| REBOOT_DEVICE | message | reboot device with optional message |
| POWEROFF_DEVICE | message | poweroff device with optional message |
| TRY_ONCE | revision | try a revision once (will rollback on failure or next reboot) |
| LOCAL_RUN | [revision](../../meta-pantavisor/getting-started/develop/cli-tools/workflows.md) | transition to specified revision |
| MAKE_FACTORY | revision | make the revision the factory revision. If revision is not set, Pantavisor will use the current one. Device needs to be [not claimed](../../meta-pantavisor/getting-started/operate/device-access/remote-pantahub.md) |
| RUN_GC | N/A | run garbage collector |
| ENABLE_SSH | N/A | [enable SSH server](../overview/pantavisor-configuration-levels.md#commands) ignoring config until reboot |
| DISABLE_SSH | N/A | [disable SSH server](../overview/pantavisor-configuration-levels.md#commands) ignoring config until reboot |
| GO_REMOTE | N/A | go remote when running on a [locals/ revision](pantavisor-commands.md#steps) if allowed by config |
| DEFER_REBOOT | new_timeout | defer reboot when debug shell is active, setting a new debug-shell-reboot timeout |
| LOCAL_RUN_COMMIT | revision | transition to revision and commit it automatically |
| LOCAL_APPLY | revision | apply revision changes without a full reboot |
| XCONNECT_GRAPH | N/A | trigger an immediate xconnect graph reconciliation |
| UNCLAIM | N/A | remove Pantacor Hub credentials so the device registers and becomes claimable again, without a reboot |

### Rejections

A command is not always accepted. These are the non-`200` responses and what causes them:

| Status | Header | Commands | Condition |
|--------|--------|----------|-----------|
| `204` | — | `GO_REMOTE` | device is already in remote mode |
| `204` | — | `UNCLAIM` | device is already unclaimed |
| `409` | — | `UPDATE_METADATA` | device is not in remote mode |
| `409` | — | `GO_REMOTE` | remote control is disabled by [`PV_CONTROL_REMOTE`](pantavisor-configuration.md#summary) |
| `409` | — | `DEFER_REBOOT` | the [debug shell](pantavisor-configuration.md#summary) is not active |
| `403` | — | `LOCAL_RUN`, `LOCAL_RUN_COMMIT` | the payload is a [devmode](../overview/devmode.md) revision and [`PV_DEVMODE_ALLOWED`](pantavisor-configuration.md#summary) is `0` |
| `409` | — | `LOCAL_RUN_COMMIT` | the payload is a devmode revision, which is never committed |
| `503` | `Retry-After: 600` | `REBOOT_DEVICE`, `POWEROFF_DEVICE`, `LOCAL_RUN`, `LOCAL_RUN_COMMIT`, `MAKE_FACTORY`, `UNCLAIM` | an [update](../overview/updates.md) is ongoing |
| `503` | `Retry-After: 120` | any | another command is still pending |

A `LOCAL_RUN` that is accepted answers `200` with an empty body. When it enters, switches or leaves [devmode](../overview/devmode.md), the device reboots and the body is `{"reboot":true}` instead. So does a `REBOOT_DEVICE` sent while a devmode revision runs; that reboot comes back into the devmode revision:

```
$ curl -X POST --header "Content-Type: application/json" --data '{"op":"LOCAL_RUN","payload":"devmode/r/12"}' --unix-socket /pantavisor/pv-ctrl http://localhost/commands
{"reboot":true}
```

## /storage

This endpoint groups [storage](../overview/storage.md) related operations.

To run the [garbage collector](../overview/storage.md#garbage-collector) synchronously. Unlike the RUN_GC [command](#commands), which is queued and executed at some later point by the state machine, the response is sent back once the collection has finished and reports the number of bytes reclaimed from orphaned objects:

```
$ curl -X POST --unix-socket /pantavisor/pv-ctrl "http://localhost/storage/gc"
{"reclaimed": 8646656}
```

## /objects

This endpoint can be used to list, send and receive objects to and from Pantavisor. Bear in mind that objects are the artifacts that form a Pantavisor revision.

An example of listing the objects that are stored in the device:

```
$ curl -X GET --unix-socket /pantavisor/pv-ctrl "http://localhost/objects"
```

Here, an example for getting one of those objects:

```
curl -X GET --unix-socket /pantavisor/pv-ctrl "http://localhost/objects/033e779113f2499a2bfb55c0c374803fba9c820361d71bbda616643007cacd5a"
```

You can even put new objects in Pantavisor. Notice that the sha256sum of object has to match the specified sha in the URI:

```
curl -X PUT --upload-file object --unix-socket /pantavisor/pv-ctrl "http://localhost/objects/033e779113f2499a2bfb55c0c374803fba9c820361d71bbda616643007cacd5a"
```

## /steps

This endpoint can be used to list, send and receive step jsons, as well as get the update progress and set the commit message for any of them.

Let us go with the examples, first, to list all steps installed in the device:

```
curl -X GET --unix-socket /pantavisor/pv-ctrl "http://localhost/steps"
```

To get an existing step json:

```
curl -X GET --unix-socket /pantavisor/pv-ctrl "http://localhost/steps/033e779113f2499a2bfb55c0c374803fba9c820361d71bbda616643007cacd5a"
```

To send a new json, the format of the new revision in the URI has to contain the "locals/" prefix. The name after the prefix must not contain any other "/" character. These revisions that are installed using the socket ([locals](../overview/local-control.md)) are treated in a different way than the ones installed from Pantacor Hub ([remotes](../overview/remote-control.md)), as you will have to manually request the transition to locals using the [run command](#commands). Most importantly, locals will not attempt any communication with Pantacor Hub during runtime unless a [go remote command](#commands) is issued.

```
curl -X PUT --upload-file json --unix-socket /pantavisor/pv-ctrl "http://localhost/steps/locals/example"
```

To get the update progress (DONE, TESTING, INPROGRESS...) and some related information of a revision:

```
curl -X GET --unix-socket /pantavisor/pv-ctrl "http://localhost/steps/033e779113f2499a2bfb55c0c374803fba9c820361d71bbda616643007cacd5a/progress"
```

Every `/steps/{sha}` route has a `locals/{name}` counterpart for revisions installed through this
socket:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/steps/locals/{name}` | read back a local revision's state json |
| `GET` | `/steps/locals/{name}/progress` | update progress of a local revision |
| `PUT` | `/steps/locals/{name}/commitmsg` | set the commit message of a local revision |

[Devmode](../overview/devmode.md) revisions are sent the same way, under `devmode/l/{name}` (based on the local revision `locals/{name}`) or `devmode/r/{number}` (based on the Hub revision `{number}`, digits only). They need [`PV_DEVMODE_ALLOWED`](pantavisor-configuration.md#summary)`=1`, set in `pantavisor.config` or the OEM config (user metadata cannot set it); otherwise the `PUT` answers `403`. Every `locals/{name}` route above also exists as `devmode/l/{name}` and `devmode/r/{number}`.

```
curl -X PUT --upload-file json --unix-socket /pantavisor/pv-ctrl "http://localhost/steps/devmode/r/12"
```

A devmode revision that does not run can be removed again. It does not need `PV_DEVMODE_ALLOWED`, because it only frees space. The answer is `200` when it is removed, `409` if it is the running revision or the one being updated to, `404` if it does not exist, and `400` if the name is not a devmode revision:

```
curl -X DELETE --unix-socket /pantavisor/pv-ctrl "http://localhost/steps/devmode/l/my-rev"
pvcontrol steps rm devmode/l/my-rev
```

Finally, you can set a commit message that will be stored along a revision and showed when listing revisions so the user can idendifcate each one of them:

```
curl -X PUT --data "message" --unix-socket /pantavisor/pv-ctrl "http://localhost/steps/033e779113f2499a2bfb55c0c374803fba9c820361d71bbda616643007cacd5a/commitmsg"
```

## /user-meta

The user-meta endpoint offers the ability to list, save and delete [user metadata](pantavisor-metadata.md#user-metadata).

To list all user meta in json format:

```
curl -X GET --unix-socket /pantavisor/pv-ctrl "http://localhost/user-meta"
```

An example of creating or updating a new user metadata pair in device:

```
curl -X PUT --data value --unix-socket /pantavisor/pv-ctrl "http://localhost/user-meta/key"
```

To delete one pair, we would do this, having in mind the same behaviour of operation modes as with putting metadata pairs:

```
curl -X DELETE --unix-socket /pantavisor/pv-ctrl "http://localhost/user-meta/key"
```

## /device-meta

The device-meta endpoint offers the ability to list [device metadata](pantavisor-metadata.md#device-metadata).

To list all device meta in json format:

```
curl -X GET --unix-socket /pantavisor/pv-ctrl "http://localhost/device-meta"
```

An example of creating or updating a new device metadata pair in device:

```
curl -X PUT --data value --unix-socket /pantavisor/pv-ctrl "http://localhost/device-meta/key"
```

To delete one pair, we would do this, having in mind the same behaviour of operation modes as with putting metadata pairs:

```
curl -X DELETE --unix-socket /pantavisor/pv-ctrl "http://localhost/device-meta/key"
```

## /xconnect-graph

This endpoint returns the current xconnect service mesh graph in JSON format. For details on how the service mesh operates and how to define manifests, see the [Pantavisor xconnect](pantavisor-xconnect.md) reference.

```
curl -X GET --unix-socket /pantavisor/pv-ctrl "http://localhost/xconnect-graph"
```

On a build without the `PANTAVISOR_XCONNECT` feature, this endpoint returns `404` with
`{"Error":"xconnect not enabled at build time"}`.

## /buildinfo

For debugging porpuses, it is possible to get the repo manifest that was used to build this Pantavisor binary.

With cURL, this would look like:

```
curl -X GET --unix-socket /pantavisor/pv-ctrl "http://localhost/buildinfo"
```

## /config

Returns the active [Pantavisor configuration](pantavisor-configuration.md) as a flat object with aliased dotted keys.

```
curl -X GET --unix-socket /pantavisor/pv-ctrl "http://localhost/config"
```

## /config2

Returns the active [Pantavisor configuration](pantavisor-configuration.md) as an array of `{key, value, modified}` records, where `modified` shows where the value came from (`default`, a config file, etc.).

```
curl -X GET --unix-socket /pantavisor/pv-ctrl "http://localhost/config2"
```

## /drivers

The drivers endpoint lets you list load and unload [managed drivers](../overview/bsp.md#managed-drivers).

To list drivers referenced by container and their load state:

```
curl -X GET --unix-socket /pantavisor/pv-ctrl http://localhost/drivers
```

To load manual drivers at bulk from within container:

```
curl -X PUT --unix-socket /pantavisor/pv-ctrl http://localhost/drivers/load
```

To load individual manual drivers, in this case one driver named "wifi":

```
curl -X PUT --unix-socket /pantavisor/pv-ctrl http://localhost/drivers/wifi/load
```

Same for unloading, it can be done at bulk:


```
curl -XPUT --unix-socket /pantavisor/pv-ctrl http://localhost/drivers/unload
```

And individually:

```
curl -XPUT --unix-socket /pantavisor/pv-ctrl http://localhost/drivers/wifi/unload
```

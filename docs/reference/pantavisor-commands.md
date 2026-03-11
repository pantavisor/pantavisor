# Pantavisor Control Socket

The pv-ctrl socket enables communication between the containers and Pantavisor during runtime.

The following subsections describe the behaviour of the HTTP API for the different endpoints, which you can test either using any HTTP client or our [pvcontrol tool](https://gitlab.com/pantacor/pv-platforms/pvr-sdk/-/blob/master/files/usr/bin/pvcontrol) from the default [pvr-sdk container](https://gitlab.com/pantacor/pv-platforms/pvr-sdk).

!!! Note
    The examples provided use cURL, but any HTTP client inside of your container should work.

## /containers

This endpoint can be used to list the containers (with their [status](containers.md#status)) that are installed in the current revision.

An example of use:

```
$ curl -X GET --unix-socket /pantavisor/pv-ctrl "http://localhost/containers"
```

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

These requests can be used to list [groups](containers.md#groups).

To list all groups in the current revision:

```
$ curl -X GET --unix-socket /pantavisor/pv-ctrl "http://localhost/groups"
```

## /signal

This type of command can be issued to alter the container [status](containers.md#status) in Pantavisor.

To send the one-shot readiness signal:

```
$ curl -X POST --header "Content-Type: application/json" --data "{\"type\":\"ready\",\"payload\":\"\"}" --unix-socket /pantavisor/pv-ctrl http://localhost/signal
```

This request will fail if the [signal type](containers.md#signals) is not supported, or if that [status goal](containers.md#status-goal) is not expected.

## /commands

These commands can perform changes in Pantavisor [container engine](pantavisor-architecture.md#container-orchestration) itself, so the result will not be inmediate to the request.

An example of a command that tells Pantavisor to transition to revision 4:

```
$ curl -X POST --header "Content-Type: application/json" --data "{\"op\":\"LOCAL_RUN\",\"payload\":\"4\"}" --unix-socket /pantavisor/pv-ctrl http://localhost/commands
```

As you can see, the body of the request contains the command itself in JSON format.

These are the different commands that are supported. You can test them by substituting ```op``` and ```payload``` in the above command:

| op | payload | Description |
| -- | ------- | ----------- |
| UPDATE_METADATA | {key, value} | upload the json as a new pair of device metadata to Pantacor Hub |
| REBOOT_DEVICE | message | reboot device with optional message |
| POWEROFF_DEVICE | message | poweroff device with optional message |
| TRY_ONCE | revision | try a revision once (will rollback on failure or next reboot) |
| LOCAL_RUN | [revision](make-a-new-revision.md) | transition to specified revision |
| MAKE_FACTORY | revision | make the revision the factory revision. If revision is not set, Pantavisor will use the current one. Device needs to be [not claimed](claim-device.md) |
| RUN_GC | N/A | run garbage collector |
| ENABLE_SSH | N/A | [enable SSH server](pantavisor-configuration-levels.md#commands) ignoring config until reboot |
| DISABLE_SSH | N/A | [disable SSH server](pantavisor-configuration-levels.md#commands) ignoring config until reboot |
| GO_REMOTE | N/A | go remote when running on a [locals/ revision](pantavisor-commands.md#steps) if allowed by config |
| DEFER_REBOOT | N/A | defer reboot when debug shell is active |
| LOCAL_RUN_COMMIT | revision | transition to revision and commit it automatically |
| LOCAL_APPLY | revision | apply revision changes without a full reboot |
| XCONNECT_GRAPH | N/A | trigger an immediate xconnect graph reconciliation |

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

To send a new json, the format of the new revision in the URI has to contain the "locals/" prefix. The name after the prefix must be under 64 characters and must not contain any other "/" character. These revisions that are installed using the socket ([locals](local-control.md)) are treated in a different way than the ones installed from Pantacor Hub ([remotes](remote-control.md)), as you will have to manually request the transition to locals using the [run command](#/commands). Most importantly, locals will not attempt any communication with Pantacor Hub during runtime unless a [go remote command](#commands) is issued.

```
curl -X PUT --upload-file json --unix-socket /pantavisor/pv-ctrl "http://localhost/steps/locals/example"
```

To get the update progress (DONE, TESTING, INPROGRESS...) and some related information of a revision:

```
curl -X GET --unix-socket /pantavisor/pv-ctrl "http://localhost/steps/033e779113f2499a2bfb55c0c374803fba9c820361d71bbda616643007cacd5a/progress"
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

## /buildinfo

For debugging porpuses, it is possible to get the repo manifest that was used to build this Pantavisor binary.

With cURL, this would look like:

```
curl -X GET --unix-socket /pantavisor/pv-ctrl "http://localhost/buildinfo"
```

## /drivers

The drivers endpoint lets you list load and unload [managed drivers](bsp.md#managed-drivers).

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

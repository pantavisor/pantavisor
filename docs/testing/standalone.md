---
title: "Running a Standalone Appengine Instance"
sidebar_position: 3
description: "Booting, driving and removing standalone appengine instances with run.docker.sh, and writing their setup json."
---
# Running a Standalone Appengine Instance

`./run.docker.sh` boots an appengine instance from a setup json and leaves it running. It
runs from an [installed distro](install.md). For what an instance is and when to use one,
see [the standalone appengine](appengine-standalone.md).

## Booting and driving an instance

```sh
./run.docker.sh up templates/run.docker.json -d -N demo  # boot in background as daemon, return once DONE
./run.docker.sh ls                                       # name, status, revision, IP, workdir
./run.docker.sh exec demo pvcontrol ls                   # any command, bash by default
./run.docker.sh attach demo                              # follow the console, Ctrl-C detaches
./run.docker.sh logs demo                                # print the console log
./run.docker.sh stop demo                                # power off, keep storage
./run.docker.sh start demo -d                            # boot it again as a daemon
./run.docker.sh down demo                                # remove the container and its workdir
```

Without `-d`, `up` and `start` show the console until Ctrl-C, which powers the instance
off.

`./run.docker.sh -h` lists every option.

## Writing a setup json

Start from the `templates/run.docker.json` template. Tarball paths are relative to the
json file:

```json
{
	"#spec": "pv-appengine@1",
	"description": "my setup",
	"setup": {
		"config": { "env": "PV_CONTROL_REMOTE=0", "usrmeta": "" },
		"containers": { "tarballs": ["../targets/appengine/local/pv-example-app.pvrexport.tgz"] }
	}
}
```

| Field | Purpose | Notes |
|-------|---------|-------|
| `#spec` | `"pv-appengine@1"` | `"pv-test@1"` also supported |
| `setup.config.env` | boot config, as space-separated `KEY=VALUE` | `-e KEY=VALUE` adds to it |
| `setup.config.pantavisor` | list of `KEY=VALUE` lines for `pantavisor.config`, for example `["PV_DEVMODE_ALLOWED=1"]` | added before pantavisor starts |
| `setup.config.usrmeta` | user metadata, as space-separated `KEY=VALUE` | saved once the instance is ready |
| `setup.containers.tarballs` | pvrexport tarballs added on top of the factory revision | relative to the json file or absolute |
| `setup.self-claim` | `"false"` | `"true"` not supported |

A `test.json` is accepted as well, using only its `setup` and resolving
`common/tarballs/` paths to the installed `targets/appengine/`:

```sh
./run.docker.sh up local/<category>/<test>/test.json
```

## Reaching the instance

The initial revision is named `locals/<name>` and boots as the factory revision, already
DONE. `-P PORT` publishes the `pvr` endpoint on the host. Without it, the instance IP on
the `test-appengine-net` bridge is reachable from the host:

```sh
pvr clone http://<ip>:12368/cgi-bin/pvr demo
```

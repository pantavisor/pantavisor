# pvtest dockerized tester

Run the pvtest suite from this directory with `./test.docker.sh`. One tester
container, built for the same architecture as the appengine (x86_64 or arm64),
drives the tests against a target that is either one or more appengine
containers or a real device.

## Layout

```
README.md           <- this file
workspace-README.md <- layout of a finished run's output
device.txt          <- device manifest template
test.docker.sh      <- the runner
test.native.sh      <- the runner without container runtime
run.docker.sh       <- standalone appengine instances
templates/          <- setup templates for run.docker.sh
images/             <- the docker images install-docker loads
local/  remote/     <- the suites
targets/<type>/     <- per target container tarballs
pvtest/             <- tester scripts, shared with the tester container
```

## Host setup

Fresh host only:

```sh
./test.docker.sh install-deps   # docker, plus qemu binfmt on x86_64 hosts
```

First install, and after every update:

```sh
./test.docker.sh install-docker # load the bundled docker images
```

For standalone instances only, `./run.docker.sh install-deps` installs the same
dependencies and `./run.docker.sh install-docker` loads just the appengine image.

The runner uses `sudo -n` (non-interactive) for a few commands while tests run,
so those must be allowed without a password. Add this once with `sudo visudo`:

```
<user> ALL=(ALL) NOPASSWD: /sbin/losetup, /sbin/modprobe, /usr/sbin/iw, /bin/chmod
```

Hub-backed tests read credentials from the environment:

```sh
export PH_USER=... PH_TOKEN=...
```

## Standalone instances

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

Each instance keeps `console.log`, `storage/`, `seed/` and `setup.json` in its
workdir (`~/.local/share/pvtest/instances/<name>`, or `-w`).

## Appengine testing (default)

```sh
./test.docker.sh ls                         # list tests
# all tests, one appengine worker with persistent storage
./test.docker.sh run
./test.docker.sh run local                  # a scope
./test.docker.sh run local/core             # a category
./test.docker.sh run local/foo              # a single test
# 4 parallel appengine worker slots, each one with a persistent storage
./test.docker.sh run local -p 4
./test.docker.sh run local --model volatile # one fresh storage per test
# interactive debug from tester container console
./test.docker.sh run local/core/foo -i
# manual run from appengine container console
./test.docker.sh run local/core/foo -m
./test.docker.sh run local/core/foo -o      # regenerate golden output
# remote tests against specific hub
./test.docker.sh run remote --hub https://api.stage.pantahub.com
```

## Device testing (`--device`)

First, install the manifest on the host, once per board. Fill it in and
uncomment:

```sh
mkdir -p ~/.config/pvtest/devices
cp device.txt ~/.config/pvtest/devices/rock5a.txt # fill in name/type/ip/exec
```

After that, install container tarballs using device manifest `type=` name:

```sh
./test.native.sh install-tarballs rock5a <dir-or-tarball>
```

Then, run it using the installed config:

```sh
./test.docker.sh run local --device rock5a                  # devices/rock5a.txt
# flash the board before each test
./test.docker.sh run local --device rock5a --model volatile
```

A device run uses the tester container to forward commands over `exec=`, so it
can also run with no container runtime at all:

```sh
./test.native.sh check                     # host readiness
./test.native.sh run local --device rock5a # run tests directly from host
```

## Output

Each run creates a workspace with `run.log`, a per runner `<name>.log` console
capture, and all of the results at `results/.../test.log` + `diff`.

A generated `README.md` inside that run workspace documents the full layout.

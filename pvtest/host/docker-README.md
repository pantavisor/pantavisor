# pvtest dockerized tester

Run the pvtest suite from this directory with `./test.docker.sh`. One x86 tester
container drives the tests against a target that is either one or more appengine
containers or a real device.

## Layout

```
README.md           <- this file
workspace-README.md <- layout of a finished run's output
device.txt          <- device manifest template
test.docker.sh      <- the runner
test.native.sh      <- the runner without container runtime
images/             <- the docker images install-docker loads
local/  remote/     <- the suites
targets/<type>/     <- per target container tarballs
pvtest/             <- tester scripts, shared with the tester container
```

## Host setup

Fresh host only:

```sh
./test.docker.sh install-deps   # docker + qemu binfmt
```

First install, and after every update:

```sh
./test.docker.sh install-docker # load the bundled docker images
```

The runner uses `sudo -n` (non-interactive) for a few commands while tests run,
so those must be allowed without a password. Add this once with `sudo visudo`:

```
<user> ALL=(ALL) NOPASSWD: /sbin/losetup, /sbin/modprobe, /usr/sbin/iw, /bin/chmod
```

Hub-backed tests read credentials from the environment:

```sh
export PH_USER=... PH_TOKEN=...
```

## Appengine testing (default)

```sh
./test.docker.sh ls                         # list tests
./test.docker.sh run                        # all tests, one appengine worker with persistent storage
./test.docker.sh run local                  # a scope
./test.docker.sh run local/core             # a category
./test.docker.sh run local/foo              # a single test
./test.docker.sh run local -p 4             # 4 parallel appengine worker slots, each one with a persistent storage
./test.docker.sh run local --model volatile # one fresh storage per test
./test.docker.sh run local/core/foo -i      # interactive debug from tester container console
./test.docker.sh run local/core/foo -m      # manual run from appengine container console
./test.docker.sh run local/core/foo -o      # regenerate golden output
./test.docker.sh run remote --hub https://api.stage.pantahub.com # remote tests against specific hub
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
./test.docker.sh run local --device rock5a --model volatile # flash the board before each test
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

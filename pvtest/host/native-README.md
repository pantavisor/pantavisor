# pvtest native tester

Run the pvtest suite from this directory with `./test.native.sh` against a real
device, natively, without using any container images for the tester.

## Layout

```
README.md           <- this file
workspace-README.md <- layout of a finished run's output
device.txt          <- device manifest template
test.native.sh      <- the runner
local/  remote/     <- the suites
targets/<type>/     <- per target container tarballs, starts empty
pvtest/             <- tester scripts, plus a static pvr in bin/
```

## Host dependencies

Verify required dependencies are installed on the host.

```sh
./test.native.sh check # host readiness
```

### Alpine

To install `./test.native.sh` dependencies on an Alpine host machine:

```sh
apk add bash jq curl openssh-client coreutils sed util-linux-misc flock tar \
        findutils grep gawk diffutils
```

### Debian / Ubuntu

On a Debian or Ubuntu host:

```sh
apt install bash jq curl openssh-client coreutils sed util-linux tar \
            findutils grep gawk diffutils
```

## Host setup

First, install the manifest on the host, once per board. Fill it in and
uncomment:

```sh
mkdir -p ~/.config/pvtest/devices
cp device.txt ~/.config/pvtest/devices/rock5a.txt # fill in name/type/ip/exec
```

Then, install container tarballs using device manifest `type=` name:

```sh
./test.native.sh install-tarballs rock5a <dir-or-tarball>
```

## Device testing (`--device`)

```sh
./test.native.sh ls                                         # list tests
./test.native.sh run --device rock5a                        # all tests on devices/rock5a.txt
./test.native.sh run local --device rock5a                  # a scope
./test.native.sh run local/lifecycle --device rock5a        # a category
./test.native.sh run local/lifecycle/foo --device rock5a    # a single test
./test.native.sh run local --device rock5a --model volatile # flash= before every test
./test.native.sh run local/lifecycle/foo --device rock5a -m # shell on the board
./test.native.sh run remote --device rock5a --hub https://api.stage.pantahub.com # remote tests against specific hub
```

## Output

Each run creates a workspace with `run.log`, a per runner `<name>.log` console
capture, and all of the results at `results/.../test.log` + `diff`.

A generated `README.md` inside that run workspace documents the full layout.

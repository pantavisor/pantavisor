---
title: "Running Against a Real Device With a Containerized Tester"
sidebar_position: 3
description: "Running tests against real devices with the help of the device manifest, hook scripts, architecture specific test containers and pvs signing."
---
# Running pvtests Against a Real Device

The [pvtest](pvtest-harness.md) suite can also run against real hardware. The tester
still runs on the host as in the [appengine](appengine.md) case. However, in this case,
the device is separated, typically connected to the same network as the host. While the
pvtest suite is the same for every target runner, the example container tarballs must be
built specifically for the architecture of the runner and signed for the base bsp CA.

The containerized tester provides a solution that lets you run the tester in your host
with a minimal set of dependencies besides Docker. It is also possible to run the tester
[natively](native.md) to avoid the container runtime entirely.

## Installing

Same as in the case of [appengine](appengine.md), everything that is needed to run pvtest
against real devices is included in the
[meta-pantavisor built](../../meta-pantavisor/overview/testing/automated/index.md)
`pantavisor-appengine-distro-<machine>.tar.gz` tarball.

Untar it and check the included `README.md` to know how to continue.

## Setup

### The device manifest

`device.txt` documents every key. Copy it, fill it in, uncomment.

A manifest describes a workstation board and the means to communicate with it, so it
should be installed in a permanent place in the host that can be reused through pvtest
installs, such as the config dir:

```
~/.config/pvtest/
  devices/        <- the only directory bind-mounted into the tester
    rock5a.txt    <- a named manifest, used by --device rock5a
    id_board      <- the SSH key referenced by exec=, 0600
  hooks/
    rock5a.conf   <- config file for setbootconfig_conf= and flash_conf=
```

`--device` always takes a value and firstly resolves it against that tree:

| Invocation | Manifest |
|---|---|
| `--device rock5a` | `~/.config/pvtest/devices/rock5a.txt` |
| `--device ./b.txt`, `--device /abs/b.txt` | path, when the config dir holds no such name |

### The setbootconfig script

`setbootconfig=` in device manifest can be used to provide pvtest harness with a hook
command that sets a board with the necessary environment configuration before each test.

This hook will be used in the [persistent model](pvtest-harness.md#persistent-model)
only. In that case, we share the storage of the target runners between test executions.
If the hook is set, we will execute it before each test that requires a boot config that
is not already met by the device. If the hook is not set and the device does not meet the
env config requirements, the test will be directly `SKIPPED`.

`setbootconfig_conf=` is not parsed by the framework but directly passed to the hook.

The contract for the hook is in `device.txt`.

### The flash script

`flash=` from device manifest can be used to provide the pvtest framework with means to
get the board to the initial setup with the containers plus env boot config required by
each test.

As tests themselves don't include the bsp itself, it is the responsibility
of the hook to install the setup initial containers along a working bsp that comes with
pvtx endpoint. If that is not the case, a container with pvr endpoint (e.g. pvr-sdk) can
do that role. Additionally, the hook could provision the board with connectivity if
remote testing is to be performed.

The hook is only used by the [volatile model](pvtest-harness.md#volatile-model), being
mandatory in this case. The hook will be executed before every test to get that fresh
board state under testing.

`flash_conf=` is not parsed by the framework but directly passed to the hook.

The contract for the hook is in `device.txt`.

### Building target tarballs

The pvtest distro includes example container tarballs used by the test suite. They are
built for the [appengine pool](appengine.md) though.

To run the tests in a real device, you are going to need to build those example
containers so they match the board architecture and are signed using the CA that is used
by its bsp to validate the revisions.

As the example containers live in meta-pantavisor, you will need to build them from
[there](../../meta-pantavisor/overview/testing/automated/index.md#building-fixtures-for-another-machine).
The list of containers that are required by the pvtest suite can be found at the
`PV_PVTEST_CONTAINERS` list in `pantavisor-appengine-distro.bb`.

### Installing target tarballs

To install the previously built target tarballs:

```bash
./test.docker.sh install-tarballs <target> <dir|tarball> ...
```

The target must be the manifest `type=`. For example:

```bash
./test.docker.sh install-tarballs rock5a /tmp/rock5a-example-containers
```

This will create a new target tree if that didn't exist before:

```
<distro-root>/
  local/  remote/                               <- shared suites, one copy
    common/templates/                           <- scope-varying, target-invariant
  targets/
    appengine/{local,remote}/*.pvrexport.tgz
    rock5a/{local,remote}/*.pvrexport.tgz
```

Every run announces the target type in `run.log`:

```
[ci-runner] 1753600000 INFO -- [test.docker.sh]: target type: rock5a (tarballs from targets/rock5a)
```

## Running

See the `README.md` included in the pvtest distro tarball to learn how to run.

## Debugging

The run workspace will include another `README.md` that documents the output layout,
including log format and its sources, useful greps, and how to interpret results.

### Expected outcomes

As you might find yourself running the tests on a new target, bear in mind that not every
non-PASSED is a bug:

- **SKIPPED on target type filter:** A test.json can contain a `"devices"` allow-list
  that excludes all targets that are not on said list. In this case, the test will be
  SKIPPED. See [test authoring rules](appengine.md#test-authoring-rules).
- **SKIPPED on unmet `config.env` with no `setbootconfig=`:** When running
  [persistent model](pvtest-harness.md#persistent-model), any test that does not meet
  the boot config env requirements will be SKIPPED.
- **ABORTED on setup timeout:** `setbootconfig=` (300 s) or `flash=` (3600 s) timeouts
  will result in the test being ABORTED.
- **FAILED on test timeout:** test script might also end up in a timeout (600 s),
  specially in boards with low specs. In that case the test will be flagged as FAILED.
  `PVTEST_TEST_TIMEOUT` could be adjusted for that.
- **FAILED on test script output diff:** this generally means the test failed. As tests
  are authored and tested against appengine pool, it is important to closely review these
  output diffs in case the test itself is not properly prepared for multi target. In case
  this is not possible to fix in the test itself, the solution is to filter it out for
  specific device types with `"devices"` from test.json.

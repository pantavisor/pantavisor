---
title: "The pvtest Harness"
sidebar_position: 1
description: "Test architecture, execution models, flow and where the code lives."
---
# The pvtest Framework

pvtest is able to run a single suite of tests against two kinds of target:

- A **slot pool** of one to many **appengine** containers driven in parallel.
- A **real device** over the network.

Both targets share the same machinery, with one **tester** (host or container) holding
`-p` slots, each slot holding one target. They differ only in how a slot's target is
obtained and re-typed (rebooted into the test-specific env and revision), which is what
[Execution Flow](#execution-flow) describes.

This page covers the framework itself, presenting its architecture and execution flow.
For running against appengine and authoring new tests, see [appengine.md](appengine.md).
For running against real hardware, see [device.md](device.md).  For the list of tests
that are both implemented and pending to do, see [pvtest-list.md](pvtest-list.md).

## Architecture

The framework is split into three parts:

- A thin **`test.docker.sh`** in charge of orchestrating the necessary Docker containers
  from the host.
- A **`pantavisor-tester`** layer, be it containerized or not, that runs, from the host,
  a flat test queue against the targets.
- The target runners themselves, which can be either a **real device** or zero to many
  **`pantavisor-appengine`** containers that expose SSH and the pvr HTTP API exactly as a
  real device would. In the second case, they run on the host too.

The tester drives each target over two channels:

- **`PVTEST_EXEC`**: a command prefix (typically `ssh ...`) used to run
  `pvcontrol`/`pventer` and other commands on the target.
- **`PVTEST_HOST`**: the host IP for the target pvr HTTP endpoint, used by `pvr`/`curl`.

The host also keeps a control channel open to the tester for the whole run, whatever the
target:

- **`PVTEST_CTRL`**: a file protocol the tester uses to ask the host for a target in a
  given config and running a given set of containers as its initial revision. What the
  host does with a request depends on `PVTEST_RETYPE`, which we will explain later.

### Topology

**Tester + appengine pool**
```
 HOST (x86)
 ┌────────────────────────────────────────────────────────────────────────┐
 │  test.docker.sh (slot pool: -p N slots, host re-types on demand)       │
 │                                                                        │
 │  ┌────────────────────┐         ┌──────────────────────────┐           │
 │  │  pantavisor-tester │──SSH───►│  pantavisor-appengine-0  │           │
 │  │   (x86, runner)    │ (EXEC)  │  ├─ pantavisor (PID1)    │           │
 │  │  pvtest-run        │──HTTP──►│  ├─ pvr-sdk (LXC)        │           │
 │  │  pvr  curl  jq     │ :12368  │  ├─ pvcontrol / pventer  │           │
 │  │  valgrind          │ (HOST)  │  └─ sshd                 │           │
 │  │                    │         └────────────┬─────────────┘           │
 │  │  N slots over a    │──SSH───►┌────────────┴─────────────┐           │
 │  │  global FIFO; each │──HTTP──►│  pantavisor-appengine-N  │  …        │
 │  │  slot re-types its │         └────────────┬─────────────┘           │
 │  │  container on      │                      │ docker logs -f          │
 │  │  demand            │                      ▼                         │
 │  └────────────────────┘              <container>.log  (on the host)    │
 └────────────────────────────────────────────────────────────────────────┘
```

**Tester + real device**
```
 HOST (x86 runner)                     external device (arm32/arm64, elsewhere)
 ┌────────────────────────────┐        ┌──────────────────────────┐
 │  test.docker.sh --device   │        │   arm32 / arm64 device   │
 │                            │  SSH   │  ├─ pantavisor (PID1)    │
 │  ┌────────────────────┐    │ (EXEC) │  ├─ pvr-sdk (LXC)        │
 │  │  pantavisor-tester │────┼───────►│  ├─ pvcontrol / pventer  │
 │  │   (x86, runner)    │────┼─HTTP──►│  └─ sshd                 │
 │  │  pvtest-run        │    │ :12368 └────────────┬─────────────┘
 │  │  pvr  curl  jq     │    │                     │ serial (tty)
 │  │                    │    │◄────────────────────┘
 │  │  1 slot over a     │    │
 │  │  global FIFO; slot │    │
 │  │  re-typed its      │    │
 │  │  device on demand  │    │
 │  │  demand            │    │
 │  └────────────────────┘    │                      
 └────────────────────────────┘
```

### Where the Code Lives

Everything is in **this repo**, under `pvtest/`, while **meta-pantavisor** assembles it
and owns the example containers the suites run with.

| Path | Role |
|---|---|
| `pvtest/tester/pvtest-run.in` | the tester main script, runs the tests against the targets |
| `pvtest/tester/utils.in` | library sourced by `pvtest-run` and by every test `resources/test` |
| `pvtest/shared/common.in` | helpers shared by the runner and the host orchestrator |
| `pvtest/host/test.docker.sh` | the host orchestrator for containerized tester, runs outside a container |
| `pvtest/host/test.native.sh` | the same for a non-containerized tester |
| `pvtest/host/host-common` | host-only library shared by the two orchestrators |
| `pvtest/host/device.txt` | device manifest template, to be installed in host at `~/.config/pvtest/devices/` |
| `pvtest/host/docker-README.md` | quick reference for running the suite |
| `pvtest/host/native-README.md` | same for a non-containerized tester |
| `pvtest/host/workspace-README.md` | layout guide for a finished run output |
| `pvtest/suites/local/`, `pvtest/suites/remote/` | the test suites |

## Execution Flow

The tester will drive the test execution in two different ways based on these runner
storage models:

- **`volatile`**: storage is new for every test.
- **`persistent`**: storage is persistent across test iterations.

### Volatile Model

Every test is executed against a newly flashed target. For the appengine pool, where 
starting a container is cheap, we get the fastest pipeline execution possible. It is also
supported on real devices to get that freshly storage status for each test.

In this model, the initial revision and env config are seeded before boot, so the target
comes up already on the test initial revision. For this, the host sets `PVTEST_RETYPE` to
tell the tester how to request for new targets to test:

- `container`: the host boots a new container with empty storage, and its `pv-appengine`
  entrypoint deploys the staged tarballs as the factory revision. Boot config is simply
  set as container environment variables.
- `flash`: the host runs the manifest's `flash=` script, which flashes the board with
  that same factory revision and boot config. A flash takes far longer than a container
  boot, so this trades speed for a factory-fresh board on every test. See
  [device.md](device.md#the-flash-script).

```
 ┌────────────────────────────┐
 │  Pick next test (queue)    │   alphabetical, per slot
 │  • stage tarballs to seed/ │
 └─────────────┬──────────────┘
               │ ctrl: cfg + storage=<test> + rev + seed
               ▼
 ┌────────────────────────────┐
 │  Boot a fresh target       │◄─────────────────────────────┐
 │  • test env cfg on the box │                              │
 │  • empty storage           │                              │
 │  • initial rev as factory  │                              │ more tests
 └─────────────┬──────────────┘                              │
               │ boots into the test's revision              │
               ▼                                             │
 ┌────────────────────────────┐                              │
 │  Bind + setup              │                              │
 │  • readiness fence         │                              │
 │  • assert rev + config     │                              │
 │  • gc, go-remote, claim    │                              │
 └─────────────┬──────────────┘                              │
               ▼                                             │
 ┌────────────────────────────┐                              │
 │  Run test  (exec_test)     │                              │
 │  • run resources/test      │                              │
 │  • diff vs golden output   │                              │
 └─────────────┬──────────────┘                              │
               ▼                                             │
 ┌────────────────────────────┐                              │
 │  Discard  (teardown)       │──────────────────────────────┘
 │  • delete device on Hub    │
 │  • drop container (pool)   │
 └────────────────────────────┘
```
This loop is repeated until the tester has executed the full flat queue sent by the host,
in alphabetical order.

### Persistent Model

Aimed at real devices with persistent storage between tests, but also compatible with
appengine, where we simulate the same behavior.

As storage will survive after each test, we need to be careful to provide each iteration
with the cleanest state possible (install and commit the initial revision, run garbage
collector, unclaim, claim or go remote whenever needed...), as well as writing the tests
in a way that they are agnostic to the device's prior state.

To achieve this, the host sets `PVTEST_RETYPE` to tell the tester how to request for
a target re-type into the desired boot configuration:

- `container`: the host just runs a new container that shares persistent storate with
  previous generations. Boot config is again set as container env variables.
- `setbootconfig`: the host runs runs the manifest `setbootconfig=` command to set the
  boot config and power-cycle the board.
- `none`: for real devices with no `setbootconfig=`. The tester binds the target as it
  is, and every test whose config the device does not already satisfy is SKIPPED.

```
 ┌────────────────────────────┐
 │  Init device(s)  (once)    │   per target, in parallel:
 │  • readiness fence         │   • collect device info
 │    (SSH..pvr endpoint)     │   • clone + export factory revision
 └─────────────┬──────────────┘
               │ pool ready
               ▼
 ┌────────────────────────────┐
 │  Install initial revision  │◄─────────────────────────────┐
 │  (setup_test)              │                              │
 │  • install locals/<test>   │                              │
 │    (pvtx; pvr fallback)    │                              │ more tests
 │  • ONE power cycle:        │                              │
 │    re-type (config change) │                              │
 │    or reboot (commit)      │                              │
 │  • gc, unclaim, go-remote  │                              │
 │  • claim state, usrmeta    │                              │
 └─────────────┬──────────────┘                              │
               │ device live on the test's revision          │
               ▼                                             │
 ┌────────────────────────────┐                              │
 │  Run test  (exec_test)     │──────────────────────────────┘
 │  • run resources/test      │
 │  • diff vs golden output   │
 └─────────────┬──────────────┘
               │ all tests done
               ▼
 ┌────────────────────────────┐
 │  Teardown  (once)          │   per target:
 │  • unclaim/delete, poweroff│   • lenient pantavisor shutdown
 └────────────────────────────┘
```

This loop is repeated until the tester has executed the full flat queue sent by the host,
pre-sorted for time optimization (claim-needing tests first, equal configs adjacent to avoid
unnecessary re-types).

## Build and install

Building the appengine distro tarball is done by a Yocto recipe that lives in
[meta-pantavisor](../../meta-pantavisor/overview/testing/automated/index.md). Because
the test data and the host scripts are staged out of *this* tree, a rebuild only picks up
a change here if the build is pointed at the checkout by bumping `PANTAVISOR_SRCREV`, or
with `devtool modify pantavisor` for local work.

To install, follow the tarball's own `README.md`.

## Invocation

`./test.docker.sh -h` lists every command, flag, path selector and environment override.
The tarball `README.md` has ready-made examples for the appengine pool and for real
devices.

## Reading a run

Every run creates a workspace that contains a `README.md` inside that documents the full
output layout, the log format and its four sources, the useful greps, and how to read the
valgrind results.

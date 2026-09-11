---
title: "The pvtest Harness"
sidebar_position: 1
description: "Test architecture, execution models, flow and where the code lives."
---
# The pvtest Framework

pvtest is able to run a single suite of tests against two kinds of target:

- A **slot pool** of one to many **appengine** containers driven in parallel.
- A **real device** over the network.

Both targets share the same machinery: one **tester** container holding `-p` slots, each slot
holding one target. They differ only in how a slot's target is obtained and re-typed (rebooted
into the test-specific env), which is what [Execution Flow](#execution-flow) describes.

This page covers the framework itself, how it is laid out, how to use it and where its output
lands. For running against appengine and authoring new tests see
[appengine.md](appengine.md). For running against real hardware see [device.md](device.md),
and for driving a device from a host with no container runtime, [native.md](native.md).
For a list of tests that are implemented and pending to do, see
[pvtest-list.md](pvtest-list.md).

## Architecture

The framework is split into three parts:

- A thin **`test.docker.sh`** in charge of orchestrating the necessary Docker containers from
  the host.
- A **`pantavisor-tester`** container that runs a flat test queue against the targets, be it
  **appengine** containers or a **real device**.
- Zero to many **`pantavisor-appengine`** containers that expose SSH and the pvr HTTP API
  exactly as a real device would. They run on the host too, and are interchangeable with a real
  device.

The tester drives each target over two channels:

- **`PVTEST_EXEC`**: a command prefix (typically `ssh …`) used to run `pvcontrol`/`pventer` on
  the target.
- **`PVTEST_HOST`**: the host IP for the target's pvr HTTP endpoint, used by `pvr`/`curl`.

The host also keeps a control channel open to the tester for the whole run, whatever the
target:

- **`PVTEST_CTRL`**: a file protocol the tester uses to ask the host for a target in a given
  config. Requests carry `slot=`, `cfg=`, `storage=`, `rev=` and `seed=`; replies carry
  `status=ready|down|failed|unsupported` plus `ae=` naming the target and `exec=`/`host=`
  saying how to reach it. What the host does with a request is decided by `PVTEST_RETYPE`,
  not by the kind of target.

### Topology

**Tester + appengine pool** — tester and appengines both on the HOST, all x86
```
 HOST (x86)
 ┌────────────────────────────────────────────────────────────────────────┐
 │  test.docker.sh   (slot pool: -p N slots, host re-types on demand)     │
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

**Tester + real device** — tester on the HOST (x86); the external device may be another arch
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
 │  └─────────┬──────────┘    │◄────────────────────┘
 │            ▼               │
 │      <name>.log            │
 └────────────────────────────┘
```

### Where the Code Lives

Everything is in **this repo**, under `pvtest/`. meta-pantavisor only assembles it, so a change
to any of the files below is a pantavisor change. The tree is split by *where a file runs* —
`tester/` in the tester container, `host/` on the workstation or CI runner, `shared/` in both,
and `suites/` for the test data.

The tester half, built when `PANTAVISOR_PVTEST=ON`:

| Path | Role | Ships as |
|---|---|---|
| `pvtest/tester/pvtest-run.in` | the tester container entrypoint, runs the tests against the targets | `pantavisor-pvtest` package → `/usr/bin/pvtest-run` |
| `pvtest/tester/utils.in` | library sourced by `pvtest-run` and by every test's `resources/test` | same package → `/usr/share/pantavisor/pvtest/utils` |
| `pvtest/shared/common.in` | helpers shared by the runner *and* the host orchestrator | same package → `/usr/share/pantavisor/pvtest/common`, and the tarball as `pvtest/common` |

The host half and the test data, plain files staged by `pantavisor:do_deploy`:

| Path | Role | Ships as |
|---|---|---|
| `pvtest/host/test.docker.sh` | the host orchestrator, runs outside every container | distro tarball root |
| `pvtest/host/test.native.sh` | the same, for a run with no container runtime | tarball root |
| `pvtest/host/host-common` | host-only library shared by the two orchestrators | tarball root, as `pvtest/host-common` |
| `pvtest/host/device.txt` | device manifest template, can be installed in host at `~/.config/pvtest/devices/` | tarball root |
| `pvtest/host/tarball-README.md` | quick reference for running the suite | tarball root, as `README.md` |
| `pvtest/host/workspace-README.md` | layout guide for a finished run's output | tarball root, copied into each run workspace as `README.md` |
| `pvtest/suites/local/`, `pvtest/suites/remote/` | the test suites | tarball root as `local/` and `remote/` |

**meta-pantavisor** does the assembly — `recipes-pv/pantavisor/pantavisor_git.bb` (`do_deploy`
stages the host half and the suites out of this source tree) and
`recipes-pv/pantavisor/pantavisor-appengine-distro.bb` (packs it into the tarball) — and owns the
`pv-example-*` container fixtures the suites run against, in `recipes-containers/pv-examples/`,
listed in `PV_PVTEST_CONTAINERS`/`_XCONNECT`. That directory also holds the containers used by the
*manual* testplans and `pv-avahi`/`pv-avahi-browse`, shipped product containers that two xconnect
tests happen to use. This repo carries no bitbake content, so a new fixture is a meta-pantavisor
change.

meta-pantavisor pulls this repo in once, as recipe source: `PANTAVISOR_SRCREV` in
`pantavisor.inc`.

Because `do_deploy` reads the recipe's `${S}`, a build with `devtool modify pantavisor` exercises
that checkout's suites. That is how the pantavisor repo's own onpush CI tests a branch before it
is pinned as `PANTAVISOR_SRCREV`:

```bash
kas shell <configs> -c \
    'devtool modify pantavisor && … git checkout <sha> && … \
     bitbake -c build pantavisor-appengine-distro'
```

## Execution Flow

The tester container will drive the test execution in two different ways based on these storage
models:

- **`volatile`**: storage is new for every test.
- **`persistent`**: storage is persistent across test iterations.

A real device does not use a separate code path: it is `-p 1` plus either the persistent model
with `setbootconfig`/`none` re-typing, or the volatile model with `flash`.

### Volatile Model

Every test gets a new target. It was designed primarily for the appengine pool, where a new
container is cheap, to get the fastest pipeline execution possible. However, it is also
supported on real devices to get that freshly flashed status for each one of the tests.

In this case, the initial revision and env config are seeded before boot, so the target comes up
already on the test's revision:

- **appengine** (`PVTEST_RETYPE=container`): the host boots a new container with empty storage,
  and its `pv-appengine` entrypoint deploys the staged tarballs as the factory revision.
- **real device** (`PVTEST_RETYPE=flash`): the host runs the manifest's `flash=` script, which
  flashes the board with that same factory revision and boot config. A flash takes far longer
  than a container boot, so this trades speed for a factory-fresh board on every test. See
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

There is no factory clone or export and no install step, which is where the time is saved.
Storage is keyed by test id rather than by slot, and the Hub device is deleted after every test
because the target's storage will not survive to be reused.

This loop is repeated until the tester has executed all of the flat queue provided by the host
in alphabetical order.

### Persistent Model

Aimed at real devices with persistent storage between tests, but also compatible with
appengine, where we simulate the same behavior.

As storage will survive after each test, we need to be careful to provide each iteration with
the cleanest state possible (install and commit the initial revision, run garbage collector,
unclaim, claim or go remote when needed...), as well as writing the tests to be agnostic to the
device's prior state.

To achieve this, the host sets `PVTEST_RETYPE` to tell the tester how a target is re-typed into
the desired env config with the following possible values:

- `container`: for the appengine pool, which just runs a new container generation while keeping
  the persistent storage.
- `setbootconfig`: for real devices, which runs the manifest's `setbootconfig=` script to set
  the boot config and power-cycle the board.
- `none`: for real devices with no `setbootconfig=`. The tester binds the target as it is, and
  every test whose config the device does not already satisfy is SKIPPED.

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

Building the appengine distro tarball is a Yocto build, and lives in meta-pantavisor:
[Building the pvtest distro](../../meta-pantavisor/overview/testing/automated/index.md). Because
the test data and the host scripts are staged out of *this* tree, a rebuild only picks up a change
here if the build is pointed at the checkout that has it — by bumping `PANTAVISOR_SRCREV`, or with
`devtool modify pantavisor` for local work.

To install, extract the tarball and load the Docker images as described in the tarball's own
`README.md`. When working directly on the build machine, the deploy directory already contains an
unpacked directory — cd into it and run `test.docker.sh` without extracting anything.

## Invocation

`./test.docker.sh -h` lists every command, flag, path selector and environment override. The
tarball `README.md` has ready-made examples for the appengine pool and for real devices.

## Reading a run

Every run creates a workspace that contains a `README.md` inside that documents the full
layout, the log format and its four sources, the useful greps, and how to read valgrind output.

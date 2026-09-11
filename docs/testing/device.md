---
title: "Running Against a Real Device"
sidebar_position: 3
description: "Running tests against real devices with the help of the device manifest, hook scripts, architecture specific test containers and pvs signing."
---
# Running pvtests Against a Real Device

The same suite that runs against the appengine pool runs against real hardware. The tester is
always x86, always runs on the host, and reaches the device over SSH and the pvr HTTP endpoint.
Only the example container tarballs the tests deploy are board-specific: they carry a rootfs
built for one architecture and signed by one CA.

For the framework itself see [pvtest-harness.md](pvtest-harness.md); for authoring tests and CI,
[appengine.md](appengine.md).

## Setup

### Install

Extract the tarball and load the Docker images as described in the tarball's own `README.md`.
Building it is a meta-pantavisor Yocto build:
[Building the pvtest distro](../../meta-pantavisor/overview/testing/automated/index.md).

### The device manifest

`device.txt` is a template: copy it, fill it in, uncomment.

| Key | Required | Default | Meaning |
|---|---|---|---|
| `name=` | yes | — | identifies this one runner, console capture lands in `<name>.log` |
| `type=` | no | `name=` | the *class* of target, shared by every board of the same kind (the Yocto MACHINE is the natural value). This is what a test's `"devices"` allow-list matches |
| `ip=` | yes | — | device IP for the pvr HTTP endpoint on `:12368` → `PVTEST_HOST` |
| `exec=` | yes | — | command prefix to run `pvcontrol`/`pventer` on the device → `PVTEST_EXEC` |
| `tty=` | yes | — | host-local serial device path for console capture. Prefer a stable `/dev/serial/by-id/…` over `/dev/ttyUSBN` |
| `baud=` | no | `115200` | `stty` baud for the console |
| `setbootconfig=` | no | — | host command that writes the device's env config based on test.json `config.env`. It also performs the necessary power-cycling. When set, and in `--model persistent`, a test whose `config.env` doesn't match the live device re-types through this script instead of SKIPping |
| `setbootconfig_conf=` | no | — | config file passed to `setbootconfig=` as `-c <file>` |
| `setbootconfig_base=` | no | — | this board's base boot-config tokens, space-separated `KEY=VALUE`, passed to `setbootconfig=` and `flash=` ahead of each test's own tokens. Useful, for example, to set `PV_LOG_SERVER_OUTPUTS=filetree,stdout_direct` so every test captures pantavisor's logs on the console |
| `flash=` | no | — | host command that flashes the device and makes the initial setup based on test.json tarballs and env. It also performs the necessary power-cycling. Required by `--model volatile`, which calls it before every test |
| `flash_conf=` | no | — | config file passed to `flash=` as `-c <file>` |

Unrecognized keys produce a `WARN` and are ignored.

A manifest describes a *workstation's* board, so it lives in the host's pvtest config dir
rather than in a workspace the next install throws away:

```
~/.config/pvtest/
  rock5a.conf             <- whatever setbootconfig=/setbootconfig_conf= reads. Host-side only
  devices/                <- the only directory bind-mounted into the tester
    rock5a.txt            <- a named manifest, used by --device rock5a
    id_board              <- the SSH key exec= names, 0600
```

`--device` always takes a value and resolves it against that tree, name first:

| Invocation | Manifest |
|---|---|
| `--device rock5a` | `~/.config/pvtest/devices/rock5a.txt` |
| `--device ./b.txt`, `--device /abs/b.txt` | that path, when the config dir holds no such name |

**An installed manifest never implies device mode.** `--device` is the only thing that
selects a board: a run without it drives the appengine pool, whatever sits in the config dir.

### The setbootconfig script

A board is a slot like any other: the tester asks the host to bring slot 0 up on a given config
over the same ctrl protocol the appengine pool uses, and the host satisfies it by running this
board's setbootconfig script (`PVTEST_RETYPE=setbootconfig`) instead of booting a container.

A board with no `setbootconfig=` answers `unsupported`, which is a normal reply rather than an
error: the tester binds the board as it is and SKIPs any test whose `config.env` it doesn't
already satisfy — so run device-mode suites **without** `--fail-on-skip` until each test's
`"devices"` array is triaged.

Path rules: `setbootconfig=`/`setbootconfig_conf=` are consumed host-side only and may point
anywhere on the host. Paths in `exec=` must be absolute and inside the manifest's own directory
— that directory is bind-mounted into the tester at the same absolute path, so an SSH key
anywhere else is invisible to it.

The contract:

```
setbootconfig contract
Invocation:  <setbootconfig> [-c <setbootconfig_conf>] KEY=VALUE ...
Inputs
  argv    the complete set of boot-config tokens the board must boot with:
          setbootconfig_base= tokens first, then the test's config.env tokens.
          A later token wins on a duplicate key. An empty value (KEY=) means
          "unset, use the default". Write them as a whole; do not merge with
          whatever the board currently has.
  -c      setbootconfig_conf=, if set. Opaque to the runner.
  env     the runner's own environment (under a lab wrapper that includes
          whatever it exports, e.g. power-port commands). No PVTEST_* is
          guaranteed. stdin is closed. cwd is unspecified: use absolute paths.
  console the runner releases tty= before the call and re-opens it after, so
          the script may open the serial device exclusively.
Outputs
  exit 0  the tokens are the board's persistent boot config (they survive the
          reboots a test itself triggers, until the next call) AND a reboot or
          power-cycle has been started. Return as soon as it has; do not wait
          for the board to come back, the runner fences READY itself.
  exit !0 failure. The runner reports the target as failed for that test.
  stdout/stderr  captured to <workspace>/dev-setbootconfig-<name>-<id>.log.
Must not: contact the board over exec= (it is rebooting), change keys it was
not given (other than by restoring setbootconfig_base=), require a TTY on
stdin, or leave the serial device open on exit.
Timing: the tester waits up to PVTEST_RETYPE_TIMEOUT (default 300 s) for the
call to return; the runner also WARNs if the console shows no activity within
30 s of return.
```

### The flash script

`setbootconfig=` sets the test env on a board that keeps its storage across tests, which is the
persistent model. The volatile model requires the test env too, plus starting each test on a fresh target
whose factory revision is the test's initial one. This is achieved by the appengine pool by
booting a new container. A real device gets it from its `flash=` script
(`PVTEST_RETYPE=flash`).

Before every test, the tester stages the test's container tarballs into the ctrl channel and
asks the host for slot 0 along with the test's config, its revision name and that seed
directory. The host runs the script and replies `ready` once it returns.

How the board is flashed is the script's business (a full reflash through the vendor tooling, or
anything else that leaves a factory-fresh storage). What the script must agree on with the
appengine pool is the result: the board boots `locals/<scope>_<category>_<name>` as its only,
committed revision, so the tester's check that it booted into the initial revision holds and
golden outputs stay target-independent. Board-specific base (BSP, pvr endpoint container...)
and connectivity are also part of the script's responsibilities.

Worth knowing before choosing the model:

- **Time.** A flash per test takes minutes, not seconds, so the tester waits up to
  `PVTEST_RETYPE_TIMEOUT` for the host to bring the slot up, 3600 s by default for `flash`.
- **Hub.** A fresh storage has no credentials, so each test that goes remote registers a new
  device on the Hub, exactly as on the appengine pool. The tester claims the `self-claim` ones
  and deletes them when the test is done automatically.
- **After the run.** The board is left running the last test's revision. Nothing powers it off.

The contract:

```
flash contract
Invocation:  <flash> [-c <flash_conf>] -r <revision> -t <tarball-dir> KEY=VALUE ...
Inputs
  -c      flash_conf=, if set. Opaque to the runner.
  -r      the name the board must boot as its factory revision:
          locals/<scope>_<category>_<name>, the same name the appengine pool
          seeds, so a test sees the same revision on every target.
  -t      host directory holding the test's container tarballs, named
          NN-<file>.pvrexport.tgz, to add in NN (test.json) order.
  argv    boot-config tokens, as for setbootconfig.
  env, console  as for setbootconfig.
Outputs
  exit 0  the board storage is fresh (no other revision, no Hub credentials,
          logs or state left by a previous test), its only revision is
          <revision> (base plus the -t tarballs) committed as DONE and selected
          by the bootloader, the tokens are its persistent boot config, AND
          the boot into it has been started. Return as soon as it has; the
          runner fences READY itself.
  exit !0 failure. The runner ABORTs that test.
  stdout/stderr  captured to <workspace>/dev-flash-<name>-<revision>.log,
          with / in <revision> replaced by _.
Must not: require a TTY on stdin, or leave the serial device open on exit.
Timing: the tester waits up to PVTEST_RETYPE_TIMEOUT (default 3600 s for
flash) for the call to return, then ABORTs the test.
```

### Building target tarballs

The example containers are ordinary `image` + `container-pvrexport` recipes with no arch
literals, so building *just those recipes* for the board's MACHINE is enough — any build config
with the right MACHINE and the right signing CA will do. The invocation is in meta-pantavisor:
[Building fixtures for another MACHINE](../../meta-pantavisor/overview/testing/automated/index.md#building-fixtures-for-another-machine).
The exports land in the deploy dir under exactly the names the tests reference, making it a
drop-in source with no renaming or staging step.

What that leaves you to check:

- **Which containers.** `PV_PVTEST_CONTAINERS` in meta-pantavisor's
  `pantavisor-appengine-distro.bb` is the authoritative list of what the suites consume. The
  `PV_PVTEST_CONTAINERS_XCONNECT` set (the dbus fixtures plus the avahi pair) is pinned
  `"devices": ["appengine"]`, so a real-device run never needs it.
- **Architecture.** Each `pv-example-*.pvrexport.tgz` embeds a squashfs of a Yocto rootfs built
  for the current MACHINE/TUNE, so its busybox and coreutils will not run on another
  architecture. Nothing else in them is arch-bound.
- **Signature.** Each tarball carries a `_sigs/<PN>.json` `pvs@2` JWS produced by `pvr sig add`
  using the CA that `pvr-ca.bbclass` fetched; a device only accepts it if its BSP trust store
  holds the same CA. To switch vendor, set `PVS_VENDOR_NAME`, `PVS_URI` and `PVS_URI_SHA256`
  consistently across `container-pvrexport`, `pvrexport`, `pvroot-image` and `pantavisor-bsp`.
- **pvtx on the device.** `setup_test` installs each test's revision with `pvtx` when the
  device rootfs has it, falling back to a tester-side `pvr post`. On a low-spec board the
  `pvtx` path is a single fast transaction and worth having; add `pantavisor-pvtx` to the
  BSP's initramfs in the test distro conf if it isn't there.

### Installing target tarballs

```bash
./test.docker.sh install-tarballs radxa-rock5a <dir|tarball>...   # creates the tree
```

The target is the first argument and is required — it is deliberately not defaulted to
`appengine`. A target tree that does not exist yet is created on first install. Each install
prints what it wrote with a sha256 prefix per tarball, and installing for one board cannot
disturb another's or the shipped appengine set.

Only the tarballs vary by target, so the suites are **not** copied per board — `local/` and
`remote/` stay single shared trees:

```
<distro-root>/
  local/  remote/                        shared suites, one copy
    common/templates/                    scope-varying, target-invariant
  targets/
    appengine/{local,remote}/*.pvrexport.tgz
    radxa-rock5a/{local,remote}/*.pvrexport.tgz
```

At tester start, `test.docker.sh` bind-mounts `targets/<type>/<scope>/` over
`/work/<scope>/common/tarballs`, so a `test.json`'s relative
`../../common/tarballs/<name>.pvrexport.tgz` resolves to the right architecture on every
target and nothing in the test data mentions a target. `<type>` is the manifest's `type=`
field, or `appengine` for a run without `--device`, and `PVTEST_DEVICE_TYPE` overrides both.
Every run announces it at `INFO` in the head of `run.log`:

```
[ci-runner] 1753600000 INFO -- [test.docker.sh]: target type: radxa-rock5a (tarballs from targets/radxa-rock5a)
```

If the resolved target has no tree under `targets/`, the run **aborts before any container
starts**, listing the targets that do exist. A tree that exists but is missing a tarball a test
asks for fails later, in the runner, naming the tarball and the test that wanted it.

Name the tarball files explicitly, or stage them into a directory of their own and pass that:
pointing `install-tarballs` at a raw deploy directory also sweeps up
`pantavisor-bsp-*.pvrexport.tgz`, `pv-pvr-sdk-*.pvrexport.tgz` and versioned duplicates, which
the suites do not want. Target trees live in the *extracted* distro, not in the meta-pantavisor
source tree — a rebuild re-stages the pristine `targets/appengine/`.

## Running

```bash
./test.docker.sh run local --device rock5a                  # persistent: one storage, re-typed through setbootconfig=
./test.docker.sh run local --device rock5a --model volatile # flash= before every test
```

`./test.docker.sh -h` and the tarball `README.md` cover the rest. Device specifics:
`--device` is incompatible with `-p>1`, `-n` and `-V`. It runs the persistent model unless
`--model volatile` is given, which needs `flash=` in the manifest (see
[The flash script](#the-flash-script)). `-i`
opens the tester console wired to the board; `-m` opens a shell on the board itself through
`exec=`, entering it as it is (no re-type, so the test's `config.env` is not applied) and
leaving it running on exit.

## Debugging

The run workspace's own `README.md` documents the layout, the log format and its sources, the
useful greps and the result lines. Two deltas against an appengine run:

- there is no `storage/` tree — the device keeps its own on-device storage;
- every `setbootconfig=` call is captured in `dev-setbootconfig-<name>-<id>.log`, and every
  `flash=` call in `dev-flash-<name>-<revision>.log`;
- pantavisor's own log sources reach `test.log` only if the manifest sets
  `setbootconfig_base=PV_LOG_SERVER_OUTPUTS=filetree,stdout_direct`. The serial console capture
  always lands in `<name>.log`.

### Expected outcomes

Not every non-PASS is a bug. Triage device results against these classes first:

- **SKIPPED because the test is pinned to another target is by design.** A test whose
  `"devices"` allow-list excludes this target never runs here (see the target-pinning rule
  in [appengine.md](appengine.md#test-authoring-rules)); the log line names the target and
  the list. Today that is `local/core/*-config-overload` (their golden output asserts
  appengine-specific config values, and `PV_POLICY=test` requires a `test.config` policy a
  BSP need not ship — a missing policy file is fatal to pantavisor init), `local/xconnect/*`
  (they need the `xconnect-dbus-systembus` build feature and its example containers), and
  `local/services/daemons` (it asserts the appengine image's daemon set).
- **SKIPPED on unmet `config.env` with no `setbootconfig=` configured is by design, not a
  failure.** It only happens in the persistent model. Without a setbootconfig script a real
  device's config is immutable per test, so e.g. the config-overload tests
  (`PV_POLICY=test`), the secureboot tests (`PV_SECUREBOOT_MODE=strict`) and `on-demand-gc`
  (`PV_STORAGE_LOGTEMPSIZE=` — persistent logs) skip wherever the device's live config says
  otherwise. Instead of changing a device's config or BSP just to un-skip a test,
  configuring a `setbootconfig=` (if the device supports boot-time config injection) is
  preferable.
- **Timeouts**: device runs default `PVTEST_TEST_TIMEOUT` to 1800 s (vs 600 s for
  containers) — updates may need real reboots and every forwarded poll pays an ssh
  round-trip.

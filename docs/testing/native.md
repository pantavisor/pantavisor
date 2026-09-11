---
title: "Running Without a Container Runtime"
sidebar_position: 4
description: "Natively running tests for driving tests from a host without Docker."
---
# Running pvtests Without a Container Runtime

`test.native.sh` is the native counterpart of `test.docker.sh`: it runs the pvtest tester
directly on the host instead of in a container. Use it to drive a **real device** from a
workstation, lab runner or CI box that has no Docker.

Everything downstream of the tester is unchanged — the same `pvtest-run`, the same suites, the
same device manifest, the same ctrl protocol, the same result format. For the framework itself
see [pvtest-harness.md](pvtest-harness.md); for the device manifest and the setbootconfig script,
[device.md](device.md).

## Why this is possible at all

With a device manifest, `PVTEST_EXEC` is set and `pv_exec` in `utils` forwards every target
command over it, so `pvcontrol`, `pventer`, `pvcurl` and `pvtx` run **on the board**. The
tester itself is architecture-independent shell plus a handful of ordinary host tools. The
container was never doing anything the host cannot.

The appengine pool is the exception and stays on `test.docker.sh`: its targets *are*
containers.

```bash
./test.native.sh run local --device rock5a      # supported
./test.native.sh run local                      # refused — no --device
```

## Getting it

The [meta-pantavisor build](../../meta-pantavisor/overview/testing/automated/index.md) deploys a
slim companion to the appengine distro tarball, holding the scripts and suites without the
container images:

```
build/tmp-scarthgap/deploy/images/<machine>/
  pantavisor-appengine-distro-<machine>.tar.gz      full: + the docker images
  pantavisor-pvtest-scripts-<machine>.tar.gz        scripts and suites only
  pantavisor-pvtest-scripts-<machine>/              same, already unpacked
```

Its `README.md` is the hands-on guide. `targets/` starts empty — a device needs tarballs built
for its own MACHINE, installed exactly as in the container flow:

```bash
./test.native.sh install-tarballs radxa-rock5a <dir-or-tarball>...
```

## Host dependencies

```bash
./test.native.sh check
```

reports every missing tool and whether the shipped runner supports relocation. Package names
for Alpine and Debian are in the tarball's `README.md`. The four that busybox cannot cover are
`coreutils` (`timeout --foreground`), `sed` (`sed -u` for the serial capture), `util-linux-misc`
(`script`, which wraps every test) and `flock`.

`pvr` is the one dependency no distro packages, so the tarball ships it: `pvtest/bin/pvr`, the
`pvr-static` build (CGO off, hence no ELF interpreter, hence glibc and musl alike). Neither of
the ordinary builds is usable here — the target one wants `/lib/ld-linux-*.so`, and the native
one's interpreter is a path inside the build tree. It is built for the tarball's architecture,
so take the tarball matching the host running the tester; a `pvr` on `PATH` always wins, and the
bundled one is used only if it actually executes.

## Running

```bash
./test.native.sh run local --device rock5a
./test.native.sh run local/lifecycle/foo --device rock5a -o   # regenerate a golden
./test.native.sh run local/lifecycle/foo --device rock5a -i   # tester shell
./test.native.sh run --device rock5a -m                       # shell on the board
./test.native.sh run remote --device rock5a --hub https://api.stage.pantahub.com
```

`--device` is required. `--hub URL` (or `PVTEST_HUB_URL`) selects the Hub as for
`test.docker.sh`. `--model` defaults to `persistent`; `--model volatile` needs `flash=` in the
manifest (see [device.md](device.md#the-flash-script)). `PVTEST_SLOTS` is always 1, because there
is one board; `-n` and `-V` do not apply. Results land in the workspace exactly
as they do for a container run — `run.log`, `results/<test>/{test.log,diff}` and the serial
capture in `<device>.log` — with `workspace-README.md` copied in beside them.

## How it differs internally

Three things the container provided have host-side stand-ins. Nothing else changes.

- **The scripts' install prefix.** `pvtest-run` finds `utils`/`common` through `PVTEST_LIBDIR`
  and derives test ids by stripping `PVTEST_ROOT`, both defaulting to the container's paths
  (`/usr/share/pantavisor/pvtest` and `/work`). The native runner points them at the unpacked
  tarball. Against a runner predating those overrides it falls back to a private user+mount
  namespace that overlays `/usr/share`, binds the scripts into place and binds the suites at
  `/work` — no root, no trace on the host, but it needs unprivileged user namespaces and an
  existing `/work`.
- **The per-target tarball mount.** The container run bind-mounts `targets/<type>/<scope>/`
  over `<scope>/common/tarballs`. With no mounts, the native runner mirrors the suites into
  the workspace as a symlink farm and points that one directory at the target's tarballs.
  Writes follow the symlinks back to the real files, so `-o` updates the golden in the source
  tree just as the bind mount does.
- **The lifecycle service.** Identical: `_retype_service` from `pvtest/host-common` answers the
  tester's re-type requests by running the manifest's `setbootconfig=` (or `flash=`, in the
  volatile model), or replies `unsupported` for a board without one.

`pvtest/host-common` is the host half shared by both runners — test selection, tarball install,
device manifest, ctrl protocol, summary. Anything that knows about containers stays in
`test.docker.sh`; anything that knows about namespaces stays in `test.native.sh`. It is **not**
the same file as `pvtest/common`, which is shared with the tester half. In the pantavisor source
tree the two sit apart by design: `pvtest/host/host-common` and `pvtest/shared/common.in`.

## Expected outcomes

The triage classes in [device.md](device.md#expected-outcomes) apply unchanged: a test pinned
to another target SKIPs, an unmet `config.env` with no `setbootconfig=` SKIPs, and the timeout defaults
to 1800 s. Run without `--fail-on-skip` until each test's `"devices"` array is triaged.

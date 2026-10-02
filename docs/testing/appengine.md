---
title: "Running Against Appengine and Authoring pvtests"
sidebar_position: 2
description: "Running tests against a pool of appengine instances, debugging tests that fail, adding new tests and containers along authoring rules."
---
# Running Against Appengine and Authoring pvtests

This page covers running the suite against the pool, debugging a failure and authoring
tests. To learn how the framework itself works, see [this](pvtest-harness.md). To run
the tests against real hardware, go [here](device.md) if you can use a containerized
runtime or [here](native.md) if that is not the case.

## Installing and running tests

First, you will need to get ahold of any of the
`pantavisor-appengine-distro-<machine>.tar.gz` deployed by the
[meta-pantavisor build](../../meta-pantavisor/overview/testing/automated/index.md).
The rest of the installation is already covered by the tarball-included own
`README.md`, as well as instructions for running the tests.

Furthermore, `./test.docker.sh -h` lists every command, flag, path selector and
environment override.

Building the tarball is covered in
[pvtest-harness.md](pvtest-harness.md#build-and-install).

## Debugging a failing test

Every run creates a workspace with a `README.md` inside that documents the full layout,
the log format and its sources, the useful greps, and how to read valgrind output.
Besides that, pvtest provides interactive and manual modes for the appengine target.

Interactive mode (`-i`) opens a console in the tester container and, in parallel, starts
an appengine container instance. From that console, the device is reachable and the full
test script can be run by hand.

Manual mode (`-m`) opens a console in the appengine container itself without starting
Pantavisor, which is handy to start Pantavisor by hand when it crashes or fails to reach
READY.

## Adding a new test

Test data lives in this repo under:

```
pvtest/suites/local/  # local tests
pvtest/suites/remote/ # remote tests
```

Each test is a directory at `<scope>/<category>/<name>/` containing `test.json`,
`resources/test`, and an `output` file.

**1. Create the test directory**

```bash
# From the workdir where appengine was installed/uncompressed (e.g. workdir/appengine-<commit>/):
./test.docker.sh add local/lifecycle/my-new-test
# Info: New test created at: .../local/lifecycle/my-new-test
```

This copies all templates (`test.json`, `resources/test`, `resources/ready`) and sets
permissions.

**2. Edit `test.json`**

| Field | Purpose | Notes |
|-------|---------|-------|
| `#spec` | always `"pv-test@1"` | do not change |
| `description` | human-readable summary | keep it short |
| `setup.config.env` | per-test env config, as space-separated `KEY=VALUE` | Prefer `setup.config.usrmeta` for keys configurable at runtime |
| `setup.config.usrmeta` | per-test runtime metadata, space-separated `KEY=VALUE` | e.g. `"PV_LOG_PUSH=1 PH_UPDATER_INTERVAL=5"` |
| `setup.containers.tarballs` | list of extra container pvrexport tarballs merged on top of the device factory state to form the test initial revision | the device/appengine should provide bsp plus a container with the pvr endpoint (e.g. pvr-sdk), so do not add those |
| `setup.self-claim` | `"true"`: claim the device in setup and delete it from hub in teardown; `"false"`: ensure the device is unclaimed in setup | requires `PH_USER`/`PH_TOKEN` when `"true"` |
| `setup.commit-initial` | whether the initial revision must be committed as a rollback point before the test body runs | `"true"` costs a full reboot cycle, so set it only when the test triggers a rollback that must land on its own revision, or asserts the initial revision survives a gc. Only affects the persistent model |
| `test-script` | path to the test script | `"resources/test"` |
| `skip` | exclude test from runs | `--fail-on-skip` (used on CI/master) fails the run on any SKIPPED |
| `devices` | allow-list of the target *classes* (`type=` in the device manifest) this test may run on | `[]` (run everywhere) |

**3. Write `resources/test`**

```sh
#!/bin/sh

source /usr/share/pantavisor/pvtest/utils

# pvcontrol talks to the device's pv-ctrl directly
# stdout is diff-ed against `output`
pvcontrol conf ls | jq -M -r '.["policy"]'
```

**4. Generate `output`**

Once `test.json` and `resources/test` are filled in, generate the golden output:

```bash
./test.docker.sh run local/lifecycle/my-new-test -o
```

**5. Port it to the source tree**

Once you have edited the test, port it back to the source tree:

```bash
cp -r <workdir>/local/lifecycle/my-new-test \
      <pantavisor>/pvtest/suites/local/lifecycle/
```

**6. Rebuild and verify**

See
[Building the pvtest distro](../../meta-pantavisor/overview/testing/automated/index.md).
A local iteration builds with `devtool modify pantavisor`.

Iterate between steps 4–6 until it passes cleanly.

**7. Mark the test as done**

We keep a list of all tests, both done and to do at [pvtest-list.md](pvtest-list.md).

### Adding a new container for a test

When a test needs a container that does not exist yet in the target trees, you will need
to make changes both in pantavisor and in meta-pantavisor repos.

**1. Create the recipe**

In meta-pantavisor, at `recipes-containers/pv-examples/<name>.bb`. Use
`pv-example-app.bb` as a reference:

```bitbake
SUMMARY = "..."
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"
inherit image container-pvrexport
IMAGE_BASENAME = "<name>"
IMAGE_INSTALL = "busybox"
IMAGE_FEATURES = ""
IMAGE_LINGUAS = ""
NO_RECOMMENDATIONS = "1"
PVRIMAGE_AUTO_MDEV = "0"
SRC_URI += "file://<script>.sh"
install_scripts() {
    install -d ${IMAGE_ROOTFS}${bindir}
    install -m 0755 ${WORKDIR}/<script>.sh ${IMAGE_ROOTFS}${bindir}/<entrypoint>
}
ROOTFS_POSTPROCESS_COMMAND += "install_scripts; "
PVR_APP_ADD_EXTRA_ARGS += "--config=Entrypoint=/usr/bin/<entrypoint>"
```

**2. Declare the new recipe**

In meta-pantavisor again, add it to the `PV_PVTEST_CONTAINERS` list in
`recipes-pv/pantavisor/pantavisor-appengine-distro.bb`:

```bitbake
PV_PVTEST_CONTAINERS ?= "pv-example-app pv-example-norole ... <name>"
```

Use `PV_PVTEST_CONTAINERS_XCONNECT` instead if the container only exists when
`PANTAVISOR_FEATURES` carries `xconnect-dbus-systembus`.

**3. Reference in `test.json`**

Back in pantavisor repo, add it to the `test.json` by its deploy name, relative to the
scope root and never naming a target. `test.docker.sh` mounts the active target tarball
tree over `/work/<scope>/common/tarballs`, so one reference resolves to the right
architecture on every board. See [device.md](device.md#installing-target-tarballs):

```json
"tarballs": [
  "../../common/tarballs/<name>.pvrexport.tgz"
]
```

**4. Build it and try it**

It is not necessary to rebuild the whole distro. The container recipe is an independent
recipe that can be built using `bitbake <name>` and will produce `<name>.pvrexport.tgz`
in the deploy dir. See
[building the pvtest distro](../../meta-pantavisor/overview/testing/automated/index.md#building-a-single-fixture).

Then, drop the export into an already-installed distro and run the test against it:

```bash
cd <workdir>/builds/<sha>
./test.docker.sh install-tarballs appengine /path/to/<name>.pvrexport.tgz
./test.docker.sh run local/<category>/<test>
```

### Test authoring rules

Before committing a new test, always check that it shares these rules:

1.  **Shared dir manipulation:** Always work in per-test dirs, never create, modify or
    delete files in a fixed shared path like `/home/checkout`.
2.  **Do not override `$HOME`:** The harness exports a per-device, Hub-authenticated
    `$HOME`. Do not override or touch that.
3.  **`pvr` clone isolation:** Any test that uses `pvr` to clone a device must do it into
    a unique per-test temp dir:
    ```sh
    checkout="$(mktemp -d)/checkout"
    pvr_clone_local_or_die "$checkout"
    cd "$checkout"
    ```
4.  **Clone source:** At the beginning of a test, clone always the device `current` state
    from its local pvr endpoint. Do not clone the accumulating trail head, which inherits
    other test leftovers.
5.  **Clone safety:** Always guard the exit code and fail loud. Suppress only stdout.
6.  **Hub revisions:** If you ever need to work with Hub revision numbers, capture the
    trail number and never hardcode. Revision numbers might vary in sequential test runs
    that share the same storage:
    ```sh
    device_id=$(pv_exec cat /run/pantavisor/pv/device-id)
    trail_url="$PVTEST_HUB_URL/trails/$device_id"
    rev=$(pvr_post_rev -m "msg" "$trail_url")
    [ -n "$rev" ] || { echo "ERROR: could not determine posted revision" >&2; exit 1; }
    wait_for_revision_state "$rev" "UPDATED"
    ```
7.  **Local revisions:** Post local revisions with a test specific name using
    `pvr post --rev "locals/<name>"` to avoid collisions between tests that share the
    same storage.
8.  **JSON output:** Always pipe JSON through `jq -M` and strip `\r`.
9.  **Volatile field obfuscation:** Mask volatile fields such as timestamps, PIDs, object
    hashes, $HOME paths, Hub revision numbers. Also secrets for obvious reasons.
10. **Output determinism:** Never hand-edit `output`, regenerate it with `run ... -o`.
11. **Clean up before returning control:** Remove any device or user metadata created
    during the test.
12. **Test must be state-independent:** In case of persistent model, there is no
    isolation mechanism between runs and the storage might be shared between tests.
    Therefore, any test must be written in a way that is independent from the state the
    device is into after previous tests (e.g. GC that deletes previous revisions).
13. **Test specific containers:** The initial test revision is the device factory clone
    plus the extra containers declared in `setup.containers.tarballs`. Never include
    `bsp` or an additional pvr endpoint container (e.g. pvr-sdk) as those should be
    already part of the device base factory revision.
14. **Base factory revision containers:** Do not manipulate the base revision
    containers. A test that manipulates a container must bring its own in its test.json
    (e.g. `pv-example-app.tgz`).
15. **Test specific configuration:** Configuration that is essential for the test should
    be specified at `setup.config` (e.g. PV_CONTROL=0 for a test that we need to execute
    in local mode). Preferably use `setup.config.usrmeta` when possible instead of
    `setup.config.env`.
16. **Target filtering:** `devices` absent or `[]` means the test is compatible with any
    target runner. Pin can be done by manifest `type=` when a test cannot pass elsewhere.
    ```
    "devices": ["appengine"] # test that will only be executed against appengine
    ```
17. **Only stdout is compared:** The script stderr goes to `test.log` and not to the
    diff. Tests must be done in a way that assert on any error.
18. **Don't lean on the device rootfs toolset:** BSPs configuration might differ across
    target runners (e.g. no `sha256sum`). Favour these operations in the tester, which
    should always have the same toolset.
19. **Prefer shared utils to re-inventing the wheel:** Always source `utils` at the top
    of the test script. It provides `pvcontrol`, `pventer`, `pvcurl`, `pv_exec`, the
    `wait_for_*` helpers, `pv_crash`, `pvr_clone_local_or_die` and `pvr_post_rev`. After
    a reboot or `pv_crash`, fence the comeback with `wait_for_down`, followed by
    `wait_for_target_ready`.
20. **Never hardcode a Hub URL:** Use `$PVTEST_HUB_URL`, exported by `utils` instead of
    directly hardcoding `api.pantahub.com`, as we test both against that and the stage
    Hub API.
21. **Use echo labels between asserts:** Besides the own test assertions, use labels to
    signify what we are doing at every moment (e.g. "== update 3: modify pv-example-app
    again =="). This will ease debugging when a test fails.

## Updating expected output for an existing test

After a behaviour change makes an existing test fail with a known-good diff, regenerate
its `output`:

```bash
./test.docker.sh -v run local/core/legacy-config-overload -o
cp <workdir>/local/core/legacy-config-overload/output \
   <pantavisor>/pvtest/suites/local/core/legacy-config-overload/output
```

First, check the output has changed as expected, then rebuild and verify as above.

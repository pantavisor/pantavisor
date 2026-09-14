# pvtest suite

Run the pvtest suite from this directory with `./test.docker.sh`. One x86 tester
container drives the tests against a target that is either one to many appengine
containers or a real device.

## One-time host setup

```
# fresh host only: ./test.docker.sh install-deps   # docker + qemu binfmt
./test.docker.sh install-docker    # load the bundled docker images
```

Set `PVTEST_IMAGE_TAG` before `install-docker` (and every `run`/`clean-docker` after it) to
give each concurrent job on a shared docker daemon its own image tag.

The runner uses `sudo -n` (non-interactive) for a few commands while tests run,
so those must be allowed without a password. Add this once with `sudo visudo`:

```
<user> ALL=(ALL) NOPASSWD: /sbin/losetup, /sbin/modprobe, /usr/sbin/iw, /bin/chmod
```

Hub-backed tests read credentials from the environment:

```
export PH_USER=... PH_PASS=...
```

A run targets one Pantacor Hub instance, selected with `--hub URL` (or `PVTEST_HUB_URL`),
default `https://api.pantahub.com`:

```
./test.docker.sh run --hub https://api.stage.pantahub.com
```

## Appengine testing (default)

```
./test.docker.sh run                        # all tests, one appengine worker with persistent storage
./test.docker.sh run local                  # a scope
./test.docker.sh run local/core             # a category
./test.docker.sh run local/foo              # a single test
./test.docker.sh run local -p 4             # 4 parallel appengine worker slots, each one with a persistent storage
./test.docker.sh run local --model volatile # one fresh storage per test
./test.docker.sh run local/core/foo -i      # interactive debug from tester container console
./test.docker.sh run local/core/foo -m      # manual run from appengine container console
```

## Device testing (`--device`)

First, install the manifest once per board, fill and uncomment:

```
mkdir -p ~/.config/pvtest/devices
cp device.txt ~/.config/pvtest/devices/rock5a.txt   # fill in name/type/ip/exec/tty/baud
```

`device.txt` documents every key. `name=`, `ip=`, `exec=` and `tty=` are
required. Without a `setbootconfig=` the board is bound as it is and any test whose
`config.env` it does not already satisfy is SKIPPED — that is by design, so run
without `--fail-on-skip` until each test's `"devices"` array is triaged. Without
a `flash=`, the board will not be able to run --model volatile.

Then, run it using the installed config:


```
./test.docker.sh run local --device rock5a                # devices/rock5a.txt
./test.docker.sh run local --device rock5a --model volatile # flash= the board before every test
```

A device run only uses the tester container to forward commands over `exec=`, so
it can also run with no container runtime at all — same suites, same manifest,
same output:

```
./test.native.sh check                                    # host readiness
./test.native.sh run local --device rock5a
```

`pantavisor-pvtest-scripts-<machine>.tar.gz` is the slim tarball for hosts that
only ever do that; its `README.md` lists the host packages. The appengine pool
stays on `test.docker.sh` — its targets *are* containers.

## Output

Each run creates a workspace with `run.log`, a per runner `<name>.log` console
capture, and `results/.../test.log` + `diff`.

A generated `README.md` inside that run workspace documents the full layout.

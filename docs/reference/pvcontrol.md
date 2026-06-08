# pvcontrol

`pvcontrol` is the on-device CLI for controlling Pantavisor from inside a
container. It is a small POSIX-shell wrapper (`tools/pvcontrol`) around
[`pvcurl`](pantavisor-tools.md#pvcurl) that talks to the pv-ctrl REST API over
a Unix socket. Every subcommand maps to one HTTP endpoint documented in
[pantavisor-commands.md](pantavisor-commands.md).

Use `pvcontrol` for everyday operations (status, metadata, lifecycle,
commands) and drop down to raw `pvcurl` only when you need a method/endpoint
`pvcontrol` does not wrap, or when you need to inspect HTTP status codes
directly.

## Synopsis

```bash
pvcontrol [options] <command> [arguments]
```

### Options

| Option | Description |
|--------|-------------|
| `-h` | Show help and exit. Also available per-command as `<command> --help`. |
| `-v` | Verbose — passes `-v` through to the underlying curl/pvcurl call. |
| `-s <path>` | Use `<path>` as the pv-ctrl socket instead of the auto-detected one. |
| `-f <path>` | Write the response body to `<path>` instead of stdout. |
| `-m <message>` | Commit message — only used by `steps install` and `steps put`. |

### Socket auto-detection

When `-s` is not given, the socket is selected in this order:

1. `/run/pantavisor/pv/pv-ctrl` — appengine / embedded mode
2. `/pv/pv-ctrl` — alternative embedded path
3. `/pantavisor/pv-ctrl` — default location inside a container (fallback)

If the chosen socket does not exist, `pvcontrol` prints `ERROR: <socket> not
found` and exits non-zero.

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CURL_CMD` | `pvcurl` | HTTP client to use. Falls back to `curl` if `pvcurl` is not on `PATH`. |
| `CURL_ARGS` | `-s -w '\n%{http_code}' --connect-timeout 5 --max-time 240` | Overrides the default curl argument set. |

### Exit codes

`pvcontrol` reports API errors through its exit code (the response body is
printed to stderr):

| Code | Meaning |
|------|---------|
| `0` | Success (HTTP 200). |
| `48` | Not enough disk space available. |
| `60` | Object has bad checksum. |
| `70` | State verification failed. |
| `255` | Any other non-200 response. |

> Because errors surface only through the exit code, assert HTTP status codes
> with raw `pvcurl -w '%{http_code}'` when you need to distinguish, e.g., 404
> from 422.

The examples below are run from inside a container on the device — a shell
obtained over SSH, `pventer`, or a service's own startup script. `pvcontrol`
finds the pv-ctrl socket automatically (see above), so no socket path is needed
in the common case.

A few examples drop down to raw `pvcurl` for endpoints `pvcontrol` does not
wrap (drivers) or to read HTTP status codes directly. Those call the socket
explicitly, e.g. `pvcurl --unix-socket /pantavisor/pv-ctrl ...`.

---

## Status and inspection

### Containers

```bash
# Short form: list containers in the current revision
pvcontrol ls

# Full lifecycle view with status, group, restart policy, roles
pvcontrol containers ls
```

Each container entry carries `name`, `group`, `status` (and `status_goal`),
`restart_policy`, `roles`, and `user_stopped`. Example output (JSON, one entry
per container):

```json
[{"name":"pv-example-app","group":"root","status":"STARTED","status_goal":"STARTED","restart_policy":"container","roles":["mgmt"],"user_stopped":"false"},
 {"name":"pv-example-norole","group":"root","status":"STARTED","status_goal":"STARTED","restart_policy":"container","roles":[],"user_stopped":"false"}]
```

### Groups

```bash
pvcontrol groups ls
```

Lists container groups with their aggregate status. Example output:

```json
[{"name":"root","status_goal":"STARTED","restart_policy":"container","status":"READY"}]
```

### Build info

```bash
pvcontrol buildinfo
```

Plain-text build manifest. May be empty on some builds.

### Configuration

```bash
pvcontrol config ls    # legacy /config — aliased key names
pvcontrol conf ls      # full /config2 — complete configuration object
```

Both return the active Pantavisor configuration. `conf ls` returns an array of
`{key, value, modified}` records (the `modified` field shows where the value
came from — `default`, a config file, etc.); `config ls` returns a flat object
with aliased dotted keys:

```json
// pvcontrol conf ls
[{"key":"PH_CREDS_HOST","value":"api.pantahub.com","modified":"ph conf file"},
 {"key":"PH_CREDS_PORT","value":"443","modified":"ph conf file"}]

// pvcontrol config ls
{"creds.host":"api.pantahub.com","creds.port":443,"metadata.usrmeta.interval":5,"updater.interval":60}
```

See [pantavisor-configuration.md](pantavisor-configuration.md) for the key
reference.

### xconnect graph

```bash
pvcontrol graph ls
```

Returns the current xconnect service-mesh graph (providers/consumers and the
links between them). See [pantavisor-xconnect.md](pantavisor-xconnect.md).

---

## Metadata

Device metadata is reported by the device; user metadata is set by the
operator. Both support `ls`, `save`, and `delete`.

```bash
# Device metadata
pvcontrol devmeta ls
pvcontrol devmeta save my-key "my-value"     # create or update
pvcontrol devmeta delete my-key

# User metadata
pvcontrol usrmeta ls
pvcontrol usrmeta save my-key "my-value"
pvcontrol usrmeta delete my-key
```

`save` with the same key overwrites the existing value. Deleting a
non-existent key returns HTTP 404 (exit code 255). See
[pantavisor-metadata.md](pantavisor-metadata.md).

A user-metadata round-trip looks like:

```console
$ pvcontrol usrmeta save greeting "hello world"
$ pvcontrol usrmeta ls
{"greeting":"hello world"}
$ pvcontrol usrmeta delete greeting
$ pvcontrol usrmeta ls
{}
```

Device metadata is auto-populated by Pantavisor — `devmeta ls` returns keys
such as `pantavisor.arch`, `pantavisor.revision`, `pantavisor.mode`,
`storage`, `interfaces`, and `sysinfo` in addition to anything saved.

---

## Container lifecycle

```bash
pvcontrol containers start <name>
pvcontrol containers stop <name>
pvcontrol containers restart <name>
```

Only containers whose restart policy is `container` can be controlled through
this API — containers under the default `system` policy cannot be stopped or
started via the lifecycle endpoints. See
[containers.md#restart-policy](../overview/containers.md#restart-policy).

```bash
# Stop a container, then start it again
pvcontrol containers stop my-app
pvcontrol containers ls | grep my-app     # STOPPED
pvcontrol containers start my-app
```

---

## Daemons

Managed daemons (e.g. `pv-xconnect`) exposed through the REST API.

```bash
pvcontrol daemons ls                  # name, pid, respawn for each daemon
pvcontrol daemons start <name>
pvcontrol daemons stop <name>
pvcontrol daemons restart <name>      # stop then start
```

Each entry carries `name`, `pid`, and `respawn`. Example output:

```json
[{"name":"hwrngd","pid":0,"respawn":true},{"name":"pv-xconnect","pid":161,"respawn":true}]
```

Stopping a daemon sets `respawn: false` and zeroes its `pid`; starting it again
sets `respawn: true` and a live `pid`. An unknown daemon name returns HTTP 404
("Daemon not found").

```bash
pvcontrol daemons stop pv-xconnect
sleep 2; pvcontrol daemons ls     # pv-xconnect gone, respawn false
pvcontrol daemons start pv-xconnect
```

---

## Signals

Status signals a container sends to Pantavisor. The `/signal` endpoint is the
one non-management endpoint — it does not require management-socket access.

```bash
pvcontrol signal ready    # container has finished starting
pvcontrol signal alive    # liveness/watchdog heartbeat
```

> Signals issued from a platform container (e.g. pvr-sdk) may return HTTP 500
> because that caller is not ready-gated; this is expected. `alive` is not a
> supported signal type on all builds.

---

## Commands

`pvcontrol cmd <subcommand>` drives the Pantavisor state machine via
`POST /commands`.

```bash
# Run / commit a locally installed revision
pvcontrol cmd run        locals/<rev>      # run an installed step
pvcontrol cmd run-commit locals/<rev>      # run and commit an installed step

# Power
pvcontrol cmd reboot   "optional message"
pvcontrol cmd poweroff "optional message"

# Maintenance
pvcontrol cmd run-gc                       # run the garbage collector now
pvcontrol cmd make-factory [revision]      # mark revision factory (unclaimed devices); current if omitted

# SSH (until next reboot, ignoring config)
pvcontrol cmd enable-ssh
pvcontrol cmd disable-ssh

# Remote / debug
pvcontrol cmd go-remote                    # go remote from a locals/ revision (if config allows)
pvcontrol cmd defer-reboot <new_timeout>   # defer a pending debug-shell reboot
```

`run-gc` may return HTTP 503 with a `Retry-After` header if a GC cycle is
already in progress.

> **`poweroff`/`reboot` are destructive.** They stop all containers and bring
> the device down.

---

## Objects

Content-addressed blobs in the object store, keyed by SHA256.

`objects ls` returns an array of `{sha256, size}` records:

```json
[{"sha256":"27be710f4b7780f844ee3bdf63348a6f8ee282a718dc6641266fbde3ab0bdfb3","size":"71"},
 {"sha256":"9e06ba6fc490b38f95695654eb6ba6936c5c0092f5b3f9e6c39ec6d3709447da","size":"8646656"}]
```

A file upload / download round-trip (a successful `put` prints nothing and
exits 0):

```console
$ echo "hello pvcontrol" > /tmp/o.txt
$ SHA=$(sha256sum /tmp/o.txt | awk '{print $1}')
$ pvcontrol objects put /tmp/o.txt "$SHA"
$ pvcontrol objects get "$SHA"          # raw body to stdout
hello pvcontrol
$ pvcontrol -f /tmp/out.bin objects get "$SHA"   # ... or to a file
```

Notes:

- Uploads are chunked, so large objects stream without buffering the whole file.
- The store is **content-verified**: a `put` whose bytes do not match the
  supplied SHA256 is rejected with HTTP 422 (exit code 60) and not stored.
- `put` is **idempotent** — re-uploading an object that already exists is a
  no-op 200.
- `get` writes the raw body. Use `-f <path>` to save it; without `-f` it goes
  to stdout.

#### Streaming an object from stdin

Instead of a file path, `objects put` accepts a path of the form `-<size>`: a
literal dash immediately followed by the object's byte count. This reads the
object body from stdin and sends it with `Content-Length: <size>` — useful for
piping objects in without staging them to a file first.

The size is **required**: a bare `-` sends an empty `Content-Length` and fails.

```bash
SHA=$(sha256sum /tmp/file.bin | awk '{print $1}')
SIZE=$(stat -c%s /tmp/file.bin)

# Redirect a file into stdin
pvcontrol objects put -"$SIZE" "$SHA" < /tmp/file.bin

# Or pipe from another command (size must still match the bytes produced)
cat /tmp/file.bin | pvcontrol objects put -"$SIZE" "$SHA"
```

---

## Steps (revisions)

Steps are revisions of device state. See
[revisions.md](../overview/revisions.md) and
[pantavisor-state-format-v2.md](pantavisor-state-format-v2.md).

```bash
pvcontrol steps ls                              # list revisions on the device
pvcontrol steps get current                     # state.json of the running revision
pvcontrol steps get 0                           # state.json of revision 0
pvcontrol steps show-progress current           # update progress (status: DONE/...)

# Save state.json straight into a new local revision (with commit message)
pvcontrol -f /tmp/state.json steps get current
pvcontrol -m "my change" steps put /tmp/state.json locals/my-rev

# Install a packaged .tgz step (json + objects/) as a local revision
pvcontrol -m "install build" steps install /tmp/step.tgz locals/my-rev
```

`steps ls` returns one record per revision, each embedding its `progress`;
`show-progress` returns just the progress object:

```json
// pvcontrol steps ls   (after a steps put created locals/my-rev)
[{"name":"0","date":"2026-05-26T10:00:50Z","commitmsg":"","progress":{"status":"DONE","status-msg":"Factory revision","progress":100,"retries":0}},
 {"name":"locals/my-rev","date":"2026-06-08T16:18:18Z","commitmsg":"my change","progress":{"status":"NEW","status-msg":"Update ready to be run","progress":0,"retries":0}}]

// pvcontrol steps show-progress current
{"status":"DONE","status-msg":"Factory revision","progress":100,"retries":0}
```

`steps install` unpacks the tarball (which must contain a `json` file and an
`objects/` directory), uploads any objects the device is missing, then
registers the state under the given `locals/<rev>` name (auto-generating a name
from the tarball SHA if `<rev>` is omitted). `steps put` uploads a bare
`state.json` only. The `-m` message is attached via the
`/steps/{name}/commitmsg` endpoint on success.

#### Streaming a state from stdin

`steps put` accepts `-` as the path, passing `--upload-file -` to the HTTP
client so the state JSON is read from stdin.

> **Backend caveat.** Unlike `objects put`, this form carries no explicit size.
> The bundled `pvcurl` backend cannot determine the length of a stdin stream,
> so it sends an empty `Content-Length` and the server rejects the body with
> HTTP 422. The stdin form therefore only works when real `curl` is the backend
> (`CURL_CMD=curl`, which uses chunked transfer encoding). With `pvcurl` —
> the default on appengine/device images — write the state to a file first and
> pass the path:
>
> ```bash
> pvcontrol steps get current > /tmp/state.json
> # ... edit /tmp/state.json ...
> pvcontrol -m "my change" steps put /tmp/state.json locals/my-rev
> ```
>
> With a `curl` backend the pipe form works directly:
>
> ```bash
> CURL_CMD=curl pvcontrol steps get current \
>     | CURL_CMD=curl pvcontrol -m "patched" steps put - locals/my-rev
> ```

`steps install` has no stdin form — it must be given a `.tgz` file path because
it unpacks the archive on disk.

To activate an installed local revision, follow with `pvcontrol cmd run` /
`run-commit`.

---

## Drivers

`pvcontrol` does not wrap the `/drivers` endpoints; use raw `pvcurl`:

```bash
SOCK=/pantavisor/pv-ctrl   # or the socket pvcontrol auto-detects on your device

# driver state for the caller's platform
pvcurl --unix-socket "$SOCK" http://localhost/drivers
# load / unload all drivers for the caller's platform
pvcurl --unix-socket "$SOCK" -X PUT http://localhost/drivers/load
pvcurl --unix-socket "$SOCK" -X PUT http://localhost/drivers/unload
```

On a platform without managed drivers these are effectively no-ops returning
200.

---

## Command-to-endpoint reference

| `pvcontrol` command | HTTP | Endpoint |
|---------------------|------|----------|
| `ls` / `containers ls` | GET | `/containers` |
| `containers start\|stop\|restart <name>` | PUT | `/containers/{name}` |
| `groups ls` | GET | `/groups` |
| `daemons ls` | GET | `/daemons` |
| `daemons start\|stop\|restart <name>` | PUT | `/daemons/{name}` |
| `graph ls` | GET | `/xconnect-graph` |
| `signal ready\|alive` | POST | `/signal` |
| `cmd <subcommand>` | POST | `/commands` |
| `devmeta ls` | GET | `/device-meta` |
| `devmeta save\|delete <key>` | PUT / DELETE | `/device-meta/{key}` |
| `usrmeta ls` | GET | `/user-meta` |
| `usrmeta save\|delete <key>` | PUT / DELETE | `/user-meta/{key}` |
| `buildinfo` | GET | `/buildinfo` |
| `config ls` | GET | `/config` |
| `conf ls` | GET | `/config2` |
| `objects ls` | GET | `/objects` |
| `objects get\|put <sha>` | GET / PUT | `/objects/{sha}` |
| `steps ls` | GET | `/steps` |
| `steps get\|show-progress <rev>` | GET | `/steps/{rev}` / `/steps/{rev}/progress` |
| `steps put\|install <path> <rev>` | PUT | `/steps/{rev}` (+ `/commitmsg`) |

For the authoritative endpoint contracts (request/response shapes, status
codes, management-socket requirements), see
[pantavisor-commands.md](pantavisor-commands.md).

# Pantavisor Tools

On-device CLI tools shipped with Pantavisor for development, debugging, and container control.

## pventer

Enter a running container's namespaces.

```bash
pventer -c <container-name> [CMD ...]
```

Without a command, drops into the container's default shell. With a command, executes it inside the container's namespace. Uses `fallbear-cmd` under the hood via LXC paths.

```bash
# Drop into a shell inside the container
pventer -c my-app

# Run a command inside the container
pventer -c my-app ps aux
```

## pvcurl

Lightweight HTTP client for the Pantavisor control socket. Drop-in replacement for `curl` in environments where curl is not available. Uses `nc` to send HTTP/1.0 requests over a Unix socket.

```bash
pvcurl --unix-socket <socket-path> [OPTIONS] <endpoint>
```

Socket paths (tried in order by pvcontrol):
- `/run/pantavisor/pv/pv-ctrl` — appengine / embedded mode
- `/pv/pv-ctrl` — alternative embedded path
- `/pantavisor/pv-ctrl` — default inside containers

```bash
# Query buildinfo
pvcurl --unix-socket /run/pantavisor/pv/pv-ctrl /buildinfo

# List running daemons
pvcurl --unix-socket /run/pantavisor/pv/pv-ctrl /daemons

# Send a signal to a container
pvcurl -X PUT --unix-socket /run/pantavisor/pv/pv-ctrl /signal \
    --data '{"name":"my-app","signal":15}'
```

Supports `-X`, `-H`, `--data`, `--upload-file`, `-s`, `-i`, `-v`, `-o`, `-w`, `--connect-timeout`.

## pvcontrol

Shell wrapper around `pvcurl` for common control operations. Prefers `curl` if available, falls back to `pvcurl`.

```bash
pvcontrol [-s <socket-path>] <command> [arguments]
```

### Key commands

```bash
# Container and group status
pvcontrol ls                         # list containers in current revision
pvcontrol containers ls              # list containers with status
pvcontrol containers start <name>
pvcontrol containers stop <name>
pvcontrol containers restart <name>
pvcontrol groups ls                  # list container groups

# xconnect service mesh
pvcontrol graph ls                   # show current xconnect service graph

# Daemon status (REST API daemons)
pvcontrol daemons ls                 # list managed daemons
pvcontrol daemons get <name>

# Status signals (sent by a container to signal readiness)
pvcontrol signal ready               # signal container is ready
pvcontrol signal alive               # signal container is alive (watchdog)

# System commands
pvcontrol cmd reboot [message]
pvcontrol cmd poweroff [message]
pvcontrol cmd run-gc                 # trigger garbage collection
pvcontrol cmd enable-ssh             # start SSH server until next reboot

# Metadata
pvcontrol devmeta ls
pvcontrol devmeta save <key> <value>
pvcontrol usrmeta ls

# Build info
pvcontrol buildinfo
```

## pvtx

Transaction tool for creating, modifying, and deploying Pantavisor system state revisions. Operates on JSON state documents that describe the desired system configuration (services, BSP, configs), with atomic commit and rollback via the pv-ctrl daemon.

### Transaction commands

```bash
pvtx begin <base> [object]
pvtx add <file> | -
pvtx remove <part>
pvtx abort
pvtx commit
pvtx show
pvtx deploy <directory>
```

| Command | Description |
|---------|-------------|
| `begin <base> [object]` | Start a new transaction. `base` is a revision hash, `current`, or `empty`. Omit `object` for a remote transaction (synced via pv-ctrl); provide a path for a local transaction written to disk. |
| `add <file> \| -` | Add a JSON or tarball (`.json`, `.tar`, `.tar.gz`, `.tgz`, `.bz2`) to the current transaction. Use `-` to read from stdin. |
| `remove <part>` | Remove a part from the revision. `part` can be a name (`nginx`), a signature path (`_sigs/nginx.json`), or a config path (`_config/nginx`). |
| `abort` | Discard the current transaction and clean up state. |
| `commit` | Commit a remote transaction to pv-ctrl; prints the new revision hash. |
| `show` | Print the current transaction state as JSON to stdout. |
| `deploy <directory>` | Write a local transaction to disk (creates `.pvr/json`, `.pvr/config`, `bsp/run.json`). |

### Queue commands

Queue mode builds an ordered sequence of operations, then applies them as a single transaction.

```bash
pvtx queue new <queue> <object>
pvtx queue remove <part>
pvtx queue unpack <tarball> | -
pvtx queue process [base] [queue] [object]
```

| Command | Description |
|---------|-------------|
| `queue new <queue> <object>` | Initialize a new queue at `<queue>`, saving objects at `<object>`. |
| `queue remove <part>` | Enqueue a remove operation for `<part>`. |
| `queue unpack <tarball> \| -` | Enqueue an unpack step for the given tarball (or stdin). |
| `queue process [base] [queue] [object]` | Execute the queue against `base` revision (`current` by default). |

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PVTXDIR` | `/var/pvr-sdk/pvtx` | Temp directory for transaction state |
| `PVTX_OBJECT_BUF_SIZE` | — | Buffer size for saving objects (512B–10M) |
| `PVTX_CTRL_BUF_SIZE` | — | Buffer size for pv-ctrl I/O (16K–10M) |

Socket paths (auto-detected): `/pv/pv-ctrl` (container root) or `/pantavisor/pv-ctrl` (inside containers).

```bash
# Remote transaction: modify current revision and commit
pvtx begin current
pvtx add /path/to/package.tar.gz
pvtx remove nginx
pvtx show
pvtx commit

# Local transaction: build a state on disk
pvtx begin empty /tmp/objects
cat package.tgz | pvtx add -
pvtx deploy /deploy/path

# Queue-based workflow: batch operations, then apply
pvtx queue new /tmp/queue /tmp/objects
pvtx queue remove nginx
pvtx queue unpack /path/to/package.tgz
pvtx begin empty
pvtx queue process
pvtx show
```

# Pantavisor Tools

Command-line tools for interacting with the Pantavisor control socket (`pv-ctrl`). These tools are built into the `pantavisor-tools` sub-package and are available inside appengine and minimal images.

## pvcurl

A lightweight shell script wrapping `nc` for HTTP-over-Unix-socket communication. Preferred inside appengine and minimal images where standard `curl` is not available.

### Flags

| Flag | Description |
|------|-------------|
| `--unix-socket <path>` | Unix socket path (required) |
| `-X <method>` | HTTP method (default: `GET`) |
| `-H` / `--header <header>` | Add a custom request header (repeatable) |
| `--data <body>` | Request body string |
| `--upload-file <path>` / `-T <path>` | Upload file as request body |
| `--connect-timeout <s>` | Connection timeout in seconds (default: `5`) |
| `-s` / `--silent` | Suppress error messages |
| `-v` / `--verbose` | Print request/response details to stderr |
| `-o <path>` / `--output <path>` | Write response body to file |
| `-i` / `--include` | Include response headers in output |
| `-w <fmt>` / `--write-out <fmt>` | Print formatted output after response (supports `%{http_code}`) |

### Examples

```sh
# Query build info
pvcurl --unix-socket /run/pantavisor/pv/pv-ctrl http://localhost/buildinfo

# Stop a daemon
pvcurl -X PUT --data '{"action":"stop"}' \
    --unix-socket /run/pantavisor/pv/pv-ctrl \
    http://localhost/daemons/pv-xconnect

# Check HTTP status code only
pvcurl -s -w '%{http_code}' \
    --unix-socket /run/pantavisor/pv/pv-ctrl \
    http://localhost/containers
```

---

## pvcontrol

A high-level CLI wrapper around `pvcurl` (or `curl` if available) for common Pantavisor control operations.

Socket auto-detection order:
1. `/run/pantavisor/pv/pv-ctrl` (initramfs path)
2. `/pv/pv-ctrl`
3. `/pantavisor/pv-ctrl` (standard container path)

Override with `-s <path>`.

### Options

| Option | Description |
|--------|-------------|
| `-s <path>` | Override socket path |
| `-f <path>` | Write output to file instead of stdout |
| `-m <message>` | Commit message (used with `steps install` and `steps put`) |
| `-v` | Verbose output |

### Commands

#### Container lifecycle

```sh
pvcontrol ls                         # list containers in current revision
pvcontrol container start <name>
pvcontrol container stop <name>
pvcontrol container restart <name>
```

#### Groups

```sh
pvcontrol groups ls
```

#### Signals

```sh
pvcontrol signal ready    # notify Pantavisor this container is ready
pvcontrol signal alive    # send keepalive heartbeat
```

#### System commands

```sh
pvcontrol cmd reboot [message]
pvcontrol cmd poweroff [message]
pvcontrol cmd run-gc
pvcontrol cmd enable-ssh
pvcontrol cmd disable-ssh
pvcontrol cmd go-remote
pvcontrol cmd run <locals/revision>
pvcontrol cmd run-commit <locals/revision>
pvcontrol cmd make-factory [revision]
pvcontrol cmd defer-reboot <timeout>
```

#### Metadata

```sh
pvcontrol devmeta ls
pvcontrol devmeta save <key> [value]
pvcontrol devmeta delete <key>

pvcontrol usrmeta ls
pvcontrol usrmeta save <key> [value]
pvcontrol usrmeta delete <key>
```

#### Build info

```sh
pvcontrol buildinfo
```

#### Objects

```sh
pvcontrol objects ls
pvcontrol objects get <sha>
pvcontrol objects put <path> <sha>
```

#### Steps (revisions)

```sh
pvcontrol steps ls
pvcontrol steps get <revision>
pvcontrol steps put <path> <revision>
pvcontrol steps install <path.tgz> [revision]
pvcontrol steps show-progress <revision>
```

#### Configuration

```sh
pvcontrol conf ls
```

#### xconnect graph

```sh
pvcontrol graph ls    # show current xconnect service graph
```

#### Daemons

```sh
pvcontrol daemons ls
pvcontrol daemons start <name>
pvcontrol daemons stop <name>
pvcontrol daemons restart <name>
```

### Examples

```sh
# List running containers
pvcontrol ls

# Restart xconnect daemon
pvcontrol daemons restart pv-xconnect

# Show xconnect service graph
pvcontrol graph ls

# Reboot the device with a message
pvcontrol cmd reboot "scheduled maintenance"

# Save device metadata
pvcontrol devmeta save firmware-version 1.2.3
```

# Pantavisor Log Sockets

The Pantavisor logging system uses two Unix sockets for inter-process log management: `pv-ctrl-log` for receiving direct log messages and `pv-fd-log` for subscribing file descriptors to be polled by Pantavisor.

## pv-ctrl-log

This socket is used by applications and containers to send log messages directly to the Pantavisor Log Server. All messages must follow the `logserver_msg` structure:

```C
struct logserver_msg {
    int code; // Protocol code: 0 for LEGACY, 256 for CMD
    int len;  // Length of the following buffer
    char buf[0]; // Log data buffer
};
```

### Legacy Protocol (code = 0)

The `buf` contains the log metadata and message, separated by null terminators (`\0`):

```
level\0platform\0source\0data
```

* **level**: Log level as a string (e.g., "3" for INFO).
* **platform**: Name of the container or "pantavisor".
* **source**: The specific source of the log (e.g., a process name or module).
* **data**: The actual log message content.

The supported log levels are:
* `0`: FATAL
* `1`: ERROR
* `2`: WARN
* `3`: INFO
* `4`: DEBUG
* `5`: ALL

## pv-fd-log

This socket allows containers to delegate the polling of their file descriptors (e.g., pipes, sockets, or open files) to Pantavisor.

### Subscription Protocol

To subscribe or unsubscribe a file descriptor, you must use the `sendmsg` system call with `SCM_RIGHTS` to pass the file descriptor.

The `msghdr` must contain an `iovec` array with 4 elements:

| iov Index | Type | Max Length | Description |
|-----------|------|------------|-------------|
| `iov[0]` | string | 50 bytes | Platform name (container name) |
| `iov[1]` | string | 50 bytes | Source name (e.g., "stdout", "syslog") |
| `iov[2]` | int | 4 bytes | Log level for the messages from this FD |
| `iov[3]` | int | 4 bytes | Action: `1` to subscribe, `0` to unsubscribe |

#### Subscribe
- Send the file descriptor using `SCM_RIGHTS`.
- Set `iov[3]` to `1`.
- Pantavisor will poll this FD and create a corresponding log file at `/storage/logs/current/<platform>/<source>`.

#### Unsubscribe
- Set `iov[3]` to `0`.
- The file descriptor passed in `SCM_RIGHTS` can be `-1`.
- Pantavisor will stop polling and close its internal reference to the FD for that platform/source pair.

!!! Note
    Only one file descriptor can be subscribed per platform-source pair. Subscribing a new FD for an existing pair will replace the previous one.

# pvcm-run — Per-MCU Runtime Process

pvcm-run is the Linux-side runtime for each MCU container in
Pantavisor. One instance runs per MCU, started by the `pv_pvcm`
plugin inside a mount namespace. From xconnect's perspective,
pvcm-run IS the container.

## Architecture

```
pantavisor
  └── pv_pvcm plugin (start)
      └── fork pvcm-run in namespace
          ├── opens UART or RPMsg transport to MCU
          ├── PVCM protocol: handshake, heartbeat, log forwarding
          ├── HTTP bridge: MCU ↔ Linux service requests
          ├── creates service sockets for xconnect injection
          └── reports health via exit code / pipe

xconnect sees pvcm-run as a normal container (init_pid + namespace)
```

## PVCM Protocol

Binary framed protocol over UART or RPMsg:

```
Frame: [ 0xAA | 0x55 | len 2B LE | payload | crc32 4B LE ]
```

Key opcodes:
- **HELLO/HELLO_RESP** (0x01/0x02) — handshake
- **HEARTBEAT** (0x10) — health monitoring, every 5s
- **LOG** (0x28) — MCU log forwarding
- **HTTP_REQ/DATA/END** (0x30-0x32) — chunked HTTP gateway
- **FW_UPDATE_START/DATA/END** (0x20-0x22) — firmware update

See `protocol/pvcm_protocol.h` for the complete wire format.

## HTTP Gateway

pvcm-run bridges HTTP between MCU and Linux:

**MCU as client** (MCU calls Linux services):
```
MCU: pvcm_get("/sensor/config")
  → HTTP_REQ frame → pvcm-run → HTTP GET http://service/sensor/config
  ← HTTP response   ← pvcm-run ← HTTP_REQ(RESPONSE) + DATA + END
```

**MCU as server** (Linux calls MCU):
```
Linux: curl http://proxy:18081/sensor/temperature
  → pvcm-run → HTTP_REQ(INVOKE) + END → MCU handler
  ← HTTP response ← pvcm-run ← HTTP_REQ(REPLY) + DATA + END
```

## Files

```
pvcm-run/
├── main.c               entry point, transport selection, session setup
├── pvcm_config.h/c      run.json parser
├── pvcm_transport.h      transport abstraction
├── pvcm_transport_uart.c UART: tty, baudrate, frame encode/decode, CRC32
├── pvcm_protocol.h/c    protocol handler: handshake, heartbeat, dispatch
├── pvcm_bridge.h/c      HTTP bridge: outbound + inbound + listener
└── test/
    ├── test_http_server.py   test HTTP server for bridge testing
    └── run-native-test.sh    test runner script
```

## Building

pvcm-run is built as part of pantavisor when `PANTAVISOR_PVCM=ON`:

```cmake
if(PANTAVISOR_PVCM)
    add_subdirectory(pvcm-run)
endif()
```

For host testing (against native_sim Zephyr binary):

```bash
gcc -o pvcm-run-test \
    pvcm-run/main.c pvcm-run/pvcm_config.c \
    pvcm-run/pvcm_transport_uart.c pvcm-run/pvcm_protocol.c \
    pvcm-run/pvcm_bridge.c \
    -I. -lpthread
```

## Testing

See `TESTPLAN-pvcm.md` in meta-pantavisor for the full test plan
using the Zephyr native_sim_64 board.

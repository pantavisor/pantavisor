# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Pantavisor is a Linux device init system that turns the runtime into containerized microservices. It's a pure C project designed for embedded devices, using LXC for container functionality. The project is built as a single binary to minimize footprint (~1MB compressed).

## Build Commands

```bash
# Standard build (out-of-source recommended)
mkdir build && cd build
cmake ..
make

# Common CMake options
cmake -DPANTAVISOR_DEBUG=ON ..           # Enable debug features
cmake -DPANTAVISOR_APPENGINE=ON ..       # Build for running inside existing OS
cmake -DPANTAVISOR_DM_VERITY=ON ..       # Enable dm-verity support
cmake -DPANTAVISOR_DM_CRYPT=ON ..        # Enable dm-crypt support
cmake -DPANTAVISOR_TESTS=ON ..           # Build test binaries
cmake -DPANTAVISOR_CLANG_FORMAT_CHECK=ON .. # Enable format checking on build

# Format code
make format

# Run tests
ctest
# Or directly run pvtx tests:
./test/pvtx/pvtx.sh <source_dir> <build_dir>
```

## Architecture

### Init Modes
Pantavisor supports three init modes (`init_mode_t` in config.h):
- **IM_EMBEDDED**: Default mode, runs as PID 1 (init system)
- **IM_STANDALONE**: Debugging mode without main loop
- **IM_APPENGINE**: Runs inside an existing OS as an application

### Core Components

**State Management** (`state.c/h`, `pv_state`):
- Central structure holding device state including BSP, platforms, volumes, objects
- Supports two state formats: SPEC_MULTI1 and SPEC_SYSTEM1
- State is declarative JSON format managed via Pantavisor CLI

**Platforms** (`platforms.c/h`, `pv_platform`):
- Represents individual containers/services
- Lifecycle states: NONE → INSTALLED → MOUNTED → STARTING → STARTED → READY → STOPPING → STOPPED
- Each platform has associated drivers, configs, and logging

**Bootloader Support** (`bootloader.c/h`):
- Multiple bootloader types: u-boot (plain/pvk/ab), GRUB, Raspberry Pi AB
- Handles boot variable management and A/B partition schemes

**Control Interface** (`ctrl/`):
- REST-like API exposed via Unix socket
- Endpoints for containers, objects, config, signals, uploads/downloads
- Located at `/var/run/pv/control` (by default)

**Update System** (`update/`, `updater.c`):
- Atomic updates with progress tracking
- Connects to Pantacor Hub for OTA updates
- Handles object downloads, verification, and state transitions

### Key Subsystems

- **plugins/**: Container runtime plugins (LXC support via `pv_lxc.c`)
- **logserver/**: Multiple log output backends (file tree, single file, stdout, update logs)
- **parser/**: State JSON parsing for different spec versions
- **pantahub/**: Cloud connectivity to Pantacor Hub
- **disk/**: Storage management including zram, dm-crypt, volumes
- **pvtx/**: Transaction tool for state manipulation (separate binary)

### Logging Pattern
Each source file defines its own module name and uses the vlog macro:
```c
#define MODULE_NAME "mymodule"
#define pv_log(level, msg, ...) \
    vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#include "log.h"
```

## Code Style

- Linux kernel-style formatting (`.clang-format` in repo)
- Run `make format` to auto-format or use `-DPANTAVISOR_CLANG_FORMAT_CHECK=ON`
- Use tabs for indentation
- Function braces on new line, control statement braces on same line

## Key Dependencies

- liblxc: Container runtime
- mbedtls: TLS/crypto
- libevent: Event loop
- thttp: HTTP client library
- picohttpparser: HTTP parsing
- zlib: Compression

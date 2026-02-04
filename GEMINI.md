# feature/wasm-engine

This branch adds support for WasmEdge integration and the `pv-xconnect` service mesh architecture.

## Architecture & Vision

- **pv-xconnect**: A standalone mediation service for cross-container and host-to-container communication.
  - Detailed design in [xconnect/XCONNECT.md](xconnect/XCONNECT.md).
- **WasmEdge Engine**: Evolving the Wasm support from a simple CLI wrapper to a C API-based host function system.
  - **Goal**: Allow Wasm apps to reach container services (D-Bus, REST) via mediated host functions.

## Service Broker Concept

Beyond WasmEdge, Pantavisor acts as a **Security Broker** for all container types (LXC, runc, Wasm):
- **Decoupling**: Containers use logical service names.
- **Security**: Isolation by default; access granted only via explicit `run.json` requirements.
- **Consistency**: Unified high-level APIs across all runtimes.
# pv-xconnect: Pantavisor Cross-Connect Service

To manage container-to-container and container-to-host interactions efficiently, a dedicated process called `pv-xconnect` handles the mediation logic via on-demand plugins. It runs as a single-threaded process driven by `libevent`.

## Architecture

### Core Process Responsibilities
- **Discovery & Reconciliation**: Consumes an `xconnect-graph` from Pantavisor's `pv-ctrl` socket and maintains the state of active connects.
- **Plumbing Helpers**: Provides a "Toolbox" of namespace-aware helpers (e.g., `inject_unix_socket`, `inject_devnode`) so plugins don't have to manage low-level `setns()` logic.
- **Security**: Acts as the single point of truth for role-based access control.

### Plugin-Driven Injection
Plugins are responsible for triggering the resource injection into the container. This ensures that the specific needs of a protocol (e.g., a Wayland socket vs. a DRM device node) are handled correctly.

1.  **Reconciliation**: Core identifies a new connect and loads the required plugin.
2.  **Setup**: Core calls `plugin->on_link_added(link)`.
3.  **Injection**: The plugin calls a core helper to plant the virtual resource (socket/device) inside the consumer's namespace.
4.  **Mediation**: The plugin attaches the resulting File Descriptors to the shared `libevent` base for data processing.

## Service Manifests

### Exports (`services.json`)
A file within a container (e.g., `services.json`) that declares what services it provides.

#### Example `services.json` (Provider):
```json
[
  {
    "name": "network-manager",
    "type": "rest",
    "socket": "/run/network-manager/api.sock"
  },
  {
    "name": "system-bus",
    "type": "dbus",
    "socket": "/run/dbus/system_bus_socket"
  }
]
```

### Arguments (`args.json`)
For containers that consume services, requirements are defined in `args.json` during the container creation process (e.g., with `pvr app add --arg-json args.json`). These arguments are then rendered into the final `run.json` manifest.

#### Example `args.json` (Consumer):
```json
{
  "PV_SERVICES_REQUIRED": [
    {
      "name": "network-manager",
      "target": "/run/nm/api.sock"
    }
  ],
  "PV_SERVICES_OPTIONAL": [
    {
      "name": "system-bus",
      "interface": "org.freedesktop.NetworkManager"
    }
  ]
}
```

### Requirements (`run.json`)
A container requests access to services in its `run.json` manifest.

#### Example Requirement in `run.json` (Consumer):
```json
{
  "#spec": "service-manifest-run@1",
  "name": "my-app",
  "services": {
    "required": [
      {
        "name": "network-manager",
        "role": "admin",
        "target": "/run/nm/api.sock"
      }
    ],
    "optional": [
      {
        "name": "system-bus",
        "interface": "org.freedesktop.NetworkManager"
      }
    ]
  },
  "type": "lxc"
}
```

## Mediation Patterns

### REST
- **Mechanism**: Identity-injected HTTP over UDS.
- **Injection**: Injects `X-PV-Client` and `X-PV-Role` headers into the first request.

### D-Bus
- **Mechanism**: Policy-aware proxy for the system/session bus.
- **Filtering**: Access is restricted to specific D-Bus Names and Interfaces declared in `run.json`.

### Raw Unix Sockets
- **Identity**: Handled via Greeting Packets, SCM_CREDENTIALS, or Role-Based Socket mapping.
- **High-Performance**: Supports FD passing (SCM_RIGHTS) and Shared Memory handles.

### DRM / Graphics
- **Master Role**: Inject `/dev/dri/cardX` for display servers (KMS access).
- **Render Role**: Inject `/dev/dri/renderDX` for accelerated apps.
- **Wayland**: Mediates the Wayland protocol for isolated UI rendering.

## Build & Integration

- **CMake Flag**: `PANTAVISOR_XCONNECT`
- **Binary**: `pv-xconnect` is installed to `/usr/bin/`.
- **Dependencies**: `libevent`, `libevent_pthreads`, `dl`.

## Testing

> **Note:** The testing instructions below assume you are working within the
> `meta-pantavisor` layer with pantavisor source code in the devtool workspace
> (`build/workspace/sources/pantavisor`).

### DRM Plugin Testing with VKMS

The DRM plugin can be tested on development machines using VKMS (Virtual Kernel Mode Setting), a software-only DRM driver included in the Linux kernel.

#### Loading VKMS

```bash
# Load the VKMS kernel module
sudo modprobe vkms

# Verify the device was created
ls -la /dev/dri/
# Expected output: card0 (or cardN if other DRM devices exist)
```

#### VKMS Limitations

VKMS only creates **card nodes** (`/dev/dri/cardX`), not **render nodes** (`/dev/dri/renderDX`). This is by design:

| Device Type | VKMS Support | Use Case |
|-------------|--------------|----------|
| `/dev/dri/card0` | ✅ Yes | KMS/display access (modesetting) |
| `/dev/dri/renderD128` | ❌ No | GPU compute/rendering |

The VKMS driver deliberately omits the `DRIVER_RENDER` capability because it has no actual GPU rendering hardware. A kernel patch proposing render node support was rejected with the reasoning: "devices without render capabilities should not fake it."

#### What VKMS Tests

With VKMS, you can validate:
- Device node injection via `mknod` into consumer namespaces
- Major/minor number preservation (226:0 for card0)
- Namespace switching (`setns`) works correctly
- Permission setting on injected devices

#### Testing Render Nodes

To test render node injection (`/dev/dri/renderDX`), you need:
- **Real GPU hardware** (Intel, AMD, NVIDIA with appropriate drivers)
- **virtio-gpu** in a VM with virgl enabled
- **Raspberry Pi** with VC4/V3D driver (creates both card and render nodes)

### DRM Test Containers

The meta-pantavisor layer provides example containers for testing:

| Recipe | Purpose | Service Required |
|--------|---------|------------------|
| `pv-example-drm-provider` | Exports DRM devices | N/A (provider) |
| `pv-example-drm-master` | Tests card0 injection | `drm-master` |
| `pv-example-drm-render` | Tests renderD128 injection | `drm-render` |

#### Provider Configuration (`services.json`)
```json
[
  {"name": "drm-master", "type": "drm", "socket": "/dev/dri/card0"},
  {"name": "drm-render", "type": "drm", "socket": "/dev/dri/renderD128"}
]
```

#### Consumer Configuration (`args.json`)
```json
{
  "PV_SERVICES_REQUIRED": [
    {"name": "drm-master", "target": "/dev/dri/card0"}
  ]
}
```

### Running DRM Tests in Appengine

> **Note:** See `meta-pantavisor/GEMINI.md` for complete appengine testing documentation.

#### 1. Build Appengine and Test Containers

```bash
cd /path/to/meta-pantavisor

# Build appengine with xconnect enabled
./kas-container build .github/configs/release/docker-x86_64-scarthgap.yaml:kas/with-workspace.yaml

# Build DRM example containers
./kas-container build .github/configs/release/docker-x86_64-scarthgap.yaml:kas/with-workspace.yaml \
    --target pv-example-drm-provider --target pv-example-drm-master
```

#### 2. Load Docker Image and VKMS

```bash
# Load the appengine docker image
docker load < build/tmp-scarthgap/deploy/images/docker-x86_64/pantavisor-appengine-docker.tar

# Load VKMS on host (provides /dev/dri/card0)
sudo modprobe vkms
ls -la /dev/dri/
```

#### 3. Prepare pvrexport Directory

```bash
mkdir -p pvtx.d
cp build/tmp-scarthgap/deploy/images/docker-x86_64/pv-example-drm-provider.pvrexport.tgz pvtx.d/
cp build/tmp-scarthgap/deploy/images/docker-x86_64/pv-example-drm-master.pvrexport.tgz pvtx.d/
```

#### 4. Run Appengine with DRM Access

```bash
# Start with fresh state
docker rm -f pva-test 2>/dev/null
docker volume rm storage-test 2>/dev/null

# Run appengine with DRM device passthrough
docker run --name pva-test -d --privileged \
    --device /dev/dri:/dev/dri \
    -v $(pwd)/pvtx.d:/usr/lib/pantavisor/pvtx.d \
    -v storage-test:/var/pantavisor/storage \
    --entrypoint /bin/sh pantavisor-appengine:1.0 -c "sleep infinity"

# Start pv-appengine and wait for READY
docker exec pva-test sh -c 'pv-appengine &'
sleep 10
docker exec pva-test grep "status is now READY" /run/pantavisor/pv/logs/0/pantavisor/pantavisor.log
```

#### 5. Test DRM Injection

```bash
# Check containers are running
docker exec pva-test lxc-ls -f

# Run pv-xconnect and observe DRM injection
docker exec pva-test stdbuf -oL timeout 10 /usr/bin/pv-xconnect 2>&1
```

Expected output:
```
pvx-drm: Injected device /dev/dri/card0 -> /dev/dri/card0 (consumer pid X, dev 226:0)
```

#### 6. Verify Injection

```bash
# Get consumer container PID
docker exec pva-test lxc-info -n pv-example-drm-master -p

# Check device exists in consumer namespace (replace PID)
docker exec pva-test ls -la /proc/<PID>/root/dev/dri/
```

#### Cleanup

```bash
docker rm -f pva-test
docker volume rm storage-test
```

### Hardware Testing Checklist

Full validation requires testing on real hardware:

- [ ] **Raspberry Pi 4/5**: VC4/V3D driver (card0 + renderD128)
- [ ] **x86 with Intel GPU**: i915 driver
- [ ] **x86 with AMD GPU**: amdgpu driver
- [ ] **ARM SoC boards**: Various Mali, Adreno drivers

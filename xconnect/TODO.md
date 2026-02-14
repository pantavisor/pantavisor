# pv-xconnect TODO

## Hardware Testing Required

### DRM Plugin - Raspberry Pi Testing

The DRM plugin has been tested with VKMS (virtual KMS) which only provides card nodes.
Full validation requires testing on real hardware:

- [ ] **Raspberry Pi 4/5** - VC4/V3D driver provides both:
  - `/dev/dri/card0` (KMS) - display output
  - `/dev/dri/card1` (V3D) - 3D acceleration
  - `/dev/dri/renderD128` - render node for GPU compute

#### Test Cases for Raspberry Pi

1. **drm-master service**: Inject card0 to a display server container
2. **drm-render service**: Inject renderD128 to a GPU compute container
3. **Multi-consumer**: Multiple containers sharing render node access
4. **Hot-plug**: Device injection after container is already running

#### Build for Raspberry Pi

```bash
# Use the release config for Raspberry Pi with workspace overlay
kas-container build \
    .github/configs/release/raspberrypi-armv8-scarthgap.yaml:kas/with-workspace.yaml
```

### Other Hardware Targets

- [ ] x86 with Intel GPU (i915 driver)
- [ ] x86 with AMD GPU (amdgpu driver)
- [ ] i.MX8 boards (etnaviv driver)
- [ ] Rockchip boards (panfrost driver)

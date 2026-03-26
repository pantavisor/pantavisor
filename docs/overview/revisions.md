---
nav_order: 2
---
# Revisions

A revision is composed by a [BSP](bsp.md) (Pantavisor binary, Linux kernel, modules and firmware) plus a number of [containers](containers.md).

In order to make revisions reproducible, they can be defined in a state JSON. This JSON is a flat representation of a set of either binary objects or other inline JSON documents. Here you can take a look at a simple example revision formed by just a BSP and a container named _awconnect_:

```
{
  "#spec": "pantavisor-service-system@1",
  "_hostconfig/pvr/docker.json": {
    "platforms": [
      "linux/arm64",
      "linux/arm"
    ]
  },
  "awconnect/lxc.container.conf": "153d58588b0327f73c8424c214c039fcdd975814bc075bc5c72f82fd3cdfd7b6",
  "awconnect/root.squashfs": "e1ddabe573021b48dd5d66d59593d94fbc57b7a2f85dac59628959ae6955d2e2",
  "awconnect/root.squashfs.docker-digest": "828054813b64d71d26756903010a52828941f6bb0859e878cb70f6f1e0ec7d2d",
  "awconnect/run.json": {
    "#spec": "service-manifest-run@1",
    "config": "lxc.container.conf",
    "name": "awconnect",
    "root-volume": "root.squashfs",
    "storage": {
      "docker--etc-NetworkManager-system-connections": {
        "persistence": "permanent"
      },
      "lxc-overlay": {
        "persistence": "boot"
      }
    },
    "type": "lxc",
    "volumes": []
  },
  "awconnect/src.json": {
    "#spec": "service-manifest-src@1",
    "docker_config": {
      "AttachStderr": false,
      "AttachStdin": false,
      "AttachStdout": false,
      "Cmd": [
        "/lib/systemd/systemd"
      ],
      "Domainname": "",
      "Env": [
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
      ],
      "Hostname": "",
      "Image": "sha256:a8c4da0f0bde245a971a4a63a205cf56e071611f78b3d650715f309b7cefc57b",
      "OpenStdin": false,
      "StdinOnce": false,
      "Tty": false,
      "User": "",
      "Volumes": {
        "/etc/NetworkManager/system-connections/": {}
      },
      "WorkingDir": "/opt/wifi-connect/"
    },
    "docker_digest": "registry.gitlab.com/pantacor/pv-platforms/wifi-connect@sha256:b2ad073c0a41d186b6338fb8b81714eb1b8da9421383bbf8914fb86a01bbcafb",
    "docker_name": "registry.gitlab.com/pantacor/pv-platforms/wifi-connect",
    "docker_source": "remote,local",
    "docker_tag": "arm32v5",
    "persistence": {},
    "template": "builtin-lxc-docker"
  },
  "bsp/addon-plymouth.cpio.xz4": "beae6a7bb235916cac52bcfece64c30615cded8c4c640e6941e7ecabe53b4920",
  "bsp/build.json": {
    "altrepogroups": "",
    "branch": "master",
    "commit": "e2a4911eb35de2032e85f74c8f239de81c6f622b",
    "gitdescribe": "014-rc14-18-ge2a4911",
    "pipeline": "436189414",
    "platform": "rpi64",
    "project": "pantacor/pv-manifest",
    "pvrversion": "pvr version 026-52-gbf3bd5d6",
    "target": "arm-rpi64",
    "time": "2021-12-24 01:25:27 +0000"
  },
  "bsp/firmware.squashfs": "f37e9699ea8add7042e2843d095e68a316e6344d832b74d41244cb0bca29464e",
  "bsp/kernel.img": "990f8b0fcab8b99f631497753cc55b70f6f522a1d91cd4ae0777a7747b98509e",
  "bsp/modules.squashfs": "0e202a7ee3a575bc502ec3869251a3587a3110079f221fc15c63da1e8d8a08ae",
  "bsp/pantavisor": "1e6561f75cba98500f023e09aae430557fe0d1b02aeb1fa9adb3c2d3b6d250c6",
  "bsp/run.json": {
    "addons": [
      "addon-plymouth.cpio.xz4"
    ],
    "firmware": "firmware.squashfs",
    "initrd": "pantavisor",
    "initrd_config": "",
    "linux": "kernel.img",
    "modules": "modules.squashfs"
  },
  "bsp/src.json": {
    "#spec": "bsp-manifest-src@1",
    "pvr": "https://pvr.pantahub.com/pantahub-ci/arm_rpi64_bsp_latest#bsp"
  }
}
```

To know more about this, you can take a look at our [state JSON reference](pantavisor-state-format-v2.md).

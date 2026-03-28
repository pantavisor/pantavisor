/*
 * PVCM Shell — two-channel RPMsg firmware.
 *
 * Channel 0 (ttyRPMSG0): Zephyr debug shell
 * Channel 1 (ttyRPMSG1): PVCM protocol (heartbeat, HTTP gateway)
 *
 * Based on zephyr/samples/subsys/ipc/openamp_rsc_table.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <string.h>
#include <stdio.h>

#include <zephyr/drivers/ipm.h>

#include <openamp/open_amp.h>
#include <metal/device.h>
#include <resource_table.h>

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(pvcm_main, LOG_LEVEL_DBG);

#include <pantavisor/pvcm.h>
#include <pantavisor/pvcm_protocol.h>
#include "shell_rpmsg.h"

/* PVCM transport hooks (from pvcm_transport_rpmsg.c) */
extern int pvcm_rpmsg_rx_cb(struct rpmsg_endpoint *ept, void *data,
			    size_t len, uint32_t src, void *priv);
extern void pvcm_rpmsg_set_endpoint(struct rpmsg_endpoint *ept);

#define SHM_DEVICE_NAME	"shm"

#if !DT_HAS_CHOSEN(zephyr_ipc_shm)
#error "Requires 'zephyr,ipc-shm' in chosen"
#endif

#define SHM_NODE	DT_CHOSEN(zephyr_ipc_shm)
#define SHM_START_ADDR	DT_REG_ADDR(SHM_NODE)
#define SHM_SIZE	DT_REG_SIZE(SHM_NODE)

#define APP_TASK_STACK_SIZE (1024)

K_THREAD_STACK_DEFINE(thread_mng_stack, APP_TASK_STACK_SIZE);

static struct k_thread thread_mng_data;

static const struct device *const ipm_handle =
	DEVICE_DT_GET(DT_CHOSEN(zephyr_ipc));

static metal_phys_addr_t shm_physmap = SHM_START_ADDR;

struct metal_device shm_device = {
	.name = SHM_DEVICE_NAME,
	.num_regions = 2,
	.regions = {
		{.virt = NULL}, /* shared memory */
		{.virt = NULL}, /* rsc_table memory */
	},
	.node = { NULL },
	.irq_num = 0,
	.irq_info = NULL
};

static struct metal_io_region *shm_io;
static struct rpmsg_virtio_shm_pool shpool;
static struct metal_io_region *rsc_io;
static struct rpmsg_virtio_device rvdev;

static void *rsc_table;
static struct rpmsg_device *rpdev;

/* protocol channel endpoint */
static struct rpmsg_endpoint proto_ept;

static K_SEM_DEFINE(data_sem, 0, 1);

static void platform_ipm_callback(const struct device *dev, void *context,
				  uint32_t id, volatile void *data)
{
	k_sem_give(&data_sem);
}

static void receive_message(void)
{
	/*
	 * Poll with short timeout instead of blocking forever.
	 * The Linux→M7 MU kick (TYPE_TX) can time out if the M7
	 * doesn't read MU RR[1] quickly enough. By polling, we
	 * process vring data even when the kick notification is lost.
	 */
	/* Poll with short timeout — the MU kick from Linux can fail
	 * with ETIME, so we must poll the vring periodically */
	k_sem_take(&data_sem, K_MSEC(50));
	rproc_virtio_notified(rvdev.vdev, VRING1_ID);
}

static void new_service_cb(struct rpmsg_device *rdev, const char *name,
			   uint32_t src)
{
	LOG_ERR("unexpected ns service: %s", name);
}

/*
 * Linux DTB: tx = <&mu 0 1>, rx = <&mu 1 1>
 * With DATA_SIZE_4, ipm_send id=N writes to MU_B TR[N].
 * Must use id=1 to reach Linux's RX at MU register index 1.
 */
#define MU_TX_IPM_ID 1

int mailbox_notify(void *priv, uint32_t id)
{
	ARG_UNUSED(priv);
	ipm_send(ipm_handle, 0, MU_TX_IPM_ID, NULL, 0);
	return 0;
}

int platform_init(void)
{
	void *rsc_tab_addr;
	int rsc_size;
	struct metal_device *device;
	struct metal_init_params metal_params = METAL_INIT_DEFAULTS;
	int status;

	/*
	 * Zero shared memory to clear stale vrings from any previous run.
	 */
	memset((void *)SHM_START_ADDR, 0, SHM_SIZE);

	status = metal_init(&metal_params);
	if (status) {
		LOG_ERR("metal_init failed: %d", status);
		return -1;
	}

	status = metal_register_generic_device(&shm_device);
	if (status) {
		LOG_ERR("metal_register failed: %d", status);
		return -1;
	}

	status = metal_device_open("generic", SHM_DEVICE_NAME, &device);
	if (status) {
		LOG_ERR("metal_device_open failed: %d", status);
		return -1;
	}

	metal_io_init(&device->regions[0], (void *)SHM_START_ADDR, &shm_physmap,
		      SHM_SIZE, -1, 0, NULL);
	shm_io = metal_device_io_region(device, 0);
	if (!shm_io) {
		LOG_ERR("failed to get shm_io");
		return -1;
	}

	rsc_table_get(&rsc_tab_addr, &rsc_size);
	rsc_table = (struct st_resource_table *)rsc_tab_addr;

	metal_io_init(&device->regions[1], rsc_table,
		      (metal_phys_addr_t *)rsc_table, rsc_size, -1, 0, NULL);
	rsc_io = metal_device_io_region(device, 1);
	if (!rsc_io) {
		LOG_ERR("failed to get rsc_io");
		return -1;
	}

	if (!device_is_ready(ipm_handle)) {
		LOG_ERR("IPM device not ready");
		return -1;
	}

	ipm_register_callback(ipm_handle, platform_ipm_callback, NULL);

	status = ipm_set_enabled(ipm_handle, 1);
	if (status) {
		LOG_ERR("ipm_set_enabled failed: %d", status);
		return -1;
	}

	return 0;
}

struct rpmsg_device *
platform_create_rpmsg_vdev(void)
{
	struct fw_rsc_vdev_vring *vring_rsc;
	struct virtio_device *vdev;
	int ret;

	vdev = rproc_virtio_create_vdev(VIRTIO_DEV_DEVICE, VDEV_ID,
					rsc_table_to_vdev(rsc_table),
					rsc_io, NULL, mailbox_notify, NULL);
	if (!vdev) {
		LOG_ERR("failed to create vdev");
		return NULL;
	}

	rproc_virtio_wait_remote_ready(vdev);

	vring_rsc = rsc_table_get_vring0(rsc_table);
	ret = rproc_virtio_init_vring(vdev, 0, vring_rsc->notifyid,
				      (void *)vring_rsc->da, rsc_io,
				      vring_rsc->num, vring_rsc->align);
	if (ret) {
		LOG_ERR("failed to init vring 0: %d", ret);
		goto failed;
	}

	vring_rsc = rsc_table_get_vring1(rsc_table);
	ret = rproc_virtio_init_vring(vdev, 1, vring_rsc->notifyid,
				      (void *)vring_rsc->da, rsc_io,
				      vring_rsc->num, vring_rsc->align);
	if (ret) {
		LOG_ERR("failed to init vring 1: %d", ret);
		goto failed;
	}

	rpmsg_virtio_init_shm_pool(&shpool, NULL, SHM_SIZE);
	ret = rpmsg_init_vdev(&rvdev, vdev, new_service_cb, shm_io, &shpool);
	if (ret) {
		LOG_ERR("rpmsg_init_vdev failed: %d", ret);
		goto failed;
	}

	return rpmsg_virtio_get_rpmsg_device(&rvdev);

failed:
	rproc_virtio_remove_vdev(vdev);
	return NULL;
}

void rpmsg_mng_task(void *arg1, void *arg2, void *arg3)
{
	ARG_UNUSED(arg1);
	ARG_UNUSED(arg2);
	ARG_UNUSED(arg3);

	printk("PVCM RPMsg init starting\n");

	if (platform_init()) {
		LOG_ERR("platform_init failed");
		return;
	}

	rpdev = platform_create_rpmsg_vdev();
	if (!rpdev) {
		LOG_ERR("create_rpmsg_vdev failed");
		return;
	}

	/* Channel 0: debug shell over RPMsg */
	extern struct shell_transport shell_transport_rpmsg;
	int ret = shell_rpmsg_set_rpdev(&shell_transport_rpmsg, rpdev);
	if (ret) {
		LOG_ERR("shell_rpmsg_set_rpdev failed: %d", ret);
	}

	/* Channel 1: PVCM protocol — uses pvcm_rpmsg_rx_cb from transport */
	ret = rpmsg_create_ept(&proto_ept, rpdev, "rpmsg-tty",
			       RPMSG_ADDR_ANY, RPMSG_ADDR_ANY,
			       pvcm_rpmsg_rx_cb, NULL);
	if (ret) {
		LOG_ERR("failed to create protocol endpoint: %d", ret);
	} else {
		pvcm_rpmsg_set_endpoint(&proto_ept);
		printk("PVCM protocol channel ready\n");
	}

	printk("PVCM RPMsg ready — entering receive loop\n");
	while (1) {
		receive_message();
	}
}

#ifdef CONFIG_PANTAVISOR_BRIDGE
/*
 * MCU HTTP server handler — serves sensor data to Linux containers.
 * Linux sends: curl http://localhost:18081/sensor
 * pvcm-proxy forwards to MCU, MCU responds with JSON.
 */
static void sensor_handler(uint8_t method, const char *path,
			   const char *headers, const char *body,
			   size_t body_len, void *ctx)
{
	printk("[mcu-server] method=%d path=%s\n", method, path);

	extern uint8_t pvcm_get_invoke_stream_id(void);
	uint8_t sid = pvcm_get_invoke_stream_id();

	if (method == PVCM_HTTP_GET) {
		const char *resp =
			"{\"temperature\":22.4,\"humidity\":65,\"uptime_ms\":"
			;
		char full_resp[128];
		snprintf(full_resp, sizeof(full_resp),
			 "%s%u}", resp, (unsigned)k_uptime_get_32());
		pvcm_http_respond(sid, 200,
				  "Content-Type: application/json\r\n",
				  full_resp, strlen(full_resp));
	} else {
		const char *resp = "{\"ok\":true}";
		pvcm_http_respond(sid, 200,
				  "Content-Type: application/json\r\n",
				  resp, strlen(resp));
	}
}
#endif /* CONFIG_PANTAVISOR_BRIDGE */

int main(void)
{
	printk("PVCM Shell starting — 2 channels (shell + protocol)\n");

#ifdef CONFIG_PANTAVISOR_BRIDGE
	pvcm_http_serve("/sensor", sensor_handler, NULL);
	printk("MCU HTTP server: /sensor registered\n");
#endif

	k_thread_create(&thread_mng_data, thread_mng_stack, APP_TASK_STACK_SIZE,
			rpmsg_mng_task,
			NULL, NULL, NULL, K_PRIO_COOP(8), 0, K_NO_WAIT);
	return 0;
}

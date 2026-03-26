/*
 * PVCM RPMsg Transport -- Zephyr side
 *
 * Uses OpenAMP rpmsg over remoteproc for communication with the
 * A53 Linux host. Creates an "rpmsg-tty" endpoint so Linux's
 * rpmsg_tty driver creates /dev/ttyRPMSG0.
 *
 * Based on zephyr/samples/subsys/ipc/openamp_rsc_table.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <pantavisor/pvcm_transport.h>
#include <pantavisor/pvcm_protocol.h>

#ifdef CONFIG_OPENAMP
#include <openamp/open_amp.h>
#include <metal/device.h>
#include <resource_table.h>
#include <zephyr/drivers/ipm.h>

LOG_MODULE_REGISTER(pvcm_rpmsg, CONFIG_LOG_DEFAULT_LEVEL);

#define SHM_DEVICE_NAME "shm"

#if !DT_HAS_CHOSEN(zephyr_ipc_shm)
#error "pvcm rpmsg transport requires 'zephyr,ipc-shm' in chosen"
#endif

#define SHM_NODE	DT_CHOSEN(zephyr_ipc_shm)
#define SHM_START_ADDR	DT_REG_ADDR(SHM_NODE)
#define SHM_SIZE	DT_REG_SIZE(SHM_NODE)

/* rx ring buffer */
#define RPMSG_RX_BUFSZ 2048
static uint8_t rx_buf[RPMSG_RX_BUFSZ];
static size_t rx_len;
static K_SEM_DEFINE(rx_sem, 0, 1);
static K_SEM_DEFINE(kick_sem, 0, 1);

static const struct device *const ipm_handle =
	DEVICE_DT_GET(DT_CHOSEN(zephyr_ipc));

static metal_phys_addr_t shm_physmap = SHM_START_ADDR;

static struct metal_device shm_device = {
	.name = SHM_DEVICE_NAME,
	.num_regions = 2,
	.regions = {
		{.virt = NULL}, /* shared memory */
		{.virt = NULL}, /* rsc_table memory */
	},
	.node = {NULL},
	.irq_num = 0,
	.irq_info = NULL
};

static struct metal_io_region *shm_io;
static struct metal_io_region *rsc_io;
static struct rpmsg_virtio_shm_pool shpool;
static struct rpmsg_virtio_device rvdev;
static struct rpmsg_device *rpdev;
static struct rpmsg_endpoint tty_ept;
static bool ep_ready;

/* IPM (mailbox) callback — kick from Linux */
static void ipm_callback(const struct device *dev, void *context,
			  uint32_t id, volatile void *data)
{
	k_sem_give(&kick_sem);
}

/* RPMsg endpoint rx callback */
static int rpmsg_rx_cb(struct rpmsg_endpoint *ept, void *data,
		       size_t len, uint32_t src, void *priv)
{
	ARG_UNUSED(ept);
	ARG_UNUSED(src);
	ARG_UNUSED(priv);

	if (len > RPMSG_RX_BUFSZ) {
		LOG_ERR("rpmsg frame too large: %zu", len);
		return RPMSG_ERR_BUFF_SIZE;
	}

	memcpy(rx_buf, data, len);
	rx_len = len;
	k_sem_give(&rx_sem);

	return RPMSG_SUCCESS;
}

/* namespace service callback (unused — we create endpoints ourselves) */
static void ns_bind_cb(struct rpmsg_device *rdev, const char *name,
		       uint32_t dest)
{
	LOG_INF("ns bind: %s -> %u", name, dest);
}

/* mailbox notify — kick Linux */
static int mailbox_notify(void *priv, uint32_t id)
{
	ARG_UNUSED(priv);
	ipm_send(ipm_handle, 0, id, NULL, 0);
	return 0;
}

/* management thread — pumps virtio rx */
static K_THREAD_STACK_DEFINE(mng_stack, 1024);
static struct k_thread mng_thread;

static void rpmsg_mng_task(void *arg1, void *arg2, void *arg3)
{
	ARG_UNUSED(arg1);
	ARG_UNUSED(arg2);
	ARG_UNUSED(arg3);

	while (1) {
		k_sem_take(&kick_sem, K_FOREVER);
		rproc_virtio_notified(rvdev.vdev, VRING1_ID);
	}
}

static int rpmsg_init(void)
{
	struct metal_init_params metal_params = METAL_INIT_DEFAULTS;
	struct metal_device *device;
	void *rsc_tab_addr;
	int rsc_size;
	int ret;

	LOG_INF("PVCM RPMsg transport initializing");

	/* init libmetal */
	ret = metal_init(&metal_params);
	if (ret) {
		LOG_ERR("metal_init failed: %d", ret);
		return -1;
	}

	/* register shared memory device */
	ret = metal_register_generic_device(&shm_device);
	if (ret) {
		LOG_ERR("metal_register_generic_device failed: %d", ret);
		return -1;
	}

	ret = metal_device_open("generic", SHM_DEVICE_NAME, &device);
	if (ret) {
		LOG_ERR("metal_device_open failed: %d", ret);
		return -1;
	}

	/* shared memory IO region */
	metal_io_init(&device->regions[0], (void *)SHM_START_ADDR,
		      &shm_physmap, SHM_SIZE, -1, 0, NULL);
	shm_io = metal_device_io_region(device, 0);
	if (!shm_io) {
		LOG_ERR("failed to get shm_io");
		return -1;
	}

	/* resource table IO region */
	rsc_table_get(&rsc_tab_addr, &rsc_size);
	metal_io_init(&device->regions[1], rsc_tab_addr,
		      (metal_phys_addr_t *)rsc_tab_addr,
		      rsc_size, -1, 0, NULL);
	rsc_io = metal_device_io_region(device, 1);
	if (!rsc_io) {
		LOG_ERR("failed to get rsc_io");
		return -1;
	}

	/* setup IPM (mailbox) */
	if (!device_is_ready(ipm_handle)) {
		LOG_ERR("IPM device not ready");
		return -1;
	}
	ipm_register_callback(ipm_handle, ipm_callback, NULL);
	ipm_set_enabled(ipm_handle, 1);

	/* create virtio device */
	struct virtio_device *vdev;
	vdev = rproc_virtio_create_vdev(VIRTIO_DEV_DEVICE, VDEV_ID,
					rsc_table_to_vdev(rsc_tab_addr),
					rsc_io, NULL, mailbox_notify, NULL);
	if (!vdev) {
		LOG_ERR("failed to create vdev");
		return -1;
	}

	/* wait for Linux to be ready */
	LOG_INF("waiting for Linux rpmsg master...");
	rproc_virtio_wait_remote_ready(vdev);
	LOG_INF("Linux rpmsg master ready");

	/* init vrings */
	struct fw_rsc_vdev_vring *vring_rsc;

	vring_rsc = rsc_table_get_vring0(rsc_tab_addr);
	ret = rproc_virtio_init_vring(vdev, 0, vring_rsc->notifyid,
				      (void *)vring_rsc->da, rsc_io,
				      vring_rsc->num, vring_rsc->align);
	if (ret) {
		LOG_ERR("failed to init vring0: %d", ret);
		return -1;
	}

	vring_rsc = rsc_table_get_vring1(rsc_tab_addr);
	ret = rproc_virtio_init_vring(vdev, 1, vring_rsc->notifyid,
				      (void *)vring_rsc->da, rsc_io,
				      vring_rsc->num, vring_rsc->align);
	if (ret) {
		LOG_ERR("failed to init vring1: %d", ret);
		return -1;
	}

	/* init rpmsg device */
	rpmsg_virtio_init_shm_pool(&shpool, NULL, SHM_SIZE);
	ret = rpmsg_init_vdev(&rvdev, vdev, ns_bind_cb, shm_io, &shpool);
	if (ret) {
		LOG_ERR("rpmsg_init_vdev failed: %d", ret);
		return -1;
	}

	rpdev = rpmsg_virtio_get_rpmsg_device(&rvdev);

	/* create "rpmsg-tty" endpoint — triggers ttyRPMSG0 on Linux */
	ret = rpmsg_create_ept(&tty_ept, rpdev, "rpmsg-tty",
			       RPMSG_ADDR_ANY, RPMSG_ADDR_ANY,
			       rpmsg_rx_cb, NULL);
	if (ret) {
		LOG_ERR("rpmsg_create_ept failed: %d", ret);
		return -1;
	}

	ep_ready = true;
	LOG_INF("PVCM RPMsg transport ready (endpoint 'rpmsg-tty')");

	/* start management thread to pump virtio rx */
	k_thread_create(&mng_thread, mng_stack, K_THREAD_STACK_SIZEOF(mng_stack),
			rpmsg_mng_task, NULL, NULL, NULL,
			K_PRIO_COOP(8), 0, K_NO_WAIT);

	return 0;
}

static int rpmsg_send_frame(const void *payload, size_t len)
{
	if (!ep_ready) {
		LOG_ERR("rpmsg endpoint not ready");
		return -1;
	}

	/* build frame: sync + len + payload + crc32 */
	uint8_t frame[4 + len + 4];
	frame[0] = PVCM_SYNC_BYTE_0;
	frame[1] = PVCM_SYNC_BYTE_1;
	frame[2] = len & 0xFF;
	frame[3] = (len >> 8) & 0xFF;
	memcpy(&frame[4], payload, len);

	uint32_t crc = pvcm_crc32(payload, len);
	frame[4 + len + 0] = crc & 0xFF;
	frame[4 + len + 1] = (crc >> 8) & 0xFF;
	frame[4 + len + 2] = (crc >> 16) & 0xFF;
	frame[4 + len + 3] = (crc >> 24) & 0xFF;

	int ret = rpmsg_send(&tty_ept, frame, 4 + len + 4);
	if (ret < 0) {
		LOG_ERR("rpmsg_send failed: %d", ret);
		return ret;
	}

	return 0;
}

static int rpmsg_recv_frame(void *payload, size_t max_len, int timeout_ms)
{
	if (k_sem_take(&rx_sem, K_MSEC(timeout_ms)) != 0)
		return -2; /* timeout */

	/* parse frame from rx_buf: skip sync + len header */
	if (rx_len < 8) { /* min: 4 header + 0 payload + 4 crc */
		LOG_ERR("rpmsg frame too short: %zu", rx_len);
		return -1;
	}

	if (rx_buf[0] != PVCM_SYNC_BYTE_0 || rx_buf[1] != PVCM_SYNC_BYTE_1) {
		LOG_ERR("rpmsg frame sync mismatch");
		return -1;
	}

	uint16_t plen = rx_buf[2] | (rx_buf[3] << 8);
	if (plen > max_len || (size_t)(4 + plen + 4) > rx_len) {
		LOG_ERR("rpmsg frame length mismatch");
		return -1;
	}

	/* verify CRC */
	uint32_t recv_crc = rx_buf[4 + plen] |
			    (rx_buf[4 + plen + 1] << 8) |
			    (rx_buf[4 + plen + 2] << 16) |
			    (rx_buf[4 + plen + 3] << 24);
	uint32_t calc_crc = pvcm_crc32(&rx_buf[4], plen);

	if (recv_crc != calc_crc) {
		LOG_ERR("rpmsg CRC mismatch: %08x vs %08x",
			recv_crc, calc_crc);
		return -1;
	}

	memcpy(payload, &rx_buf[4], plen);
	return (int)plen;
}

static const struct pvcm_transport rpmsg_transport = {
	.init = rpmsg_init,
	.send_frame = rpmsg_send_frame,
	.recv_frame = rpmsg_recv_frame,
};

/* init thread — runs the blocking OpenAMP init sequence */
static K_THREAD_STACK_DEFINE(init_stack, 2048);
static struct k_thread init_thread;

static void rpmsg_init_thread(void *arg1, void *arg2, void *arg3)
{
	ARG_UNUSED(arg1);
	ARG_UNUSED(arg2);
	ARG_UNUSED(arg3);

	int ret = rpmsg_init();
	if (ret) {
		LOG_ERR("rpmsg_init failed: %d", ret);
	}
}

/* auto-start init thread at APPLICATION level */
static int pvcm_rpmsg_sys_init(void)
{
	k_thread_create(&init_thread, init_stack,
			K_THREAD_STACK_SIZEOF(init_stack),
			rpmsg_init_thread, NULL, NULL, NULL,
			K_PRIO_COOP(7), 0, K_NO_WAIT);
	return 0;
}

SYS_INIT(pvcm_rpmsg_sys_init, APPLICATION, CONFIG_APPLICATION_INIT_PRIORITY);

#endif /* CONFIG_OPENAMP */

#ifdef CONFIG_PANTAVISOR_TRANSPORT_RPMSG
const struct pvcm_transport *pvcm_transport_get(void)
{
#ifdef CONFIG_OPENAMP
	return &rpmsg_transport;
#else
	return NULL;
#endif
}
#endif

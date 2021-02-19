/*
 * Copyright (c) 2018-2021 Pantacor Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#define MODULE_NAME             "device"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "device.h"

#include "init.h"

int pv_device_capture_logs_activated(struct pantavisor *pv)
{
	if (pv && pv->config)
		return pv->config->log.capture;

	// default
	return true;
}

bool pv_device_use_updater_tmp_objects(struct pantavisor *pv)
{
	if (pv && pv->config)
		return pv->config->updater.use_tmp_objects;

	// default
	return true;
}

int pv_device_get_gc_reserved(struct pantavisor *pv)
{
	if (pv && pv->config)
		return pv->config->storage.gc.reserved;

	return 0;
}

int pv_device_get_gc_threshold(struct pantavisor *pv)
{
	if (pv && pv->config)
		return pv->config->storage.gc.threshold;

	return 0;
}

static int pv_device_init(struct pv_init *this)
{
	struct pantavisor *pv = NULL;
	struct pantavisor_config *config = NULL;
	char tmp[256];
	int fd = -1;

	pv = get_pv_instance();
	if (!pv || !pv->config)
		return -1;
	config = pv->config;
	// create hints
	fd = open("/pv/challenge", O_CREAT | O_SYNC | O_WRONLY, 0444);
	close(fd);
	fd = open("/pv/device-id", O_CREAT | O_SYNC | O_WRONLY, 0444);
	if (strcmp(config->creds.prn, "") == 0) {
		pv->flags |= DEVICE_UNCLAIMED;
	} else {
		sprintf(tmp, "%s\n", config->creds.id);
		write(fd, tmp, strlen(tmp));
	}
	close(fd);
	fd = open("/pv/pantahub-host", O_CREAT | O_SYNC | O_WRONLY, 0444);
	sprintf(tmp, "https://%s:%d\n", config->creds.host, config->creds.port);
	write(fd, tmp, strlen(tmp));
	close(fd);

	pv->dev = calloc(1, sizeof(struct pv_device));
	if (pv->dev) {
		pv->dev->id = strdup(pv->config->creds.id);
		if (!pv->dev->id) {
			free(pv->dev);
			pv->dev = NULL;
		}
	}
	if (pv_cmd_socket_open(pv, "/pv/pv-ctrl") < 0)
		pv_log(DEBUG, "control socket initialized fd=%d", pv->ctrl_fd);

	return 0;
}

static void pv_device_free(struct pv_device *dev)
{
	if (!dev)
		return;

	pv_log(DEBUG, "removing device");

	if (dev->id)
		free(dev->id);
	if (dev->nick)
		free(dev->nick);
	if (dev->owner)
		free(dev->owner);
	if (dev->prn)
		free(dev->prn);

	free(dev);
}

void pv_device_remove(struct pantavisor *pv)
{
	pv_device_free(pv->dev);
	pv->dev = NULL;
}

struct pv_init pv_init_device = {
	.init_fn = pv_device_init,
	.flags = 0,
};

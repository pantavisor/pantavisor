/*
 * Copyright (c) 2024 Pantacor Ltd.
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "phlogger_range.h"
#include "phlogger_service.h"
#include "phlogger_json_buffer.h"
#include "phlogger_client.h"
#include "paths.h"
#include "utils/fs.h"

#include <fcntl.h>
#include <linux/limits.h>
#include <stdio.h>

#define MODULE_NAME "phrange"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define PHLOGGER_LINE_DELIM (0x1E)

struct phrange {
	char *buf;
	struct phlogger_client *client;
	struct phlogger_service srv;
};

static int pv_phrange_init(void);
static void pv_phrange_run(void);

struct phrange phrange = {
	.buf = NULL,
	.client = NULL,
	.srv = {
		.name = MODULE_NAME,
		.type = PHLOGGER_SERVICE_ONE_SHOT,
		.pid = -1,
		.flags = 0,
		.rev = NULL,
		.init = pv_phrange_init,
		.proc = pv_phrange_run,
	},
};

static void pv_phrange_run()
{
	char path[PATH_MAX] = { 0 };
	pv_paths_pv_log_plat(path, sizeof(path), phrange.srv.rev,
			     pv_config_get_str(PH_LOG_TMP_FILE));

	FILE *fd = fopen(path, "r");

	if (!fd)
		return;

	if (pv_phlogger_json_buffer_init(&phrange.buf) != 0) {
		pv_log(WARN, "couldn't initialize buffer");
		return;
	}

	char *log = NULL;
	size_t len = 0;
	ssize_t nread = 0;

	bool ok = true;

	while ((nread = getdelim(&log, &len, PHLOGGER_LINE_DELIM, fd)) != -1) {
		int err = 0;
		if (pv_phlogger_json_buffer_need_flush(phrange.buf, nread)) {
			err = pv_phlogger_client_send_logs(phrange.client,
							   phrange.buf);
			if (err != 0)
				pv_log(WARN,
				       "couldn't send logs, some logs could be missing in the cloud");

			pv_phlogger_json_buffer_init(&phrange.buf);
		}

		err = pv_phlogger_json_buffer_add(&phrange.buf, log);

		if (err != 0) {
			pv_log(WARN,
			       "couldn't add data to the buffer, finishing service");

			ok = false;
			goto out;
		}
	}

out:
	if(ok)
		pv_fs_path_remove(path, false);

	fclose(fd);
	free(log);
}

static int pv_phrange_init()
{
	phrange.client = pv_phlogger_client_new();
	if (!phrange.client)
		return -1;
	return 0;
}

void pv_phlogger_range_stop_lenient()
{
	phlogger_service_stop_lenient(&phrange.srv);
}

void pv_phlogger_range_stop_force()
{
	phlogger_service_stop_force(&phrange.srv);
}

void pv_phlogger_range_start(const char *rev)
{
	struct pantavisor *pv = pv_get_instance();
	if (!pv)
		return;

	if (pv_config_get_bool(PV_LOG_PUSH) && pv->remote_mode) {
		if (phlogger_service_start(&phrange.srv, rev) == 0)
			pv_log(DEBUG, "range service started");
	}
}
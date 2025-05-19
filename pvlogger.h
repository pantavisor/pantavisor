/*
 * Copyright (c) 2018-2022 Pantacor Ltd.
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

#ifndef __PV_LOGGER_H_
#define __PV_LOGGER_H_

#include <stdlib.h>
#include <stdbool.h>

#include "utils/list.h"

struct pv_logger_config {
	struct dl_list item_list;
	/*
	 * This is a null terminated list of key/value
	 * pairs for the log configuration.
	 * */
	const char ***pair; /*equiv to char *pair[][2]. key, val*/
	/*
	 * Only when logger config is statically allocated.
	 * Do not use both pair and static_pair.
	 * */
	const char *(*static_pair)[2];
};

struct pv_log_info {
	char *logfile;
	char *name;
	struct dl_list next;
	off_t truncate_size;
	bool islxc;
	pid_t logger_pid;
	const char *(*pv_log_get_config_item)(struct pv_logger_config *config,
					      const char *key);
	struct pv_platform *platform;
};

int start_pvlogger(struct pv_log_info *log_info, const char *platform);

void pv_log_info_free(struct pv_log_info *l);

const char *pv_log_get_config_item(struct pv_logger_config *config,
				   const char *key);
static void pv_logger_config_free(struct pv_logger_config *item_config)
{
	int i = 0;

	if (!item_config)
		return;

	while (item_config->pair[i][0]) {
		if (item_config->pair[i][1])
			free((void *)item_config->pair[i][1]);
		free((void *)item_config->pair[i][0]);
		free((void *)item_config->pair[i]);
		i++;
	}
	/*
	 * We've a NULL terminated pair..
	 * */
	free((void *)item_config->pair[i]);
	free(item_config);
}

struct pv_log_info *pv_new_log(bool islxc, struct pv_logger_config *,
			       const char *name);

/*
 * user.* attributes are available usually for most file systems.
 * user. prefix is hence necessary! Otherwise filesystem(s) complaint
 * of ENOTSUP.
 * */
#define PV_LOGGER_POS_XATTR "trusted.pv.logger.pos"
#define PV_LOGGER_FILE_WAIT_TIMEOUT (1)
#endif /*__PV_LOGGER_H_*/

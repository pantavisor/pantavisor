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

#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <inttypes.h>
#include <stdio.h>
#include <logger.h>
#include <libgen.h>

#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>

#include "pvlogger.h"
#include "platforms.h"
#include "pvctl_utils.h"
#include "json.h"
#include "utils/fs.h"
#include "utils/str.h"
#include "utils/math.h"
#include "paths.h"
#include "logserver/logserver.h"

#define MODULE_NAME "pvlogger"
#include "log.h"

static const char *module_name = MODULE_NAME;

static char *logger_cmd; //Leave some room to create json
static struct log default_log;
struct pv_log_info *pv_log_info = NULL;

#define PV_LOG_BUF_START_OFFSET (0)
#define PV_LOG_BUF_SIZE (4096)

static int logger_pos = PV_LOG_BUF_START_OFFSET;

static const char *pv_logger_get_logfile(struct pv_log_info *log_info)
{
	return log_info->logfile ? log_info->logfile : "/var/log/messages";
}

static void pv_log(int level, char *msg, ...)
{
	char __formatted[PV_LOG_BUF_SIZE + (PV_LOG_BUF_SIZE / 2)];
	int to_write = 0;
	int written = 0;
	int offset = 0;
	va_list args;
	va_start(args, msg);
	vsnprintf(__formatted, sizeof(__formatted), msg, args);
	va_end(args);
	to_write = strlen(__formatted) + 1;

	while (to_write > 0) {
		written = pv_logserver_send_log(
			true, pv_log_info->platform->name,
			(char *)pv_logger_get_logfile(pv_log_info), level,
			"%s\n", __formatted);

		if (written <= 0)
			pv_log(ERROR,
			       "error in pv_logserver_send_log %d from pvlogger",
			       written);

		offset += written;
		to_write -= written;
		if (!written)
			break;
	}
}

static int set_logger_xattr(struct log *log)
{
	off_t pos = ftello(log->backing_file);
	char place_holder[MAX_DEC_STRING_SIZE_OF_TYPE(pos)];
	const char *fname = pv_logger_get_logfile(pv_log_info);

	if (pos < 0)
		return 0;
	SNPRINTF_WTRUNC(place_holder, sizeof(place_holder), "%" PRId64, pos);

	return setxattr(fname, PV_LOGGER_POS_XATTR, place_holder,
			strlen(place_holder), 0);
}

static int pvlogger_flush(struct log *log, char *buf, int buflen)
{
	int ret = 0;

	while (buflen > 0) {
		int avail_buflen = PV_LOG_BUF_SIZE - 1 - logger_pos;
		char *new_line_at = NULL;
		int written = 0;
		int to_write = buflen;

		if (avail_buflen == 0) {
			pv_log(INFO, "%.*s", PV_LOG_BUF_SIZE - 1, logger_cmd);
			logger_pos = PV_LOG_BUF_START_OFFSET;
			avail_buflen = PV_LOG_BUF_SIZE - 1;
			memset(logger_cmd + PV_LOG_BUF_START_OFFSET, 0,
			       PV_LOG_BUF_SIZE - PV_LOG_BUF_START_OFFSET);
		}

		new_line_at = strchr(buf, '\n');
		if (new_line_at)
			to_write = new_line_at - buf;
		else {
			new_line_at = strchr(buf, '\r');
			if (new_line_at)
				to_write = new_line_at - buf;
		}

		if (to_write > avail_buflen) {
			SNPRINTF_WTRUNC(logger_cmd + logger_pos,
					avail_buflen + 1, "%.*s", avail_buflen,
					buf);
			written = avail_buflen;
		} else {
			SNPRINTF_WTRUNC(logger_cmd + logger_pos,
					avail_buflen + 1, "%.*s", to_write,
					buf);
			written = to_write;
		}

		buf += written;
		buflen -= written;
		logger_pos += written;

		if (new_line_at) {
			/*move past the new line.*/
			buf += 1;
			/*move past the new line.*/
			buflen -= 1;
			pv_log(INFO, "%s", logger_cmd);
			memset(logger_cmd + PV_LOG_BUF_START_OFFSET, 0,
			       PV_LOG_BUF_SIZE - PV_LOG_BUF_START_OFFSET);
			logger_pos = PV_LOG_BUF_START_OFFSET;
		}
	}
	ret = set_logger_xattr(log);
	if (ret < 0)
		pv_log(DEBUG, "Setting xattr failed, return code is %d ", ret);
	return 0;
}

static int stop_logger = 0;

static int get_logger_xattr(struct log *log)
{
	off_t stored_pos = 0;
	char buf[32];
	const char *fname = pv_logger_get_logfile(pv_log_info);

	if (getxattr(fname, PV_LOGGER_POS_XATTR, buf, 32) < 0) {
		pv_log(DEBUG, "Attribute %s not present", PV_LOGGER_POS_XATTR);
	} else {
		sscanf(buf, "%" PRId64, &stored_pos);
	}
	return stored_pos;
}

static int pvlogger_start(struct log *log, int was_init_ok)
{
	int log_file_fd = -1;
	off_t stored_pos = 0;
	struct stat st;

	if (was_init_ok != LOG_OK) {
		pv_log(WARN, "Cannot init log file");
		goto out;
	}
	pv_log(INFO, "Started pvlogger\n");
	log_file_fd = fileno(log->backing_file);
	stored_pos = get_logger_xattr(log);
	if (!fstat(log_file_fd, &st)) {
		if (st.st_size < stored_pos)
			stored_pos = 0;
	}
	pv_log(DEBUG, "pvlogger %s seeking to position %" PRId64 "\n",
	       module_name, stored_pos);
	fseek(log->backing_file, stored_pos, SEEK_SET);
out:
	return was_init_ok;
}

/*
 * There's a window where while we're setting up the watch
 * the file has been created and hence no event will come to us.
 * This function should thus be called in a loop.
 * */
static int wait_for_logfile(const char *logfile)
{
	int ret = LOG_NOK;
	const char *filename = NULL;
	struct stat stbuf;
	char *file_dup = NULL;

	if (!logfile) {
		ret = LOG_NOK;
		goto out;
	}

	file_dup = strdup(logfile);

	if (!file_dup) {
		pv_log(WARN,
		       "Memory allocation failed for logfile duplication");
		ret = LOG_NOK;
		goto out;
	}
	filename = basename(file_dup);

	if ((!strlen(filename)) || *filename == '/' || *filename == '.') {
		pv_log(WARN,
		       "Configured log file name %s is not correct"
		       ".\n",
		       logfile);
		ret = LOG_NOK;
		goto out;
	}

	if (!stat(logfile, &stbuf)) {
		ret = LOG_OK;
		goto out;
	}

	sleep(PV_LOGGER_FILE_WAIT_TIMEOUT);
out:
	if (file_dup)
		free(file_dup);

	return ret;
}

int start_pvlogger(struct pv_log_info *log_info, const char *platform)
{
	int ret = -1;
	struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
	char pr_name[16] = { 0 };
	const char *logfile = NULL;

	logger_cmd = calloc(PV_LOG_BUF_SIZE, sizeof(char));

	/*Can't log it only thing we can do is print it on console*/
	if (!logger_cmd)
		return -1;

	pv_log_info = log_info;
	module_name = strdup(platform);
	snprintf(pr_name, sizeof(pr_name), "pvlogger-%s", module_name);
	prctl(PR_SET_NAME, (unsigned long)pr_name, 0, 0, 0);

	if (!pv_log_info) /*We can't even try and log cuz it maybe for lxc.*/
		return 0;
	logfile = pv_logger_get_logfile(pv_log_info);
	tv.tv_sec = 2;
	tv.tv_usec = 0;
	memset(&default_log, 0, sizeof(default_log));
	default_log.do_start_log = pvlogger_start;

	if (logfile && logfile[0] != '/') {
		pv_log(WARN,
		       "Logfile must be an absolute pathname"
		       " %s\n",
		       logfile);
		return -1;
	}

init_again:
	pv_log(INFO, "pvlogger %s has been setup", module_name);
	ret = log_init(&default_log, pv_logger_get_logfile(pv_log_info));
	while (ret != LOG_OK) {
		ret = wait_for_logfile(pv_logger_get_logfile(pv_log_info));
		if (ret == LOG_OK)
			goto init_again;
	}
	/*
	 * These need to be set after initiliaztion
	 * is over.
	 * log.truncate needs to be set after log_init if
	 * it's required to truncate the backing file.
	 */
	default_log.tv_notify = &tv;
	default_log.do_flush_log = pvlogger_flush;
	if (pv_log_info->truncate_size)
		default_log.log_limit = pv_log_info->truncate_size;

	while (!stop_logger) {
		if (log_flush_pv(&default_log) < 0) {
			pv_log(WARN, "Stopping pvlogger %s", module_name);
			log_stop(&default_log);
			goto init_again;
		}
		tv.tv_sec = 2;
		tv.tv_usec = 0;
	}
	pv_log(WARN, "Exiting, pv_logger %s", module_name);
	return 0;
}

void pv_log_info_free(struct pv_log_info *l)
{
	if (l->logfile)
		free(l->logfile);
	if (l->name)
		free(l->name);

	free(l);
}

/*
 * Don't free the returned value.
 * */
const char *pv_log_get_config_item(struct pv_logger_config *config,
				   const char *key)
{
	int i = 0;
	if (config->static_pair) {
		while (config->static_pair[i][0]) {
			if (!strncmp(config->static_pair[i][0], key,
				     strlen(key)))
				return config->static_pair[i][1];
			i++;
		}
	} else if (config->pair) {
		while (config->pair[i][0]) {
			if (!strncmp(config->pair[i][0], key, strlen(key)))
				return config->pair[i][1];
			i++;
		}
	}
	return NULL;
}

struct pv_log_info *
pv_new_log(bool islxc, struct pv_logger_config *logger_config, const char *name)
{
	struct pv_log_info *log_info = NULL;
	const char *const logger_name_plat = "pvlogger";
	const char *const logger_name_lxc = "pvlogger-lxc";
	const char *logger_name = NULL;
	const char *trunc_val = NULL;
	const char *enabled = NULL;

	if (!logger_config)
		goto out;

	if (islxc) {
		/*
		 * Check lxc or console item in config.
		 */
		enabled = pv_log_get_config_item(logger_config, "lxc");
		if (!enabled)
			enabled = pv_log_get_config_item(logger_config,
							 "console");
		if (!enabled)
			goto out;
		else if (strncmp(enabled, "enable", strlen("enable")))
			goto out;
	} else {
		/*
		 * Check if something from lxc was left over.
		 * if the config contains lxc or console keys then
		 * don't create this logger.
		 */
		;
		if (pv_log_get_config_item(logger_config, "lxc"))
			goto out;
		else {
			if (pv_log_get_config_item(logger_config, "console"))
				goto out;
		}
	}
	log_info = calloc(1, sizeof(struct pv_log_info));

	if (!log_info)
		goto out;

	logger_name = pv_log_get_config_item(logger_config, "name");
	log_info->islxc = islxc;

	if (!logger_name) {
		if (name)
			logger_name = name;
		else if (islxc)
			logger_name = logger_name_lxc;
		else
			logger_name = logger_name_plat;
	}
	log_info->name = strdup(logger_name);
	trunc_val = pv_log_get_config_item(logger_config, "truncate");
	if (trunc_val) {
		if (!strncmp(trunc_val, "true", strlen("true"))) {
			trunc_val = pv_log_get_config_item(logger_config,
							   "maxsize");
			if (trunc_val)
				sscanf(trunc_val, "%" PRId64,
				       &log_info->truncate_size);
		}
	}
	dl_list_init(&log_info->next);
	/*
	 * Used from the pv_lxc plugin
	 * */
	log_info->pv_log_get_config_item = pv_log_get_config_item;
	return log_info;
out:
	return NULL;
}

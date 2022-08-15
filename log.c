/*
 * Copyright (c) 2017-2022 Pantacor Ltd.
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

#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/prctl.h>

#include <linux/limits.h>

#include "config.h"
#include "utils/fs.h"
#include "thttp.h"
#include "trest.h"
#include "paths.h"
#include "utils/str.h"
#include "utils/math.h"
#include "loop.h"
#include "init.h"
#include "bootloader.h"
#include "version.h"
#include "ph_logger.h"
#include "buffer.h"
#include "paths.h"
#include "logserver.h"

#define MODULE_NAME "log"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

struct level_name {
	int log_level;
	char *name;
};

#define LEVEL_NAME(LEVEL)                                                      \
	{                                                                      \
		LEVEL, #LEVEL                                                  \
	}
static struct level_name level_names[] = { LEVEL_NAME(FATAL), LEVEL_NAME(ERROR),
					   LEVEL_NAME(WARN), LEVEL_NAME(INFO),
					   LEVEL_NAME(DEBUG) };

static pid_t log_init_pid = -1;

static const int MAX_BUFFER_COUNT = 10;
static struct pantavisor *global_pv = NULL;

static int logging_stdout = 0;

static void __vlog_to_console(char *module, int level, const char *fmt,
			      va_list args)
{
	char time_buf[MAX_DEC_STRING_SIZE_OF_TYPE(unsigned long long)];
	epochsecstring(time_buf, sizeof(time_buf), time(NULL));

	// construct string because we cannot lock stdout
	size_t size =
		snprintf(NULL, 0, "[pantavisor] %s %s\t -- [%s]: ", time_buf,
			 level_names[level].name, module);
	size += vsnprintf(NULL, 0, fmt, args) + 1; // NULL byte
	char *buf = calloc(sizeof(char), size);
	if (!buf) {
		// Fall back to multiple printfs instead of printing once
		// Ouptu may get split up by other processes.
		printf("[pantavisor] %s %s\t -- [%s]: ", time_buf,
		       level_names[level].name, module);
		vprintf(fmt, args);
		printf("\n");
	} else {
		int offs = snprintf(buf, size,
				    "[pantavisor] %s %s\t -- [%s]: ", time_buf,
				    level_names[level].name, module);
		vsnprintf(buf + offs, size - offs, fmt, args);
		printf("%s\n", buf);

		free(buf);
	}
	return;
}

static void __vlog(char *module, int level, const char *fmt, va_list args)
{
	int ret;

	if (0 > pv_logserver_send_vlog(false, PV_PLATFORM_STR, module, level,
				       fmt, args))
		ret = -1;
	else
		ret = 0;

	if (ret != 0 || logging_stdout)
		__vlog_to_console(module, level, fmt, args);
}

static void log_libthttp(int level, const char *fmt, va_list args)
{
	if (level > pv_config_get_libthttp_loglevel())
		return;

	if (log_init_pid != getpid())
		return;

	__vlog("libthttp", DEBUG, fmt, args);
}

static void pv_log_init(struct pantavisor *pv, const char *rev)
{
	char pv_logs_path[PATH_MAX], storage_logs_path[PATH_MAX];

	log_init_pid = getpid();
	global_pv = pv;

	pv_paths_pv_log(pv_logs_path, PATH_MAX, "");
	pv_fs_mkdir_p(pv_logs_path, 0755);

	pv_paths_storage_log(storage_logs_path, PATH_MAX);
	mount_bind(storage_logs_path, pv_logs_path);

	pv_buffer_init(MAX_BUFFER_COUNT, pv_config_get_log_logsize() * 1024);

	if (pv_logserver_init()) {
		pv_log(ERROR, "logserver initialization failed");
	}

	pv_log(DEBUG, "initialized pantavisor logs...");

	// enable libthttp debug logs
	thttp_set_log_func(log_libthttp);
}

void exit_error(int err, char *msg)
{
	printf("ERROR: %s (err=%d)\n", msg, err);
	printf("ERROR: rebooting system in 30 seconds\n");

	sleep(20);
	exit(0);
}

void __log_to_console(char *module, int level, const char *fmt, ...)
{
	va_list args;

	if (level > pv_config_get_log_loglevel())
		return;

	if (log_init_pid != getpid())
		return;

	va_start(args, fmt);

	__vlog_to_console(module, level, fmt, args);

	va_end(args);
}

void __log(char *module, int level, const char *fmt, ...)
{
	va_list args;

	if (level > pv_config_get_log_loglevel())
		return;

	if (log_init_pid != getpid())
		return;

	va_start(args, fmt);

	__vlog(module, level, fmt, args);

	va_end(args);
}

const char *pv_log_level_name(int level)
{
	if (level < FATAL || level >= ALL)
		return "UNDEFINED";
	return level_names[level].name;
}

void pv_log_umount(void)
{
	char path[PATH_MAX];

	pv_paths_pv_log(path, PATH_MAX, "");
	umount(path);
}

static int pv_log_early_init(struct pv_init *this)
{
	struct pantavisor *pv = pv_get_instance();

	pv_log_init(pv, pv_bootloader_get_rev());

	pv_log(INFO, "______           _              _                ");
	pv_log(INFO, "| ___ \\         | |            (_)               ");
	pv_log(INFO, "| |_/ /_ _ _ __ | |_ __ ___   ___ ___  ___  _ __ ");
	pv_log(INFO, "|  __/ _` | '_ \\| __/ _` \\ \\ / / / __|/ _ \\| '__|");
	pv_log(INFO, "| | | (_| | | | | || (_| |\\ V /| \\__ \\ (_) | |   ");
	pv_log(INFO, "\\_|  \\__,_|_| |_|\\__\\__,_| \\_/ |_|___/\\___/|_|   ");
	pv_log(INFO, "                                                 ");
	pv_log(INFO, "Pantavisor (TM) (%s) - www.pantahub.com",
	       pv_build_version);
	pv_log(INFO, "                                                 ");
	pv_log(INFO, "storage.path = '%s'", pv_config_get_storage_path());
	pv_log(INFO, "storage.fstype = '%s'", pv_config_get_storage_fstype());
	pv_log(INFO, "storage.opts = '%s'", pv_config_get_storage_opts());
	pv_log(INFO, "storage.mntpoint = '%s'",
	       pv_config_get_storage_mntpoint());
	pv_log(INFO, "storage.mnttype = '%s'", pv_config_get_storage_mnttype());
	pv_log(INFO, "secureboot.mode = '%d'", pv_config_get_secureboot_mode());
	pv_log(INFO, "creds.host = '%s'", pv_config_get_creds_host());
	pv_log(INFO, "creds.port = '%d'", pv_config_get_creds_port());
	pv_log(INFO, "creds.host_proxy = '%s'",
	       pv_config_get_creds_host_proxy());
	pv_log(INFO, "creds.port_proxy = '%d'",
	       pv_config_get_creds_port_proxy());
	pv_log(INFO, "creds.noproxyconnect = '%d'",
	       pv_config_get_creds_noproxyconnect());
	pv_log(INFO, "creds.id = '%s'", pv_config_get_creds_id());
	pv_log(INFO, "creds.prn = '%s'", pv_config_get_creds_prn());
	pv_log(INFO, "creds.secret = '%s'", pv_config_get_creds_secret());
	pv_log(INFO, "log.loggers = '%d'", pv_config_get_log_loggers());
	pv_log(INFO, "log.stdout = '%d'", pv_config_get_log_stdout());
	pv_log(INFO, "log.capture = '%d'", pv_config_get_log_capture());
	pv_log(INFO, "log.push = '%d'", pv_config_get_log_push());
	pv_log(INFO, "log.logdir = '%s'", pv_config_get_log_logdir());
	pv_log(INFO, "log.logmax = '%d'", pv_config_get_log_logmax());
	pv_log(INFO, "log.loglevel = '%d'", pv_config_get_log_loglevel());
	pv_log(INFO, "log.logsize = '%d'", pv_config_get_log_logsize());
	pv_log(INFO, "lxc.log.level = '%d'", pv_config_get_lxc_loglevel());
	pv_log(INFO, "log.server.outputs = '%d'",
	       pv_config_get_log_server_outputs());
	pv_log(INFO, "libthttp.loglevel = '%d'",
	       pv_config_get_libthttp_loglevel());
	pv_bootloader_print();

	logging_stdout = pv_config_get_log_stdout();

	return 0;
}

struct pv_init pv_init_log = {
	.init_fn = pv_log_early_init,
	.flags = 0,
};

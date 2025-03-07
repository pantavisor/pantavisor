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
#include "buffer.h"
#include "paths.h"
#include "logserver/logserver.h"

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

static void __vlog(char *module, int level, const char *fmt, va_list args)
{
	pv_logserver_send_vlog(false, PV_PLATFORM_STR, module, level, fmt,
			       args);
}

static void log_libthttp(int level, const char *fmt, va_list args)
{
	if (level > pv_config_get_int(PV_LIBTHTTP_LOG_LEVEL))
		return;

	if (log_init_pid != getpid())
		return;

	__vlog("ph_client_libthttp", DEBUG, fmt, args);
}

static void pv_log_init(const char *rev)
{
	char pv_logs_path[PATH_MAX], storage_logs_path[PATH_MAX];

	log_init_pid = getpid();

	pv_paths_pv_log(pv_logs_path, PATH_MAX, "");
	pv_fs_mkdir_p(pv_logs_path, 0755);

	pv_paths_storage_log(storage_logs_path, PATH_MAX);
	mount_bind(storage_logs_path, pv_logs_path);

	pv_buffer_init(MAX_BUFFER_COUNT,
		       pv_config_get_int(PV_LOG_BUF_NITEMS) * 1024);

	if (pv_logserver_init(rev))
		pv_log(ERROR, "logserver initialization failed");

	pv_log(DEBUG, "initialized pantavisor logs...");

	// enable libthttp debug logs
	thttp_set_log_func(log_libthttp);
}

void exit_error(int err, char *msg)
{
	if (msg)
		pv_log(FATAL, "%s: %s", msg, strerror(err));
	pv_log(FATAL, "rebooting system in 20 seconds");

	sleep(20);
	exit(0);
}

void __log(char *module, int level, const char *fmt, ...)
{
	va_list args;

	if ((level != FATAL) && (level > pv_config_get_int(PV_LOG_LEVEL)))
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
	pv_log(DEBUG, "unmounting '%s'", path);

	if (umount(path))
		pv_log(ERROR, "cannot unmount '%s': %s", path, strerror(errno));
}

static int pv_log_early_init(struct pv_init *this)
{
	pv_log_init(pv_bootloader_get_rev());

	// this should be the only message we directly printf
	printf("Pantavisor (TM) (%s) - pantavisor.io\n", pv_build_version);

	pv_log(INFO, "______           _              _                ");
	pv_log(INFO, "| ___ \\         | |            (_)               ");
	pv_log(INFO, "| |_/ /_ _ _ __ | |_ __ ___   ___ ___  ___  _ __ ");
	pv_log(INFO, "|  __/ _` | '_ \\| __/ _` \\ \\ / / / __|/ _ \\| '__|");
	pv_log(INFO, "| | | (_| | | | | || (_| |\\ V /| \\__ \\ (_) | |   ");
	pv_log(INFO, "\\_|  \\__,_|_| |_|\\__\\__,_| \\_/ |_|___/\\___/|_|   ");
	pv_log(INFO, "                                                 ");
	pv_log(INFO, "Pantavisor (TM) (%s) - pantavisor.io", pv_build_version);
	pv_log(INFO, "                                                 ");
	// we print stuff here that was initialized before logs
	pv_bootloader_print();
	pv_config_print();
	pv_init_print_cmdline();

	return 0;
}

struct pv_init pv_init_log = {
	.init_fn = pv_log_early_init,
	.flags = 0,
};
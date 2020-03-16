/*
 * Copyright (c) 2017 Pantacor Ltd.
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include <ctype.h>
#include <dirent.h>

#include <linux/limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "tsh.h"
#include "thttp.h"

#define MODULE_NAME		"log"
#define pv_log(level, msg, ...)		vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "pantahub.h"
#include "loop.h"
#include "utils.h"

#define LEVEL_NAME(LEVEL)	{ LEVEL, #LEVEL }
static struct level_name level_names[] = {
	LEVEL_NAME(FATAL),
	LEVEL_NAME(ERROR),
	LEVEL_NAME(WARN),
	LEVEL_NAME(INFO),
	LEVEL_NAME(DEBUG)
};

static int prio = ALL;
static char *log_dir = 0;
static pid_t log_init_pid = -1;

static struct pantavisor *global_pv = NULL;

static int log_external(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);

	__vlog("external", DEBUG, fmt, args);

	va_end(args);

	return 1;
}

void pv_log_init(struct pantavisor *pv, int rev)
{
	// make logs available for platforms
	thttp_set_log_func(log_external);
	log_init_pid = getpid();
	global_pv = pv;

	
	mkdir_p("/pv/logs", 0755);
	mount_bind(pv->config->logdir, "/pv/logs");
	log_dir = calloc(1, PATH_MAX);
	if (!log_dir) {
		printf("Couldn't reserve space for log directory\n");
		printf("Pantavisor logs won't be available\n");
		return;
	}
	snprintf(log_dir, PATH_MAX, "/pv/logs/%d/pantavisor", rev);
	if (mkdir_p(log_dir, 0755)) {
		printf("Couldn't make dir %s,"
			"pantavisor logs won't be available\n", log_dir);
	}

	// enable libthttp debug logs
	pv_log(DEBUG, "Initialized pantavisor logs...");
}

void exit_error(int err, char *msg)
{
	printf("ERROR: %s (err=%d)", msg, err);
	printf("ERROR: rebooting system in 30 seconds");

	sleep(20);
	exit(0);
}

void __vlog(char *module, int level, const char *fmt, va_list args)
{
	struct stat log_stat;
	char log_path [PATH_MAX];
	int log_fd = -1;
	int max_gzip = 3;
	// hold 2MiB max of log entries in open file
	//Check on disk file size.
	
	if (!log_dir)
		return;
	snprintf(log_path, sizeof(log_path), "%s/%s",log_dir, LOG_NAME);
	log_fd = open(log_path, O_RDWR | O_APPEND | O_CREAT | O_SYNC, 0644);

	if (!stat(log_path, &log_stat)) {
		if (log_stat.st_size >= LOG_MAX_FILE_SIZE) {
			int i = 0;

			for( i = 0; i < max_gzip; i++) {
				struct stat stat_gz;
				char gzip_path[PATH_MAX];

				snprintf(gzip_path, sizeof(gzip_path),
						"%s.%d.gzip", log_path, (i+1));
				if (stat(gzip_path, &stat_gz))
					gzip_file(log_path, gzip_path);
			}
			if (log_fd >= 0) {
				ftruncate(log_fd, 0);
				lseek(log_fd, 0, SEEK_SET);
			}
		}
	}
	if (log_fd >= 0) {
		dprintf(log_fd, "[pantavisor] %s\t -- ", level_names[level].name);
		dprintf(log_fd, "[%s]: ", module);
		vdprintf(log_fd, fmt, args);
		dprintf(log_fd, "\n");
		close(log_fd);
	}
}

void __log(char *module, int level, const char *fmt, ...)
{
	va_list args;

#if 0
	if (log_init_pid != getpid())
		return;
#endif
	va_start(args, fmt);

	__vlog(module, level, fmt, args);

	va_end(args); 
}

int pv_log_set_level(unsigned int level)
{
	if (level <= ALL)
		prio = level;

	return prio;
}

const char *pv_log_level_name(int level)
{
	if (level < FATAL || level >= ALL)
		return "UNDEFINED";
	return level_names[level].name;
}

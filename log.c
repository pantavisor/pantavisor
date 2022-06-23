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
#include "file.h"
#include "thttp.h"
#include "trest.h"
#include "utils/fs.h"
#include "utils/str.h"
#include "utils/math.h"
#include "loop.h"
#include "init.h"
#include "bootloader.h"
#include "version.h"
#include "ph_logger/ph_logger.h"
#include "buffer.h"
#include "paths.h"

#define MODULE_NAME		"log"
#define pv_log(level, msg, ...)		vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

struct level_name {
	int log_level;
	char *name;
};

#define LEVEL_NAME(LEVEL)	{ LEVEL, #LEVEL }
static struct level_name level_names[] = {
	LEVEL_NAME(FATAL),
	LEVEL_NAME(ERROR),
	LEVEL_NAME(WARN),
	LEVEL_NAME(INFO),
	LEVEL_NAME(DEBUG)
};

static char log_dir[PATH_MAX];
static char log_path[PATH_MAX];
static pid_t log_init_pid = -1;

static const int MAX_BUFFER_COUNT = 10;
static struct pantavisor *global_pv = NULL;

static int logging_initialized = 0;
static int logging_stdout = 0;

static void __vlog(char *module, int level, const char *fmt, va_list args)
{
	struct stat log_stat;
	int log_fd = -1;
	int max_gzip = 3;
	char time_buf[MAX_DEC_STRING_SIZE_OF_TYPE (unsigned long long)];
	epochsecstring(time_buf, sizeof (time_buf), time(NULL));
	// hold 2MiB max of log entries in open file
	//Check on disk file size.

	if (!logging_initialized || logging_stdout) {
		// construct string because we cannot lock stdout
		size_t size = snprintf(NULL, 0,
				"[pantavisor] %s %s\t -- [%s]: ",
				time_buf, level_names[level].name, module);
		size += vsnprintf(NULL, 0, fmt, args);
		// 1 '\0' char
		size++;
		char *buf = calloc(size, sizeof(char));
		if (!buf) {
			// Fall back to multiple printfs instead of printing once
			// Ouptu may get split up by other processes.
			printf("[pantavisor] %s %s\t -- [%s]: ",
					time_buf, level_names[level].name, module);
			vprintf(fmt, args);
			printf("\n");
		} else {
			size_t offs = snprintf(buf, size,
					"[pantavisor] %s %s\t -- [%s]: ",
					time_buf, level_names[level].name, module);
			offs += vsnprintf(buf + offs, size - offs, fmt, args);
			printf("%s%s\n", buf, offs >= size ? " [TRUNC]": "");
			free(buf);
		}

		if (!logging_stdout || !logging_initialized)
			return;
	}

	log_fd = open(log_path, O_RDWR | O_APPEND | O_CREAT | O_SYNC, 0644);

	if (log_fd >= 0) {
		int ret = 0;
		int lock_file_errno = 0;
		do {
			ret = pv_file_lock_file(log_fd);
		} while (ret < 0 && (errno == EAGAIN || errno == EACCES));

		if (ret < 0)
			lock_file_errno = errno;
		/*
		 * We weren't able to take the lock.
		 */
		if (ret) {
			char err_file[PATH_MAX];
			char proc_name[17] = {0};
			int len = 0;
			int err_fd = -1;

			SNPRINTF_WTRUNC(err_file, PATH_MAX, "%s/%s", log_dir, LOGS_ERROR_DNAME);

			mkdir_p(err_file, 0755);
			len = strlen(err_file);
			SNPRINTF_WTRUNC(err_file + len, PATH_MAX - len, "/%d.error", getpid());

			err_fd = open(err_file,
					O_EXCL|O_RDWR|O_CREAT|O_APPEND|O_SYNC, 0644);
			if (err_fd >= 0) {
				prctl(PR_GET_NAME, (unsigned long)proc_name, 0, 0, 0, 0);
				dprintf(err_fd, "process %s couldn't acquire "LOGS_PV_FNAME" lock\n", proc_name);
				dprintf(err_fd, "error code %d: %s\n", errno, strerror(lock_file_errno));
				dprintf(err_fd, "[pantavisor] %s\t -- ", level_names[level].name);
				dprintf(err_fd, "[%s]: ", module);
				vdprintf(err_fd, fmt, args);
				dprintf(err_fd, "\n");
				close(err_fd);
			}
			close(log_fd);
			return;
		}
	}

	if (!stat(log_path, &log_stat)) {
		if (log_stat.st_size >= LOG_MAX_FILE_SIZE) {
			int i = 0;

			for( i = 0; i < max_gzip; i++) {
				struct stat stat_gz;
				char gzip_path[PATH_MAX];

				SNPRINTF_WTRUNC(gzip_path, PATH_MAX, "%s.%d.gzip", log_path, (i+1));
				if (stat(gzip_path, &stat_gz))
					pv_file_gzip_file(log_path, gzip_path);
			}
			if (log_fd >= 0) {
				ftruncate(log_fd, 0);
				lseek(log_fd, 0, SEEK_SET);
			}
		}
	}
	if (log_fd >= 0) {
		dprintf(log_fd, "[pantavisor] %s %s\t -- ", time_buf, level_names[level].name);
		dprintf(log_fd, "[%s]: ", module);
		vdprintf(log_fd, fmt, args);
		dprintf(log_fd, "\n");
		pv_file_unlock_file(log_fd);
		close(log_fd);
	}
}

static void log_libthttp(int level, const char *fmt, va_list args)
{
	if (level > pv_config_get_libthttp_loglevel())
		return;

	if (log_init_pid != getpid())
		return;

	__vlog("libthttp", DEBUG, fmt, args);
}

static int pv_log_set_log_dir(const char *rev)
{
	pv_paths_pv_log_plat(log_dir, PATH_MAX, rev, LOGS_PV_DNAME);
	pv_paths_pv_log_file(log_path, PATH_MAX, rev, LOGS_PV_DNAME, LOGS_PV_FNAME);

	if (mkdir_p(log_dir, 0755)) {
		printf("Couldn't make dir %s," "pantavisor logs won't be available\n", log_dir);
		return -1;
	}

	return 0;
}

static void pv_log_init(struct pantavisor *pv, const char *rev)
{
	char pv_logs_path[PATH_MAX], storage_logs_path[PATH_MAX];

	log_init_pid = getpid();
	global_pv = pv;

	pv_paths_pv_log(pv_logs_path, PATH_MAX, "");
	mkdir_p(pv_logs_path, 0755);

	pv_paths_storage_log(storage_logs_path, PATH_MAX);
	mount_bind(storage_logs_path, pv_logs_path);

	if (pv_log_start(pv, rev) < 0)
		return;

	pv_buffer_init(MAX_BUFFER_COUNT, pv_config_get_log_logsize());
	logging_initialized = 1;

	// enable libthttp debug logs
	pv_log(DEBUG, "Initialized pantavisor logs...");

	thttp_set_log_func(log_libthttp);
}

void exit_error(int err, char *msg)
{
	printf("ERROR: %s (err=%d)\n", msg, err);
	printf("ERROR: rebooting system in 30 seconds\n");

	sleep(20);
	exit(0);
}

int pv_log_start(struct pantavisor *pv, const char *rev)
{
	if (!pv_config_get_log_capture())
		return 0;

	if (pv_log_set_log_dir(rev) < 0) {
		printf("Error: unable to start "LOGS_PV_FNAME"\n");
		return -1;
	}

	return 0;
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

static int pv_log_early_init(struct pv_init *this)
{
	struct pantavisor *pv = pv_get_instance();
	char path[PATH_MAX];

	pv_log_init(pv, pv_bootloader_get_rev());

	pv_log(INFO, "______           _              _                ");
	pv_log(INFO, "| ___ \\         | |            (_)               ");
	pv_log(INFO, "| |_/ /_ _ _ __ | |_ __ ___   ___ ___  ___  _ __ ");
	pv_log(INFO, "|  __/ _` | '_ \\| __/ _` \\ \\ / / / __|/ _ \\| '__|");
	pv_log(INFO, "| | | (_| | | | | || (_| |\\ V /| \\__ \\ (_) | |   ");
	pv_log(INFO, "\\_|  \\__,_|_| |_|\\__\\__,_| \\_/ |_|___/\\___/|_|   ");
	pv_log(INFO, "                                                 ");
	pv_log(INFO, "Pantavisor (TM) (%s) - www.pantahub.com", pv_build_version);
	pv_log(INFO, "                                                 ");
	pv_log(INFO, "storage.path = '%s'", pv_config_get_storage_path());
	pv_log(INFO, "storage.fstype = '%s'", pv_config_get_storage_fstype());
	pv_log(INFO, "storage.opts = '%s'", pv_config_get_storage_opts());
	pv_log(INFO, "storage.mntpoint = '%s'", pv_config_get_storage_mntpoint());
	pv_log(INFO, "storage.mnttype = '%s'", pv_config_get_storage_mnttype());
	pv_log(INFO, "secureboot.mode = '%d'", pv_config_get_secureboot_mode());
	pv_log(INFO, "creds.host = '%s'", pv_config_get_creds_host());
	pv_log(INFO, "creds.port = '%d'", pv_config_get_creds_port());
	pv_log(INFO, "creds.host_proxy = '%s'", pv_config_get_creds_host_proxy());
	pv_log(INFO, "creds.port_proxy = '%d'", pv_config_get_creds_port_proxy());
	pv_log(INFO, "creds.noproxyconnect = '%d'", pv_config_get_creds_noproxyconnect());
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
	pv_log(INFO, "libthttp.loglevel = '%d'", pv_config_get_libthttp_loglevel());
	pv_bootloader_print();

	logging_stdout = pv_config_get_log_stdout();

	pv_paths_pv_file(path, PATH_MAX, LOGCTRL_FNAME);
	if (ph_logger_init(path)) {
		pv_log(ERROR, "ph logger initialization failed");
		return -1;
	}

	return 0;
}

struct pv_init pv_init_log = {
	.init_fn = pv_log_early_init,
	.flags = 0,
};

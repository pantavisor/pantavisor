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
#include <sys/prctl.h>

#include "tsh.h"
#include "thttp.h"

#define MODULE_NAME		"log"
#define pv_log(level, msg, ...)		vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "pantahub.h"
#include "loop.h"
#include "utils.h"
#include "init.h"
#include "revision.h"
#include "version.h"
#include "ph_logger/ph_logger.h"

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

static char *log_dir = 0;
static pid_t log_init_pid = -1;

static DEFINE_DL_LIST(log_buffer_list);
static DEFINE_DL_LIST(log_buffer_list_double);
static const int MAX_BUFFER_COUNT = 10;
static struct pantavisor *global_pv = NULL;

static struct log_buffer* __pv_log_get_buffer(struct dl_list *head)
{
	struct log_buffer *log_buffer = NULL;

	if (dl_list_empty(head))
		return NULL;
	log_buffer = dl_list_first(head, 
			struct log_buffer, free_list);
	dl_list_del(&log_buffer->free_list);
	dl_list_init(&log_buffer->free_list);
	return log_buffer;
}

struct log_buffer* pv_log_get_buffer(bool large)
{
	if (large)
		return __pv_log_get_buffer(&log_buffer_list_double);
	return __pv_log_get_buffer(&log_buffer_list);
}

void pv_log_put_buffer(struct log_buffer *log_buffer)
{
	if (!log_buffer)
		return;
	if (!dl_list_empty(&log_buffer->free_list))
		return;
	if (global_pv->config->logsize == log_buffer->size)
		dl_list_add(&log_buffer_list, &log_buffer->free_list);
	else
		dl_list_add(&log_buffer_list_double, &log_buffer->free_list);

}

static struct log_buffer* pv_log_alloc_buffer(int buf_size)
{
	struct log_buffer *buffer =  NULL;

	if (buf_size <= 0)
		return NULL;
	buffer = (struct log_buffer*) calloc(1, sizeof(*buffer));
	if (buffer) {
		buffer->buf = (char*)calloc(1, buf_size);
		if (!buffer->buf) {
			free(buffer);
			buffer = NULL;
		} else {
			buffer->size = buf_size;
		}
	}
	return buffer;
}

static int pv_log_init_buf_cache(int items, int size, struct dl_list *head) 
{
	int allocated = 0;

	if (!dl_list_empty(head)) {
		struct log_buffer *item, *tmp;
		dl_list_for_each_safe(item, tmp, head,
				struct log_buffer, free_list) {
			dl_list_del(&item->free_list);
			free(item->buf);
			free(item);
		}
	}
	while (items > 0) {
		struct log_buffer *buffer =  NULL;

		if (allocated >= MAX_BUFFER_COUNT)
			break;
		buffer = pv_log_alloc_buffer(size);
		if (buffer) {
			dl_list_add(head, &buffer->free_list);
			allocated++;
		}
		items--;
	}
	return allocated;
}

static void __vlog(char *module, int level, const char *fmt, va_list args)
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
	
	if (log_fd >= 0) {
		int ret = 0;
		int lock_file_errno = 0;
		do {
			ret = lock_file(log_fd);
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


			snprintf(err_file, PATH_MAX, "%s/%s", log_dir, ERROR_DIR);
			mkdir_p(err_file, 0755);
			len = strlen(err_file);
			snprintf(err_file + len, PATH_MAX - len, "/%d.error",getpid());

			err_fd = open(err_file, 
					O_EXCL|O_RDWR|O_CREAT|O_APPEND|O_SYNC, 0644);
			if (err_fd >= 0) {
				prctl(PR_GET_NAME, (unsigned long)proc_name, 0, 0, 0, 0);
				dprintf(err_fd, "process %s couldn't acquire pantavisor.log lock\n", proc_name);
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
		unlock_file(log_fd);
		close(log_fd);
	}
}

static int log_external(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);

	__vlog("external", DEBUG, fmt, args);

	va_end(args);

	return 1;
}

static int pv_log_set_log_dir(int rev)
{
	if (!log_dir)
		log_dir = calloc(1, PATH_MAX);

	if (!log_dir) {
		printf("Couldn't reserve space for log directory\n");
		printf("Pantavisor logs won't be available\n");
		return -1;
	}

	snprintf(log_dir, PATH_MAX, "/pv/logs/%d/pantavisor", rev);
	if (mkdir_p(log_dir, 0755)) {
		printf("Couldn't make dir %s,"
			"pantavisor logs won't be available\n", log_dir);
		return -1;
	}

	return 0;
}

static void pv_log_init(struct pantavisor *pv, int rev)
{
	// make logs available for platforms
	thttp_set_log_func(log_external);
	log_init_pid = getpid();
	global_pv = pv;
	int allocated_cache = 0;
	int allocated_dcache = 0;

	allocated_cache = pv_log_init_buf_cache(MAX_BUFFER_COUNT,
					pv->config->logsize, &log_buffer_list);

	allocated_dcache = pv_log_init_buf_cache(MAX_BUFFER_COUNT,
					pv->config->logsize * 2, &log_buffer_list_double);

	mkdir_p("/pv/logs", 0755);
	mount_bind(pv->config->logdir, "/pv/logs");

	if (pv_log_start(pv, rev) < 0)
		return;

	// enable libthttp debug logs
	pv_log(DEBUG, "Initialized pantavisor logs...");
	pv_log(INFO, "Allocated %d log buffers of size %d bytes",
			allocated_cache, pv->config->logsize);
	pv_log(INFO, "Allocated %d log buffers of size %d bytes",
			allocated_dcache, pv->config->logsize * 2);
}

void exit_error(int err, char *msg)
{
	printf("ERROR: %s (err=%d)", msg, err);
	printf("ERROR: rebooting system in 30 seconds");

	sleep(20);
	exit(0);
}

int pv_log_start(struct pantavisor *pv, int rev)
{
	if (pv_log_set_log_dir(rev) < 0) {
		printf("Error: unable to start pantavisor.log");
		return -1;
	}


	return 0;
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

const char *pv_log_level_name(int level)
{
	if (level < FATAL || level >= ALL)
		return "UNDEFINED";
	return level_names[level].name;
}

static int pv_log_early_init(struct pv_init *this)
{
	struct pantavisor *pv = NULL;
	struct pantavisor_config *config = NULL;
	int pv_rev = 0;
	int ret = -1;

	pv = get_pv_instance();
	if (!pv || !pv->config)
		goto out;

	ret = 0;
	config = pv->config;
	pv_rev = pv_revision_get_rev();

	pv_log_init(pv, pv_rev);

	pv_log(INFO, "______           _              _                ");
	pv_log(INFO, "| ___ \\         | |            (_)               ");
	pv_log(INFO, "| |_/ /_ _ _ __ | |_ __ ___   ___ ___  ___  _ __ ");
	pv_log(INFO, "|  __/ _` | '_ \\| __/ _` \\ \\ / / / __|/ _ \\| '__|");
	pv_log(INFO, "| | | (_| | | | | || (_| |\\ V /| \\__ \\ (_) | |   ");
	pv_log(INFO, "\\_|  \\__,_|_| |_|\\__\\__,_| \\_/ |_|___/\\___/|_|   ");
	pv_log(INFO, "                                                 ");
	pv_log(INFO, "Pantavisor (TM) (%s) - www.pantahub.com", pv_build_version);
	pv_log(INFO, "                                                 ");
	pv_log(DEBUG, "c->storage.path = '%s'", config->storage.path);
	pv_log(DEBUG, "c->storage.fstype = '%s'", config->storage.fstype);
	pv_log(DEBUG, "c->storage.opts = '%s'", config->storage.opts);
	pv_log(DEBUG, "c->storage.mntpoint = '%s'", config->storage.mntpoint);
	pv_log(DEBUG, "c->storage.mnttype = '%s'", config->storage.mnttype ? config->storage.mnttype : "");
	pv_log(DEBUG, "c->creds.host = '%s'", config->creds.host);
	pv_log(DEBUG, "c->creds.port = '%d'", config->creds.port);
	pv_log(DEBUG, "c->creds.id = '%s'", config->creds.id);
	pv_log(DEBUG, "c->creds.prn = '%s'", config->creds.prn);
	pv_log(DEBUG, "c->creds.secret = '%s'", config->creds.secret);

out:
	return ret;
}

struct pv_init pv_init_log = {
	.init_fn = pv_log_early_init,
	.flags = 0,
};

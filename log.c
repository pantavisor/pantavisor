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
static int log_count = 0;
static int log_written = 0;
static int log_maxsize = 0;
static char *log_dir = 0;
static pid_t log_init_pid = -1;

// default STDOUT
int log_fd = 1;

#define LOG_NAME		"pantavisor.log"
#define LOG_ITEM_SIZE		4096
#define LOG_DATA_SIZE		LOG_ITEM_SIZE-48

typedef struct {
	uint64_t tsec;		// 8 bytes
	uint32_t tusec;		// 4 bytes
	uint32_t level;		// 4 bytes
	char source[32];
	char data[LOG_DATA_SIZE];
} log_entry_t;

typedef struct {
	void *buf_start;
	void *buf_end;
	log_entry_t *head;
	log_entry_t *tail;
	log_entry_t *last;
	uint32_t buf_size;
	uint32_t size;
	uint32_t count;
} log_buf_t;

static log_buf_t *lb = NULL;
static struct pantavisor *global_pv = NULL;

static void log_reset(void)
{
	if (!lb)
		return;

	memset(lb->buf_start, 0, lb->buf_size);
	lb->tail = lb->buf_start;
	lb->head = lb->buf_start;
	lb->count = 0;
}

static int log_external(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);

	__vlog("external", DEBUG, fmt, args);

	return 1;
}

void pv_log_init(struct pantavisor *pv)
{
	char path[PATH_MAX];

	if (!pv)
		return;

	global_pv = pv;

	if (lb)
		return;

	// allocate ring buffer
	if (pv->config->logsize == 0)
		return;

	lb = calloc(1, sizeof(log_buf_t));
	if (!lb)
		return;

	lb->size = pv->config->logsize;
	lb->buf_size = sizeof(log_entry_t) * lb->size;
	lb->buf_start = calloc(1, lb->buf_size);
	lb->buf_end = (char *) lb->buf_start + lb->buf_size;
	lb->head = (log_entry_t*) lb->buf_start;
	lb->tail = lb->buf_start;

	// init log file
	log_dir = pv->config->logdir;
	log_maxsize = pv->config->logmax;
	sprintf(path, "/%s/%s", log_dir, LOG_NAME);
	log_fd = open(path, O_CREAT | O_SYNC | O_RDWR | O_APPEND, 0644);
	log_count = 0;

	// make logs available for platforms
	mkdir_p("/pv/logs", 0644);
	mount_bind(pv->config->logdir, "/pv/logs");

	// enable libthttp debug logs
	thttp_set_log_func(log_external);
	log_init_pid = getpid();

	pv_log(DEBUG, "%s() logsize: %d items, buffer of %d KiB", __func__, lb->size, lb->buf_size / 1024);
}

void exit_error(int err, char *msg)
{
	printf("ERROR: %s (err=%d)\n", msg, err);
	printf("ERROR: rebooting system in 30 seconds\n");

	sleep(20);
	exit(0);
}

static void log_print_date(int fd)
{
	char date[sizeof(DATE_FORMAT)];
	struct timeval tv;
	const struct tm *t;

	gettimeofday(&tv, NULL);
	t = localtime(&tv.tv_sec);

	strftime(date, sizeof(date), "%Y-%m-%d %H:%M:%S", t);

	dprintf(fd, "[%s] ", date);
}

static char *replace_char(char *str, char c, char r)
{
	char *t = str;

	t = strchr(t, c);
	while (t) {
		*t = r;
		t = strchr(t, c);
	}

	return (char *) t;
}

static void log_add(log_entry_t *e)
{
	// FIXME: backup to disk if (lb->head == lb->tail)
	lb->last = lb->head;
	memcpy(lb->head, e, sizeof(log_entry_t));
	lb->head += 1;
	if (lb->head == lb->buf_end) {
		lb->head = lb->buf_start;
	}

	if (lb->count < lb->size)
		lb->count++;
}

static void rotate_log(void)
{
	int n, fd, bytes;
	char *at = 0;
	char path[PATH_MAX];
	struct dirent **d;

	lseek(log_fd, 0, SEEK_SET);

	char *in = calloc(1, log_written);
	bytes = read(log_fd, in, log_written);

	sprintf(path, "%s.", LOG_NAME);
	n = scandir(log_dir, &d, NULL, alphasort);
	while (n--) {
		if (strncmp(d[n]->d_name, path, strlen(path))) {
			free(d[n]);
			continue;
		}
		at = strtok(d[n]->d_name + strlen(path), ".");
		if (at) {
			if (atoi(at) >= 3) {
				free(d[n]);
				continue;
			}
			char new_path[PATH_MAX], old_path[PATH_MAX];
			sprintf(new_path, "/%s/%s.%d.gz", log_dir, LOG_NAME, atoi(at) + 1);
			sprintf(old_path, "/%s/%s.%d.gz", log_dir, LOG_NAME, atoi(at));
			rename(old_path, new_path);
		}
		free(d[n]);
	}

	sprintf(path, "/%s/%s.%d", log_dir, LOG_NAME, 1);

	fd = open(path, O_CREAT | O_WRONLY, 0644);
	write(fd, in, log_written);
	close(fd);

	char tmp[1024];
	sprintf(tmp, "gzip %s", path);
	tsh_run(tmp, 1);

	lseek(log_fd, 0, SEEK_SET);
	ftruncate(log_fd, 0);
	log_count = 0;
	log_written = 0;

	if (d)
		free(d);
	if (fd)
		close(fd);
	if (in)
		free(in);
}

static void log_last_entry_to_file(void)
{
	log_entry_t *e = lb->last;

	// hold 2MiB max of log entries in open file
	if (log_written > log_maxsize)
		rotate_log();

	log_written += dprintf(log_fd, "[pantavisor] %s\t", level_names[e->level].name);
	log_written += dprintf(log_fd, "[%"PRId64".%"PRId32"] ", e->tsec, e->tusec);
	log_written += dprintf(log_fd, "-- [%s]: %s\n", e->source, e->data);
	log_count++;
}

void __vlog(char *module, int level, const char *fmt, va_list args)
{
	struct timeval tv;
	char buf[LOG_DATA_SIZE];
	char *format = 0;

	if (!lb)
		return;

	if (level >= prio)
		return;

	// construct log entry in heap to copy
	log_entry_t e;

	gettimeofday(&tv, NULL);

	e.tsec = (uint64_t) tv.tv_sec;
	e.tusec = (uint32_t) tv.tv_usec;
	e.level = level;

	snprintf(e.source, 32, "%s", module);

	vsnprintf(e.data, sizeof(buf), fmt, args);

	// escape problematic json chars
	replace_char(e.data, '\n', ' ');
	replace_char(e.data, '\"', '\'');
	replace_char(e.data, '\t', ' ');

	// add to ring buffer
	log_add(&e);

	// if config-logfile
	log_last_entry_to_file();

	free((char *) format);

	// try to push north
	if (level < DEBUG)
		pv_log_flush(global_pv, level == ERROR ? true : false);
}

void __log(char *module, int level, const char *fmt, ...)
{
	va_list args;

	if (log_init_pid != getpid())
		return;

	va_start(args, fmt);

	__vlog(module, level, fmt, args);

	va_end(args); 
}

void pv_log_raw(struct pantavisor *pv, char *buf, int len, const char *platform)
{
	struct timeval tv;
	log_entry_t e;

	memset(&e, 0, sizeof(log_entry_t));

	gettimeofday(&tv, NULL);

	e.tsec = (uint64_t) tv.tv_sec;
	e.tusec = (uint32_t) tv.tv_usec;
	e.level = DEBUG;

	if (!platform)
		snprintf(e.source, sizeof(e.source), "PLATFORM");
	else
		snprintf(e.source, sizeof(e.source), "%s", platform);
		

	strncpy(e.data, buf, len > LOG_DATA_SIZE ? LOG_DATA_SIZE : len);

	// escape problematic json chars
	replace_char(e.data, '\n', ' ');
	replace_char(e.data, '\"', '\'');
	replace_char(e.data, '\t', ' ');

	// add to ring buffer
	log_add(&e);

	log_last_entry_to_file();
}

static int log_entry_null(log_entry_t *e)
{
	if (!e)
		return 1;

	if (e->tsec == 0 && e->tusec == 0)
		return 1;

	return 0;
}

static void log_get_next(log_entry_t **e)
{
	log_entry_t *next;

	next = (*e)+1;
	if (next == lb->buf_end)
		next = lb->buf_start;

	if (next == lb->tail)
		next = NULL;

	*e = next;
	return;
}

void pv_log_flush(struct pantavisor *pv, bool force)
{
	char *entry, *body, *tmp;
	unsigned long i = 1, j = 0, c = 0;
	int size;

	if (!pv)
		return;

	if (!pv->online)
		return;

	// FIXME: load rolled over logs and flush those first
	if (!lb)
		return;

	if (lb->count == 0)
		return;

	if (lb->count < 3 && !force)
		return;

	// take tail of log buffer
	log_entry_t *e = lb->tail;

	body = calloc(1, BUF_CHUNK * sizeof(char));
	sprintf(body, "[");

	for (;;) {
		size = sizeof(JSON_FORMAT) + 32;  // adjust timestamp
		size += strlen(level_names[e->level].name);
		size += strlen(e->source);
		size += strlen(e->data);
		entry = calloc(1, size * sizeof(char));

		for (c = 0, j = 0; e->data[j]; j++)
			if (e->data[j] == '\\') c++;

		if (c) {
			tmp = calloc(1, strlen(e->data) + (c * sizeof(char)));
			c = 0; j = 0;
			while (c < strlen(e->data)) {
				if (e->data[c] == '\\') {
					*(tmp+j) = '\\';
					j++;
				}
				*(tmp+j) = e->data[c];
				j++;
				c++;
			}
			snprintf(entry, size, JSON_FORMAT, e->tsec,
				e->tusec, level_names[e->level].name,
				e->source, tmp);
			free(tmp);
		} else {
			snprintf(entry, size, JSON_FORMAT, e->tsec,
				e->tusec, level_names[e->level].name,
				e->source, e->data);
		}

		if ((strlen(body) + size + 3) > BUF_CHUNK*i) {
			body = realloc(body, BUF_CHUNK*(i+1)* sizeof(char));
			memset(body+(BUF_CHUNK*i), 0, BUF_CHUNK * sizeof(char));
			i++;
		}
		body = strncat(body, entry, size);
		free(entry);
		log_get_next(&e);
		if (log_entry_null(e))
			break;
		body = strncat(body, ",", 1);
	}
	body = strcat(body, "]");

	if (pv_ph_upload_logs(pv, body))
		log_reset();

	free(body);

	return;
}

int pv_log_set_level(unsigned int level)
{
	if (level <= ALL)
		prio = level;

	return prio;
}

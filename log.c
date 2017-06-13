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

#include <sys/types.h>

#include "log.h"
#include "pantahub.h"

#define LEVEL_NAME(LEVEL)	{ LEVEL, #LEVEL }
static struct level_name level_names[] = {
	LEVEL_NAME(FATAL),
	LEVEL_NAME(ERROR),
	LEVEL_NAME(WARN),
	LEVEL_NAME(INFO),
	LEVEL_NAME(DEBUG)
};

static int prio = ERROR;

// default STDOUT
int log_fd = 1;

#define LOG_RING_SIZE		LOG_ITEM_SIZE * 64
#define LOG_ITEM_SIZE		4096	// JSON size

typedef struct {
	uint64_t tsec;		// 8 bytes
	uint32_t tusec;		// 4 bytes
	uint32_t level;		// 4 bytes
	char source[32];
	char data[LOG_ITEM_SIZE-48];	// 4096-48 bytes
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

static void log_reset(void)
{
	if (!lb)
		return;

	memset(lb->buf_start, 0, lb->buf_size);
	lb->tail = lb->buf_start;
	lb->head = lb->buf_start;
	lb->count = 0;
}

void pv_log_init(struct pantavisor *pv)
{
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

static void log_last_entry_to_file(void)
{
	log_entry_t *e = lb->last;

	dprintf(log_fd, "[pantavisor] %s\t", level_names[e->level].name);
	dprintf(log_fd, "[%"PRId64".%"PRId32"] ", e->tsec, e->tusec);
	dprintf(log_fd, "-- [%s]: %s\n", e->source, e->data);
}

void __vlog(char *module, int level, const char *fmt, ...)
{
	struct timeval tv;
	char buf[LOG_ITEM_SIZE-8];
	char *format = 0;
	va_list args;
	va_start(args, fmt);

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

	// add to ring buffer
	log_add(&e);

	// if config-logfile
	log_last_entry_to_file();

	free((char *) format);
	va_end(args);
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

void pv_log_flush(struct pantavisor *pv)
{
	char *entry, *body;
	unsigned long i = 1;
	int size;

	if (!pv->online)
		return;

	// FIXME: load rolled over logs and flush those first
	if (!lb)
		return;

	if (lb->count == 0)
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

		snprintf(entry, size, JSON_FORMAT, e->tsec,
				e->tusec, level_names[e->level].name,
				e->source, e->data);

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

	log_fd = open("/tmp/pantavisor.log", O_CREAT | O_SYNC | O_WRONLY | O_APPEND, 0644);

	return prio;
}

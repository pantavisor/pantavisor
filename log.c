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

#include <sys/types.h>

#include "log.h"

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
#define LOG_ITEM_SIZE		4096

typedef struct {
	unsigned long time;		// 4 bytes
	unsigned long level;		// 4 bytes
	char msg[LOG_ITEM_SIZE-8];	// 4096-8 bytes
} log_entry_t;

typedef struct {
	void *buf_start;
	void *buf_end;
	log_entry_t *head;
	log_entry_t *tail;
} log_buf_t;

static log_buf_t *lb = NULL;

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

	lb->buf_start = calloc(1, sizeof(log_entry_t) * pv->config->logsize);
	lb->buf_end = (char *) lb->buf_start + (sizeof(log_entry_t) * pv->config->logsize);
	lb->head = (log_entry_t*) lb->buf_start + 1;
	lb->tail = lb->buf_start;
}

void exit_error(int err, char *msg)
{
	printf("ERROR: %s (err=%d)\n", msg, err);
	printf("ERROR: rebooting system in 30 seconds\n");

	// FIXME: Should drop to ash console
	sync();
	sleep(30);
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

static char *strip_newline(const char *str)
{
	char *c = strdup(str);
	char *t = c;

	t = strchr(t, '\n');
	while (t) {
		*t = 32; // whitespace
		t = strchr(t, '\n');
	}

	return (char *) c;
}

static void log_add(log_entry_t *e)
{
	// FIXME: flush if (lb->head == lb->tail)

	memcpy(lb->head, e, sizeof(log_entry_t));
	lb->head += 1;
	if (lb->head == lb->buf_end) {
		lb->head = lb->buf_start;
	}
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
	e.time = (unsigned long) tv.tv_sec;
	e.level = level;

	format = strip_newline(fmt);
	snprintf(buf, sizeof(buf), "[%s]: %s", module, format);
	vsnprintf(e.msg, sizeof(buf), buf, args);

	log_add(&e);

	char date[sizeof(DATE_FORMAT)];
	const struct tm *t;
	t = localtime((time_t*) &e.time);

	dprintf(log_fd, "[pantavisor] %s\t", level_names[e.level].name);
	strftime(date, sizeof(date), "%Y-%m-%d %H:%M:%S", t);
	dprintf(log_fd, "[%s] ", date);
	dprintf(log_fd, "%s", e.msg);
	if (fmt[strlen(fmt)] != '\n')
		dprintf(log_fd, "\n");

	free((char *) format);
	va_end(args);
}

void pv_log_flush(struct pantavisor *pv)
{
	// FIXME: Push to cloud somehow, device meta?

	return;
}

int pv_log_set_level(unsigned int level)
{
	if (level <= ALL)
		prio = level;

	log_fd = open("/tmp/pantavisor.log", O_CREAT | O_SYNC | O_WRONLY | O_APPEND, 0644);

	return prio;
}

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

struct pv_json_format {
	char ch;
	int *off_dst;
	int *off_src;
	const char *src;
	char *dst;
	int (*format)(struct pv_json_format *);
};

static bool pv_log_is_json_special(char ch)
{
	switch(ch) {
		case '\\':
		case '\"':
		case '\n':
		case '\r':
		case '\t':
			return true;
		default:
			return false;
	}
}

static int pv_log_modify_to_json(struct pv_json_format *json_fmt)
{
	char replacement_char;

	json_fmt->dst[(*json_fmt->off_dst)++] = '\\';

	switch(json_fmt->ch) {
		case '\\':
		case '\"':
		case '/':
			replacement_char = json_fmt->ch;
			break;
		case '\n':
			replacement_char = 'n';
			break;
		case '\t':
			replacement_char = 't';
			break;
		case '\f':
			replacement_char = 'f';
			break;
		case '\b':
			replacement_char = 'b';
			break;
		case '\r':
			replacement_char = 'r';
			break;
		default:
			/*
			 * TODO: Return non-zero here instead of replacing
			 * with space.
			 * */
			replacement_char = ' ';
			break;

	}
	json_fmt->dst[(*json_fmt->off_dst)++] = replacement_char;
	return 0;
}

static char* pv_log_format_json(char *buf, int len)
{
	char *json_string = NULL;
	int idx = 0;
	int json_str_idx = 0;

	if (len > 0) //We make enough room for worst case.
		json_string = (char*) calloc(1, (len * 2) + 1); //Add 1 for '\0'.

	if (!json_string)
		goto out;
	while (len > idx) {
		if (pv_log_is_json_special(buf[idx])) {
			struct pv_json_format json_fmt = {
				.src = buf,
				.dst = json_string,
				.off_dst = &json_str_idx,
				.off_src = &idx,
				.ch = buf[idx],
				.format = pv_log_modify_to_json
			};
			json_fmt.format(&json_fmt);
		} else
			json_string[json_str_idx++] = buf[idx];
		idx++;
	}
out:
	return json_string;
}

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
	mkdir_p("/pv/logs", 0755);
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
	if (lb->head >= (log_entry_t*)lb->buf_end) {
		pv_log_flush(global_pv, true);
		lb->head = lb->buf_start;
	}
	lb->last = lb->head;
	memcpy(lb->head, e, sizeof(log_entry_t));
	lb->head += 1;

	if (lb->count < lb->size)
		lb->count++;
}

static void rotate_log(void)
{
	int n, fd, bytes;
	char *at = 0;
	char path[PATH_MAX];
	struct dirent **d;
	int cmd_status;

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
	tsh_run(tmp, 1, &cmd_status);

	lseek(log_fd, 0, SEEK_SET);
	ftruncate(log_fd, 0);
	log_count = 0;
	log_written = 0;
	/*
	 * We just resetted the counts above. So this
	 * should be safe to do.
	 * */
	__log("pantavisor", DEBUG, "Command %s execution status was %d\n",
			tmp, cmd_status);

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
	unsigned int written = 0;
	log_entry_t e;

	if (!lb)
		return;

	if (level >= prio)
		return;

	if (log_init_pid != getpid())
		return;
	// construct log entry in heap to copy

	gettimeofday(&tv, NULL);

	e.tsec = (uint64_t) tv.tv_sec;
	e.tusec = (uint32_t) tv.tv_usec;
	e.level = level;

	snprintf(e.source, sizeof(e.source), "%s", module);

	written = vsnprintf(e.data, sizeof(e.data), fmt, args);
	if (written >= sizeof(e.data))
		written = sizeof(e.data) - 1;
	if (e.data[written - 1] == '\n')
		e.data[written - 1] = ' ';

	// add to ring buffer
	log_add(&e);

	// if config-logfile
	log_last_entry_to_file();

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
	char *entry, *body, *formatted_json;
	unsigned long i = 1;
	int size;
	ssize_t buf_len = 0;
	ssize_t buf_rem = BUF_CHUNK - 1;/*Leave 1 NULL byte*/
	static volatile bool in_progress = false;

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

	if (!in_progress)
		in_progress = true;
	else
		goto exit;

	body = calloc(1, BUF_CHUNK * sizeof(char));
	if (!body)
		return;
	buf_len += sprintf(body, "[");

	for (;;) {
		bool break_loop = false;

		buf_rem -= buf_len;
		size = sizeof(JSON_FORMAT) + 32;  // adjust timestamp
		size += strlen(level_names[e->level].name);
		size += strlen(e->source);
		formatted_json = pv_log_format_json(e->data, strlen(e->data));
		if (!formatted_json)
			break;
		size += strlen(formatted_json);
		entry = calloc(1, (size + 1) * sizeof(char)); /* Add one for null*/
		if (!entry) {
			break_loop = true;
			goto free_json;
		}
		snprintf(entry, size + 1, JSON_FORMAT, e->tsec,
				e->tusec, level_names[e->level].name,
				e->source, formatted_json);

		if (buf_rem < size + 3) { /*3 = , ] and \0*/
			char *new_body = realloc(body, BUF_CHUNK*(i+1)* sizeof(char));

			if (!new_body) {
				break_loop = true;
				goto free_entry;
			}
			body = new_body;
			buf_rem += BUF_CHUNK;
			i++;
		}
		body = strncat(body, entry, size);
		buf_len += size;
free_entry:
		free(entry);
free_json:
		free(formatted_json);
		if (break_loop) /*Check separately to avoid loosing the next entry.*/
			break;
		log_get_next(&e);
		if (log_entry_null(e))
			break;
		body = strcat(body, ",");
		buf_len += 1;
	}
	if (buf_rem > 0)
		body = strcat(body, "]");
	else {
		/*
		 * We need to put the remaining ] and a NULL byte at the
		 * end.
		 * */
		char *new_body = realloc(body, strlen(body) + 2);

		if (new_body) {
			strcat(new_body, "]");
			body = new_body;
		} else {
			/*
			 * Worst case.
			 * Miss a byte instead of missing everything.
			 * */
			int body_len = strlen(body);

			body[body_len - 2] = ']';
		}
	}
	if (pv_ph_upload_logs(pv, body))
		log_reset();
	
	in_progress = false;
	free(body);
exit:
	return;
}

int pv_log_set_level(unsigned int level)
{
	if (level <= ALL)
		prio = level;

	return prio;
}

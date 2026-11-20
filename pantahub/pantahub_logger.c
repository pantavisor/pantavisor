/*
 * Copyright (c) 2020-2026 Pantacor Ltd.
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
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <linux/limits.h>
#include <sys/stat.h>
#include <sys/xattr.h>

#include "pantahub/pantahub_logger.h"
#include "pantahub/pantahub_proto.h"

#include "event/event.h"

#include "buffer.h"
#include "config.h"
#include "pantavisor.h"
#include "paths.h"
#include "state.h"

#include "utils/fs.h"
#include "utils/json.h"
#include "utils/list.h"
#include "utils/math.h"
#include "utils/str.h"

#define MODULE_NAME "pantahub_logger"
#define pv_log(level, msg, ...)                                                \
	vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__,       \
	     ##__VA_ARGS__)
#include "log.h"

#define LOGGER_JSON_FORMAT                                                     \
	"{ \"tsec\": %" PRId64 ", \"tnano\": %" PRId32 ",\
\"lvl\": \"%s\", \"src\": \"%s\",\"plat\":\"%s\",\
\"rev\": \"%s\" , \"msg\": \"%s\" }"

#define LOGGER_POS_XATTR "trusted.ph.logger.pos"

/*
 * Caps for a single POST /logs/ request. A single oversized POST is silently
 * dropped by pantahub, so we keep each request comfortably below the doubled
 * log buffer size (the reader block is PV_LOG_BUF_NITEMS * 1024, 128K by
 * default; the doubled buffer used for formatting is 256K).
 */
#define LOGGER_PUSH_MAX_BYTES (256 * 1024)
#define LOGGER_PUSH_MAX_FRAGS (200)

// seconds between passes that found nothing to send, or failed to
#define LOGGER_BACKOFF_MAX (10)

// an unreachable Hub fails every push; warn on the first, then summarise
#define LOGGER_FAIL_WARN_INTERVAL_S (600)

#define MAX_XATTR_SIZE 32

struct logger_file {
	char *path;
	off_t pos;
	struct dl_list list; // logger_file
};

/*
 * Two jobs share the code that reads the files and builds the batches. Push
 * sends the running revision as it is written and runs whenever the device is
 * logged in, updates included. Range sends what is left in older revisions,
 * newest first, and runs only while idle. Each has at most one request in
 * flight. The saved file position only moves in the response callback, for
 * the lines that request carried.
 */
struct logger_job {
	const char *name;
	pv_logs_req_t req;
	// the Hub client is in a state that runs this job
	bool started;
	// revision whose files the job reads
	char *rev;
	// file the last request came from
	char *cursor;
	// batch in flight
	char *file;
	off_t batch_end;
	int batch_frags;
	char *batch_head;
	// a rejected batch is retried one fragment at a time
	bool isolate;
	// seconds to wait before the next pass
	int backoff;
	struct pv_event_timer timer;
};

struct logger {
	// running revision, the one push reads
	char *rev;
	struct logger_job push;
	struct logger_job range;
	// next revision range visits, -1 when all are done
	int range_rev;
	struct dl_list files; // logger_file
	struct {
		unsigned long count;
		unsigned long suppressed;
		time_t last_warn;
	} push_fail;
};

static struct logger logger = {
	.push = { .name = "push", .req = PV_LOGS_PUSH },
	.range = { .name = "range", .req = PV_LOGS_RANGE },
	.range_rev = -1,
	.files = { &logger.files, &logger.files },
};

struct logger_batch {
	char *buf;
	size_t len;
	size_t cap;
	int frags;
};

static void _note_push_failure(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);

	logger.push_fail.count++;
	if (logger.push_fail.count > 1 &&
	    ts.tv_sec - logger.push_fail.last_warn <
		    LOGGER_FAIL_WARN_INTERVAL_S) {
		logger.push_fail.suppressed++;
		return;
	}

	pv_log(WARN,
	       "POST /logs/ got no HTTP response (transport error/timeout), failures=%lu, suppressed=%lu",
	       logger.push_fail.count, logger.push_fail.suppressed);
	logger.push_fail.suppressed = 0;
	logger.push_fail.last_warn = ts.tv_sec;
}

static void _note_push_ok(void)
{
	if (!logger.push_fail.count)
		return;

	pv_log(INFO, "POST /logs/ recovered after %lu failed attempts",
	       logger.push_fail.count);
	memset(&logger.push_fail, 0, sizeof(logger.push_fail));
}

static bool _is_pos_persistent(void)
{
	const char *tmpsize = pv_config_get_str(PV_STORAGE_LOGTEMPSIZE);

	return !tmpsize || !strlen(tmpsize);
}

static struct logger_file *_search_log_file(const char *path)
{
	struct logger_file *f, *tmp;
	dl_list_for_each_safe(f, tmp, &logger.files, struct logger_file, list)
	{
		if (pv_str_matches(path, strlen(path), f->path,
				   strlen(f->path)))
			return f;
	}

	return NULL;
}

static void _save_log_file_pos(off_t pos, const char *path)
{
	struct logger_file *f;

	f = _search_log_file(path);
	if (!f) {
		pv_log(DEBUG,
		       "log file '%s' not yet stored in memory. Saving new file...",
		       path);
		f = calloc(1, sizeof(struct logger_file));
		if (f) {
			f->path = strdup(path);
			if (!f->path) {
				free(f);
				f = NULL;
			} else {
				dl_list_add(&logger.files, &f->list);
			}
		}
	}
	if (!f) {
		pv_log(ERROR, "could not initialize log file: %s",
		       strerror(errno));
		return;
	}

	f->pos = pos;

	if (_is_pos_persistent()) {
		char value[MAX_DEC_STRING_SIZE_OF_TYPE(pos)];
		SNPRINTF_WTRUNC(value, sizeof(value), "%jd", (intmax_t)pos);
		if (setxattr(path, LOGGER_POS_XATTR, value, strlen(value), 0))
			pv_log(WARN, "xattr could not be saved in '%s': %s",
			       path, strerror(errno));
	}
}

static off_t _load_log_file_pos(const char *path)
{
	struct logger_file *f;
	char dst[MAX_XATTR_SIZE] = { 0 };
	off_t pos = 0;

	f = _search_log_file(path);
	if (f)
		return f->pos;

	pv_log(TRACE, "unknown file found in '%s'", path);

	if (!_is_pos_persistent())
		return pos;

	if (getxattr(path, LOGGER_POS_XATTR, dst, MAX_XATTR_SIZE - 1) > 0) {
		intmax_t parsed = 0;
		if (sscanf(dst, "%jd", &parsed) == 1)
			pos = (off_t)parsed;
	} else if (errno == ENODATA) {
		// if xattr does not yet exist for that path, we save it with pos 0
		_save_log_file_pos(pos, path);
	} else {
		pv_log(WARN, "xattr could not be loaded: %s", strerror(errno));
	}

	return pos;
}

static char *strnchr(char *src, char ch, int len)
{
	int idx = 0;

	if (!src || len <= 0)
		return NULL;
	for (idx = 0; idx < len && src[idx]; idx++) {
		if (src[idx] == ch)
			return src + idx;
	}
	return NULL;
}

static int _batch_append(struct logger_batch *batch, const char *frag)
{
	size_t len = strlen(frag);
	// ',' or '[' before the fragment, ']' and '\0' after it
	size_t need = batch->len + len + 3;

	if (need > batch->cap) {
		size_t cap = batch->cap ? batch->cap : 4096;
		char *buf;

		while (cap < need)
			cap *= 2;
		buf = realloc(batch->buf, cap);
		if (!buf)
			return -1;
		batch->buf = buf;
		batch->cap = cap;
	}

	batch->buf[batch->len++] = batch->frags ? ',' : '[';
	memcpy(batch->buf + batch->len, frag, len);
	batch->len += len;
	batch->buf[batch->len] = '\0';
	batch->frags++;

	return 0;
}

static bool _batch_is_full(struct logger_batch *batch, bool isolate,
			   size_t next_len)
{
	if (!batch->frags)
		return false;

	if (isolate || batch->frags >= LOGGER_PUSH_MAX_FRAGS)
		return true;

	// always take one fragment so an oversized single line still makes progress
	return batch->len + next_len + 2 > LOGGER_PUSH_MAX_BYTES;
}

static char *_new_fragment(const char *line, const char *platform,
			   const char *source, const char *rev)
{
	char *formatted, *frag;
	int len;

	formatted = pv_json_format(line, strlen(line));
	if (!formatted)
		return NULL;

	len = snprintf(NULL, 0, LOGGER_JSON_FORMAT, (uint64_t)0, (uint32_t)0,
		       pv_log_level_name(INFO), source, platform, rev,
		       formatted);
	frag = calloc(len + 1, sizeof(char));
	if (frag)
		snprintf(frag, len + 1, LOGGER_JSON_FORMAT, (uint64_t)0,
			 (uint32_t)0, pv_log_level_name(INFO), source, platform,
			 rev, formatted);

	free(formatted);
	return frag;
}

static void _job_clear_batch(struct logger_job *job)
{
	free(job->file);
	job->file = NULL;
	free(job->batch_head);
	job->batch_head = NULL;
	job->batch_end = 0;
	job->batch_frags = 0;
}

static int _job_send(struct logger_job *job, struct logger_batch *batch,
		     const char *filename, off_t end, const char *head)
{
	batch->buf[batch->len++] = ']';
	batch->buf[batch->len] = '\0';

	_job_clear_batch(job);
	job->file = strdup(filename);
	job->batch_head = strndup(head, 256);
	job->batch_end = end;
	job->batch_frags = batch->frags;
	if (!job->file) {
		_job_clear_batch(job);
		return -1;
	}

	if (pv_pantahub_proto_post_logs(job->req, batch->buf)) {
		_job_clear_batch(job);
		return -1;
	}

	// not DEBUG: this line would be pushed again with the next batch
	pv_log(TRACE, "%s: POST /logs/ with %d lines from %s up to %jd",
	       job->name, batch->frags, filename, (intmax_t)end);

	return 1;
}

static bool _is_file_in_flight(const char *filename)
{
	return (logger.push.file && !strcmp(logger.push.file, filename)) ||
	       (logger.range.file && !strcmp(logger.range.file, filename));
}

/*
 * The log files contain each line ending in a '\n'. Read a block of the file
 * from the saved position and send the complete lines in it as one batch.
 * If a new line isn't found, it's probably not written yet so wait for it to
 * appear and try again later.
 *
 * Returns 1 if a request was sent, 0 if there was nothing to send and -1 on
 * error.
 */
static int _push_file(struct logger_job *job, const char *filename,
		      const char *platform, const char *source)
{
	struct logger_batch batch = { 0 };
	struct buffer *log_buff = NULL, *large_buff = NULL;
	char *head = NULL;
	off_t pos, end;
	struct stat st;
	int ret = 0, fd = -1;
	int bytes_read, offset = 0;

	// the other job has lines of this file in flight: wait for them
	if (_is_file_in_flight(filename)) {
		pv_log(DEBUG, "%s: %s busy, trying later", job->name, filename);
		return -1;
	}

	pos = _load_log_file_pos(filename);

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		pv_log(ERROR, "open failed for %s: %s", filename,
		       strerror(errno));
		return -1;
	}

	// the stored position is past the end: the file was truncated
	if (!fstat(fd, &st) && st.st_size < pos)
		pos = 0;

	if (lseek(fd, pos, SEEK_SET) == (off_t)-1) {
		pv_log(ERROR, "Unable to seek to position %jd for %s",
		       (intmax_t)pos, filename);
		ret = -1;
		goto out;
	}

	large_buff = pv_buffer_get(true);
	log_buff = pv_buffer_get(false);
	if (!large_buff || !log_buff) {
		ret = -1;
		goto out;
	}

	bytes_read = pv_fs_file_read_nointr(fd, log_buff->buf, log_buff->size);
	if (bytes_read <= 0)
		goto out;

	/*
	 * we've to get rid of all NULL bytes in buf otherwise the
	 * pv_json_format won't really work as it'll see the length of the
	 * string short.
	 */
	pv_str_replace_char(log_buff->buf, bytes_read, '\0', ' ');

	end = pos;
	while (offset < bytes_read) {
		char *src = log_buff->buf + offset;
		char *line = large_buff->buf;
		int remaining = bytes_read - offset;
		char *newline_at = strnchr(src, '\n', remaining);
		char *frag;
		int len;

		if (newline_at) {
			len = newline_at - src;
			memcpy(line, src, len);
			line[len] = '\0';
			len++;
		} else if (bytes_read == log_buff->size && !offset) {
			/*
			 * We've read a full block and found no newline: there
			 * is nothing else we can do but send it as it is.
			 */
			len = remaining;
			memcpy(line, src, len);
			line[len] = '\0';
		} else {
			/*
			 * We can't differentiate between a slow growing file
			 * and a file that doesn't grow at all, so a last line
			 * without '\n' is not sent until it gets one.
			 */
			break;
		}

		if (!strlen(line)) {
			offset += len;
			end = pos + offset;
			continue;
		}

		frag = _new_fragment(line, platform, source, job->rev);
		if (!frag) {
			// don't try for next lines if this one couldn't be json escaped
			pv_log(ERROR, "json format error for filename %s",
			       filename);
			break;
		}

		if (_batch_is_full(&batch, job->isolate, strlen(frag))) {
			free(frag);
			break;
		}

		if (_batch_append(&batch, frag)) {
			pv_log(ERROR, "alloc error for filename %s", filename);
			free(frag);
			break;
		}

		if (!head)
			head = frag;
		else
			free(frag);

		offset += len;
		end = pos + offset;
	}

	if (batch.frags)
		ret = _job_send(job, &batch, filename, end, head);
	else if (end != pos)
		// only empty lines were found
		_save_log_file_pos(end, filename);

out:
	free(head);
	free(batch.buf);
	pv_buffer_drop(log_buff);
	pv_buffer_drop(large_buff);
	close(fd);
	return ret;
}

/*
 * The path under the revision log directory is <platform>/<source>.
 */
static int _push_path(struct logger_job *job, const char *path, int offset)
{
	char platform[64];
	const char *source = path;
	const char *slash_at = strchr(path + offset, '/');

	if (!slash_at) {
		SNPRINTF_WTRUNC(platform, sizeof(platform),
				"pantavisor-UNKNOWN");
	} else {
		SNPRINTF_WTRUNC(platform, sizeof(platform), "%.*s",
				(int)(slash_at - (path + offset)),
				path + offset);
		source = slash_at;
	}

	return _push_file(job, path, platform, source);
}

struct logger_paths {
	char **v;
	int n;
	int cap;
};

static void _paths_free(struct logger_paths *paths)
{
	for (int i = 0; i < paths->n; i++)
		free(paths->v[i]);
	free(paths->v);
}

static int _paths_add(struct logger_paths *paths, const char *path)
{
	if (paths->n == paths->cap) {
		int cap = paths->cap ? paths->cap * 2 : 32;
		char **v = realloc(paths->v, cap * sizeof(char *));
		if (!v)
			return -1;
		paths->v = v;
		paths->cap = cap;
	}

	paths->v[paths->n] = strdup(path);
	if (!paths->v[paths->n])
		return -1;
	paths->n++;

	return 0;
}

static int _paths_cmp(const void *a, const void *b)
{
	return strcmp(*(char *const *)a, *(char *const *)b);
}

static void _collect_files(const char *dir, struct logger_paths *paths)
{
	char path[PATH_MAX];
	struct dirent *d;
	struct stat st;
	DIR *dp;

	dp = opendir(dir);
	if (!dp)
		return;

	while ((d = readdir(dp))) {
		if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
			continue;

		SNPRINTF_WTRUNC(path, sizeof(path), "%s/%s", dir, d->d_name);
		if (lstat(path, &st))
			continue;

		if (S_ISDIR(st.st_mode))
			_collect_files(path, paths);
		else if (S_ISREG(st.st_mode) && !strstr(d->d_name, ".gz"))
			_paths_add(paths, path);
	}

	closedir(dp);
}

/*
 * One request per pass, from the first file after the one the last request
 * came from, so a file that never stops growing cannot starve the others.
 *
 * Returns 1 if a request was sent, 0 if there was nothing to send and -1 if
 * nothing was sent but some file could not be read.
 */
static int _push_revision(struct logger_job *job)
{
	struct logger_paths paths = { 0 };
	char dir[PATH_MAX];
	int offset, start = 0, ret = 0;

	pv_paths_pv_log(dir, sizeof(dir), job->rev);
	// skip <logs>/<revision>/ to get to <platform>/<source>
	offset = strlen(dir) + 1;

	_collect_files(dir, &paths);
	qsort(paths.v, paths.n, sizeof(char *), _paths_cmp);

	if (job->cursor) {
		while (start < paths.n &&
		       strcmp(paths.v[start], job->cursor) <= 0)
			start++;
	}

	for (int i = 0; i < paths.n; i++) {
		const char *path = paths.v[(start + i) % paths.n];
		int res = _push_path(job, path, offset);

		if (res > 0) {
			free(job->cursor);
			job->cursor = strdup(path);
			ret = 1;
			break;
		}
		if (res < 0)
			ret = -1;
	}

	_paths_free(&paths);
	return ret;
}

static int _get_max_revision(void)
{
	char path[PATH_MAX];
	struct dirent *d;
	DIR *dp;
	int max_revision = 0;

	pv_paths_pv_log(path, sizeof(path), "");
	dp = opendir(path);
	if (!dp)
		return max_revision;

	while ((d = readdir(dp))) {
		int this_rev = -1;

		if (d->d_type != DT_DIR && d->d_type != DT_UNKNOWN)
			continue;
		if (sscanf(d->d_name, "%d", &this_rev) == 1 &&
		    this_rev > max_revision)
			max_revision = this_rev;
	}

	closedir(dp);
	return max_revision;
}

static void _job_set_rev(struct logger_job *job, const char *rev)
{
	free(job->rev);
	job->rev = rev ? strdup(rev) : NULL;
	free(job->cursor);
	job->cursor = NULL;
}

static int _range_next(void)
{
	struct logger_job *job = &logger.range;
	char rev[16];
	int ret;

	while (logger.range_rev >= 0) {
		SNPRINTF_WTRUNC(rev, sizeof(rev), "%d", logger.range_rev);

		// skip current revision
		if (logger.rev && !strcmp(rev, logger.rev)) {
			logger.range_rev--;
			continue;
		}

		_job_set_rev(job, rev);
		ret = _push_revision(job);
		if (ret)
			return ret;

		pv_log(DEBUG, "range: all logs pushed for rev %s", rev);
		logger.range_rev--;
	}

	pv_log(INFO, "range: all previous revisions pushed");
	_job_set_rev(job, NULL);
	return 0;
}

static bool _is_enabled(struct pantavisor *pv)
{
	return pv && pv->state && pv->state->rev && pv->remote_mode &&
	       pv_config_get_bool(PV_LOG_PUSH) &&
	       (pv_config_get_log_server_outputs() &
		LOG_SERVER_OUTPUT_FILE_TREE);
}

static void _job_cb(evutil_socket_t fd, short event, void *arg);

static void _job_arm(struct logger_job *job, int timeout)
{
	pv_event_timer_arm(&job->timer, timeout, _job_cb, job);
}

// runs a pass now unless the job is stopped or waiting for a response
static void _job_kick(struct logger_job *job)
{
	if (job->started && !pv_pantahub_proto_is_posting_logs(job->req))
		_job_arm(job, 0);
}

static void _job_backoff(struct logger_job *job)
{
	if (job->backoff < LOGGER_BACKOFF_MAX)
		job->backoff++;
	_job_arm(job, job->backoff);
}

static void _set_running_rev(const char *rev)
{
	pv_log(DEBUG, "pushing logs of revision %s", rev);

	free(logger.rev);
	logger.rev = strdup(rev);

	// let in-flight requests finish: their callbacks only touch their file
	_job_set_rev(&logger.push, rev);
	logger.push.backoff = 0;
	_job_kick(&logger.push);

	logger.range_rev = _get_max_revision();
	logger.range.backoff = 0;
	_job_kick(&logger.range);
}

/*
 * Common to both jobs before a pass. Returns false if the pass must not go on:
 * log push is off, or the running revision changed after a non-reboot update
 * and both jobs were restarted.
 */
static bool _job_prepare(struct logger_job *job)
{
	struct pantavisor *pv = pv_get_instance();

	// checked on every pass, so PV_LOG_PUSH applies at run time
	if (!_is_enabled(pv)) {
		_job_arm(job, LOGGER_BACKOFF_MAX);
		return false;
	}

	if (!logger.rev || strcmp(logger.rev, pv->state->rev)) {
		_set_running_rev(pv->state->rev);
		return false;
	}

	return true;
}

static void _push_run(void)
{
	struct logger_job *job = &logger.push;

	if (!_job_prepare(job))
		return;

	// a request is in flight: its response decides what comes next
	if (_push_revision(job) > 0)
		return;

	_job_backoff(job);
}

static void _range_run(void)
{
	struct logger_job *job = &logger.range;

	if (!_job_prepare(job))
		return;

	// done until the running revision changes
	if (logger.range_rev < 0)
		return;

	if (_range_next() > 0)
		return;

	_job_backoff(job);
}

static void _job_run(struct logger_job *job)
{
	if (!job->started || pv_pantahub_proto_is_posting_logs(job->req))
		return;

	if (job == &logger.push)
		_push_run();
	else
		_range_run();
}

static void _job_cb(evutil_socket_t fd, short event, void *arg)
{
	pv_log(TRACE, "run event: cb=%p", (void *)_job_cb);
	_job_run(arg);
}

static bool _is_transient(int status)
{
	return status < 400 || status == 401 || status == 403 ||
	       status == 408 || status == 429 || status >= 500;
}

void pv_pantahub_logger_on_posted(pv_logs_req_t which, int status,
				  const char *body)
{
	struct logger_job *job =
		which == PV_LOGS_PUSH ? &logger.push : &logger.range;
	bool again = true;

	if (!job->file)
		return;

	if (status >= 200 && status < 300) {
		_note_push_ok();
		_save_log_file_pos(job->batch_end, job->file);
		job->isolate = false;
		job->backoff = 0;
	} else if (status < 0) {
		_note_push_failure();
		again = false;
	} else if (_is_transient(status)) {
		pv_log(WARN,
		       "POST /logs/ transient HTTP error (code=%d; body='%s')",
		       status, body ? body : "");
		again = false;
	} else if (job->batch_frags > 1) {
		// pin down the offending line before dropping it
		pv_log(WARN,
		       "POST /logs/ rejected batch content (code=%d; body='%s')",
		       status, body ? body : "");
		job->isolate = true;
	} else {
		/*
		 * A single fragment the server will never accept: drop it and
		 * advance past it so the rest of the backlog and all newer logs
		 * still upload, instead of wedging the whole stream on one
		 * poison line.
		 */
		pv_log(ERROR,
		       "dropping log fragment POST /logs/ refused (code=%d); advancing past pos %jd: %s",
		       status, (intmax_t)job->batch_end,
		       job->batch_head ? job->batch_head : "");
		_save_log_file_pos(job->batch_end, job->file);
		job->isolate = false;
	}

	_job_clear_batch(job);

	if (!job->started)
		return;

	if (again)
		// keep draining the backlog right away
		_job_run(job);
	else
		_job_backoff(job);
}

static void _job_start(struct logger_job *job)
{
	if (job->started)
		return;

	job->started = true;
	_job_kick(job);
}

static void _job_pause(struct logger_job *job)
{
	job->started = false;
	pv_event_timer_stop(&job->timer);
}

// in-flight requests are cancelled by the session close
static void _job_reset(struct logger_job *job)
{
	_job_pause(job);
	_job_clear_batch(job);
	_job_set_rev(job, NULL);
	job->isolate = false;
	job->backoff = 0;
}

void pv_pantahub_logger_start_push(void)
{
	_job_start(&logger.push);
}

void pv_pantahub_logger_start_range(void)
{
	_job_start(&logger.range);
}

void pv_pantahub_logger_pause(void)
{
	_job_pause(&logger.push);
	_job_pause(&logger.range);
}

void pv_pantahub_logger_stop(void)
{
	struct logger_file *f, *tmp;

	_job_reset(&logger.push);
	_job_reset(&logger.range);
	logger.range_rev = -1;
	free(logger.rev);
	logger.rev = NULL;

	dl_list_for_each_safe(f, tmp, &logger.files, struct logger_file, list)
	{
		dl_list_del(&f->list);
		free(f->path);
		free(f);
	}
}

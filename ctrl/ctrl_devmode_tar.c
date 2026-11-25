/*
 * Copyright (c) 2025 Pantacor Ltd.
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "ctrl_devmode_tar.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/http_struct.h>

#define MODULE_NAME "devmode-tar"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define TAR_BLOCK 512
// bytes put into one HTTP chunk
#define TAR_CHUNK (64 * 1024)
// the connection is given time to send when it holds more than this
#define TAR_HIGH_WATER (1024 * 1024)
// folders below this depth are listed but not entered
#define TAR_MAX_DEPTH 128

struct tar_level {
	DIR *dir;
	size_t pathlen;
};

struct tar_stream {
	struct evhttp_request *req;
	struct event *timer;
	// counts what is skipped without writing anything
	bool dry;
	bool done;
	int skipped;

	// the first entry, then the content of the folders on the stack
	int dirfd;
	char leaf[NAME_MAX];
	bool first;
	struct tar_level *stack;
	size_t depth, cap;
	char path[PATH_MAX];

	// the file being written
	int fd;
	off_t remaining;
	size_t pad;
};

static int tar_digits(size_t n)
{
	int d = 1;

	while (n >= 10) {
		n /= 10;
		d++;
	}

	return d;
}

static void tar_octal(char *dst, size_t len, unsigned long long v)
{
	char tmp[32];

	// the field is zeroed already, so it ends with a NUL
	snprintf(tmp, sizeof(tmp), "%0*llo", (int)len - 1, v);
	memcpy(dst, tmp, len - 1);
}

// an octal field of len bytes holds values below 8^(len-1)
static bool tar_fits(unsigned long long v, int len)
{
	return v < (1ULL << (3 * (len - 1)));
}

static void tar_block(struct evbuffer *out, char *h)
{
	unsigned int sum = 0;

	memset(h + 148, ' ', 8);
	for (int i = 0; i < TAR_BLOCK; i++)
		sum += (unsigned char)h[i];
	snprintf(h + 148, 8, "%06o", sum);
	h[155] = ' ';
	evbuffer_add(out, h, TAR_BLOCK);
}

static void tar_padding(struct evbuffer *out, size_t size)
{
	static const char zero[TAR_BLOCK];
	size_t pad = (TAR_BLOCK - size % TAR_BLOCK) % TAR_BLOCK;

	if (pad)
		evbuffer_add(out, zero, pad);
}

static size_t tar_pax_record(char *dst, const char *key, const char *val)
{
	size_t rest = strlen(key) + strlen(val) + 3;
	int d = 1;

	while (tar_digits(rest + d) != d)
		d++;

	return snprintf(dst, rest + d + 1, "%zu %s=%s\n", rest + d, key, val);
}

// one header block, with a pax header before it for what ustar cannot hold
static void tar_header(struct evbuffer *out, const char *name, char type,
		       const struct stat *st, size_t size, const char *link)
{
	char h[TAR_BLOCK] = { 0 };
	char *pax = malloc(2 * PATH_MAX + 1024);
	size_t plen = 0;
	char num[32];
	long long mtime = st->st_mtim.tv_sec;

	if (!pax)
		return;

	if (strlen(name) > 100)
		plen += tar_pax_record(pax + plen, "path", name);
	if (link && strlen(link) > 100)
		plen += tar_pax_record(pax + plen, "linkpath", link);
	if (!tar_fits(size, 12)) {
		snprintf(num, sizeof(num), "%zu", size);
		plen += tar_pax_record(pax + plen, "size", num);
	}
	if (!tar_fits(st->st_uid, 8)) {
		snprintf(num, sizeof(num), "%u", st->st_uid);
		plen += tar_pax_record(pax + plen, "uid", num);
	}
	if (!tar_fits(st->st_gid, 8)) {
		snprintf(num, sizeof(num), "%u", st->st_gid);
		plen += tar_pax_record(pax + plen, "gid", num);
	}
	if (mtime < 0 || !tar_fits(mtime, 12)) {
		snprintf(num, sizeof(num), "%lld", mtime);
		plen += tar_pax_record(pax + plen, "mtime", num);
		mtime = 0;
	}

	if (plen) {
		char x[TAR_BLOCK] = { 0 };

		snprintf(x, 100, "PaxHeader");
		tar_octal(x + 100, 8, 0644);
		tar_octal(x + 124, 12, plen);
		tar_octal(x + 136, 12, 0);
		x[156] = 'x';
		memcpy(x + 257, "ustar", 6);
		memcpy(x + 263, "00", 2);
		tar_block(out, x);
		evbuffer_add(out, pax, plen);
		tar_padding(out, plen);
	}
	free(pax);

	memcpy(h, name, strlen(name) > 100 ? 99 : strlen(name));
	tar_octal(h + 100, 8, st->st_mode & 07777);
	tar_octal(h + 108, 8, tar_fits(st->st_uid, 8) ? st->st_uid : 0);
	tar_octal(h + 116, 8, tar_fits(st->st_gid, 8) ? st->st_gid : 0);
	tar_octal(h + 124, 12, tar_fits(size, 12) ? size : 0);
	tar_octal(h + 136, 12, mtime);
	h[156] = type;
	if (link)
		memcpy(h + 157, link, strlen(link) > 100 ? 99 : strlen(link));
	memcpy(h + 257, "ustar", 6);
	memcpy(h + 263, "00", 2);
	tar_block(out, h);
}

static void tar_push(struct tar_stream *t, DIR *d, size_t pathlen)
{
	if (t->depth == t->cap) {
		size_t cap = t->cap ? t->cap * 2 : 16;
		struct tar_level *s = realloc(t->stack, cap * sizeof(*s));

		if (!s) {
			closedir(d);
			t->skipped++;
			return;
		}
		t->stack = s;
		t->cap = cap;
	}
	t->stack[t->depth].dir = d;
	t->stack[t->depth].pathlen = pathlen;
	t->depth++;
}

// write the entry for name in dirfd, whose path relative to the container root is t->path
static void tar_entry(struct tar_stream *t, struct evbuffer *out, int dirfd,
		      const char *name)
{
	struct stat st;
	char link[PATH_MAX];
	char full[PATH_MAX + 2];
	size_t pathlen = strlen(t->path);
	int fd;

	if (fstatat(dirfd, name, &st, AT_SYMLINK_NOFOLLOW)) {
		t->skipped++;
		return;
	}

	if (S_ISDIR(st.st_mode)) {
		DIR *d = NULL;

		fd = openat(dirfd, name,
			    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		if (fd >= 0)
			d = fdopendir(fd);
		if (!d) {
			if (fd >= 0)
				close(fd);
			t->skipped++;
			return;
		}
		if (!t->dry) {
			snprintf(full, sizeof(full), "%s/", t->path);
			tar_header(out, full, '5', &st, 0, NULL);
		}
		if (t->depth >= TAR_MAX_DEPTH) {
			closedir(d);
			t->skipped++;
		} else {
			tar_push(t, d, pathlen);
		}
	} else if (S_ISLNK(st.st_mode)) {
		ssize_t n = readlinkat(dirfd, name, link, sizeof(link) - 1);

		if (n < 0) {
			t->skipped++;
			return;
		}
		link[n] = '\0';
		if (!t->dry)
			tar_header(out, t->path, '2', &st, 0, link);
	} else if (S_ISREG(st.st_mode)) {
		struct stat fst;

		if (t->dry)
			return;
		fd = openat(dirfd, name,
			    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
		if (fd < 0 || fstat(fd, &fst) || !S_ISREG(fst.st_mode)) {
			if (fd >= 0)
				close(fd);
			t->skipped++;
			return;
		}
		tar_header(out, t->path, '0', &fst, fst.st_size, NULL);
		t->fd = fd;
		t->remaining = fst.st_size;
		t->pad = fst.st_size;
	} else {
		t->skipped++;
	}
}

// add the next entry to out; false when there are none left
static bool tar_next(struct tar_stream *t, struct evbuffer *out)
{
	struct tar_level *top;
	struct dirent *de;
	size_t len;

	if (t->first) {
		t->first = false;
		if (*t->leaf) {
			tar_entry(t, out, t->dirfd, t->leaf);
		} else {
			DIR *d = fdopendir(t->dirfd);

			if (!d)
				return false;
			t->dirfd = -1;
			tar_push(t, d, 0);
		}
		return true;
	}

	while (t->depth) {
		top = &t->stack[t->depth - 1];
		de = readdir(top->dir);
		if (!de) {
			closedir(top->dir);
			t->depth--;
			continue;
		}
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;

		len = strlen(de->d_name);
		if (top->pathlen + len + 3 > sizeof(t->path)) {
			t->skipped++;
			return true;
		}
		snprintf(t->path + top->pathlen, sizeof(t->path) - top->pathlen,
			 "%s%s", top->pathlen ? "/" : "", de->d_name);
		tar_entry(t, out, dirfd(top->dir), de->d_name);
		return true;
	}

	return false;
}

static void tar_step(struct tar_stream *t, struct evbuffer *out)
{
	static char rbuf[TAR_CHUNK];

	if (t->fd >= 0) {
		size_t want = t->remaining > (off_t)sizeof(rbuf) ?
				      sizeof(rbuf) :
				      (size_t)t->remaining;
		ssize_t n = want ? read(t->fd, rbuf, want) : 0;

		// a file that shrank is padded with zeros to the size in its header
		if (n <= 0) {
			memset(rbuf, 0, want);
			n = want;
		}
		evbuffer_add(out, rbuf, n);
		t->remaining -= n;
		if (t->remaining <= 0) {
			close(t->fd);
			t->fd = -1;
			tar_padding(out, t->pad);
		}
		return;
	}

	if (!tar_next(t, out)) {
		char end[2 * TAR_BLOCK] = { 0 };

		evbuffer_add(out, end, sizeof(end));
		t->done = true;
	}
}

static void tar_free(struct tar_stream *t)
{
	if (!t)
		return;
	if (t->timer)
		event_free(t->timer);
	if (t->fd >= 0)
		close(t->fd);
	while (t->depth)
		closedir(t->stack[--t->depth].dir);
	if (t->dirfd >= 0)
		close(t->dirfd);
	free(t->stack);
	free(t);
}

static void tar_on_complete(struct evhttp_request *req, void *ctx)
{
	(void)req;
	tar_free(ctx);
}

static void tar_tick(evutil_socket_t sock, short events, void *ctx)
{
	struct tar_stream *t = ctx;
	struct evbuffer *buf = evbuffer_new();
	struct evhttp_connection *con = evhttp_request_get_connection(t->req);
	struct timeval tv = { 0, 0 };
	struct bufferevent *bev =
		con ? evhttp_connection_get_bufferevent(con) : NULL;

	(void)sock;
	(void)events;
	if (!buf)
		return;

	while (!t->done && evbuffer_get_length(buf) < TAR_CHUNK)
		tar_step(t, buf);

	if (evbuffer_get_length(buf))
		evhttp_send_reply_chunk(t->req, buf);
	evbuffer_free(buf);

	if (t->done) {
		// the complete callback frees the stream
		evhttp_send_reply_end(t->req);
		return;
	}

	// the client reads slower than we send: wait instead of queueing more
	if (bev &&
	    evbuffer_get_length(bufferevent_get_output(bev)) > TAR_HIGH_WATER)
		tv.tv_usec = 5000;
	event_add(t->timer, &tv);
}

int pv_ctrl_devmode_tar_start(struct evhttp_request *req, int dirfd,
			      const char *leaf, const char *path)
{
	struct tar_stream *t, *dry;
	struct evkeyvalq *headers;
	struct evhttp_connection *con;
	struct evbuffer *scratch;
	struct stat st;
	struct timeval now = { 0, 0 };
	char num[16];

	if (strlen(leaf) >= NAME_MAX || strlen(path) >= PATH_MAX - 2) {
		errno = ENAMETOOLONG;
		return -1;
	}
	if (*leaf && fstatat(dirfd, leaf, &st, AT_SYMLINK_NOFOLLOW))
		return -1;

	t = calloc(1, sizeof(*t));
	dry = calloc(1, sizeof(*dry));
	scratch = evbuffer_new();
	if (!t || !dry || !scratch) {
		free(t);
		free(dry);
		if (scratch)
			evbuffer_free(scratch);
		errno = ENOMEM;
		return -1;
	}

	// the number of skipped entries goes in a header, so it is counted first;
	// the folder is opened again because a directory descriptor shares its read position
	dry->dry = true;
	dry->first = true;
	dry->fd = -1;
	dry->dirfd =
		*leaf ? dup(dirfd) : openat(dirfd, ".", O_RDONLY | O_DIRECTORY);
	snprintf(dry->leaf, sizeof(dry->leaf), "%s", leaf);
	snprintf(dry->path, sizeof(dry->path), "%s", path);
	if (dry->dirfd >= 0) {
		while (tar_next(dry, scratch))
			;
	}
	evbuffer_free(scratch);

	t->req = req;
	t->first = true;
	t->fd = -1;
	t->dirfd = dirfd;
	snprintf(t->leaf, sizeof(t->leaf), "%s", leaf);
	snprintf(t->path, sizeof(t->path), "%s", path);

	con = evhttp_request_get_connection(req);
	t->timer = evtimer_new(evhttp_connection_get_base(con), tar_tick, t);
	if (!t->timer) {
		t->dirfd = -1;
		tar_free(t);
		tar_free(dry);
		errno = ENOMEM;
		return -1;
	}

	headers = evhttp_request_get_output_headers(req);
	evhttp_add_header(headers, "Content-Type", "application/x-tar");
	snprintf(num, sizeof(num), "%d", dry->skipped);
	evhttp_add_header(headers, "X-Pv-Skipped", num);
	// an HTTP/1.0 client has no chunks: the end of the body is the close
	if (req->major == 1 && req->minor == 0)
		evhttp_add_header(headers, "Connection", "close");
	tar_free(dry);

	evhttp_request_set_on_complete_cb(req, tar_on_complete, t);
	evhttp_send_reply_start(req, HTTP_OK, "OK");
	event_add(t->timer, &now);

	return 0;
}

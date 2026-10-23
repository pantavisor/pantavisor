/*
 * Copyright (c) 2026 Pantacor Ltd.
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

#include "ctrl_endpoints.h"
#include "ctrl.h"
#include "ctrl_file.h"
#include "ctrl_upload.h"
#include "ctrl_util.h"
#include "pantavisor.h"
#include "platforms.h"
#include "state.h"
#include "storage.h"
#include "volumes.h"
#include "utils/json.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <event2/buffer.h>
#include <event2/http.h>
#include <event2/http_struct.h>
#include <event2/keyvalq_struct.h>

#if __has_include(<linux/openat2.h>)
#include <linux/openat2.h>
#else
struct open_how {
	unsigned long long flags;
	unsigned long long mode;
	unsigned long long resolve;
};
#define RESOLVE_NO_MAGICLINKS 0x02
#define RESOLVE_IN_ROOT 0x10
#endif

#ifndef SYS_openat2
#define SYS_openat2 437
#endif

#define MODULE_NAME "devmode-files-ep"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define DMF_PREFIX "/devmode/files/"
#define DMF_TMP_PREFIX ".pv-devmode-tmp."

struct dmf_ctx {
	char container[NAME_MAX];
	// relative to the container root, no "." or ".." segments, empty for the root
	char path[PATH_MAX];
	struct evkeyvalq query;
	struct pv_platform *plat;
	// the filesystem of the container as the container sees it
	int rootfd;
};

struct dmf_put {
	int dirfd;
	char tmp[NAME_MAX];
	char leaf[NAME_MAX];
	char path[PATH_MAX];
	mode_t mode;
	bool set_owner;
	uid_t uid;
	gid_t gid;
	bool pending;
};

static void dmf_ctx_clear(struct dmf_ctx *c)
{
	evhttp_clear_headers(&c->query);
	if (c->rootfd >= 0)
		close(c->rootfd);
	c->rootfd = -1;
}

// the path as the client sent it, without a leading slash; -1 if it is not safe
static int dmf_normalize(const char *in, char *out, size_t size)
{
	size_t len = 0;

	out[0] = '\0';
	if (*in == '/')
		return -1;

	while (*in) {
		const char *end = strchr(in, '/');
		size_t seg = end ? (size_t)(end - in) : strlen(in);

		if (seg >= NAME_MAX)
			return -1;
		if (seg == 2 && !strncmp(in, "..", 2))
			return -1;
		if (seg && !(seg == 1 && in[0] == '.')) {
			if (len + seg + 2 > size)
				return -1;
			if (len)
				out[len++] = '/';
			memcpy(out + len, in, seg);
			len += seg;
			out[len] = '\0';
		}
		in += seg;
		while (*in == '/')
			in++;
	}

	return 0;
}

static const char *dmf_query(struct dmf_ctx *c, const char *key)
{
	return evhttp_find_header(&c->query, key);
}

// split the request uri into container, path and query; 0 or an HTTP code with a message
static int dmf_parse(struct evhttp_request *req, struct dmf_ctx *c,
		     const char **msg)
{
	struct evhttp_uri *uri;
	const char *raw_path, *query, *rest;
	char *path = NULL;
	char *slash;
	int code = HTTP_BADREQUEST;

	memset(c, 0, sizeof(*c));
	c->rootfd = -1;
	TAILQ_INIT(&c->query);
	*msg = "Bad path";

	uri = evhttp_uri_parse(evhttp_request_get_uri(req));
	if (!uri)
		return code;

	raw_path = evhttp_uri_get_path(uri);
	query = evhttp_uri_get_query(uri);
	if (query)
		evhttp_parse_query_str(query, &c->query);

	path = raw_path ? evhttp_uridecode(raw_path, 0, NULL) : NULL;
	if (!path || strncmp(path, DMF_PREFIX, strlen(DMF_PREFIX)))
		goto out;

	rest = path + strlen(DMF_PREFIX);
	slash = strchr(rest, '/');
	if (slash)
		*slash = '\0';
	if (!*rest || strlen(rest) >= NAME_MAX || !strcmp(rest, ".") ||
	    !strcmp(rest, "..")) {
		*msg = "Missing container name";
		goto out;
	}
	snprintf(c->container, sizeof(c->container), "%s", rest);

	if (slash && dmf_normalize(slash + 1, c->path, sizeof(c->path))) {
		*msg = "The path must be relative to the container root and cannot contain ..";
		goto out;
	}

	code = 0;
out:
	free(path);
	evhttp_uri_free(uri);
	if (code)
		evhttp_clear_headers(&c->query);

	return code;
}

// devmode must run and the container must have an inlay; 0 or an HTTP code with a message
static int dmf_find_container(struct dmf_ctx *c, const char **msg)
{
	struct pantavisor *pv = pv_get_instance();
	int code = pv_ctrl_devmode_check(msg);

	if (code)
		return code;

	c->plat = pv_state_fetch_platform(pv->state, c->container);
	if (!c->plat || !c->plat->devmode_inlay) {
		*msg = "Container not found";
		return HTTP_NOTFOUND;
	}

	return 0;
}

// the overlay of the container that pantavisor mounts for the devmode folder:
// a delete there leaves an overlay delete marker in the inlay
static int dmf_open_root(struct dmf_ctx *c, const char **msg)
{
	char root[PATH_MAX] = { 0 };

	if (pv_volumes_devmode_fs_root(c->plat, root, sizeof(root))) {
		*msg = "The container has no devmode filesystem";
		return PV_HTTP_CONFLICT;
	}

	c->rootfd = open(root, O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (c->rootfd < 0) {
		*msg = "Cannot open the devmode filesystem";
		return HTTP_INTERNAL;
	}

	return 0;
}

// open rel inside the root: a symlink, also an absolute one or one with .., can
// only lead to something inside the root. Without openat2 symlinks are refused.
static int dmf_walk_open(int rootfd, const char *rel, int flags, mode_t mode)
{
	char buf[PATH_MAX];
	char *save = NULL, *seg, *next;
	int cur = openat(rootfd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);

	if (cur < 0)
		return -1;
	snprintf(buf, sizeof(buf), "%s", rel);
	seg = strtok_r(buf, "/", &save);
	if (!seg) {
		close(cur);
		return openat(rootfd, ".", flags | O_CLOEXEC);
	}

	while (seg) {
		int fd;

		next = strtok_r(NULL, "/", &save);
		if (next)
			fd = openat(cur, seg,
				    O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
					    O_CLOEXEC);
		else
			fd = openat(cur, seg, flags | O_NOFOLLOW | O_CLOEXEC,
				    mode);
		close(cur);
		if (fd < 0)
			return -1;
		cur = fd;
		seg = next;
	}

	return cur;
}

static int dmf_openat(int rootfd, const char *rel, int flags, mode_t mode)
{
	struct open_how how = { 0 };
	int fd;

	how.flags = flags | O_CLOEXEC;
	how.mode = mode;
	how.resolve = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS;

	fd = syscall(SYS_openat2, rootfd, *rel ? rel : ".", &how, sizeof(how));
	if (fd >= 0 || errno != ENOSYS)
		return fd;

	return dmf_walk_open(rootfd, rel, flags, mode);
}

// the directory part of rel and the name in it
static void dmf_split(const char *rel, char *dir, size_t dsize, char *leaf,
		      size_t lsize)
{
	const char *slash = strrchr(rel, '/');

	if (slash) {
		snprintf(dir, dsize, "%.*s", (int)(slash - rel), rel);
		snprintf(leaf, lsize, "%s", slash + 1);
	} else {
		dir[0] = '\0';
		snprintf(leaf, lsize, "%s", rel);
	}
}

// open a directory, creating the ones that are missing
static int dmf_open_dir(int rootfd, const char *rel, bool create)
{
	char prefix[PATH_MAX];
	size_t len = 0;
	int parent = dmf_openat(rootfd, "", O_RDONLY | O_DIRECTORY, 0);
	const char *p = rel;

	if (parent < 0)
		return -1;

	while (*p) {
		const char *end = strchr(p, '/');
		size_t seg = end ? (size_t)(end - p) : strlen(p);
		char name[NAME_MAX];
		int fd;

		snprintf(name, sizeof(name), "%.*s", (int)seg, p);
		if (len)
			prefix[len++] = '/';
		memcpy(prefix + len, p, seg);
		len += seg;
		prefix[len] = '\0';

		fd = dmf_openat(rootfd, prefix, O_RDONLY | O_DIRECTORY, 0);
		if (fd < 0 && create && errno == ENOENT) {
			if (mkdirat(parent, name, 0755) && errno != EEXIST) {
				close(parent);
				return -1;
			}
			fd = dmf_openat(rootfd, prefix, O_RDONLY | O_DIRECTORY,
					0);
		}
		close(parent);
		if (fd < 0)
			return -1;
		parent = fd;
		p += seg;
		while (*p == '/')
			p++;
	}

	return parent;
}

static int dmf_errno_code(const char **msg)
{
	switch (errno) {
	case ENOENT:
		*msg = "Not found";
		return HTTP_NOTFOUND;
	case ENOTDIR:
	case EISDIR:
	case EEXIST:
	case ENOTEMPTY:
		*msg = "A directory is in the way, or the path is not a directory";
		return PV_HTTP_CONFLICT;
	case ELOOP:
	case EXDEV:
		*msg = "The path leads through a symlink that cannot be followed";
		return HTTP_BADREQUEST;
	case ENOSPC:
	case EDQUOT:
		*msg = "Not enough disk space available";
		return PV_HTTP_INSF_STORAGE;
	default:
		*msg = "Cannot access the path";
		return HTTP_INTERNAL;
	}
}

static void dmf_json_number_field(struct pv_json_ser *js, const char *key,
				  double v)
{
	pv_json_ser_key(js, key);
	pv_json_ser_number(js, v);
}

static void dmf_json_octal_field(struct pv_json_ser *js, const char *key,
				 mode_t mode)
{
	char buf[16];

	snprintf(buf, sizeof(buf), "%04o", (unsigned)(mode & 07777));
	pv_json_ser_key(js, key);
	pv_json_ser_string(js, buf);
}

static char *dmf_fd_sha256(int fd)
{
	char path[64];

	snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);

	return pv_storage_calculate_sha256sum(path);
}

static void dmf_send_put_reply(struct evhttp_request *req, int code,
			       const char *path, int fd)
{
	struct pv_json_ser js;
	struct stat st;
	char *sha = dmf_fd_sha256(fd);

	if (!sha || fstat(fd, &st)) {
		free(sha);
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL,
					 "Cannot read back the file");
		return;
	}

	pv_json_ser_init(&js, 512);
	pv_json_ser_object(&js);
	pv_json_ser_key(&js, "path");
	pv_json_ser_string(&js, path);
	pv_json_ser_key(&js, "sha256");
	pv_json_ser_string(&js, sha);
	dmf_json_number_field(&js, "size", st.st_size);
	pv_json_ser_object_pop(&js);
	free(sha);

	pv_ctrl_utils_send_json(req, code, NULL, pv_json_ser_str(&js));
}

// manifest of the inlay

struct dmf_entry {
	char name[NAME_MAX + 1];
};

static int dmf_entry_cmp(const void *a, const void *b)
{
	return strcmp(((const struct dmf_entry *)a)->name,
		      ((const struct dmf_entry *)b)->name);
}

static void dmf_list_dir(struct pv_json_ser *js, int dirfd, const char *rel);

static void dmf_list_entry(struct pv_json_ser *js, int dirfd, const char *rel,
			   const char *name)
{
	char path[PATH_MAX];
	struct stat st;

	if (fstatat(dirfd, name, &st, AT_SYMLINK_NOFOLLOW))
		return;

	snprintf(path, sizeof(path), "%s%s%s", rel, *rel ? "/" : "", name);
	pv_json_ser_object(js);
	pv_json_ser_key(js, "path");
	pv_json_ser_string(js, path);

	if (S_ISCHR(st.st_mode) && st.st_rdev == 0) {
		pv_json_ser_key(js, "type");
		pv_json_ser_string(js, "deleted");
	} else if (S_ISREG(st.st_mode)) {
		int fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
		char *sha = fd >= 0 ? dmf_fd_sha256(fd) : NULL;

		pv_json_ser_key(js, "type");
		pv_json_ser_string(js, "file");
		dmf_json_number_field(js, "size", st.st_size);
		dmf_json_octal_field(js, "mode", st.st_mode);
		dmf_json_number_field(js, "uid", st.st_uid);
		dmf_json_number_field(js, "gid", st.st_gid);
		pv_json_ser_key(js, "sha256");
		pv_json_ser_string(js, sha ? sha : "");
		free(sha);
		if (fd >= 0)
			close(fd);
	} else if (S_ISDIR(st.st_mode)) {
		pv_json_ser_key(js, "type");
		pv_json_ser_string(js, "dir");
		dmf_json_octal_field(js, "mode", st.st_mode);
		dmf_json_number_field(js, "uid", st.st_uid);
		dmf_json_number_field(js, "gid", st.st_gid);
	} else if (S_ISLNK(st.st_mode)) {
		char target[PATH_MAX] = { 0 };

		if (readlinkat(dirfd, name, target, sizeof(target) - 1) < 0)
			target[0] = '\0';
		pv_json_ser_key(js, "type");
		pv_json_ser_string(js, "symlink");
		pv_json_ser_key(js, "target");
		pv_json_ser_string(js, target);
		dmf_json_number_field(js, "uid", st.st_uid);
		dmf_json_number_field(js, "gid", st.st_gid);
	} else {
		pv_json_ser_key(js, "type");
		pv_json_ser_string(js, "special");
		dmf_json_octal_field(js, "mode", st.st_mode);
	}
	pv_json_ser_object_pop(js);

	if (S_ISDIR(st.st_mode)) {
		int sub =
			openat(dirfd, name,
			       O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		if (sub >= 0) {
			dmf_list_dir(js, sub, path);
			close(sub);
		}
	}
}

// entries sorted, a directory before its content
static void dmf_list_dir(struct pv_json_ser *js, int dirfd, const char *rel)
{
	struct dmf_entry *arr = NULL;
	size_t n = 0, cap = 0;
	struct dirent *de;
	int dup_fd = dup(dirfd);
	DIR *d = dup_fd >= 0 ? fdopendir(dup_fd) : NULL;

	if (!d) {
		if (dup_fd >= 0)
			close(dup_fd);
		return;
	}

	while ((de = readdir(d))) {
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;
		if (n == cap) {
			struct dmf_entry *bigger = realloc(
				arr, (cap ? cap * 2 : 32) * sizeof(*arr));
			if (!bigger)
				break;
			arr = bigger;
			cap = cap ? cap * 2 : 32;
		}
		snprintf(arr[n].name, sizeof(arr[n].name), "%s", de->d_name);
		n++;
	}
	closedir(d);

	qsort(arr, n, sizeof(*arr), dmf_entry_cmp);
	for (size_t i = 0; i < n; i++)
		dmf_list_entry(js, dirfd, rel, arr[i].name);
	free(arr);
}

static void dmf_manifest(struct evhttp_request *req, struct dmf_ctx *c)
{
	struct pantavisor *pv = pv_get_instance();
	struct pv_json_ser js;
	char inlay[PATH_MAX] = { 0 };
	int fd;

	pv_ctrl_devmode_inlay_path(pv->state, c->plat, inlay, sizeof(inlay));

	pv_json_ser_init(&js, 4096);
	pv_json_ser_object(&js);
	pv_json_ser_key(&js, "container");
	pv_json_ser_string(&js, c->container);
	pv_json_ser_key(&js, "files");
	pv_json_ser_array(&js);

	fd = open(inlay, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (fd >= 0) {
		dmf_list_dir(&js, fd, "");
		close(fd);
	}

	pv_json_ser_array_pop(&js);
	pv_json_ser_object_pop(&js);

	pv_ctrl_utils_send_json(req, HTTP_OK, NULL, pv_json_ser_str(&js));
}

// GET

static void dmf_get_file(struct evhttp_request *req, struct dmf_ctx *c)
{
	const char *msg = NULL;
	struct stat st;
	int fd, code;

	code = dmf_open_root(c, &msg);
	if (code) {
		pv_ctrl_utils_send_error(req, code, msg);
		return;
	}

	fd = dmf_openat(c->rootfd, c->path, O_RDONLY, 0);
	if (fd < 0) {
		code = dmf_errno_code(&msg);
		pv_ctrl_utils_send_error(req, code, msg);
		return;
	}

	if (fstat(fd, &st) || !S_ISREG(st.st_mode)) {
		close(fd);
		pv_ctrl_utils_send_error(req, HTTP_BADREQUEST,
					 "Not a regular file");
		return;
	}

	evhttp_add_header(evhttp_request_get_output_headers(req),
			  "Content-Type", "application/octet-stream");
	if (st.st_size > 0 &&
	    evbuffer_add_file(evhttp_request_get_output_buffer(req), fd, 0,
			      st.st_size)) {
		close(fd);
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL,
					 "Cannot send the file");
		return;
	}
	if (st.st_size <= 0)
		close(fd);

	evhttp_send_reply(req, HTTP_OK, NULL, NULL);
}

static void dmf_get(struct evhttp_request *req, void *ctx)
{
	struct dmf_ctx c;
	const char *msg = NULL;
	int code;

	if (pv_ctrl_utils_is_req_ok(req, ctx, NULL) != 0)
		return;

	code = dmf_parse(req, &c, &msg);
	if (!code)
		code = dmf_find_container(&c, &msg);
	if (code) {
		pv_ctrl_utils_send_error(req, code, msg);
		dmf_ctx_clear(&c);
		return;
	}

	if (*c.path)
		dmf_get_file(req, &c);
	else
		dmf_manifest(req, &c);

	dmf_ctx_clear(&c);
}

// DELETE

static int dmf_remove_tree(int dirfd, const char *name)
{
	struct stat st;
	int sub, dup_fd;
	DIR *d;
	struct dirent *de;
	int ret = 0;

	if (fstatat(dirfd, name, &st, AT_SYMLINK_NOFOLLOW))
		return -1;
	if (!S_ISDIR(st.st_mode))
		return unlinkat(dirfd, name, 0);

	sub = openat(dirfd, name,
		     O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (sub < 0)
		return -1;
	dup_fd = dup(sub);
	d = dup_fd >= 0 ? fdopendir(dup_fd) : NULL;
	if (!d) {
		if (dup_fd >= 0)
			close(dup_fd);
		close(sub);
		return -1;
	}

	// removing while reading is fine for the names already read, so read all first
	size_t n = 0, cap = 0;
	struct dmf_entry *arr = NULL;

	while ((de = readdir(d))) {
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;
		if (n == cap) {
			struct dmf_entry *bigger = realloc(
				arr, (cap ? cap * 2 : 32) * sizeof(*arr));
			if (!bigger) {
				ret = -1;
				break;
			}
			arr = bigger;
			cap = cap ? cap * 2 : 32;
		}
		snprintf(arr[n].name, sizeof(arr[n].name), "%s", de->d_name);
		n++;
	}
	closedir(d);

	for (size_t i = 0; !ret && i < n; i++)
		ret = dmf_remove_tree(sub, arr[i].name);
	free(arr);
	close(sub);

	return ret ? ret : unlinkat(dirfd, name, AT_REMOVEDIR);
}

static void dmf_delete(struct evhttp_request *req, void *ctx)
{
	struct dmf_ctx c;
	const char *msg = NULL;
	char dir[PATH_MAX], leaf[NAME_MAX];
	const char *rec;
	struct stat st;
	int code, dirfd;

	if (pv_ctrl_utils_is_req_ok(req, ctx, NULL) != 0)
		return;

	code = dmf_parse(req, &c, &msg);
	if (!code)
		code = dmf_find_container(&c, &msg);
	if (!code && !*c.path) {
		msg = "Missing path";
		code = HTTP_BADREQUEST;
	}
	if (!code)
		code = dmf_open_root(&c, &msg);
	if (code) {
		pv_ctrl_utils_send_error(req, code, msg);
		dmf_ctx_clear(&c);
		return;
	}

	rec = dmf_query(&c, "recursive");
	dmf_split(c.path, dir, sizeof(dir), leaf, sizeof(leaf));
	dirfd = dmf_open_dir(c.rootfd, dir, false);
	if (dirfd < 0 || fstatat(dirfd, leaf, &st, AT_SYMLINK_NOFOLLOW)) {
		code = dmf_errno_code(&msg);
		if (dirfd >= 0)
			close(dirfd);
		pv_ctrl_utils_send_error(req, code, msg);
		dmf_ctx_clear(&c);
		return;
	}

	if (S_ISDIR(st.st_mode) && rec && strcmp(rec, "0") && *rec)
		code = dmf_remove_tree(dirfd, leaf);
	else
		code = unlinkat(dirfd, leaf,
				S_ISDIR(st.st_mode) ? AT_REMOVEDIR : 0);
	if (code)
		code = dmf_errno_code(&msg);
	close(dirfd);
	dmf_ctx_clear(&c);

	if (code) {
		pv_ctrl_utils_send_error(req, code, msg);
		return;
	}

	pv_ctrl_utils_send_ok(req);
}

// PUT

static void dmf_put_free(void *priv)
{
	struct dmf_put *put = priv;

	if (!put)
		return;
	if (put->pending)
		unlinkat(put->dirfd, put->tmp, 0);
	if (put->dirfd >= 0)
		close(put->dirfd);
	free(put);
}

static int dmf_put_done(struct pv_ctrl_file *file)
{
	struct dmf_put *put = file->priv;
	const char *msg = NULL;
	int code;

	// a failed upload is answered by the caller
	if (!file->ok)
		return -1;

	if (fchmod(file->fd, put->mode) ||
	    (put->set_owner && fchown(file->fd, put->uid, put->gid)) ||
	    fsync(file->fd) ||
	    renameat(put->dirfd, put->tmp, put->dirfd, put->leaf)) {
		code = dmf_errno_code(&msg);
		pv_ctrl_utils_send_error(file->req, code, msg);
		return -1;
	}
	put->pending = false;
	fsync(put->dirfd);

	pv_log(INFO, "devmode file %s stored", put->path);
	dmf_send_put_reply(file->req, HTTP_OK, put->path, file->fd);

	return 0;
}

static bool dmf_parse_number(const char *s, int base, unsigned long max,
			     unsigned long *out)
{
	char *end = NULL;

	errno = 0;
	*out = strtoul(s, &end, base);

	return *s && end && !*end && !errno && *out <= max;
}

// mode, uid and gid from the query; false if one is not a number
static bool dmf_put_attrs(struct dmf_ctx *c, struct dmf_put *put)
{
	const char *v;
	unsigned long n;

	put->mode = 0644;
	v = dmf_query(c, "mode");
	if (v) {
		if (!dmf_parse_number(v, 8, 07777, &n))
			return false;
		put->mode = n;
	}

	v = dmf_query(c, "uid");
	if (v) {
		if (!dmf_parse_number(v, 10, 0xfffffffeUL, &n))
			return false;
		put->uid = n;
		put->set_owner = true;
	}
	v = dmf_query(c, "gid");
	if (v) {
		if (!dmf_parse_number(v, 10, 0xfffffffeUL, &n))
			return false;
		put->gid = n;
		put->set_owner = true;
	}
	if (put->set_owner) {
		// an owner given in part keeps root for the other half
		if (!dmf_query(c, "uid"))
			put->uid = 0;
		if (!dmf_query(c, "gid"))
			put->gid = 0;
	}

	return true;
}

static void dmf_put_other(struct evhttp_request *req, struct dmf_ctx *c,
			  struct dmf_put *put, const char *type)
{
	int dirfd = put->dirfd;
	const char *msg = NULL, *target = dmf_query(c, "target");
	struct pv_json_ser js;
	int code = 0, fd;

	if (!strcmp(type, "dir")) {
		if (mkdirat(dirfd, put->leaf, put->mode) && errno != EEXIST)
			code = dmf_errno_code(&msg);
		else if ((fd = openat(dirfd, put->leaf,
				      O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
					      O_CLOEXEC)) < 0)
			code = dmf_errno_code(&msg);
		else {
			if (dmf_query(c, "mode"))
				fchmod(fd, put->mode);
			if (put->set_owner)
				fchown(fd, put->uid, put->gid);
			close(fd);
		}
	} else {
		struct stat st;

		if (!target || !*target) {
			msg = "A symlink needs a target";
			code = HTTP_BADREQUEST;
		} else if (!fstatat(dirfd, put->leaf, &st,
				    AT_SYMLINK_NOFOLLOW) &&
			   S_ISDIR(st.st_mode)) {
			msg = "A directory is in the way";
			code = PV_HTTP_CONFLICT;
		} else {
			unlinkat(dirfd, put->leaf, 0);
			if (symlinkat(target, dirfd, put->leaf))
				code = dmf_errno_code(&msg);
			else if (put->set_owner)
				fchownat(dirfd, put->leaf, put->uid, put->gid,
					 AT_SYMLINK_NOFOLLOW);
		}
	}

	if (code) {
		pv_ctrl_utils_send_error(req, code, msg);
		return;
	}

	pv_json_ser_init(&js, 256);
	pv_json_ser_object(&js);
	pv_json_ser_key(&js, "path");
	pv_json_ser_string(&js, put->path);
	pv_json_ser_key(&js, "type");
	pv_json_ser_string(&js, type);
	pv_json_ser_object_pop(&js);
	pv_ctrl_utils_send_json(req, HTTP_OK, NULL, pv_json_ser_str(&js));
}

static void dmf_put_file(struct evhttp_request *req, struct dmf_put *put)
{
	static unsigned int counter;
	const char *msg = NULL;
	struct pv_ctrl_file *file;
	struct stat st;
	int fd, code;

	if (!fstatat(put->dirfd, put->leaf, &st, AT_SYMLINK_NOFOLLOW)) {
		if (S_ISDIR(st.st_mode)) {
			pv_ctrl_utils_drain_on_arrive_with_err(
				req, PV_HTTP_CONFLICT,
				"A directory is in the way");
			dmf_put_free(put);
			return;
		}
	}

	snprintf(put->tmp, sizeof(put->tmp), "%s%d.%u", DMF_TMP_PREFIX,
		 (int)getpid(), counter++);
	fd = openat(put->dirfd, put->tmp,
		    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0) {
		code = dmf_errno_code(&msg);
		pv_ctrl_utils_drain_on_arrive_with_err(req, code, msg);
		dmf_put_free(put);
		return;
	}
	put->pending = true;

	file = pv_ctrl_file_new_fd(req, fd, put->path);
	if (!file) {
		close(fd);
		pv_ctrl_utils_drain_on_arrive_with_err(req, HTTP_INTERNAL,
						       "Out of memory");
		dmf_put_free(put);
		return;
	}
	file->priv = put;
	file->priv_free = dmf_put_free;

	pv_ctrl_upload_start_file(req, file, dmf_put_done);
}

static void dmf_put(struct evhttp_request *req, void *ctx)
{
	struct dmf_ctx c;
	struct dmf_put *put = NULL;
	const char *msg = NULL, *type = "file";
	char dir[PATH_MAX];
	char err[PV_CTRL_MAX_ERR] = { 0 };
	int code;

	code = pv_ctrl_utils_is_req_ok(req, ctx, err);
	if (code) {
		pv_ctrl_utils_drain_on_arrive_with_err(req, code, err);
		return;
	}

	code = dmf_parse(req, &c, &msg);
	if (code) {
		pv_ctrl_utils_drain_on_arrive_with_err(req, code, msg);
		return;
	}

	code = dmf_find_container(&c, &msg);
	if (!code && !*c.path) {
		msg = "Missing path";
		code = HTTP_BADREQUEST;
	}
	if (!code)
		code = dmf_open_root(&c, &msg);
	if (!code) {
		put = calloc(1, sizeof(*put));
		if (!put) {
			msg = "Out of memory";
			code = HTTP_INTERNAL;
		} else {
			put->dirfd = -1;
		}
	}
	if (!code && !dmf_put_attrs(&c, put)) {
		msg = "mode must be octal, uid and gid decimal numbers";
		code = HTTP_BADREQUEST;
	}
	if (dmf_query(&c, "type") && *dmf_query(&c, "type"))
		type = dmf_query(&c, "type");
	if (!code && strcmp(type, "file") && strcmp(type, "dir") &&
	    strcmp(type, "symlink")) {
		msg = "type must be file, dir or symlink";
		code = HTTP_BADREQUEST;
	}
	if (code)
		goto fail;

	snprintf(put->path, sizeof(put->path), "%s", c.path);
	dmf_split(c.path, dir, sizeof(dir), put->leaf, sizeof(put->leaf));
	put->dirfd = dmf_open_dir(c.rootfd, dir, true);
	if (put->dirfd < 0) {
		code = dmf_errno_code(&msg);
		goto fail;
	}

	if (!strcmp(type, "file")) {
		dmf_ctx_clear(&c);
		dmf_put_file(req, put);
		return;
	}

	pv_ctrl_utils_drain_req(req);
	dmf_put_other(req, &c, put, type);
	dmf_put_free(put);
	dmf_ctx_clear(&c);
	return;

fail:
	pv_ctrl_utils_drain_on_arrive_with_err(req, code, msg);
	dmf_put_free(put);
	dmf_ctx_clear(&c);
}

int pv_ctrl_endpoints_devmode_files_init(void)
{
	pv_ctrl_add_endpoint("/devmode/files/{}", EVHTTP_REQ_GET, true,
			     dmf_get);
	pv_ctrl_add_endpoint("/devmode/files/{}/{*}", EVHTTP_REQ_GET, true,
			     dmf_get);
	pv_ctrl_add_endpoint("/devmode/files/{}/{*}", EVHTTP_REQ_PUT, true,
			     dmf_put);
	pv_ctrl_add_endpoint("/devmode/files/{}/{*}", EVHTTP_REQ_DELETE, true,
			     dmf_delete);

	return 0;
}

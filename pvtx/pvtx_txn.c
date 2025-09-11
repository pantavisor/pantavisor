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

#include "pvtx_txn.h"

#include "utils/fs.h"
#include "pvtx_state.h"
#include "pvtx_ctrl.h"
#include "pvtx_buffer.h"
#include "pvtx_tar.h"
#include "pvtx_jsmn_utils.h"
#include "pvtx_utils/sha256_i.h"

#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <dirent.h>
#include <linux/limits.h>
#include <sys/random.h>
#include <sys/stat.h>

#define PVTX_TXN_PATH "PVTXDIR"
#define PVTX_TXN_PREFIX_PATH "PREFIX"
#define PVTX_TXN_DEFAULT_PATH "/var/pvr-sdk/pvtx"
#define PVTX_TXN_FILE ".status"
#define PVTX_TXN_JSON "current.json"
#define PVTX_TXN_DST_CONFIG ".pvr/config"
#define PVTX_TXN_DST_JSON ".pvr/json"
#define PVTX_TXN_DST_RUNJS "bsp/run.json"
#define PVTX_TXN_OBJ_EXP "^[0-9a-f]{64}$"
#define PVTX_TXN_BUF_ENV "PVTX_OBJECT_BUF_SIZE"
#define PVTX_TXN_BUF_MIN (512)
#define PVTX_TXN_BUF_MAX (10485760)

enum pvtx_txn_status {
	PVTX_TXN_STATUS_ERROR,
	PVTX_TXN_STATUS_SET,
	PVTX_TXN_STATUS_ACTIVE,
	PVTX_TXN_STATUS_ABORTED,
	PVTX_TXN_STATUS_COMMITED,
	PVTX_TXN_STATUS_DEPLOYED,
	PVTX_TXN_STATUS_UNKNOWN,
};

struct pvtx_txn {
	int status;
	int is_local;
	char obj[PATH_MAX];
};

struct pvtx_queue {
	struct pvtx_txn txn;
	char queue[PATH_MAX];
	int count;
	int error;
};

static char pvtxdir_cache[PATH_MAX] = { 0 };
static char pvtx_state_json_cache[PATH_MAX] = { 0 };

static const char *get_pvtxdir(void)
{
	if (pvtxdir_cache[0] != '\0')
		return pvtxdir_cache;

	char *dir = getenv(PVTX_TXN_PATH);
	if (dir) {
		memccpy(pvtxdir_cache, dir, '\0', PATH_MAX);
		return pvtxdir_cache;
	}

	char *pfx = getenv(PVTX_TXN_PREFIX_PATH);
	if (pfx)
		pv_fs_path_concat(pvtxdir_cache, 2, pfx, PVTX_TXN_DEFAULT_PATH);
	else
		memccpy(pvtxdir_cache, PVTX_TXN_DEFAULT_PATH, '\0', PATH_MAX);

	return pvtxdir_cache;
}

static const char *get_json_path(void)
{
	if (pvtx_state_json_cache[0] != '\0')
		return pvtx_state_json_cache;

	pv_fs_path_concat(pvtx_state_json_cache, 2, get_pvtxdir(),
			  PVTX_TXN_JSON);

	return pvtx_state_json_cache;
}

static void get_data_file(char *path)
{
	pv_fs_path_concat(path, 2, get_pvtxdir(), PVTX_TXN_FILE);
}

static struct pv_pvtx_buffer *get_buffer()
{
	return pv_pvtx_buffer_from_env(PVTX_TXN_BUF_ENV, PVTX_TXN_BUF_MIN,
				       PVTX_TXN_BUF_MAX, 512);
}

static char *url_encode(const char *url)
{
	int count = 0;
	const char *p = url;
	while ((p = strchr(p + 1, '/')))
		++count;

	char *enc = calloc(strlen(url) + count * 2 + 1, sizeof(char));
	if (!enc)
		return NULL;

	for (size_t i = 0, j = 0; j < strlen(url); j++) {
		if (url[j] != '/') {
			enc[i] = url[j];
			i++;
			continue;
		}

		enc[i] = '%';
		enc[i + 1] = '2';
		enc[i + 2] = 'F';
		i += 3;
	}
	return enc;
}

static char *url_decode(const char *url)
{
	int count = 0;
	const char *p = url;
	while ((p = strcasestr(p + 1, "%2F")))
		++count;

	char *dec = calloc(strlen(url) - count * 2 + 1, sizeof(char));
	if (!dec)
		return NULL;

	for (size_t i = 0, j = 0; i < strlen(url); i++) {
		if (!strncmp(&url[j], "%2", 2) &&
		    (url[j + 2] == 'f' || url[j + 2] == 'F')) {
			dec[i] = '/';
			j += 3;
			continue;
		}

		dec[i] = url[j];
		j++;
	}

	return dec;
}

static int pvtx_save(void *data, size_t size)
{
	char path[PATH_MAX] = { 0 };
	get_data_file(path);
	return pv_fs_file_write_no_sync(path, data, size);
}

static void *pvtx_load()
{
	char path[PATH_MAX] = { 0 };
	get_data_file(path);
	return pv_fs_file_read(path, NULL);
}

static int write_object_from_content(const char *path,
				     struct pv_pvtx_tar_content *con,
				     struct pv_pvtx_error *err)
{
	char tmp[PATH_MAX] = { 0 };
	int fd = pv_fs_file_tmp(path, tmp);
	if (fd < 0) {
		PVTX_ERROR_SET(err, -1,
			       "couldn't create temp file, object %s "
			       "will not be written",
			       con->name);
		return -1;
	}

	int ret = -1;
	struct pv_pvtx_buffer *buf = get_buffer();
	if (!buf) {
		PVTX_ERROR_SET(err, -1,
			       "couldn't allocate buffer, object %s "
			       "will not be written",
			       con->name);
		goto out;
	}

	ssize_t written = 0;
	while (written < con->size) {
		ssize_t cur = pv_pvtx_tar_content_read_block(con, buf->data,
							     buf->size);
		if (cur <= 0)
			break;

		ssize_t to_write = cur;
		if ((written + cur) > con->size)
			to_write = con->size - written;
		written += pv_fs_file_write_nointr(fd, buf->data, to_write);
		memset(buf->data, 0, buf->size);
	}

	if (rename(tmp, path) != 0) {
		PVTX_ERROR_SET(err, -1,
			       "couldn't move temp file, object %s"
			       "will not be written",
			       con->name);

		remove(tmp);
		goto out;
	}

	pv_pvtx_error_clear(err);
out:
	close(fd);
	pv_pvtx_buffer_free(buf);

	return err->code;
}

static char *find_json(const char *dir)
{
	struct stat st = { 0 };
	if (stat(dir, &st) != 0)
		return NULL;

	if (!S_ISDIR(st.st_mode))
		return strdup(dir);

	char test_path[PATH_MAX] = { 0 };
	const char *loc[] = { "json", ".pvr/json" };
	for (size_t i = 0; i < sizeof(loc) / sizeof(loc[0]); i++) {
		pv_fs_path_concat(test_path, 2, dir, loc[i]);

		if (pv_fs_path_exist(test_path))
			return strdup(test_path);

		memset(test_path, 0, PATH_MAX);
	}
	return NULL;
}

static int init_state_json(const char *from, struct pv_pvtx_error *err)
{
	char *json = NULL;
	size_t json_len = 0;
	struct pv_pvtx_state *st = NULL;
	const char *err_msg = "couldn't initialize json with %s: %s";

	pv_pvtx_error_clear(err);

	if (!strncmp(from, "current", strlen("current"))) {
		struct pv_pvtx_ctrl *ctrl = pv_pvtx_ctrl_new(NULL);
		if (!ctrl) {
			PVTX_ERROR_SET(err, -1, err_msg, from,
				       "pv-ctrl connection error");
			goto out;
		}
		json = pv_pvtx_ctrl_steps_get(ctrl, "current", &json_len);
		pv_pvtx_ctrl_free(ctrl);
		goto out;

	} else if (!strncmp(from, "empty", strlen("empty"))) {
		json = strdup(PVTX_STATE_EMPTY);
		json_len = strlen(json);
	} else {
		char *loc = find_json(from);
		if (!loc) {
			PVTX_ERROR_SET(err, -1, err_msg, from,
				       "trail location error");
			goto out;
		}

		st = pv_pvtx_state_from_file(loc, err);

		if (!st)
			PVTX_ERROR_PREPEND(err, "error loding %s", loc);

		free(loc);

		if (st) {
			json = st->json;
			json_len = st->len;
		}
	}
out:
	if (json) {
		pv_fs_file_write_no_sync(get_json_path(), json, json_len);
		free(json);
	} else {
		PVTX_ERROR_SET(err, -1, err_msg, from,
			       "error creating state json");
	}

	return err->code;
}

static bool is_active_txn()
{
	struct pvtx_txn *txn = pvtx_load();
	if (!txn)
		return false;

	bool ret = txn->status == PVTX_TXN_STATUS_ACTIVE;
	free(txn);

	return ret;
}

static int save_state_json(struct pv_pvtx_state *st, struct pv_pvtx_error *err)
{
	pv_pvtx_error_clear(err);

	char tmp[PATH_MAX] = { 0 };
	int fd = pv_fs_file_tmp(get_json_path(), tmp);
	if (fd < 0) {
		PVTX_ERROR_SET(err, fd, "error creating temp file");
		goto out;
	}
	close(fd);

	if (pv_fs_file_write_no_sync(tmp, st->json, st->len) != 0) {
		PVTX_ERROR_SET(err, -1, "error writing temp file");
		goto out;
	}

	if (rename(tmp, get_json_path()) != 0) {
		remove(tmp);
		PVTX_ERROR_SET(err, -1, "rename error %s", strerror(errno));
	}
out:
	return err->code;
}

static int add_json(const char *json, size_t size, struct pv_pvtx_error *err)
{
	pv_pvtx_error_clear(err);

	struct pv_pvtx_state *cur =
		pv_pvtx_state_from_file(get_json_path(), err);
	if (!cur) {
		PVTX_ERROR_PREPEND(err, "couldn't load current state json");
		return -1;
	}

	struct pv_pvtx_state *st = pv_pvtx_state_from_str(json, size, err);
	if (!st) {
		PVTX_ERROR_PREPEND(err, "couldn't load incoming json");
		goto out;
	}

	if (pv_pvtx_state_add(cur, st) != 0) {
		PVTX_ERROR_SET(err, -1, "couldn't merge incoming json");
		goto out;
	}

	save_state_json(cur, err);
out:
	pv_pvtx_state_free(cur);
	pv_pvtx_state_free(st);

	return err->code;
}

static bool is_object_ok(const char *path)
{
	struct pv_pvtx_buffer *buf = get_buffer();
	if (!buf)
		return false;

	bool ok = false;
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		goto out;

	struct sha256_state state = { 0 };
	sha256_init(&state);

	ssize_t len = 0;
	while ((len = read(fd, buf->data, buf->size)) != 0) {
		sha256_process(&state, buf->data, len);
		memset(buf->data, 0, buf->size);
	}

	unsigned char hash[32] = { 0 };
	sha256_done(&state, hash);

	char name[NAME_MAX] = { 0 };
	pv_fs_basename(path, name);

	char hash_str[65] = { 0 };
	for (int i = 0; i < 32; ++i)
		snprintf(hash_str + i * 2, 3, "%02x", hash[i]);

	ok = strncmp(hash_str, name, 64) == 0;
out:
	if (fd > -1)
		close(fd);

	pv_pvtx_buffer_free(buf);
	return ok;
}

static int add_object_local(struct pv_pvtx_tar_content *con,
			    const char *obj_path, struct pv_pvtx_error *err)
{
	char path[PATH_MAX] = { 0 };
	pv_fs_path_concat(path, 2, obj_path, con->name + strlen("objects/"));

	if (pv_fs_path_exist(path) && is_object_ok(path))
		return 0;

	return write_object_from_content(path, con, err);
}

static int add_object_remote(struct pv_pvtx_tar_content *con,
			     struct pv_pvtx_error *err)
{
	struct pv_pvtx_ctrl *ctrl = pv_pvtx_ctrl_new(NULL);
	if (!ctrl) {
		PVTX_ERROR_SET(err, -1,
			       "couldn't send object %s, allocation failed",
			       con->name);
		return -1;
	}

	int ret = pv_pvtx_ctrl_obj_put(ctrl, con);

	if (ret != 0)
		memcpy(err, &ctrl->error, sizeof(struct pv_pvtx_error));

	pv_pvtx_ctrl_free(ctrl);
	return ret;
}

static int add_tar(struct pv_pvtx_tar *tar, struct pv_pvtx_error *err)
{
	pv_pvtx_error_clear(err);

	const char *obj_pfx = "objects/";

	struct pvtx_txn *txn = pvtx_load();
	if (!txn) {
		PVTX_ERROR_SET(err, -1, "couldn't load current transaction");
		return -1;
	}

	char tmp[PATH_MAX] = { 0 };
	int fd = pv_fs_file_tmp(get_json_path(), tmp);
	if (fd < 0) {
		PVTX_ERROR_SET(err, fd,
			       "couldn't get tmp file for pkg json "
			       "process aborted");
		goto out;
	}
	close(fd);

	struct pv_pvtx_tar_content con = { 0 };

	while (pv_pvtx_tar_next(tar, &con) == 0) {
		if (!strncmp(con.name, "json", strlen(con.name))) {
			if (write_object_from_content(tmp, &con, err) != 0)
				goto out;
		} else if (!strncmp(con.name, obj_pfx, strlen(obj_pfx))) {
			int ret = 0;
			if (txn->is_local)
				ret = add_object_local(&con, txn->obj, err);
			else
				ret = add_object_remote(&con, err);
			if (ret != 0)
				goto out;
		}
	}

	size_t js_size = 0;
	char *json = pv_fs_file_read(tmp, &js_size);
	add_json(json, js_size, err);
	free(json);
out:
	remove(tmp);

	if (txn)
		free(txn);

	return err->code;
}

static void init_pvtxdir()
{
	const char *pvtxdir = get_pvtxdir();
	pv_fs_path_remove_recursive_no_sync(pvtxdir);
	pv_fs_mkdir_p(pvtxdir, 0755);
}

static int get_sha256(const unsigned char *data, size_t len,
		      unsigned char *hash)
{
	struct sha256_state state = { 0 };
	sha256_init(&state);
	sha256_process(&state, data, len);

	return sha256_done(&state, hash);
}

static char *get_rev_name(const char *data, size_t len)
{
	char *rev = NULL;

	unsigned char hash[32] = { 0 };
	if (get_sha256((unsigned char *)data, len, hash) != 0)
		goto out;

	char hash8[9] = { 0 };
	for (int i = 0; i < 4; ++i)
		snprintf(hash8 + i * 2, 3, "%02x", hash[i]);

	unsigned int rand = 0;
	if (getrandom(&rand, sizeof(unsigned int), 0) == -1)
		goto out;

	int n = asprintf(&rev, "locals/pvtx-%jd-%s-%d", (intmax_t)time(NULL),
			 hash8, (rand % 1000));
	if (n == -1)
		rev = NULL;
out:
	return rev;
}

static int init_config(const char *deploy_path, const char *tmpdir,
		       const char *obj_path)
{
	char path[PATH_MAX] = { 0 };
	pv_fs_path_concat(path, 2, deploy_path, PVTX_TXN_DST_CONFIG);

	char dst[PATH_MAX] = { 0 };
	pv_fs_path_concat(dst, 2, tmpdir, PVTX_TXN_DST_CONFIG);

	char tmp_parent[PATH_MAX] = { 0 };
	pv_fs_dirname(dst, tmp_parent);

	pv_fs_mkdir_p(tmp_parent, 0755);

	if (pv_fs_path_exist(path)) {
		char tmp[PATH_MAX] = { 0 };
		int fd = pv_fs_file_tmp(dst, tmp);
		pv_fs_file_copy_no_sync(path, dst, 0600);
		return 0;
	}

	char *init_conf = NULL;
	int err = asprintf(&init_conf, "{\"ObjectsDir\": \"%s\"}", obj_path);
	if (err < 0)
		return -1;

	int ret = pv_fs_file_write_no_sync(dst, init_conf, strlen(init_conf));

	free(init_conf);

	return ret;
}

static int create_element(const char *deploy_path, const char *obj_path,
			  bool is_obj, const char *file_path, const char *val)
{
	if (!strncmp(val, "#spec", strlen("#spec")))
		return 0;

	char parent_dir[PATH_MAX] = { 0 };
	pv_fs_dirname(file_path, parent_dir);

	char path[PATH_MAX] = { 0 };
	pv_fs_path_concat(path, 2, deploy_path, parent_dir);
	pv_fs_mkdir_p(path, 0755);

	char local_obj[PATH_MAX] = { 0 };
	pv_fs_path_concat(local_obj, 2, deploy_path, file_path);

	if (pv_fs_path_exist(local_obj))
		remove(local_obj);

	if (is_obj) {
		char real_obj[PATH_MAX] = { 0 };
		pv_fs_path_concat(real_obj, 2, obj_path, val);
		errno = 0;
		int ret = link(real_obj, local_obj);
		return ret;
	}
	return pv_fs_file_write_no_sync(local_obj, (char *)val, strlen(val));
}

static char *token_to_str(const char *data, jsmntok_t *tkn)
{
	return strndup(data + tkn->start, tkn->end - tkn->start);
}

static int create_from_json(const char *deploy_path, const char *obj_path)
{
	regex_t exp = { 0 };

	size_t size = 0;
	char *data = pv_fs_file_read(get_json_path(), &size);
	if (!data)
		return -1;

	int ret = 0;

	int tkn_len = 0;
	jsmntok_t *tkn = pv_pvtx_jsmn_parse_data(data, size, &tkn_len);

	if (!tkn) {
		ret = -2;
		goto out;
	}

	if (regcomp(&exp, PVTX_TXN_OBJ_EXP, REG_EXTENDED)) {
		ret = -3;
		goto out;
	}

	int i = 0;
	int no_top = 0;

	// start from 3 to skip the #spec
	for (int i = 3; i < tkn_len; i++) {
		if ((tkn[i].type != JSMN_STRING &&
		     tkn[i].type != JSMN_UNDEFINED) ||
		    no_top) {
			no_top--;
			goto next;
		}

		if (!strncmp(data + tkn[i].start, "#spec", strlen("#spec")))
			continue;

		char *key = token_to_str(data, &tkn[i]);
		char *val = token_to_str(data, &tkn[i + 1]);
		bool is_obj = regexec(&exp, val, 0, NULL, 0) == 0;

		ret = create_element(deploy_path, obj_path, is_obj, key, val);
		free(key);
		free(val);
		if (ret != 0)
			goto out;
	next:
		no_top += tkn[i].size;
	}
	ret = 0;

out:
	if (data)
		free(data);
	if (tkn)
		free(tkn);

	regfree(&exp);

	return ret;
}

static int create_link(const char *deploy_path, const char *file,
		       const char *linkname)
{
	char link_path[PATH_MAX] = { 0 };
	pv_fs_path_concat(link_path, 3, deploy_path, ".pv", linkname);

	char bsp_file[PATH_MAX] = { 0 };
	pv_fs_path_concat(bsp_file, 3, deploy_path, "bsp", file);

	if (pv_fs_path_exist(link_path))
		remove(link_path);

	return link(bsp_file, link_path);
}

static int create_bsp_link(const char *deploy_path)
{
	char pv_dir[PATH_MAX] = { 0 };
	pv_fs_path_concat(pv_dir, 2, deploy_path, ".pv");

	pv_fs_path_remove_recursive_no_sync(pv_dir);
	pv_fs_mkdir_p(pv_dir, 0755);

	char bsp_runjs[PATH_MAX] = { 0 };
	pv_fs_path_concat(bsp_runjs, 2, deploy_path, PVTX_TXN_DST_RUNJS);

	int ret = 0;

	size_t json_len = 0;
	char *json = pv_fs_file_read(bsp_runjs, &json_len);
	jsmntok_t *tkn = NULL;

	// if !json probably there isn't a bsp defined
	if (!json)
		goto out;

	int tkn_len = 0;
	tkn = pv_pvtx_jsmn_parse_data(json, json_len, &tkn_len);

	const char *keys[] = {
		"fit", "pantavisor", "initrd", "kernel", "linux", "ftd",
	};

	const char *linkname[] = {
		"pantavisor.fit", "pv-initrd.img", "pv-initrd.img",
		"pv-kernel.img",  "pv-kernel.img", "pv-ftd.img",
	};

	int keys_len = sizeof(keys) / sizeof(char *);

	int no_top = 0;
	for (int i = 1; i < tkn_len; i++) {
		if ((tkn[i].type != JSMN_STRING &&
		     tkn[i].type == JSMN_UNDEFINED) ||
		    no_top) {
			no_top--;
			goto next;
		}

		char *k = json + tkn[i].start;
		int k_sz = tkn[i].end - tkn[i].start;
		for (int j = 0; j < keys_len; j++) {
			if (strncmp(k, keys[j], k_sz))
				continue;

			char *file = token_to_str(json, &tkn[i + 1]);
			ret = create_link(deploy_path, file, linkname[j]);
			free(file);

			if (ret != 0)
				goto out;
			break;
		}
	next:
		no_top += tkn[i].size;
	}

out:
	if (json)
		free(json);
	if (tkn)
		free(tkn);

	return ret;
}

static int create_fs(const char *obj_path, const char *deploy_path,
		     struct pv_pvtx_error *err)
{
	pv_pvtx_error_clear(err);

	char js_dst[PATH_MAX] = { 0 };
	pv_fs_path_concat(js_dst, 2, deploy_path, PVTX_TXN_DST_JSON);
	pv_fs_mkbasedir_p(js_dst, 0755);
	int ret = pv_fs_file_copy_no_sync(get_json_path(), js_dst, 0600);
	if (ret != 0) {
		PVTX_ERROR_SET(err, ret, "couldn't write state json: %s",
			       strerror(errno));
		return ret;
	}

	if (create_from_json(deploy_path, obj_path) != 0) {
		PVTX_ERROR_SET(err, -1, "couldn't create objects from json: %s",
			       strerror(errno));
		return err->code;
	}

	if (create_bsp_link(deploy_path) != 0)
		PVTX_ERROR_SET(err, -1, "couldn't link bsp to .pv/");

	return err->code;
}

static int add_json_from_disk(const char *path, struct pv_pvtx_error *err)
{
	pv_pvtx_error_clear(err);

	size_t size = 0;
	char *json = pv_fs_file_read(path, &size);

	if (!json) {
		PVTX_ERROR_SET(err, -1, "couldn't load json from %s", path);
		return err->code;
	}

	int ret = add_json(json, size, err);
	free(json);

	return ret;
}

static int get_queue_file_path(const char *part, const char *suffix,
			       char *fname)
{
	struct pvtx_queue *q = pvtx_load();
	if (!q)
		return -1;

	int ret = snprintf(fname, PATH_MAX, "%s/%03d__%s%s", q->queue, q->count,
			   part, suffix);
	if (ret < 0) {
		ret = -1;
		memset(fname, 0, PATH_MAX);
		goto out;
	}

	ret = 0;
	q->count++;
	pvtx_save(q, sizeof(struct pvtx_queue));
out:
	free(q);
	return ret;
}

static int get_queue_json_path(const char *part, char *fname)
{
	if (get_queue_file_path(part, "/json", fname) != 0)
		return -1;

	pv_fs_mkbasedir_p(fname, 0755);
	return 0;
}

static int get_queue_remove_file(const char *part, char *fname)
{
	if (get_queue_file_path(part, ".remove", fname) != 0)
		return -1;
	return 0;
}

static int move_objects(const char *dirname, const char *queue,
			const char *obj_path, struct pv_pvtx_error *err)
{
	char pkg_fld[PATH_MAX] = { 0 };
	pv_fs_path_concat(pkg_fld, 3, queue, dirname, "objects");

	DIR *dir = opendir(pkg_fld);
	if (!dir)
		goto out;

	struct dirent *entry = NULL;
	while ((entry = readdir(dir)) != NULL) {
		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
			continue;

		char src[PATH_MAX] = { 0 };
		pv_fs_path_concat(src, 2, pkg_fld, entry->d_name);

		char dst[PATH_MAX] = { 0 };
		pv_fs_path_concat(dst, 2, obj_path, entry->d_name);

		if (rename(src, dst) != 0) {
			PVTX_ERROR_SET(err, -1,
				       "couldn't move %s to object dir (%s)",
				       src, obj_path);
			goto out;
		}
	}
out:
	closedir(dir);

	return err->code;
}

static int process_add_directory(struct pv_pvtx_state *st, const char *dirname,
				 const char *queue, const char *obj_path,
				 struct pv_pvtx_error *err)
{
	char js[PATH_MAX] = { 0 };
	pv_fs_path_concat(js, 3, queue, dirname, "json");

	struct pv_pvtx_state *new = pv_pvtx_state_from_file(js, err);
	if (!new) {
		PVTX_ERROR_PREPEND(err, "couldn't add %s", js);
		return err->code;
	}

	if (pv_pvtx_state_add(st, new) != 0) {
		PVTX_ERROR_SET(err, -1,
			       "couldn't add json, operation add failed");
		goto out;
	}

	move_objects(dirname, queue, obj_path, err);

out:
	pv_pvtx_state_free(new);

	return err->code;
}

static int process_remove_file(struct pv_pvtx_state *st, const char *fname)
{
	char name[NAME_MAX] = { 0 };
	memccpy(name, fname, '\0', NAME_MAX);
	*strrchr(name, '.') = '\0';
	char *part = &name[strlen("NNN__")];
	return pv_pvtx_state_remove(st, part);
}

static int queue_add_tar(struct pv_pvtx_tar *tar, const char *name,
			 struct pv_pvtx_error *err)
{
	pv_pvtx_error_clear(err);

	const char *obj_pfx = "objects/";

	struct pvtx_queue *q = pvtx_load();
	if (!q) {
		PVTX_ERROR_SET(err, -1, "couldn't load current queue");
		return err->code;
	}

	struct pv_pvtx_tar_content con = { 0 };

	char tmp[PATH_MAX] = { 0 };
	int fd = pv_fs_file_tmp(q->queue, tmp);
	if (fd < 0) {
		PVTX_ERROR_SET(err, -1, "couldn't create json temp file");
		goto out;
	}
	close(fd);

	int ret = 0;
	while (pv_pvtx_tar_next(tar, &con) == 0) {
		if (!strncmp(con.name, "json", strlen(con.name))) {
			ret = write_object_from_content(tmp, &con, err);
		} else if (!strncmp(con.name, obj_pfx, strlen(obj_pfx)))
			ret = add_object_local(&con, q->txn.obj, err);

		if (ret != 0) {
			PVTX_ERROR_SET(err, ret, "couldn't save obejct: %s",
				       con.name);
			goto out;
		}
	}

	char fname[PATH_MAX] = { 0 };
	if (get_queue_json_path(name ? name : "package", fname) != 0) {
		PVTX_ERROR_SET(err, -1, "couldn't create json path");
		goto out;
	}

	if (rename(tmp, fname) != 0) {
		remove(tmp);
		PVTX_ERROR_SET(err, -1, "couldn't add tar: %s",
			       strerror(errno));
		goto out;
	}
out:
	if (q)
		free(q);

	return err->code;
}

static void sync_all(const char *path)
{
	int fd = open(path, O_RDONLY);
	if (!fd)
		return;

	syncfs(fd);
	close(fd);
}

int pv_pvtx_txn_begin(const char *from, const char *obj_path,
		      struct pv_pvtx_error *err)
{
	void *op = NULL;
	size_t op_size = 0;
	struct pvtx_queue *q = NULL;
	struct pvtx_txn *txn = pvtx_load();
	if (txn && txn->status == PVTX_TXN_STATUS_ACTIVE) {
		PVTX_ERROR_SET(err, -1,
			       "there is a previous transaction active.");
		goto out;
	}

	if (!txn || txn->status != PVTX_TXN_STATUS_SET) {
		init_pvtxdir();

		if (!txn) {
			txn = calloc(1, sizeof(struct pvtx_txn));
			if (!txn) {
				PVTX_ERROR_SET(
					err, -1,
					"couldn't create new transaction");
				goto out;
			}
		}

		txn->status = PVTX_TXN_STATUS_ACTIVE;

		memset(txn->obj, 0, PATH_MAX);
		if (obj_path) {
			memccpy(txn->obj, obj_path, '\0', PATH_MAX);
			txn->is_local = 1;
		} else {
			txn->is_local = 0;
		}

		op = txn;
		op_size = sizeof(struct pvtx_txn);
	} else {
		q = pvtx_load();
		if (!q) {
			PVTX_ERROR_SET(err, -1, "couldn't load current config");
			goto out;
		}

		q->txn.status = PVTX_TXN_STATUS_ACTIVE;
		op = q;
		op_size = sizeof(struct pvtx_queue);
	}

	if (init_state_json(from, err) != 0) {
		PVTX_ERROR_PREPEND(err, "couldn't init transaction");
		goto out;
	}

	pvtx_save(op, op_size);
out:
	if (txn)
		free(txn);
	if (q)
		free(q);

	return err->code;
}

int pv_pvtx_txn_add_from_disk(const char *path, struct pv_pvtx_error *err)
{
	pv_pvtx_error_clear(err);

	if (!is_active_txn()) {
		PVTX_ERROR_SET(
			err, 1,
			"no active transaction. Start a transaction first.");
		return err->code;
	}

	enum pv_pvtx_tar_type type = pv_pvtx_tar_type_get(path, err);
	if (type == PVTX_TAR_UNKNOWN) {
		if (err->code != 0)
			return err->code;

		return add_json_from_disk(path, err);
	}
	struct pv_pvtx_tar *tar = pv_pvtx_tar_from_path(path, type, err);
	if (!tar)
		return err->code;

	int ret = add_tar(tar, err);
	pv_pvtx_tar_free(tar);
	return ret;
}

int pv_pvtx_txn_add_tar_from_fd(int fd, struct pv_pvtx_error *err)
{
	pv_pvtx_error_clear(err);

	if (!is_active_txn()) {
		PVTX_ERROR_SET(
			err, 1,
			"no active transaction. Start a transaction first.");
		return err->code;
	}

	struct pv_pvtx_tar *tar = pv_pvtx_tar_from_fd(fd, PVTX_TAR_GZIP, err);
	if (!tar)
		return err->code;

	int ret = add_tar(tar, err);
	pv_pvtx_tar_free(tar);
	return ret;
}

int pv_pvtx_txn_abort(struct pv_pvtx_error *err)
{
	struct pvtx_txn *txn = pvtx_load();
	if (!txn)
		return 0;

	if (unlink(get_json_path()) != 0)
		PVTX_ERROR_SET(err, -1, "couldn't delete current json file");

	char path[PATH_MAX] = { 0 };
	get_data_file(path);

	if (unlink(path) != 0)
		PVTX_ERROR_SET(err, -1, "couldn't delete current status file");

	return err->code;
}

char *pv_pvtx_txn_commit(struct pv_pvtx_error *err)
{
	char *json = NULL;
	struct pv_pvtx_ctrl *ctrl = NULL;
	struct pvtx_txn *txn = pvtx_load();

	if (!txn || txn->status != PVTX_TXN_STATUS_ACTIVE) {
		PVTX_ERROR_SET(
			err, 11,
			"no active transaction. Start a transaction first.");
		goto out;
	}

	if (txn->is_local) {
		PVTX_ERROR_SET(err, 12,
			       "this is a local transaction, only can "
			       "be deployed with pvtx deploy");
		goto out;
	}

	ctrl = pv_pvtx_ctrl_new(NULL);
	if (!ctrl) {
		PVTX_ERROR_SET(err, -1, "couldn't communicate with pv-ctrl");
		goto out;
	}

	size_t json_len = 0;
	json = pv_fs_file_read(get_json_path(), &json_len);

	if (!json) {
		PVTX_ERROR_SET(err, -1, "couldn't load state json");
		goto out;
	}

	char *rev = get_rev_name(json, json_len);

	if (!rev) {
		PVTX_ERROR_SET(err, -1, "couldn't build revision string");
		goto out;
	}

	if (pv_pvtx_ctrl_steps_put(ctrl, json, json_len, rev) != 0) {
		PVTX_ERROR_SET(err, -1, "couldn't set rev %s", rev);
		goto out;
	}

	txn->status = PVTX_TXN_STATUS_COMMITED;
	pvtx_save(txn, sizeof(struct pvtx_txn));
	pv_pvtx_error_clear(err);
out:
	if (txn)
		free(txn);
	if (json)
		free(json);

	pv_pvtx_ctrl_free(ctrl);

	return rev;
}

char *pv_pvtx_txn_get_json(struct pv_pvtx_error *err)
{
	if (!is_active_txn()) {
		PVTX_ERROR_SET(
			err, 11,
			"no active transaction. Start a transaction first.");
		return NULL;
	}

	errno = 0;
	char *json = pv_fs_file_read(get_json_path(), NULL);
	if (!json) {
		PVTX_ERROR_SET(err, -1, "couldn't get state json: %s",
			       strerror(errno));
		return NULL;
	}

	return json;
}

int pv_pvtx_txn_deploy(const char *path, struct pv_pvtx_error *err)
{
	if (!is_active_txn()) {
		PVTX_ERROR_SET(err, 11, "no active transaction");
		return 11;
	}

	struct pvtx_txn *txn = pvtx_load();

	if (!txn || !txn->is_local) {
		PVTX_ERROR_SET(err, -1,
			       "this not a local transaction. Only "
			       "local transaction can be deployed");
		goto out;
	}

	char tmpdir[PATH_MAX] = { 0 };
	if (pv_fs_path_tmpdir(path, tmpdir) != 0) {
		PVTX_ERROR_SET(err, -1,
			       "couldn't set up temp dir; deploy failed");
		goto out;
	}

	if (init_config(path, tmpdir, txn->obj) != 0) {
		PVTX_ERROR_SET(err, -1, "couldn't initialize config");
		goto out;
	}

	if (create_fs(txn->obj, tmpdir, err) != 0)
		goto out;

	char bakdir[PATH_MAX] = { 0 };
	snprintf(bakdir, PATH_MAX, "%s.bak", path);

	if (rename(path, bakdir) != 0) {
		pv_fs_path_remove_recursive_no_sync(tmpdir);
		PVTX_ERROR_SET(err, -1,
			       "couldn't backup directory, deploy failed: %s",
			       strerror(errno));
		goto out;
	}

	if (rename(tmpdir, path) != 0) {
		rename(bakdir, path);
		pv_fs_path_remove_recursive_no_sync(tmpdir);
		PVTX_ERROR_SET(err, -1, "couldn't deploy current rev: %s",
			       strerror(errno));
		goto out;
	}

	pv_fs_path_remove_recursive_no_sync(bakdir);
	txn->status = PVTX_TXN_STATUS_DEPLOYED;
	pvtx_save(txn, sizeof(struct pvtx_txn));
	pv_pvtx_error_clear(err);

	sync_all(txn->obj);
	sync_all(path);

out:
	if (txn)
		free(txn);

	return err->code;
}

int pv_pvtx_txn_remove(const char *part, struct pv_pvtx_error *err)
{
	if (!is_active_txn()) {
		PVTX_ERROR_SET(
			err, 3,
			"no active transaction. Start a transaction first.");
		return 3;
	}

	struct pv_pvtx_state *st =
		pv_pvtx_state_from_file(get_json_path(), err);
	if (!st) {
		PVTX_ERROR_PREPEND(err, "couldn't load state json");
		return -1;
	}

	if (pv_pvtx_state_remove(st, part) != 0) {
		PVTX_ERROR_SET(err, -1, "couldn't remove part %s", part);
		goto out;
	}

	if (save_state_json(st, err) == 0)
		pv_pvtx_error_clear(err);
out:
	pv_pvtx_state_free(st);
	return err->code;
}

int pv_pvtx_queue_new(const char *queue_path, const char *obj_path,
		      struct pv_pvtx_error *err)
{
	if (is_active_txn()) {
		PVTX_ERROR_SET(err, 12,
			       "active transaction; finish your work "
			       "with 'deploy', 'commit' or 'abort' first");
		return 12;
	}

	init_pvtxdir();

	struct pvtx_queue q = {
		.txn.is_local = 1,
		.txn.status = PVTX_TXN_STATUS_SET,
		.count = 0,
		.error = 0,
	};

	if (!pv_fs_path_exist(queue_path))
		pv_fs_mkdir_p(queue_path, 0775);

	memccpy(q.queue, queue_path, '\0', PATH_MAX);
	memccpy(q.txn.obj, obj_path, '\0', PATH_MAX);

	if (pvtx_save(&q, sizeof(struct pvtx_queue)) != 0) {
		PVTX_ERROR_SET(err, -1,
			       "couldn't create queue, save operation failed");
		return -1;
	}

	pv_pvtx_error_clear(err);

	return 0;
}

int pv_pvtx_queue_remove(const char *part, struct pv_pvtx_error *err)
{
	struct pvtx_queue *q = pvtx_load();
	char *enc = NULL;

	if (!q || !pv_fs_path_exist(q->queue)) {
		PVTX_ERROR_SET(err, 1, "queue %s does not exist",
			       q ? q->queue : "");
		goto out;
	}

	enc = url_encode(part);
	if (!enc) {
		PVTX_ERROR_SET(err, -1, "couldn't encode name");
		goto out;
	}

	char fname[PATH_MAX] = { 0 };
	if (get_queue_remove_file(enc, fname) != 0) {
		PVTX_ERROR_SET(err, -1, "couldn't create .remove file name");
		goto out;
	}

	if (pv_fs_file_write_no_sync(fname, NULL, 0) != 0) {
		PVTX_ERROR_SET(err, -1, "couldn't create file %s", fname);
		goto out;
	}

	pv_pvtx_error_clear(err);

out:
	if (q)
		free(q);
	if (enc)
		free(enc);

	return err->code;
}

int pv_pvtx_queue_unpack_from_disk(const char *part, struct pv_pvtx_error *err)
{
	struct pvtx_queue *q = pvtx_load();
	if (!q || !pv_fs_path_exist(q->queue)) {
		PVTX_ERROR_SET(err, 1, "queue %s does not exist",
			       q ? q->queue : "");
		if (q)
			free(q);
		return 1;
	}

	if (!pv_fs_path_exist(q->txn.obj))
		pv_fs_mkdir_p(q->txn.obj, 0775);

	free(q);

	enum pv_pvtx_tar_type type = pv_pvtx_tar_type_get(part, err);
	if (type == PVTX_TAR_UNKNOWN) {
		if (err->code != 0)
			return err->code;

		char fname[PATH_MAX] = { 0 };
		if (get_queue_json_path(part, fname) != 0) {
			PVTX_ERROR_SET(err, -1, "couldn't create json path");
			return -1;
		}

		if (pv_fs_file_copy_no_sync(part, fname, 0644) != 0) {
			PVTX_ERROR_SET(err, -1, "couldn't copy %s to %s", part,
				       fname);
			return -1;
		}
		pv_pvtx_error_clear(err);
		return 0;
	}

	struct pv_pvtx_tar *tar = pv_pvtx_tar_from_path(part, type, err);
	if (!tar)
		return -1;

	char bname[NAME_MAX] = { 0 };
	pv_fs_basename(part, bname);

	queue_add_tar(tar, bname, err);
	pv_pvtx_tar_free(tar);

	return err->code;
}

int pv_pvtx_queue_unpack_tar_from_fd(int fd, struct pv_pvtx_error *err)
{
	struct pvtx_queue *q = pvtx_load();
	if (!q || !pv_fs_path_exist(q->queue)) {
		PVTX_ERROR_SET(err, 1, "queue %s does not exist",
			       q ? q->queue : "");
		if (q)
			free(q);

		return 1;
	}

	if (!pv_fs_path_exist(q->txn.obj))
		pv_fs_mkdir_p(q->txn.obj, 0775);

	free(q);

	struct pv_pvtx_tar *tar = pv_pvtx_tar_from_fd(fd, PVTX_TAR_GZIP, err);
	if (!tar)
		return err->code;

	int ret = queue_add_tar(tar, NULL, err);
	pv_pvtx_tar_free(tar);

	return ret;
}

int pv_pvtx_queue_process(const char *from, const char *queue_path,
			  const char *obj_path, struct pv_pvtx_error *err)
{
	if (queue_path && obj_path) {
		int ret = pv_pvtx_queue_new(queue_path, obj_path, err);
		if (ret != 0)
			return ret;
	}

	struct dirent **entry = NULL;
	struct pv_pvtx_state *st = NULL;
	struct pvtx_queue *q = pvtx_load();

	if (!q) {
		PVTX_ERROR_SET(err, -1, "couldn't load current config");
		return err->code;
	}

	if (!pv_fs_path_exist(q->queue)) {
		PVTX_ERROR_SET(err, -1, "queue %s does not exist");
		goto out;
	}

	if (from && pv_pvtx_txn_begin(from, q->txn.obj, err) != 0)
		goto out;

	if (!is_active_txn()) {
		PVTX_ERROR_SET(err, 3, "no active transaction");
		goto out;
	}

	int len = scandir(q->queue, &entry, NULL, alphasort);
	if (len < 0) {
		PVTX_ERROR_SET(err, -1, "couldn't scan directory %s", q->queue);
		goto out;
	}

	st = pv_pvtx_state_from_file(get_json_path(), err);
	if (!st) {
		PVTX_ERROR_PREPEND(err, "couldn't process queue, "
					"error loading current state json");
		goto out;
	}

	for (int i = 0; i < len; i++) {
		char *fn = url_decode(entry[i]->d_name);
		if (!strncmp(fn, ".", strlen(fn)) ||
		    !strncmp(fn, "..", strlen(fn))) {
			free(fn);
			continue;
		}
		char *ext = strrchr(fn, '.');
		if (ext && !strncmp(ext, ".remove", strlen(ext))) {
			if (process_remove_file(st, fn) != 0) {
				PVTX_ERROR_SET(err, -1, "couldn't remove %s",
					       fn);
				free(fn);
				goto out;
			}
		} else if (entry[i]->d_type == DT_DIR) {
			int ret = process_add_directory(st, fn, q->queue,
							q->txn.obj, err);
			if (ret != 0) {
				free(fn);
				goto out;
			}
		}
		free(fn);
	}

	if (save_state_json(st, err) != 0)
		goto out;

	pv_pvtx_error_clear(err);
out:
	if (entry) {
		for (int i = 0; i < len; i++)
			free(entry[i]);
		free(entry);
	}

	if (q)
		free(q);

	pv_pvtx_state_free(st);

	return err->code;
}
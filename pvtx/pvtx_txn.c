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
	// keep always at the end
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
static char pvtx_state_json_cahe[PATH_MAX] = { 0 };

static const char *get_pvtxdir(void)
{
	if (pvtxdir_cache[0] != '\0')
		return pvtxdir_cache;

	char *dir = getenv(PVTX_TXN_PATH);
	if (dir) {
		memccpy(pvtxdir_cache, dir, '\0', PATH_MAX);
	} else {
		char *pfx = getenv(PVTX_TXN_PREFIX_PATH);
		if (pfx)
			pv_fs_path_concat(pvtxdir_cache, 2, pfx,
					  PVTX_TXN_DEFAULT_PATH);
		else
			memccpy(pvtxdir_cache, PVTX_TXN_DEFAULT_PATH, '\0',
				PATH_MAX);
	}

	return pvtxdir_cache;
}

static const char *get_json_path(void)
{
	if (pvtx_state_json_cahe[0] != '\0')
		return pvtx_state_json_cahe;

	pv_fs_path_concat(pvtx_state_json_cahe, 2, get_pvtxdir(),
			  PVTX_TXN_JSON);

	return pvtx_state_json_cahe;
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
		// while ((p = strstr(p + 1, "%2F")))
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
	return pv_fs_file_write(path, data, size);
}

static void *pvtx_load()
{
	char path[PATH_MAX] = { 0 };
	get_data_file(path);
	return pv_fs_file_read(path, NULL);
}

static void write_object_from_content(const char *path,
				      struct pv_pvtx_tar_content *con)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
	if (fd < 0)
		return;

	struct pv_pvtx_buffer *buf = get_buffer();
	if (!buf)
		goto out;

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
	pv_pvtx_buffer_free(buf);
out:
	close(fd);
}

static int state_json_save(const char *from)
{
	int ret = 0;
	char *json = NULL;
	size_t json_len = 0;
	struct pv_pvtx_state *st = NULL;

	if (strlen(from) == 0) {
		struct pv_pvtx_ctrl *ctrl = pv_pvtx_ctrl_new(NULL);
		json = pv_pvtx_ctrl_steps_get(ctrl, "current", &json_len);
		pv_pvtx_ctrl_free(ctrl);
		goto out;
	}

	if (strncmp(from, "empty", strlen(from))) {
		char path[PATH_MAX] = { 0 };
		char *loc[] = { "json", ".pvr/json", NULL };
		for (size_t i = 0; i < sizeof(loc) / sizeof(char *); ++i) {
			pv_fs_path_concat(path, 2, from, loc[i]);

			if (pv_fs_path_exist(path))
				break;

			memset(path, 0, PATH_MAX);
		}
		st = pv_pvtx_state_from_file(path);
	}

	json = pv_pvtx_state_to_str(st, &json_len);
out:
	if (json) {
		ret = pv_fs_file_write(get_json_path(), json, json_len);
		free(json);
	} else {
		ret = 13;
	}

	return ret;
}

static bool is_active_txn()
{
	bool is_active = false;
	struct pvtx_txn *txn = pvtx_load();
	if (txn) {
		is_active = txn->status == PVTX_TXN_STATUS_ACTIVE;
		free(txn);
	}

	return is_active;
}

static int add_json(const char *json, size_t size, struct pv_pvtx_error *err)
{
	struct pv_pvtx_state *cur = pv_pvtx_state_from_file(get_json_path());
	if (!cur) {
		pv_pvtx_error_set(err, -1, "couldn't load current state json");
		return -1;
	}

	int ret = 0;
	struct pv_pvtx_state *st = pv_pvtx_state_from_str(json, size);
	if (!st) {
		ret = -1;
		pv_pvtx_error_set(err, ret, "couldn't load incoming json");
		goto out;
	}

	ret = pv_pvtx_state_add(cur, st);
	if (ret != 0) {
		pv_pvtx_error_set(err, ret, "couldn't merge incoming json");
		goto out;
	}

	size_t str_size = 0;
	char *str = pv_pvtx_state_to_str(cur, &str_size);
	ret = pv_fs_file_write(get_json_path(), str, str_size);

	if (ret != 0)
		pv_pvtx_error_set(err, ret, "couldn't write state json");

out:
	if (cur)
		pv_pvtx_state_free(cur);
	if (st)
		pv_pvtx_state_free(st);
	if (str)
		free(str);

	return 0;
}

static int add_object_local(struct pv_pvtx_tar_content *con,
			    const char *obj_path)
{
	char path[PATH_MAX] = { 0 };
	pv_fs_path_concat(path, 2, obj_path, con->name + strlen("objects/"));

	write_object_from_content(path, con);

	return 0;
}

static int add_object_remote(struct pv_pvtx_tar_content *con)
{
	struct pv_pvtx_ctrl *ctrl = pv_pvtx_ctrl_new(NULL);
	if (!ctrl)
		return -1;

	int ret = pv_pvtx_ctrl_obj_put(ctrl, con);
	pv_pvtx_ctrl_free(ctrl);
	return ret;
}

static int add_tar(struct pv_pvtx_tar *tar, struct pv_pvtx_error *err)
{
	const char *obj_pfx = "objects/";

	struct pvtx_txn *txn = pvtx_load();
	if (!txn) {
		pv_pvtx_error_set(err, -1, "couldn't load current transaction");
		return -1;
	}

	int ret = -1;
	struct pv_pvtx_tar_content con = { 0 };

	while (pv_pvtx_tar_next(tar, &con) == 0) {
		if (!strncmp(con.name, "json", strlen(con.name))) {
			char *data = calloc(con.size, sizeof(char));
			pv_pvtx_tar_content_read_object(&con, data);
			ret = add_json(data, con.size, err);
			free(data);
			if (ret != 0)
				goto out;
		} else if (!strncmp(con.name, obj_pfx, strlen(obj_pfx))) {
			if (txn->is_local)
				ret = add_object_local(&con, txn->obj);
			else
				ret = add_object_remote(&con);
			if (ret != 0) {
				pv_pvtx_error_set(err, ret,
						  "couldn't save obejct");
				goto out;
			}
		}
	}
out:
	if (txn)
		free(txn);
	return ret;
}

static void init_pvtxdir()
{
	const char *pvtxdir = get_pvtxdir();
	pv_fs_path_remove(pvtxdir, true);
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

static int init_config(const char *deploy_path, const char *obj_path)
{
	char path[PATH_MAX] = { 0 };
	pv_fs_path_concat(path, 2, deploy_path, PVTX_TXN_DST_CONFIG);

	if (pv_fs_path_exist(path))
		return 0;

	char parent_dir[PATH_MAX] = { 0 };
	pv_fs_dirname(path, parent_dir);
	pv_fs_mkdir_p(parent_dir, 0755);

	char *init_conf = NULL;
	int err = asprintf(&init_conf, "{\"ObjectsDir\": \"%s\"}", obj_path);
	if (err < 0)
		return -1;

	int ret = pv_fs_file_write(path, init_conf, strlen(init_conf));

	free(init_conf);

	return ret;
}

static int write_state_json(const char *deploy_path)
{
	size_t size = 0;
	char *data = pv_fs_file_read(get_json_path(), &size);

	char dst[PATH_MAX] = { 0 };
	pv_fs_path_concat(dst, 2, deploy_path, PVTX_TXN_DST_JSON);

	if (pv_fs_path_exist(dst))
		pv_fs_path_remove(dst, false);

	int ret = pv_fs_file_write(dst, data, size);
	free(data);

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
		pv_fs_path_remove(local_obj, false);

	if (is_obj) {
		char real_obj[PATH_MAX] = { 0 };
		pv_fs_path_concat(real_obj, 2, obj_path, val);
		errno = 0;
		int ret = link(real_obj, local_obj);
		return ret;
	}
	return pv_fs_file_write(local_obj, (char *)val, strlen(val));
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
		if (ret != 0) {
			return ret;
			goto out;
		}

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
		pv_fs_path_remove(link_path, false);

	return link(bsp_file, link_path);
}

static int create_bsp_link(const char *deploy_path)
{
	char pv_dir[PATH_MAX] = { 0 };
	pv_fs_path_concat(pv_dir, 2, deploy_path, ".pv");

	pv_fs_path_remove(pv_dir, true);
	pv_fs_mkdir_p(pv_dir, 0755);

	char bsp_runjs[PATH_MAX] = { 0 };
	pv_fs_path_concat(bsp_runjs, 2, deploy_path, PVTX_TXN_DST_RUNJS);

	size_t json_len = 0;
	char *json = pv_fs_file_read(bsp_runjs, &json_len);

	int tkn_len = 0;
	jsmntok_t *tkn = pv_pvtx_jsmn_parse_data(json, json_len, &tkn_len);

	const char *keys[] = {
		"fit", "pantavisor", "initrd", "kernel", "linux", "ftd",
	};

	const char *linkname[] = {
		"pantavisor.fit", "pv-initrd.img", "pv-initrd.img",
		"pv-kernel.img",  "pv-kernel.img", "pv-ftd.img",
	};

	int keys_len = sizeof(keys) / sizeof(char *);

	int ret = 0;
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
	int ret = write_state_json(deploy_path);
	if (ret != 0) {
		pv_pvtx_error_set(err, ret, "couldn't write state json");
		return ret;
	}

	ret = create_from_json(deploy_path, obj_path);
	if (ret != 0) {
		pv_pvtx_error_set(err, ret,
				  "couldn't create objects from json: %s",
				  strerror(errno));
		return ret;
	}

	ret = create_bsp_link(deploy_path);
	if (ret != 0)
		pv_pvtx_error_set(err, ret, "couldn't link bsp to .pv/");

	return ret;
}

int pv_pvtx_txn_begin(const char *from, const char *obj_path,
		      struct pv_pvtx_error *err)
{
	int ret = 0;
	struct pvtx_txn *txn = pvtx_load();
	if (txn && txn->status == PVTX_TXN_STATUS_ACTIVE) {
		ret = 12;
		pv_pvtx_error_set(err, ret,
				  "active transaction; finish your work "
				  "with 'deploy', 'commit' or 'abort' first");
		return ret;
	}

	if (!txn || txn->status != PVTX_TXN_STATUS_SET) {
		init_pvtxdir();
		struct pvtx_txn txn_new = { .status = PVTX_TXN_STATUS_ACTIVE };

		if (obj_path) {
			memccpy(txn_new.obj, obj_path, '\0', PATH_MAX);
			txn_new.is_local = 1;
		} else {
			txn_new.is_local = 0;
		}

		pvtx_save(&txn_new, sizeof(struct pvtx_txn));
	} else {
		struct pvtx_queue *q = pvtx_load();
		if (!q) {
			ret = -1;
			pv_pvtx_error_set(err, -1,
					  "couldn't load current config");
			goto out;
		}

		q->txn.status = PVTX_TXN_STATUS_ACTIVE;
		pvtx_save(q, sizeof(struct pvtx_queue));
	}

	ret = state_json_save(from);
out:
	if (txn)
		free(txn);
	return ret;
}

static int add_json_from_disk(const char *path, struct pv_pvtx_error *err)
{
	size_t size = 0;
	char *json = pv_fs_file_read(path, &size);

	if (!json) {
		pv_pvtx_error_set(err, -1, "couldn't load json from %s", path);
		return -1;
	}

	int ret = add_json(json, size, err);
	free(json);

	return ret;
}

int pv_pvtx_txn_add_from_disk(const char *path, struct pv_pvtx_error *err)
{
	enum pv_pvtx_tar_type type = pv_pvtx_tar_type_get(path, err);
	if (type == PVTX_TAR_UNKNOWN) {
		if (err->code != 0)
			return err->code;
		return add_json_from_disk(path, err);
	}
	struct pv_pvtx_tar *tar = pv_pvtx_tar_from_path(path, type, err);
	if (!tar)
		return -1;
	int ret = add_tar(tar, err);
	pv_pvtx_tar_free(tar);
	return ret;
}

int pv_pvtx_txn_add_tar_from_fd(int fd, struct pv_pvtx_error *err)
{
	if (!is_active_txn()) {
		pv_pvtx_error_set(err, 1, "no active transaction");
		return 1;
	}

	struct pv_pvtx_tar *tar = pv_pvtx_tar_from_fd(fd, PVTX_TAR_GZIP, err);
	if (!tar) {
		return err->code;
	}

	int ret = add_tar(tar, err);
	pv_pvtx_tar_free(tar);

	return ret;
}

int pv_pvtx_txn_abort(struct pv_pvtx_error *err)
{
	struct pvtx_txn *txn = pvtx_load();
	if (!txn)
		return 0;

	txn->status = PVTX_TXN_STATUS_ABORTED;
	int ret = pvtx_save(txn, sizeof(struct pvtx_txn));
	free(txn);

	if (ret != 0) {
		pv_pvtx_error_set(err, ret,
				  "couldn't write transaction status");
		return ret;
	}

	return 0;
}

int pv_pvtx_txn_commit(struct pv_pvtx_error *err)
{
	int ret = 0;
	char *json = NULL;
	struct pv_pvtx_ctrl *ctrl = NULL;
	struct pvtx_txn *txn = pvtx_load();

	if (!txn || txn->status != PVTX_TXN_STATUS_ACTIVE) {
		pv_pvtx_error_set(err, 11, "not active transaction");
		return 11;
	}

	if (txn->is_local) {
		ret = 12;
		pv_pvtx_error_set(err, ret,
				  "this is a local transaction, only can "
				  "be deployed with pvtx deploy");
		return ret;
	}

	ctrl = pv_pvtx_ctrl_new(NULL);
	if (!ctrl) {
		ret = -1;
		pv_pvtx_error_set(err, ret,
				  "couldn't communicate with pv-ctrl");
		goto out;
	}

	size_t json_len = 0;
	json = pv_fs_file_read(get_json_path(), &json_len);

	if (!json) {
		ret = -1;
		pv_pvtx_error_set(err, ret, "couldn't load state json");
		goto out;
	}

	char *rev = get_rev_name(json, json_len);

	if (!rev) {
		ret = -1;
		pv_pvtx_error_set(err, ret, "couldn't build revision string");
		goto out;
	}

	ret = pv_pvtx_ctrl_steps_put(ctrl, json, json_len, rev);
	printf("%s\n", rev);

	txn->status = PVTX_TXN_STATUS_COMMITED;
	pvtx_save(txn, sizeof(struct pvtx_txn));
out:
	if (txn)
		free(txn);
	if (ctrl)
		pv_pvtx_ctrl_free(ctrl);
	if (json)
		free(json);

	return ret;
}

char *pv_pvtx_txn_get_json(struct pv_pvtx_error *err)
{
	if (!is_active_txn()) {
		pv_pvtx_error_set(err, 11, "no active transaction");
		return NULL;
	}

	char *json = pv_fs_file_read(get_json_path(), NULL);
	if (!json) {
		pv_pvtx_error_set(err, -1,
				  "unknown error, couldn't get state json");
		return NULL;
	}

	return json;
}

int pv_pvtx_txn_deploy(const char *path, struct pv_pvtx_error *err)
{
	if (!is_active_txn()) {
		pv_pvtx_error_set(err, 11, "no active transaction");
		return 11;
	}

	int ret = -1;
	struct pvtx_txn *txn = pvtx_load();

	if (!txn->is_local) {
		pv_pvtx_error_set(err, ret,
				  "this not a local transaction. Only "
				  "local transaction can be deployed");
		goto out;
	}

	if (init_config(path, txn->obj) != 0) {
		pv_pvtx_error_set(err, ret, "couldn't initialize config");
		goto out;
	}

	ret = create_fs(txn->obj, path, err);

	txn->status = PVTX_TXN_STATUS_DEPLOYED;
	pvtx_save(txn, sizeof(struct pvtx_txn));

out:
	if (txn)
		free(txn);
	return ret;
}

int pv_pvtx_txn_remove(const char *part, struct pv_pvtx_error *err)
{
	if (!is_active_txn()) {
		pv_pvtx_error_set(err, 3, "no active transaction");
		return 3;
	}

	const char *json_path = get_json_path();
	struct pv_pvtx_state *st = pv_pvtx_state_from_file(json_path);
	if (!st) {
		pv_pvtx_error_set(err, -1, "couldn't load state json");
		return -1;
	}

	int ret = pv_pvtx_state_remove(st, part);

	size_t str_size = 0;
	char *str = pv_pvtx_state_to_str(st, &str_size);
	ret = pv_fs_file_write(get_json_path(), str, str_size);

	if (ret != 0)
		pv_pvtx_error_set(err, ret, "couldn't write state json");

	pv_pvtx_state_free(st);

	return ret;
}
int pv_pvtx_queue_new(const char *queue_path, const char *obj_path,
		      struct pv_pvtx_error *err)
{
	if (is_active_txn()) {
		pv_pvtx_error_set(err, 12,
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

	return pvtx_save(&q, sizeof(struct pvtx_queue));
}

int pv_pvtx_queue_remove(const char *part, struct pv_pvtx_error *err)
{
	struct pvtx_queue *q = pvtx_load();
	if (!q || !pv_fs_path_exist(q->queue)) {
		pv_pvtx_error_set(err, 1, "queue %s does not exist",
				  q ? q->queue : "");
		return 1;
	}

	int ret = 0;
	char *enc = url_encode(part);
	if (!enc) {
		ret = -1;
		pv_pvtx_error_set(err, ret, "couldn't encode name");
		goto out;
	}

	char fname[PATH_MAX] = { 0 };
	int len = snprintf(fname, PATH_MAX, "%s/%03d__%s.remove", q->queue,
			   q->count, enc);
	if (len < 0) {
		ret = -1;
		pv_pvtx_error_set(err, ret,
				  "couldn't create .remove file name");
		goto out;
	}

	ret = pv_fs_file_write(fname, NULL, 0);
	if (ret != 0) {
		pv_pvtx_error_set(err, ret, "couldn't create file %s", fname);
		goto out;
	}

	q->count++;
	pvtx_save(q, sizeof(struct pvtx_queue));

out:
	if (q)
		free(q);
	if (enc)
		free(enc);

	return ret;
}

static void queue_get_json_path(const char *part, char *fname)
{
	struct pvtx_queue *q = pvtx_load();
	if (!q)
		return;

	char bname[PATH_MAX] = { 0 };
	int len = snprintf(bname, PATH_MAX, "%s/%03d__%s", q->queue, q->count,
			   part);
	if (len < 0) {
		goto out;
	}

	pv_fs_mkdir_p(bname, 0755);
	pv_fs_path_concat(fname, 2, bname, "json");

out:
	q->count++;
	pvtx_save(q, sizeof(struct pvtx_queue));
	free(q);
}

static int queue_add_tar(struct pv_pvtx_tar *tar, const char *name,
			 struct pv_pvtx_error *err)
{
	const char *obj_pfx = "objects/";

	struct pvtx_queue *q = pvtx_load();
	if (!q) {
		pv_pvtx_error_set(err, -1, "couldn't load current queue");
		return -1;
	}

	int ret = 0;
	struct pv_pvtx_tar_content con = { 0 };

	while (pv_pvtx_tar_next(tar, &con) == 0) {
		if (!strncmp(con.name, "json", strlen(con.name))) {
			const char *part = name ? name : "package";

			char fname[PATH_MAX] = { 0 };
			queue_get_json_path(part, fname);

			write_object_from_content(fname, &con);
		} else if (!strncmp(con.name, obj_pfx, strlen(obj_pfx))) {
			ret = add_object_local(&con, q->txn.obj);
			if (ret != 0) {
				pv_pvtx_error_set(err, ret,
						  "couldn't save obejct");
				goto out;
			}
		}
	}
out:
	if (q)
		free(q);

	return ret;
}

int pv_pvtx_queue_unpack_from_disk(const char *part, struct pv_pvtx_error *err)
{
	struct pvtx_queue *q = pvtx_load();
	if (!q || !pv_fs_path_exist(q->queue)) {
		pv_pvtx_error_set(err, 1, "queue %s does not exist",
				  q ? q->queue : "");
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
		queue_get_json_path(part, fname);
		int ret = pv_fs_file_copy(part, fname, 0644);
		if (ret != 0) {
			pv_pvtx_error_set(err, ret, "couldn't copy %s to %s",
					  part, fname);
		}
		return ret;
	}

	struct pv_pvtx_tar *tar = pv_pvtx_tar_from_path(part, type, err);
	if (!tar) {
		return -1;
	}

	char bname[NAME_MAX] = { 0 };
	pv_fs_basename(part, bname);

	int ret = queue_add_tar(tar, bname, err);
	pv_pvtx_tar_free(tar);

	return ret;
}

int pv_pvtx_queue_unpack_tar_from_fd(int fd, struct pv_pvtx_error *err)
{
	struct pvtx_queue *q = pvtx_load();
	if (!q || !pv_fs_path_exist(q->queue)) {
		pv_pvtx_error_set(err, 1, "queue %s does not exist",
				  q ? q->queue : "");
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
	pv_pvtx_error_clear(err);
	if (queue_path && obj_path) {
		int ret = pv_pvtx_queue_new(queue_path, obj_path, err);
		if (ret != 0)
			return ret;
	}

	int ret = 0;
	struct pvtx_queue *q = pvtx_load();
	if (!q) {
		pv_pvtx_error_set(err, -1, "couldn't load current config");
		return -1;
	}

	if (!pv_fs_path_exist(q->queue)) {
		pv_pvtx_error_set(err, 1, "queue %s does not exist");
		ret = 1;
		goto out;
	}

	if (from) {
		ret = pv_pvtx_txn_begin(from, q->txn.obj, err);
		if (ret != 0)
			goto out;
	}

	if (!is_active_txn()) {
		pv_pvtx_error_set(err, 3, "no active transaction");
		ret = 3;
		goto out;
	}

	struct dirent **entry = NULL;

	int len = scandir(q->queue, &entry, NULL, alphasort);
	if (len < 0) {
		pv_pvtx_error_set(err, -1, "couldn't scan directory %s",
				  q->queue);
		return err->code;
	}

	for (int i = 0; i < len; i++) {
		const char *fname = entry[i]->d_name;
		if (!strncmp(fname, ".", strlen(fname)) ||
		    !strncmp(fname, "..", strlen(fname))) {
			continue;
		}
		char *ext = strrchr(fname, '.');
		if (!ext || strncmp(ext, ".remove", strlen(ext))) {
			char complete_path[PATH_MAX] = { 0 };
			pv_fs_path_concat(complete_path, 3, q->queue, fname,
					  "json");
			if (pv_pvtx_txn_add_from_disk(complete_path, err) != 0)
				break;
		} else {
			char name[NAME_MAX] = { 0 };
			memccpy(name, fname, '\0', NAME_MAX);
			*strchr(name, '.') = '\0';
			char *part = &name[strlen("NNN__")];
			if (pv_pvtx_txn_remove(part, err) != 0)
				break;
		}
	}

	for (int i = 0; i < len; i++)
		free(entry[i]);
	free(entry);

out:
	if (q)
		free(q);

	return 0;
}
/*
 * Copyright (c) 2018-2025 Pantacor Ltd.
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

#include <libgen.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <trest.h>

#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/time.h>
#include <sys/sysinfo.h>

#include <linux/limits.h>

#include <jsmn/jsmnutil.h>

#include "metadata.h"
#include "version.h"
#include "state.h"
#include "init.h"
#include "str.h"
#include "paths.h"
#include "json.h"
#include "config.h"
#include "config_parser.h"
#include "storage.h"
#include "platforms.h"
#include "buffer.h"
#include "loop.h"

#include "pantahub/pantahub.h"

#include "utils/math.h"
#include "utils/system.h"
#include "utils/str.h"
#include "utils/math.h"
#include "utils/system.h"
#include "utils/fs.h"

#define MODULE_NAME "metadata"
#define pv_log(level, msg, ...)                                                \
	vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__,       \
	     ##__VA_ARGS__)
#include "log.h"

#define PV_DEVMETA_UPTIME_PATH "/proc/uptime"

static const unsigned int METADATA_MAX_SIZE = 4096;

#define PV_USERMETA_ADD (1 << 0)
struct pv_meta {
	char *key;
	char *value;
	bool updated;
	struct dl_list list; // pv_meta
};

struct pv_devmeta_read {
	char *key;
	char *buf;
	int buflen;
	int (*reader)(struct pv_devmeta_read *);
	// re-read on every serialization; such a value is never persisted
	bool dynamic;
};

static int pv_metadata_mount_usrmeta_vol()
{
	struct stat st;
	char src_path[PATH_MAX], dst_path[PATH_MAX];

	pv_paths_volumes_plat_file(src_path, PATH_MAX, BSP_DNAME,
				   USRMETAVOL_DNAME);
	if (stat(src_path, &st)) {
		pv_log(INFO, "%s does not exist. Mounting storage...",
		       src_path);
		return 0;
	}

	pv_paths_pv_usrmeta_key(dst_path, PATH_MAX, "");
	if (stat(dst_path, &st) != 0)
		pv_fs_mkdir_p(dst_path, 0755);
	if (mount_bind(src_path, dst_path)) {
		pv_log(ERROR, "user meta vol to pv mount failed");
		return -1;
	}

	pv_log(DEBUG, "mounted '%s' at '%s'", src_path, dst_path);

	return 1;
}

static int pv_metadata_mount_usrmeta_storage()
{
	struct stat st;
	char src_path[PATH_MAX], dst_path[PATH_MAX];

	pv_paths_storage_usrmeta(src_path, PATH_MAX);
	if (stat(src_path, &st) != 0)
		pv_fs_mkdir_p(src_path, 0500);

	pv_paths_pv_usrmeta_key(dst_path, PATH_MAX, "");
	if (stat(dst_path, &st) != 0)
		pv_fs_mkdir_p(dst_path, 0755);
	if (mount_bind(src_path, dst_path)) {
		pv_log(ERROR, "user meta storage to pv mount failed");
		return -1;
	}

	pv_log(DEBUG, "mounted '%s' at '%s'", src_path, dst_path);

	return 0;
}

static int pv_metadata_mount_devmeta_vol()
{
	struct stat st;
	char src_path[PATH_MAX], dst_path[PATH_MAX];

	pv_paths_volumes_plat_file(src_path, PATH_MAX, BSP_DNAME,
				   DEVMETAVOL_DNAME);
	if (stat(src_path, &st)) {
		pv_log(INFO, "%s does not exist. Mounting storage...",
		       src_path);
		return 0;
	}

	pv_paths_pv_devmeta_key(dst_path, PATH_MAX, "");
	if (stat(dst_path, &st) != 0)
		pv_fs_mkdir_p(dst_path, 0755);
	if (mount_bind(src_path, dst_path)) {
		pv_log(ERROR, "dev meta vol to pv mount failed");
		return -1;
	}

	pv_log(DEBUG, "mounted '%s' at '%s'", src_path, dst_path);

	return 1;
}

static int pv_metadata_mount_devmeta_storage()
{
	struct stat st;
	char src_path[PATH_MAX], dst_path[PATH_MAX];

	pv_paths_storage_devmeta(src_path, PATH_MAX);
	if (stat(src_path, &st) != 0)
		pv_fs_mkdir_p(src_path, 0500);

	pv_paths_pv_devmeta_key(dst_path, PATH_MAX, "");
	if (stat(dst_path, &st) != 0)
		pv_fs_mkdir_p(dst_path, 0755);
	if (mount_bind(src_path, dst_path)) {
		pv_log(ERROR, "dev meta storage to pv mount failed");
		return -1;
	}

	pv_log(DEBUG, "mounted '%s' at '%s'", src_path, dst_path);

	return 0;
}

static int pv_metadata_mount()
{
	int res;

	res = pv_metadata_mount_usrmeta_vol();
	if (res < 0) {
		pv_log(ERROR, "cannot mount user meta vol");
		return -1;
	} else if (!res) {
		if (pv_metadata_mount_usrmeta_storage()) {
			pv_log(ERROR, "cannot mount user meta storage");
			return -1;
		}
	}

	res = pv_metadata_mount_devmeta_vol();
	if (res < 0) {
		pv_log(ERROR, "cannot mount dev meta vol");
		return -1;
	} else if (!res) {
		if (pv_metadata_mount_devmeta_storage()) {
			pv_log(ERROR, "cannot mount dev meta storage");
			return -1;
		}
	}

	return 0;
}

void pv_metadata_umount()
{
	char path[PATH_MAX];

	pv_paths_pv_usrmeta_key(path, PATH_MAX, "");
	pv_log(DEBUG, "unmounting '%s'...", path);
	if (umount(path))
		pv_log(ERROR, "error unmounting '%s': %s", path,
		       strerror(errno)) else pv_log(DEBUG,
						    "unmounted successfully");

	pv_paths_pv_devmeta_key(path, PATH_MAX, "");
	pv_log(DEBUG, "unmounting '%s'...", path);
	if (umount(path))
		pv_log(ERROR, "error unmounting '%s': %s", path,
		       strerror(errno)) else pv_log(DEBUG,
						    "unmounted successfully");
}

static int pv_devmeta_buf_check(struct pv_devmeta_read *pv_devmeta_read)
{
	char *buf = pv_devmeta_read->buf;
	int buflen = pv_devmeta_read->buflen;

	if (!buf || buflen <= 0)
		return -1;
	return 0;
}

static int pv_devmeta_read_version(struct pv_devmeta_read *pv_devmeta_read)
{
	char *buf = pv_devmeta_read->buf;
	int buflen = pv_devmeta_read->buflen;

	if (pv_devmeta_buf_check(pv_devmeta_read))
		return -1;
	SNPRINTF_WTRUNC(buf, buflen, "%s", (char *)pv_build_version);
	return 0;
}

static int pv_devmeta_read_arch(struct pv_devmeta_read *pv_devmeta_read)
{
	char *buf = pv_devmeta_read->buf;
	int buflen = pv_devmeta_read->buflen;

	if (pv_devmeta_buf_check(pv_devmeta_read))
		return -1;
	SNPRINTF_WTRUNC(buf, buflen, "%s/%s/%s", PV_ARCH, PV_BITS,
			get_endian() ? "EL" : "EB");
	return 0;
}

static int pv_devmeta_read_dtmodel(struct pv_devmeta_read *pv_devmeta_read)
{
	char *buf = pv_devmeta_read->buf;
	int buflen = pv_devmeta_read->buflen;
	int ret = -1;

	if (pv_devmeta_buf_check(pv_devmeta_read))
		return -1;

	ret = get_dt_model(buf, buflen);
	if (ret < 0)
		memset(buf, 0, buflen);
	return 0;
}

static int pv_devmeta_read_cpumodel(struct pv_devmeta_read *pv_devmeta_read)
{
	char *buf = pv_devmeta_read->buf;
	int buflen = pv_devmeta_read->buflen;
	int ret = -1;

	if (pv_devmeta_buf_check(pv_devmeta_read))
		return -1;

	ret = get_cpu_model(buf, buflen);
	if (ret < 0)
		memset(buf, 0, buflen);
	return 0;
}

static int pv_devmeta_uname(struct pv_devmeta_read *pv_devmeta_read)
{
	char *buf = pv_devmeta_read->buf;
	int buflen = pv_devmeta_read->buflen;

	if (pv_devmeta_buf_check(pv_devmeta_read))
		return -1;

	struct utsname data = { 0 };
	int err = uname(&data);

	if (err) {
		pv_log(WARN, "Couldn't add uname data: %s (%d)",
		       strerror(errno), errno);
		memset(buf, 0, buflen);
		return -1;
	}

	struct pv_json_ser js;
	pv_json_ser_init(&js, 512);

	pv_json_ser_object(&js);
	{
		pv_json_ser_key(&js, "kernel.name");
		pv_json_ser_string(&js, data.sysname);
		pv_json_ser_key(&js, "kernel.release");
		pv_json_ser_string(&js, data.release);
		pv_json_ser_key(&js, "kernel.version");
		pv_json_ser_string(&js, data.version);
		pv_json_ser_key(&js, "node.name");
		pv_json_ser_string(&js, data.nodename);
		pv_json_ser_key(&js, "machine");
		pv_json_ser_string(&js, data.machine);
		pv_json_ser_object_pop(&js);
	}

	char *js_str = pv_json_ser_str(&js);
	strncpy(buf, js_str, buflen);
	free(js_str);

	return 0;
}

static int pv_devmeta_time(struct pv_devmeta_read *pv_devmeta_read)
{
	char *buf = pv_devmeta_read->buf;
	int buflen = pv_devmeta_read->buflen;

	if (pv_devmeta_buf_check(pv_devmeta_read))
		return -1;

	struct timeval tm = { 0 };
	struct timezone tz = { 0 };
	int err = gettimeofday(&tm, &tz);

	if (err != 0) {
		pv_log(WARN, "Couldn't add time data: %s (%d)", strerror(errno),
		       errno);
		memset(buf, 0, buflen);
		return -1;
	}

	struct pv_json_ser js;
	pv_json_ser_init(&js, 512);

	pv_json_ser_object(&js);
	{
		pv_json_ser_key(&js, "timeval");
		pv_json_ser_object(&js);
		{
			pv_json_ser_key(&js, "tv_sec");
			pv_json_ser_number(&js, tm.tv_sec);
			pv_json_ser_key(&js, "tv_usec");
			pv_json_ser_number(&js, tm.tv_usec);
			pv_json_ser_object_pop(&js);
		}
		pv_json_ser_key(&js, "timezone");
		pv_json_ser_object(&js);
		{
			pv_json_ser_key(&js, "tz_minuteswest");
			pv_json_ser_number(&js, tz.tz_minuteswest);
			pv_json_ser_key(&js, "tz_dsttime");
			pv_json_ser_number(&js, tz.tz_dsttime);
			pv_json_ser_object_pop(&js);
		}
		pv_json_ser_object_pop(&js);
	}

	char *js_str = pv_json_ser_str(&js);
	strncpy(buf, js_str, buflen);
	free(js_str);

	return 0;
}

// second field is idle time summed over all CPUs, so it can exceed uptime
static int pv_devmeta_get_uptime(double *uptime, double *idle)
{
	FILE *fp = fopen(PV_DEVMETA_UPTIME_PATH, "r");
	if (!fp) {
		pv_log(DEBUG, "couldn't open %s", PV_DEVMETA_UPTIME_PATH);
		return -1;
	}

	int ret = fscanf(fp, "%lf %lf", uptime, idle);
	fclose(fp);

	if (ret != 2) {
		pv_log(DEBUG, "couldn't read %s (got %d fields)",
		       PV_DEVMETA_UPTIME_PATH, ret);
		return -1;
	}

	return 0;
}

static int pv_devmeta_sysinfo(struct pv_devmeta_read *pv_devmeta_read)
{
	char *buf = pv_devmeta_read->buf;
	int buflen = pv_devmeta_read->buflen;

	if (pv_devmeta_buf_check(pv_devmeta_read))
		return -1;

	struct sysinfo info = { 0 };
	int err = sysinfo(&info);
	if (err) {
		pv_log(WARN, "Couldn't get sysinfo %s (%d)", strerror(errno),
		       errno);
		memset(buf, 0, buflen);
		return -1;
	}

	double uptime = 0;
	double idle = 0;
	// sysinfo() only has whole seconds and no idle time at all
	bool has_idle = pv_devmeta_get_uptime(&uptime, &idle) == 0;

	if (!has_idle)
		uptime = (double)info.uptime;

	struct pv_json_ser js;
	pv_json_ser_init(&js, 512);

	pv_json_ser_object(&js);
	{
		pv_json_ser_key(&js, "uptime");
		pv_json_ser_number_fixed(&js, uptime, 2);
		if (has_idle) {
			pv_json_ser_key(&js, "idle");
			pv_json_ser_number_fixed(&js, idle, 2);
		}
		pv_json_ser_key(&js, "loads.0");
		pv_json_ser_number(&js, info.loads[0]);
		pv_json_ser_key(&js, "loads.1");
		pv_json_ser_number(&js, info.loads[1]);
		pv_json_ser_key(&js, "loads.2");
		pv_json_ser_number(&js, info.loads[2]);
		pv_json_ser_key(&js, "totalram");
		pv_json_ser_number(&js, info.totalram);
		pv_json_ser_key(&js, "freeram");
		pv_json_ser_number(&js, info.freeram);
		pv_json_ser_key(&js, "sharedram");
		pv_json_ser_number(&js, info.sharedram);
		pv_json_ser_key(&js, "bufferram");
		pv_json_ser_number(&js, info.bufferram);
		pv_json_ser_key(&js, "totalswap");
		pv_json_ser_number(&js, info.totalswap);
		pv_json_ser_key(&js, "freeswap");
		pv_json_ser_number(&js, info.freeswap);
		pv_json_ser_key(&js, "procs");
		pv_json_ser_number(&js, info.procs);
		pv_json_ser_key(&js, "totalhigh");
		pv_json_ser_number(&js, info.totalhigh);
		pv_json_ser_key(&js, "freehigh");
		pv_json_ser_number(&js, info.freehigh);
		pv_json_ser_key(&js, "mem_unit");
		pv_json_ser_number(&js, info.mem_unit);
		pv_json_ser_object_pop(&js);
	}

	char *js_str = pv_json_ser_str(&js);
	strncpy(buf, js_str, buflen);
	free(js_str);

	return 0;
}

static int pv_devmeta_read_revision(struct pv_devmeta_read *pv_devmeta_read)
{
	char *buf = pv_devmeta_read->buf;
	int buflen = pv_devmeta_read->buflen;
	struct pantavisor *pv = pv_get_instance();

	if (pv_devmeta_buf_check(pv_devmeta_read))
		return -1;

	SNPRINTF_WTRUNC(buf, buflen, "%s", pv->state->rev);
	return 0;
}

static int pv_devmeta_read_mode(struct pv_devmeta_read *pv_devmeta_read)
{
	char *buf = pv_devmeta_read->buf;
	int buflen = pv_devmeta_read->buflen;
	struct pantavisor *pv = pv_get_instance();

	if (pv_devmeta_buf_check(pv_devmeta_read))
		return -1;

	if (pv->remote_mode)
		SNPRINTF_WTRUNC(buf, buflen, "remote");
	else
		SNPRINTF_WTRUNC(buf, buflen, "local");
	return 0;
}

static int pv_devmeta_read_online(struct pv_devmeta_read *pv_devmeta_read)
{
	char *buf = pv_devmeta_read->buf;
	int buflen = pv_devmeta_read->buflen;
	struct pantavisor *pv = pv_get_instance();

	if (pv_devmeta_buf_check(pv_devmeta_read))
		return -1;

	if (pv_pantahub_is_online())
		SNPRINTF_WTRUNC(buf, buflen, "1");
	else
		SNPRINTF_WTRUNC(buf, buflen, "0");
	return 0;
}

static int pv_devmeta_read_claimed(struct pv_devmeta_read *pv_devmeta_read)
{
	char *buf = pv_devmeta_read->buf;
	int buflen = pv_devmeta_read->buflen;
	struct pantavisor *pv = pv_get_instance();

	if (pv_devmeta_buf_check(pv_devmeta_read))
		return -1;

	if (pv->unclaimed)
		SNPRINTF_WTRUNC(buf, buflen, "0");
	else
		SNPRINTF_WTRUNC(buf, buflen, "1");
	return 0;
}

static int pv_devmeta_storage(struct pv_devmeta_read *pv_devmeta_read)
{
	char *buf = pv_devmeta_read->buf;
	int buflen = pv_devmeta_read->buflen;

	if (pv_devmeta_buf_check(pv_devmeta_read))
		return -1;

	char *json = pv_storage_get_meta_json();
	if (!json) {
		pv_log(WARN, "couldn't get storage usage");
		return -1;
	}

	SNPRINTF_WTRUNC(buf, buflen, "%s", json);
	free(json);

	return 0;
}

static struct pv_devmeta_read pv_devmeta_readkeys[] = {
	{ .key = DEVMETA_KEY_PV_ARCH, .reader = pv_devmeta_read_arch },
	{ .key = DEVMETA_KEY_PV_VERSION, .reader = pv_devmeta_read_version },
	{ .key = DEVMETA_KEY_PV_DTMODEL, .reader = pv_devmeta_read_dtmodel },
	{ .key = DEVMETA_KEY_PV_CPUMODEL, .reader = pv_devmeta_read_cpumodel },
	{ .key = DEVMETA_KEY_PV_REVISION, .reader = pv_devmeta_read_revision },
	{ .key = DEVMETA_KEY_PV_MODE, .reader = pv_devmeta_read_mode },
	{ .key = DEVMETA_KEY_PH_ONLINE, .reader = pv_devmeta_read_online },
	{ .key = DEVMETA_KEY_PH_CLAIMED, .reader = pv_devmeta_read_claimed },
	{ .key = DEVMETA_KEY_PV_UNAME, .reader = pv_devmeta_uname },
	{ .key = DEVMETA_KEY_PV_TIME,
	  .reader = pv_devmeta_time,
	  .dynamic = true },
	{ .key = DEVMETA_KEY_PV_SYSINFO,
	  .reader = pv_devmeta_sysinfo,
	  .dynamic = true },
	{ .key = DEVMETA_KEY_STORAGE,
	  .reader = pv_devmeta_storage,
	  .dynamic = true }
};

static void pv_metadata_free(struct pv_meta *usermeta)
{
	if (usermeta->key)
		free(usermeta->key);
	if (usermeta->value)
		free(usermeta->value);

	free(usermeta);
}

static void pv_usermeta_remove(struct pv_metadata *metadata)
{
	struct pv_meta *curr, *tmp;
	struct dl_list *head = &metadata->usermeta;

	if (dl_list_empty(&metadata->usermeta))
		return;

	pv_log(DEBUG, "removing user meta list");

	dl_list_for_each_safe(curr, tmp, head, struct pv_meta, list)
	{
		dl_list_del(&curr->list);
		pv_metadata_free(curr);
	}
}

static void pv_devmeta_remove(struct pv_metadata *metadata)
{
	struct pv_meta *curr, *tmp;
	struct dl_list *head = &metadata->devmeta;

	if (dl_list_empty(&metadata->devmeta))
		return;

	pv_log(DEBUG, "removing devmeta list");

	dl_list_for_each_safe(curr, tmp, head, struct pv_meta, list)
	{
		dl_list_del(&curr->list);
		pv_metadata_free(curr);
	}
}

static struct pv_meta *pv_metadata_get_by_key(struct dl_list *head,
					      const char *key)
{
	struct pv_meta *curr, *tmp;

	dl_list_for_each_safe(curr, tmp, head, struct pv_meta, list)
	{
		if (!strcmp(key, curr->key))
			return curr;
	}

	return NULL;
}

static int pv_metadata_add(struct dl_list *head, const char *key,
			   const char *value)
{
	int ret = -1;
	struct pv_meta *curr;

	if (!head || !key || !value)
		goto out;

	// find and update value
	curr = pv_metadata_get_by_key(head, key);
	if (curr) {
		ret = 0;
		if (!strcmp(curr->value, value) == 0) {
			free(curr->value);
			curr->value = strdup(value);
			ret = 1;
		}
		goto out;
	}

	// add new key and value pair
	curr = calloc(1, sizeof(struct pv_meta));
	if (curr) {
		dl_list_init(&curr->list);
		curr->key = strdup(key);
		curr->value = strdup(value);
		if (curr->key && curr->value) {
			dl_list_add(head, &curr->list);
			ret = 1;
		} else {
			if (curr->key)
				free(curr->key);
			if (curr->value)
				free(curr->value);
			free(curr);
		}
	}

out:
	return ret;
}

int pv_metadata_add_usermeta(const char *key, const char *value)
{
	struct pantavisor *pv = pv_get_instance();
	struct pv_meta *curr;
	int ret = pv_metadata_add(&pv->metadata->usermeta, key, value);

	// set updated flags for all current existing pairs so they are not deleted
	if (ret >= 0) {
		curr = pv_metadata_get_by_key(&pv->metadata->usermeta, key);
		if (curr)
			curr->updated = true;
	}

	if (ret > 0) {
		pv_log(DEBUG, "user metadata key %s added or updated", key);
		pv_config_override_value(key, value);
		pv_storage_save_usermeta(key, value);
	}

	return ret;
}

int pv_metadata_rm_usermeta(const char *key)
{
	struct pantavisor *pv = pv_get_instance();
	struct pv_meta *meta;

	meta = pv_metadata_get_by_key(&pv->metadata->usermeta, key);

	if (meta) {
		dl_list_del(&meta->list);
		pv_storage_rm_usermeta(meta->key);
		pv_metadata_free(meta);
		pv_config_unset_value(key);
		return 0;
	}

	return -1;
}

static int pv_usermeta_parse(struct pantavisor *pv, char *buf)
{
	int ret = 0, tokc, n;
	jsmntok_t *tokv;
	jsmntok_t **keys, **key_i;
	char *key = NULL, *value;

	ret = jsmnutil_parse_json(buf, &tokv, &tokc);
	keys = jsmnutil_get_object_keys(buf, tokv);

	key_i = keys;
	while (*key_i) {
		n = (*key_i)->end - (*key_i)->start;

		// copy key
		key = calloc(n + 1, sizeof(char));
		if (!key)
			break;

		strncpy(key, buf + (*key_i)->start, n);

		// copy value
		n = (*key_i + 1)->end - (*key_i + 1)->start;
		value = calloc(n + 1, sizeof(char));
		if (!value)
			break;

		strncpy(value, buf + (*key_i + 1)->start, n);
		pv_str_unescape_to_ascii(value, n);

		// add or update metadata
		// primitives with value 'null' have value NULL
		if ((*key_i + 1)->type != JSMN_PRIMITIVE ||
		    strcmp("null", value))
			pv_metadata_add_usermeta(key, value);

		// free intermediates
		if (key) {
			free(key);
			key = 0;
		}
		if (value) {
			free(value);
			value = 0;
		}

		key_i++;
	}

	jsmnutil_tokv_free(keys);

out:
	if (tokv)
		free(tokv);
	if (key)
		free(key);

	return ret;
}

static void usermeta_clear(struct pantavisor *pv)
{
	struct pv_meta *curr, *tmp;
	struct dl_list *head = NULL;

	if (!pv)
		return;
	if (!pv->metadata)
		return;

	head = &pv->metadata->usermeta;
	dl_list_for_each_safe(curr, tmp, head, struct pv_meta, list)
	{
		// clear the flag updated for next iteration
		if (curr->updated)
			curr->updated = false;
		// not updated means user meta is no longer in cloud
		else
			pv_metadata_rm_usermeta(curr->key);
	}
}

static int _pv_metadata_add_devmeta(const char *key, const char *value,
				    bool persist)
{
	struct pantavisor *pv = pv_get_instance();
	int ret = pv_metadata_add(&pv->metadata->devmeta, key, value);

	// a dynamic value changes on every read, so neither the write-through
	// nor the log line below carry any information worth the flash wear
	if (ret > 0 && persist) {
		pv_log(DEBUG, "device metadata key %s added or updated", key);
		pv_storage_save_devmeta(key, value);
	}

	return ret;
}

int pv_metadata_add_devmeta(const char *key, const char *value)
{
	return _pv_metadata_add_devmeta(key, value, true);
}

int pv_metadata_rm_devmeta(const char *key)
{
	struct pantavisor *pv = pv_get_instance();
	struct pv_meta *curr;

	curr = pv_metadata_get_by_key(&pv->metadata->devmeta, key);

	if (curr) {
		dl_list_del(&curr->list);
		pv_storage_rm_devmeta(curr->key);
		pv_metadata_free(curr);
		return 0;
	}

	return -1;
}

void pv_metadata_parse_devmeta(const char *buf)
{
	int tokc, n;
	jsmntok_t *tokv = NULL;
	jsmntok_t **key = NULL;
	char *metakey = NULL, *metavalue = NULL;

	// parse device metadata json
	jsmnutil_parse_json(buf, &tokv, &tokc);
	key = jsmnutil_get_object_keys(buf, tokv);

	if (!key)
		goto out;

	// parse key
	n = (*key)->end - (*key)->start;
	metakey = malloc(n + 1);
	if (!metakey)
		goto out;

	SNPRINTF_WTRUNC(metakey, n + 1, "%s", buf + (*key)->start);

	// parse value
	n = (*key + 1)->end - (*key + 1)->start;
	metavalue = malloc(n + 1);
	if (!metavalue)
		goto out;

	SNPRINTF_WTRUNC(metavalue, n + 1, "%s", buf + (*key + 1)->start);

	pv_metadata_add_devmeta(metakey, metavalue);

out:
	if (metakey)
		free(metakey);
	if (metavalue)
		free(metavalue);

	jsmnutil_tokv_free(key);

	if (tokv)
		free(tokv);
}

int pv_metadata_init_devmeta(struct pantavisor *pv)
{
	char *buf = NULL;
	struct buffer *buffer = NULL;
	int i = 0, bufsize = 0;
	/*
	 * we can use one of the large buffer. Since
	 * this information won't be very large, it's safe
	 * to assume even the complete json would
	 * be small enough to fit inside this buffer.
	 */
	buffer = pv_buffer_get(true);
	if (!buffer) {
		pv_log(INFO, "couldn't allocate buffer to store device info");
		return -1;
	}

	buf = buffer->buf;
	bufsize = buffer->size;

	// add system info to initial device metadata
	for (i = 0; i < ARRAY_LEN(pv_devmeta_readkeys); i++) {
		struct pv_devmeta_read *rk = &pv_devmeta_readkeys[i];
		int ret = 0;

		// drop copies persisted by pantavisor versions that wrote
		// dynamic keys through to storage
		if (rk->dynamic)
			pv_storage_rm_devmeta(rk->key);

		rk->buf = buf;
		rk->buflen = bufsize;
		ret = rk->reader(rk);
		if (!ret)
			_pv_metadata_add_devmeta(rk->key, buf, !rk->dynamic);
		rk->buf = NULL;
		rk->buflen = 0;
	}
	pv_buffer_drop(buffer);

	return 0;
}

void pv_metadata_parse_usermeta(char *buf)
{
	struct pantavisor *pv = pv_get_instance();
	char *body = strdup(buf);

	pv_usermeta_parse(pv, body);

	if (body)
		free(body);

	usermeta_clear(pv);
}

char *pv_metadata_get_usermeta(char *key)
{
	struct pantavisor *pv = pv_get_instance();
	struct dl_list *head = &pv->metadata->usermeta;
	struct pv_meta *curr, *tmp;

	dl_list_for_each_safe(curr, tmp, head, struct pv_meta, list)
	{
		if (!strcmp(curr->key, key))
			return curr->value;
	}
	return NULL;
}

static void pv_metadata_load_usermeta()
{
	struct dl_list files; // pv_path
	struct pv_path *curr, *tmp;
	char path[PATH_MAX];
	char *value;

	dl_list_init(&files);
	pv_paths_pv_usrmeta_key(path, PATH_MAX, "");
	pv_storage_get_subdir(path, "", &files);

	if (dl_list_empty(&files))
		return;

	pv_log(DEBUG, "loading user meta from %s", path);

	dl_list_for_each_safe(curr, tmp, &files, struct pv_path, list)
	{
		if (!strncmp(curr->path, "..", strlen("..")) ||
		    !strncmp(curr->path, ".", strlen(".")))
			continue;

		pv_paths_pv_usrmeta_key(path, PATH_MAX, curr->path);
		value = pv_fs_file_load(path, METADATA_MAX_SIZE);
		if (!value) {
			pv_log(ERROR, "could not load %s: %s", path,
			       strerror(errno));
			continue;
		}

		pv_metadata_add_usermeta(curr->path, value);
		free(value);
	}

	pv_storage_free_subdir(&files);
}

static void pv_metadata_load_devmeta()
{
	struct dl_list files; // pv_path
	struct pv_path *curr, *tmp;
	char path[PATH_MAX];
	char *value;

	dl_list_init(&files);
	pv_paths_pv_devmeta_key(path, PATH_MAX, "");
	pv_storage_get_subdir(path, "", &files);

	if (dl_list_empty(&files))
		return;

	pv_log(DEBUG, "loading device meta from %s", path);

	dl_list_for_each_safe(curr, tmp, &files, struct pv_path, list)
	{
		if (!strncmp(curr->path, "..", strlen("..")) ||
		    !strncmp(curr->path, ".", strlen(".")))
			continue;

		pv_paths_pv_devmeta_key(path, PATH_MAX, curr->path);
		value = pv_fs_file_load(path, METADATA_MAX_SIZE);
		if (!value) {
			pv_log(ERROR, "could not load %s: %s", path,
			       strerror(errno));
			continue;
		}

		pv_metadata_add_devmeta(curr->path, value);
		free(value);
	}

	pv_storage_free_subdir(&files);
}

int pv_metadata_init()
{
	if (pv_metadata_mount())
		return -1;

	struct pantavisor *pv = pv_get_instance();

	pv->metadata = calloc(1, sizeof(struct pv_metadata));
	if (!pv->metadata)
		return -1;

	dl_list_init(&pv->metadata->usermeta);
	dl_list_init(&pv->metadata->devmeta);

	pv_metadata_load_usermeta();
	pv_metadata_load_devmeta();

	return 0;
}

// Refresh every key whose value is only meaningful at the moment it is read,
// so that what we hand out is current instead of frozen at pv_metadata_init_devmeta().
static void pv_devmeta_refresh_dynamic(void)
{
	struct buffer *buffer = pv_buffer_get(true);
	if (!buffer) {
		pv_log(WARN, "couldn't refresh dynamic devmeta: no buffer");
		return;
	}

	for (int i = 0; i < ARRAY_LEN(pv_devmeta_readkeys); i++) {
		struct pv_devmeta_read *rk = &pv_devmeta_readkeys[i];

		if (!rk->dynamic)
			continue;

		rk->buf = buffer->buf;
		rk->buflen = buffer->size;
		if (rk->reader(rk) != 0) {
			pv_log(DEBUG, "couldn't refresh devmeta key %s",
			       rk->key);
		} else {
			_pv_metadata_add_devmeta(rk->key, rk->buf, false);
		}

		// the buffer goes back to the pool below; do not leave the
		// table pointing into it
		rk->buf = NULL;
		rk->buflen = 0;
	}

	pv_buffer_drop(buffer);
}

static char *pv_metadata_get_meta_string(struct dl_list *meta_list)
{
	struct pv_meta *curr, *tmp;
	int len = 1, line_len;
	char *json = calloc(len, sizeof(char));

	// open json
	json[0] = '{';

	if (dl_list_empty(meta_list)) {
		len++;
		goto out;
	}

	// add value,key pair to json
	dl_list_for_each_safe(curr, tmp, meta_list, struct pv_meta, list)
	{
		if (!curr->value)
			continue;

		if (!pv_json_is_valid(curr->value)) {
			char *escaped = pv_json_format(curr->value,
						       strlen(curr->value));
			if (!escaped)
				continue;
			line_len = strlen(curr->key) + strlen(escaped) + 6;
			json = realloc(json, len + line_len + 1);
			SNPRINTF_WTRUNC(&json[len], line_len + 1,
					"\"%s\":\"%s\",", curr->key, escaped);
			free(escaped);
		} else {
			line_len = strlen(curr->key) + strlen(curr->value) + 4;
			json = realloc(json, len + line_len + 1);
			SNPRINTF_WTRUNC(&json[len], line_len + 1, "\"%s\":%s,",
					curr->key, curr->value);
		}
		len += line_len;
	}

out:
	len += 1;
	json = realloc(json, len);
	// close json
	json[len - 2] = '}';
	json[len - 1] = '\0';

	return json;
}

// Change policy: what makes a devmeta key worth a Hub roundtrip. Keys and
// fields not listed are compared verbatim, so state keys keep report-on-change.
typedef enum {
	DEVMETA_SIG_EXACT,
	DEVMETA_SIG_NEVER,
	DEVMETA_SIG_REL,
} devmeta_sig_t;

struct pv_devmeta_sig {
	const char *name;
	devmeta_sig_t sig;
	int pct; // DEVMETA_SIG_REL only; 0 means metadata.devmeta.threshold
	const struct pv_devmeta_sig *sub; // policy for a flat object value
};

static const struct pv_devmeta_sig pv_devmeta_sig_sysinfo[] = {
	// both only ever grow and Hub can derive them from the PUT it just
	// received, so they must never be the reason we send one
	{ .name = "uptime", .sig = DEVMETA_SIG_NEVER },
	{ .name = "idle", .sig = DEVMETA_SIG_NEVER },
	// Thresholds below are the measured noise floor on an idle board sampled
	// one devmeta interval apart: loads.0 moved 19%, sharedram 78% and freeram
	// 12% with nothing happening, so anything tighter just sends every cycle.
	// The heartbeat still carries these out at least once per period.
	{ .name = "loads.0", .sig = DEVMETA_SIG_NEVER },
	{ .name = "loads.1", .sig = DEVMETA_SIG_NEVER },
	{ .name = "loads.2", .sig = DEVMETA_SIG_NEVER },
	{ .name = "sharedram", .sig = DEVMETA_SIG_NEVER },
	{ .name = "procs", .sig = DEVMETA_SIG_REL, .pct = 10 },
	{ .name = "freeram", .sig = DEVMETA_SIG_REL, .pct = 25 },
	{ .name = "bufferram", .sig = DEVMETA_SIG_REL, .pct = 25 },
	{ .name = "freeswap", .sig = DEVMETA_SIG_REL, .pct = 25 },
	{ .name = "freehigh", .sig = DEVMETA_SIG_REL, .pct = 25 },
	// totalram, totalswap, totalhigh and mem_unit stay exact: they only
	// move when the machine itself changed
	{ 0 }
};

static const struct pv_devmeta_sig pv_devmeta_sig_storage[] = {
	{ .name = "free", .sig = DEVMETA_SIG_REL },
	{ .name = "real_free", .sig = DEVMETA_SIG_REL },
	// total and reserved stay exact
	{ 0 }
};

static const struct pv_devmeta_sig pv_devmeta_sig_keys[] = {
	{ .name = DEVMETA_KEY_PV_TIME, .sig = DEVMETA_SIG_NEVER },
	{ .name = DEVMETA_KEY_PV_SYSINFO,
	  .sig = DEVMETA_SIG_EXACT,
	  .sub = pv_devmeta_sig_sysinfo },
	{ .name = DEVMETA_KEY_STORAGE,
	  .sig = DEVMETA_SIG_EXACT,
	  .sub = pv_devmeta_sig_storage },
	{ 0 }
};

static const struct pv_devmeta_sig *
pv_devmeta_sig_get(const struct pv_devmeta_sig *tbl, const char *name, int len)
{
	if (!tbl)
		return NULL;

	for (; tbl->name; tbl++) {
		if ((int)strlen(tbl->name) == len &&
		    !strncmp(tbl->name, name, len))
			return tbl;
	}

	return NULL;
}

static jsmntok_t *pv_devmeta_sig_find(const char *buf, jsmntok_t **keys,
				      const char *name, int len)
{
	for (jsmntok_t **k = keys; *k; k++) {
		int n = (*k)->end - (*k)->start;

		if (n == len && !strncmp(buf + (*k)->start, name, len))
			return *k + 1;
	}

	return NULL;
}

static bool pv_devmeta_sig_num(const char *prev, int prev_len, const char *next,
			       int next_len, int pct)
{
	char a[32], b[32];
	char *ea = NULL, *eb = NULL;

	if (prev_len >= (int)sizeof(a) || next_len >= (int)sizeof(b))
		return true;

	memcpy(a, prev, prev_len);
	a[prev_len] = '\0';
	memcpy(b, next, next_len);
	b[next_len] = '\0';

	double va = strtod(a, &ea);
	double vb = strtod(b, &eb);
	if (ea == a || eb == b)
		return true;

	if (pct <= 0)
		pct = pv_config_get_int(PH_METADATA_DEVMETA_THRESHOLD);
	if (pct <= 0)
		return true;

	double delta = vb > va ? vb - va : va - vb;
	double base = va < 0 ? -va : va;

	// a percentage of nearly nothing is noise; take any whole-unit move
	if (base < 1)
		return delta >= 1;

	return delta * 100 >= base * pct;
}

// Compare two flat json objects under tbl. Fails safe: anything we cannot parse
// counts as a change so we never sit on an update we failed to understand.
static bool pv_devmeta_sig_obj(const char *prev, const char *next,
			       const struct pv_devmeta_sig *tbl)
{
	jsmntok_t *ptokv = NULL, *ntokv = NULL;
	jsmntok_t **pkeys = NULL, **nkeys = NULL;
	int ptokc = 0, ntokc = 0;
	bool sig = true;

	if (jsmnutil_parse_json(prev, &ptokv, &ptokc) < 0 || !ptokv)
		goto out;
	if (jsmnutil_parse_json(next, &ntokv, &ntokc) < 0 || !ntokv)
		goto out;

	pkeys = jsmnutil_get_object_keys(prev, ptokv);
	nkeys = jsmnutil_get_object_keys(next, ntokv);
	if (!pkeys || !nkeys)
		goto out;

	for (jsmntok_t **k = nkeys; *k; k++) {
		int len = (*k)->end - (*k)->start;
		const char *name = next + (*k)->start;
		const struct pv_devmeta_sig *e =
			pv_devmeta_sig_get(tbl, name, len);
		devmeta_sig_t kind = e ? e->sig : DEVMETA_SIG_EXACT;

		if (kind == DEVMETA_SIG_NEVER)
			continue;

		jsmntok_t *pt = pv_devmeta_sig_find(prev, pkeys, name, len);
		if (!pt)
			goto out;

		jsmntok_t *nt = *k + 1;
		int plen = pt->end - pt->start;
		int nlen = nt->end - nt->start;
		const char *pval = prev + pt->start;
		const char *nval = next + nt->start;

		if (plen == nlen && !memcmp(pval, nval, plen))
			continue;

		if (e && e->sub) {
			char *ps = strndup(pval, plen);
			char *ns = strndup(nval, nlen);
			bool sub = !ps || !ns ||
				   pv_devmeta_sig_obj(ps, ns, e->sub);

			free(ps);
			free(ns);
			if (sub)
				goto out;
			continue;
		}

		if (kind == DEVMETA_SIG_REL) {
			if (pv_devmeta_sig_num(pval, plen, nval, nlen, e->pct))
				goto out;
			continue;
		}

		goto out;
	}

	// a key that disappeared is a change too, unless we ignore it anyway
	for (jsmntok_t **k = pkeys; *k; k++) {
		int len = (*k)->end - (*k)->start;
		const char *name = prev + (*k)->start;
		const struct pv_devmeta_sig *e =
			pv_devmeta_sig_get(tbl, name, len);

		if (e && e->sig == DEVMETA_SIG_NEVER)
			continue;
		if (!pv_devmeta_sig_find(next, nkeys, name, len))
			goto out;
	}

	sig = false;
out:
	if (pkeys)
		jsmnutil_tokv_free(pkeys);
	if (nkeys)
		jsmnutil_tokv_free(nkeys);
	if (ptokv)
		free(ptokv);
	if (ntokv)
		free(ntokv);

	return sig;
}

bool pv_metadata_devmeta_significant(const char *prev, const char *next)
{
	if (!prev || !next)
		return true;

	if (!strcmp(prev, next))
		return false;

	return pv_devmeta_sig_obj(prev, next, pv_devmeta_sig_keys);
}

char *pv_metadata_get_user_meta_string()
{
	return pv_metadata_get_meta_string(
		&pv_get_instance()->metadata->usermeta);
}

char *pv_metadata_get_device_meta_string()
{
	pv_devmeta_refresh_dynamic();

	return pv_metadata_get_meta_string(
		&pv_get_instance()->metadata->devmeta);
}

void pv_metadata_remove()
{
	struct pantavisor *pv = pv_get_instance();

	if (!pv->metadata)
		return;

	pv_log(DEBUG, "removing metadata");

	pv_usermeta_remove(pv->metadata);
	pv_devmeta_remove(pv->metadata);

	free(pv->metadata);
	pv->metadata = NULL;
}

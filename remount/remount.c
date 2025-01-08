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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <regex.h>
#include <sys/mount.h>

#include <jsmn/jsmnutil.h>

#include "utils/fs.h"
#include "utils/list.h"
#include "utils/json.h"
#include "utils/str.h"

#define STORAGE_TRAILS_CURRENT_PVR_JSON_PATH "/storage/trails/current/.pvr/json"
#define PROC_MOUNTS_PATH "/proc/mounts"

// ~ bit
#define MS_INVERTED_VALUE (1u << 31)

struct remount_entry {
	char *exp;
	char *opts;
	struct dl_list list; // remount_entry
};

static void free_remount_entry(struct remount_entry* entry)
{
	if (!entry)
		return;

	if (entry->exp)
		free(entry->exp);
	if (entry->opts)
		free(entry->opts);
	free(entry);
}

static void parse_remount_entry(char *json, struct dl_list *remount_entries)
{
	printf("DEBUG: parsing remount entry '%s'...\n\r", json);

	int tokc, n, ret = -1;
	jsmntok_t *tokv;
	jsmntok_t **k;

	if (jsmnutil_parse_json(json, &tokv, &tokc) < 0) {
		printf("WARN: JSON could not be parsed\n\r");
		goto out;
	}

	k = jsmnutil_get_object_keys(json, tokv);
	if (!k) {
		printf("WARN: key not found\n\r");
		goto out;
	}
	if (!(k + 1)) {
		printf("WARN: value not found\n\r");
		goto out;
	}

	struct remount_entry *p;
	p = calloc(1, sizeof(struct remount_entry));
	if (!p)
		goto out;

	char *prefix = getenv("LXC_ROOTFS_MOUNT");
	size_t prefix_len = 0;
	if (prefix)
		prefix_len = strlen(prefix);

	// parse regex key
	n = (*k)->end - (*k)->start;
	p->exp = calloc(n + prefix_len + 2 + 1, sizeof(char));
	if (!p->exp)
		goto out;
	// force begin before prefix and key regex
	p->exp[0] = '^';
	// add LXC mount prefix when defined
	if (prefix)
		strncpy(p->exp + 1, prefix, prefix_len);
	// add regex key
	strncpy(p->exp + prefix_len + 1, json + (*k)->start, n);
	// force end after key regex and remove trailing /
	if (p->exp[prefix_len + n] == '/')
		p->exp[prefix_len + n] = '$';
	else
		p->exp[prefix_len + n + 1] = '$';

	// parse options value
	n = (*k + 1)->end - (*k + 1)->start;
	p->opts = calloc(n + 1, sizeof(char));
	if (!p->opts)
		goto out;
	snprintf(p->opts, n + 1, "%s", json + (*k + 1)->start);

	printf("DEBUG: parsed remount regex '%s' with opts '%s'...\n\r",
	       p->exp, p->opts);

	dl_list_add_tail(remount_entries, &p->list);

	ret = 0;

out:
	free_remount_entry(p);

	jsmnutil_tokv_free(k);

	if (tokv)
		free(tokv);
}

static void parse_remount_array(char *json, struct dl_list *remount_entries)
{
	printf("DEBUG: parsing remount array...\n\r");

	char *str = NULL;
	int tokc, size;
	jsmntok_t *tokv, *t;

	if (jsmnutil_parse_json(json, &tokv, &tokc) < 0)
		goto out;

	size = jsmnutil_array_count(json, tokv);
	if (size <= 0)
		goto out;

	t = tokv + 1;
	while ((str = pv_json_array_get_one_str(json, &size, &t))) {
		printf("DEBUG: remount entry object '%s' found\n\r", str);

		parse_remount_entry(str, remount_entries);
		free(str);
		str = NULL;
		t = t + 2;
	}

out:
	if (str)
		free(str);
	if (tokv)
		free(tokv);
}

static void parse_remount_object(char *json, struct dl_list *remount_entries)
{
	printf("DEBUG: parsing remount object...\n\r");

	int tokc;
	jsmntok_t *tokv = NULL;

	if (jsmnutil_parse_json(json, &tokv, &tokc) < 0) {
		printf("WARN: JSON could not be parsed\n\r");
		goto out;
	}

	char *policy = NULL;
	policy = getenv("PV_REMOUNT_POLICY");
	if (!policy)
		policy = getenv("pv_remount_policy");
	if (!policy)
		policy = "default";
	printf("DEBUG: remount policy '%s' to be used\n\r", policy);

	char *remount_array = NULL;
	remount_array = pv_json_get_value(json, policy, tokv, tokc);
	if (!remount_array) {
		printf("WARN: '%s' key not found\n\r", policy);
		goto out;
	}

	parse_remount_array(remount_array, remount_entries);
	free(remount_array);

out:
	if (tokv)
		free(tokv);
}

static void parse_device_run_object(char *json, struct dl_list *remount_entries)
{
	printf("DEBUG: parsing component JSON...\n\r");

	int tokc;
	jsmntok_t *tokv = NULL;

	if (jsmnutil_parse_json(json, &tokv, &tokc) < 0) {
		printf("WARN: JSON could not be parsed\n\r");
		goto out;
	}

	char *remount_object = NULL;
	remount_object = pv_json_get_value(json, "remount", tokv, tokc);
	if (!remount_object) {
		printf("WARN: remount key not found\n\r");
		goto out;
	}

	parse_remount_object(remount_object, remount_entries);
	free(remount_object);

out:
	if (tokv)
		free(tokv);
}

static char *get_run_json_rel_path(void)
{
	char *pname = NULL;
	pname = getenv("LXC_NAME");
	if (!pname) {
		printf("ERROR: LXC_NAME env not set\n\r");
		return NULL;
	}
	printf("DEBUG: container name '%s' to be used\n\r", pname);

	char *path_fmt = "%s/run.json";
	size_t len = snprintf(NULL, 0, path_fmt, pname) + 1;
	char *path = calloc(len, sizeof(char));
	snprintf(path, len, path_fmt, pname);
	return path;
}

static int parse_state_json(char *json, struct dl_list *remount_entries)
{
	printf("DEBUG: parsing state JSON...\n\r");

	int tokc, ret = -1;
	jsmntok_t *tokv = NULL;

	if (jsmnutil_parse_json(json, &tokv, &tokc) < 0) {
		printf("WARN: JSON could not be parsed\n\r");
		goto out;
	}

	printf("DEBUG: searching for device.json...\n\r");

	char *device_json = NULL;
	device_json = pv_json_get_value(json, "device.json", tokv, tokc);
	if (device_json) {
		parse_device_run_object(device_json, remount_entries);
		free(device_json);
	} else
		printf("WARN: device.json not found\n\r");

	char *rel_path = NULL;
	rel_path = get_run_json_rel_path();
	if (!rel_path) {
		printf("ERROR: could not form run.json relative path\n\r");
		goto out;
	}

	printf("DEBUG: searching for '%s'...\n\r", rel_path);

	char *run_json = NULL;
	run_json = pv_json_get_value(json, rel_path, tokv, tokc);
	if (run_json) {
		parse_device_run_object(run_json, remount_entries);
		free(run_json);
	} else
		printf("WARN: '%s' not found\n\r", rel_path);

	ret = 0;

out:
	if (rel_path)
		free(rel_path);
	if (tokv)
		free(tokv);

	return ret;
}

static char *load_state_json(void)
{
	char *json = NULL;
	char *path = STORAGE_TRAILS_CURRENT_PVR_JSON_PATH;

	printf("DEBUG: loading state JSON from '%s'...\n\r", path);

	json = pv_fs_file_load(path, 0);
	if (!json) {
		printf("ERROR: could not load '%s': '%s'\n\r", path,
		       strerror(errno));
		return NULL;
	}

	return json;
}

static int load_remount_entries(struct dl_list *remount_entries)
{
	printf("DEBUG: loading remount settings from state JSON...\n\r");

	int ret = -1;

	char *json = NULL;
	json = load_state_json();
	if (!json) {
		printf("ERROR: could not load state JSON\n\r");
		goto out;
	}

	if (parse_state_json(json, remount_entries)) {
		printf("ERROR: could not parse state JSON\n\r");
		goto out;
	}

	ret = 0;

out:
	if (json)
		free(json);

	return ret;
}

struct mount_option {
	const char *option;
	unsigned long flag;
};

static const struct mount_option mount_options[] = {
	{ "nosuid", MS_NOSUID },
	{ "suid", ~MS_NOSUID },
	{ "dev", ~MS_NODEV },
	{ "nodev", MS_NODEV },
	{ "exec", ~MS_NOEXEC },
	{ "noexec", MS_NOEXEC },
	{ "sync", MS_SYNCHRONOUS },
	{ "dirsync", MS_DIRSYNC },
	{ "async", ~MS_SYNCHRONOUS },
	{ "atime", ~MS_NOATIME },
	{ "noatime", MS_NOATIME },
	{ "diratime", ~MS_NODIRATIME },
	{ "nodiratime", MS_NODIRATIME },
	{ "relatime", MS_RELATIME },
	{ "norelatime", ~MS_RELATIME },
	{ "strictatime", MS_STRICTATIME },
	{ "nostrictatime", ~MS_STRICTATIME },
	{ "lazytime", MS_LAZYTIME },
	{ "nolazytime", ~MS_LAZYTIME },
	{ "nosymfollow", MS_NOSYMFOLLOW },
	{ "mand", MS_MANDLOCK },
	{ "nomand", ~MS_MANDLOCK },
	{ "loud", ~MS_SILENT },
	{ "rbind", MS_BIND | MS_REC },
	{ "bind", MS_BIND },
	{ "move", MS_MOVE },
	{ "shared", MS_SHARED },
	{ "slave", MS_SLAVE },
	{ "private", MS_PRIVATE },
	{ "unbindable", MS_UNBINDABLE },
	{ "rshared", MS_SHARED | MS_REC },
	{ "rslave", MS_SLAVE | MS_REC },
	{ "rprivate", MS_PRIVATE | MS_REC },
	{ "runbindable", MS_UNBINDABLE | MS_REC },
	{ "ro", MS_RDONLY },
	{ "rw", ~MS_RDONLY },
	{ "remount", MS_REMOUNT },
	{ NULL, 0 }
};

static unsigned long parse_mount_options(const char *options,
				  unsigned long existing_flags)
{
	char *opts, *o;
	opts = strdup(options);
	o = opts;
	unsigned long flags = existing_flags;

	while (o) {
		char *comma = strchr(o, ',');
		if (comma) {
			*comma = '\0';
		}

		size_t len = strlen(o);
		if (len <= 0)
			break;

		printf("DEBUG: new mount option '%s' found\n\r", o);

		for (const struct mount_option *mo = mount_options;
		     mo->option != NULL; mo++) {
			if (pv_str_matches(o, len, mo->option,
					   strlen(mo->option))) {
				if (mo->flag & MS_INVERTED_VALUE)
					flags &= mo->flag;
				else
					flags |= mo->flag;

				break;
			}
		}

		if (!comma)
			break;

		*comma = ',';
		comma++;
		o = comma;
	}

	free(opts);

	return flags;
}

struct mounted_path {
	char *path;
	unsigned long flags;
	struct dl_list list; // mounted_path
};

static int load_mounted_paths(struct dl_list *mounted_paths)
{
	printf("DEBUG: loading mounted paths...\n\r");

	FILE *fd;
	char *path = PROC_MOUNTS_PATH;
	fd = fopen(path, "r");
	if (!fd) {
		printf("ERROR: could not open '%s': %s\n\r", path,
		       strerror(errno));
		return -1;
	}

	char buf[1024];
	char *begin, *end, *tmp;
	size_t len;
	struct mounted_path *p;
	while (fgets(buf, sizeof(buf), fd)) {
		printf("DEBUG: parsing mount row '%s'...\n\r", buf);

		// skip source
		begin = strchr(buf, ' ');
		if (!begin)
			continue;
		begin++;

		// parse destination
		end = strchr(begin, ' ');
		if (!end)
			continue;
		len = end - begin;
		if (!len)
			continue;
		p = calloc(1, sizeof(struct mounted_path));
		if (!p)
			break;
		p->path = calloc(1, len + 1);
		strncpy(p->path, begin, len);
		begin = end + 1;

		// skip type
		end = strchr(begin, ' ');
		if (!end)
			continue;
		begin = end + 1;

		// parse options
		end = strchr(begin, ' ');
		if (!end)
			continue;
		len = end - begin;
		if (!len)
			continue;
		tmp = calloc(1, len + 1);
		if (!tmp)
			continue;
		strncpy(tmp, begin, len);
		p->flags = parse_mount_options(tmp, MS_SILENT);
		free(tmp);

		dl_list_add_tail(mounted_paths, &p->list);
		printf("DEBUG: new path '%s' with flags %lu\n\r", p->path,
		       p->flags);
	}

	fclose(fd);

	return 0;
}

static void free_mounted_paths(struct dl_list *mounted_paths)
{
	printf("DEBUG: freeing %d mounted paths...\n\r",
	       dl_list_len(mounted_paths));

	struct mounted_path *p, *tmp;
	dl_list_for_each_safe(p, tmp, mounted_paths, struct mounted_path, list)
	{
		dl_list_del(&p->list);
		if (p->path)
			free(p->path);
		free(p);
	}
}

static int remount_exp(const char *exp, const char *opts,
		struct dl_list *mounted_paths)
{
	printf("DEBUG: remounting regexp '%s' with opts '%s'\n\r", exp, opts);

	regex_t re;
	if (regcomp(&re, exp, REG_EXTENDED | REG_NOSUB)) {
		printf("ERROR: regular expression '%s' not valid\n\r", exp);
		return -1;
	}

	int ret = -1;
	struct mounted_path *p, *tmp;
	dl_list_for_each_safe(p, tmp, mounted_paths, struct mounted_path, list)
	{
		if (!regexec(&re, p->path, 0, NULL, 0)) {
			printf("DEBUG: remounting %s + bind,remount,%s\n\r",
			       p->path, opts);
			unsigned long flags =
				parse_mount_options(opts, p->flags);
			printf("DEBUG: opts '%s' translated into '%lu'\n\r",
			       opts, flags);
			if (mount(NULL, p->path, NULL,
				  MS_REMOUNT | MS_BIND | flags, NULL)) {
				printf("ERROR: could not remount '%s': %s\n\r",
				       p->path, strerror(errno));
				goto out;
			}
			p->flags = flags;
		}
	}

	ret = 0;

out:
	regfree(&re);

	return ret;
}

static int remount_all(struct dl_list *remount_entries, struct dl_list *mounted_paths)
{
	printf("DEBUG: executing %d remount entries...\n\r",
	       dl_list_len(remount_entries));

	struct remount_entry *p, *tmp;
	dl_list_for_each_safe(p, tmp, remount_entries, struct remount_entry,
			      list)
	{
		remount_exp(p->exp, p->opts, mounted_paths);
	}

	return 0;
}

static void free_remount_entries(struct dl_list *remount_entries)
{
	printf("DEBUG: freeing %d remount entries...\n\r",
	       dl_list_len(remount_entries));

	struct remount_entry *p, *tmp;
	dl_list_for_each_safe(p, tmp, remount_entries, struct remount_entry,
			      list)
	{
		dl_list_del(&p->list);
		free_remount_entry(p);
	}
}

int main()
{
	struct dl_list remount_entries; // remount_entry
	dl_list_init(&remount_entries);

	if (load_remount_entries(&remount_entries)) {
		printf("ERROR: could not load remount entries\n\r");
		return -1;
	}

	struct dl_list mounted_paths; // mounted_path
	dl_list_init(&mounted_paths);

	if (load_mounted_paths(&mounted_paths)) {
		printf("ERROR: could not load \n\r");
		return -1;
	}

	if (remount_all(&remount_entries, &mounted_paths)) {
		printf("ERROR: could not remount paths\n\r");
		return -1;
	}

	free_mounted_paths(&mounted_paths);
	free_remount_entries(&remount_entries);

	return 0;
}

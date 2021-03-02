/*
 * Copyright (c) 2017-2020 Pantacor Ltd.
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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <dirent.h>
#include <ctype.h>
#include <libgen.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <linux/limits.h>

#include "updater.h"
#include "pantavisor.h"
#include "cmd.h"
#include "config.h"
#include "state.h"
#include "utils.h"
#include "addons.h"
#include "parser/parser.h"
#include "version.h"
#include "controller.h"
#include "init.h"

#define MODULE_NAME             "core"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

static struct pantavisor* global_pv;

struct pantavisor* get_pv_instance()
{
	return global_pv;
}

static void pv_remove(struct pantavisor *pv)
{

	pv_log(DEBUG, "removing pantavisor");

	if (pv->step)
		free(pv->step);
	if (pv->conn)
		free(pv->conn);

	pv_update_free(pv->update);
	pv->update = NULL;
	pv_state_free(pv->state);
	pv->state = NULL;
	pv_cmd_req_remove(pv);
	pv_trail_remote_remove(pv);
	pv_config_free();

	free(pv);
	pv = NULL;
}

void pv_teardown(struct pantavisor *pv)
{
	if (!pv)
		return;

	pv_cmd_socket_close(pv);

	pv_remove(pv);
}

void pv_set_active(struct pantavisor *pv)
{
	struct stat st;
	char *path, *cur;

	/*
	 * Error case should at least remove
	 * the trails/current symlink so we don't
	 * point to a previous revision.
	 */
	path = calloc(1, PATH_MAX);
	if (!path)
		return;

	sprintf(path, "%s/trails/%d", pv_config_get_storage_mntpoint(), pv->state->rev);
	cur = calloc(1, PATH_MAX);

	/*
	 * [PKS]
	 * Instead of bailing out should we remove
	 * the current link at-least to the current
	 * doesn't point to a previous revision?
	 */
	if (!cur)
		goto out;

	sprintf(cur, "%s/trails/current", pv_config_get_storage_mntpoint());
	unlink(cur);

	if (!stat(path, &st))
		symlink(path, cur);

out:
	if (cur)
		free(cur);
	if (path)
		free(path);
}

int pv_make_config(struct pantavisor *pv)
{
	struct stat st;
	char targetpath[128];
	char srcpath[128];
	char cmd[PATH_MAX];
	int rv;

	sprintf(srcpath, "%s/trails/%d/_config/", pv_config_get_storage_mntpoint(), pv->state->rev);
	sprintf(targetpath, "/configs/");

	if (stat(targetpath, &st))
		mkdir_p(targetpath, 0755);

	memset(&st, '\0', sizeof(st));

	// we allow overloading behaviour via plugin from initrd addon
	if (!stat("/usr/local/bin/pvext_sysconfig", &st) &&
			st.st_mode & S_IXUSR ) {
		sprintf(cmd, "/usr/local/bin/pvext_sysconfig %s %s", srcpath, targetpath);
		pv_log(INFO, "Processing trail _config: %s", cmd);
	} else {
		sprintf(cmd, "/bin/cp -a %s/* %s/", srcpath, targetpath);
		pv_log(INFO, "Processing trail_config: %s", cmd);
	}

	/*
	 * [PKS]
	 * Should we do a tsh_run and wait
	 * for command to finish?
	 */
	rv = system(cmd);
	return rv;
}

void pv_set_rev_done(struct pantavisor *pv, int rev)
{
	// DEPRECATED: this done files are not used anymore for rollback and bootloader env
	// are used insted. We keep it here to serve old versions in case a device needs to
	// be downgraded

	int fd;
	char path[256];

	sprintf(path, "%s/trails/%d/.pv/done", pv_config_get_storage_mntpoint(), rev);

	fd = open(path, O_CREAT | O_WRONLY, 0644);
	if (!fd) {
		pv_log(WARN, "unable to set current(done) flag for revision %d", rev);
		return;
	}

	// commit to disk
	fsync(fd);
	close(fd);
}
int *pv_get_revisions(struct pantavisor *pv)
{
	int n, i = 0;
	int bufsize = 1;
	int *revs = calloc(1, bufsize * sizeof (int));
	struct dirent **dirs;
	char basedir[PATH_MAX];

	sprintf(basedir, "%s/trails/", pv_config_get_storage_mntpoint());
	n = scandir(basedir, &dirs, NULL, alphasort);
	while (n--) {
		char *tmp = dirs[n]->d_name;

		while (*tmp && isdigit(*tmp))
			tmp++;

		if (tmp[0] != '\0')
			continue;

		if (i >= bufsize) {
			int *t = realloc(revs, (bufsize+1) * sizeof(int));
			if (!t)
				return NULL;
			revs = t;
			bufsize++;
		}

		revs[i] = atoi(dirs[n]->d_name);
		i++;
		free(dirs[n]);
	}

	revs = realloc(revs, (bufsize+1) * sizeof(int));
	if (!i)
		revs[0] = -1;

	// terminate with -1
	revs[bufsize] = -1;

	free(dirs);

	return revs;
}

void pv_meta_set_objdir(struct pantavisor *pv)
{
	int fd = 0;
	char path[PATH_MAX];
	struct stat st;

	if (!pv)
		return;

	sprintf(path, "%s/trails/%d/.pvr/config", pv_config_get_storage_mntpoint(), pv->state->rev);
	if (stat(path, &st) == 0)
		return;

	fd = open(path, O_CREAT | O_WRONLY, 0644);
	/*
	 * [PKS]
	 * check for
	 * fd < 0
	 */
	if (!fd)
		goto err;

	sprintf(path, "{\"ObjectsDir\": \"%s/objects\"}", pv_config_get_storage_mntpoint());
	/*
	 * [PKS]
	 * Use write_nointr
	 */
	if (write(fd, path, strlen(path)) < 0)
		goto err;

	close(fd);
	pv_log(DEBUG, "wrote '%s' to .pvr/config @rev=%d", path, pv->state->rev);

	return;
err:
	pv_log(WARN, "unable to set ObjectsDir pvr config key");
	if (fd)
		close(fd);
}

int pv_meta_expand_jsons(struct pantavisor *pv, struct pv_state *s)
{
	int fd = -1, n, bytes, tokc;
	int ret = 0;
	char *buf = 0, *key = 0, *ext = 0;
	char *value = 0, *file = 0, *dir = 0;
	char path[PATH_MAX];
	struct stat st;
	jsmntok_t *tokv = 0;
	jsmntok_t **k, **keys;

	if (!pv || !s)
		goto out;

	buf = strdup(s->json);
	ret = jsmnutil_parse_json(buf, &tokv, &tokc);
	if (ret < 0)
		goto out;

	keys = jsmnutil_get_object_keys(buf, tokv);
	k = keys;

	while (*k) {
		n = (*k)->end - (*k)->start;

		// copy key
		key = malloc(n+1);
		snprintf(key, n+1, "%s", buf+(*k)->start);
		ext = strrchr(key, '.');
		if (!ext || strcmp(ext, ".json")) {
			free(key);
			k++;
			continue;
		}

		// copy value
		n = (*k+1)->end - (*k+1)->start;
		value = malloc(n+1);
		snprintf(value, n+1, "%s", buf+(*k+1)->start);

		sprintf(path, "%s/trails/%d/%s",
			pv_config_get_storage_mntpoint(), s->rev, key);

		if (stat(path, &st) == 0)
			goto out;

		file = strdup(path);
		dir = dirname(file);
		if (stat(dir, &st))
			mkdir_p(dir, 0755);
		free(file);

		fd = open(path, O_CREAT | O_SYNC | O_WRONLY, 0644);
		if (fd < 0)
			goto out;

		bytes = write(fd, value, strlen(value));
		if (bytes)
			pv_log(DEBUG, "%s: written %d bytes", path, bytes);

		close(fd);
		k++;
	}
	jsmnutil_tokv_free(keys);

	ret = 1;

out:
	if (buf)
		free(buf);
	if (tokv)
		free(tokv);
	if (fd > 0)
		close(fd);

	return ret;
}

void pv_meta_set_tryonce(struct pantavisor *pv, int value)
{
	int fd;
	char path[PATH_MAX];

	sprintf(path, "%s/trails/%d/.pv/.tryonce", pv_config_get_storage_mntpoint(), pv->state->rev);

	if (value) {
		fd = open(path, O_WRONLY | O_CREAT | O_SYNC, 0444);
		if (fd > 0)
			close(fd);
	} else {
		remove(path);
		sync();
	}
}

int pv_meta_link_boot(struct pantavisor *pv, struct pv_state *s)
{
	int i;
	char src[PATH_MAX], dst[PATH_MAX], fname[PATH_MAX], prefix[32];
	struct pv_addon *a, *tmp;
	struct dl_list *addons = NULL;

	if (!s)
		s = pv->state;

	/*
	 * Toggle directory depth with null prefix
	 */
	switch (pv_state_spec(s)) {
	case SPEC_SYSTEM1:
		sprintf(prefix, "bsp/");
		break;
	case SPEC_MULTI1:
	default:
		prefix[0] = '\0';
		break;
	}

	// initrd
	sprintf(dst, "%s/trails/%d/.pv/", pv_config_get_storage_mntpoint(), s->rev);
	sprintf(src, "%s/trails/%d/%s%s", pv_config_get_storage_mntpoint(), s->rev, prefix, s->bsp.initrd);

	mkdir_p(dst, 0755);
	strcat(dst, "pv-initrd.img");

	remove(dst);
	if (link(src, dst) < 0)
		goto err;

	// addons
	i = 0;
	addons = &s->addons;
	dl_list_for_each_safe(a, tmp, addons,
			struct pv_addon, list) {
		sprintf(dst, "%s/trails/%d/.pv/", pv_config_get_storage_mntpoint(), s->rev);
		sprintf(src, "%s/trails/%d/%s%s", pv_config_get_storage_mntpoint(), s->rev, prefix, a->name);
		sprintf(fname, "pv-initrd.img.%d", i++);
		strcat(dst, fname);
		remove(dst);
		if (link(src, dst) < 0)
			goto err;
	}

	// kernel
	sprintf(dst, "%s/trails/%d/.pv/pv-kernel.img", pv_config_get_storage_mntpoint(), s->rev);
	sprintf(src, "%s/trails/%d/%s%s", pv_config_get_storage_mntpoint(), s->rev, prefix, s->bsp.kernel);

	remove(dst);
	if (link(src, dst) < 0)
		goto err;

	// fdt
	if (s->bsp.fdt) {
		sprintf(dst, "%s/trails/%d/.pv/pv-fdt.dtb", pv_config_get_storage_mntpoint(), s->rev);
		sprintf(src, "%s/trails/%d/%s%s", pv_config_get_storage_mntpoint(), s->rev, prefix, s->bsp.fdt);

		remove(dst);
		if (link(src, dst) < 0)
			goto err;
	}


	pv_log(DEBUG, "linked boot assets for rev=%d", s->rev);

	return 0;
err:
	pv_log(ERROR, "unable to link '%s' to '%s', errno %d", src, dst, errno);
	return 1;
}

struct pv_state* pv_get_state(struct pantavisor *pv, int rev)
{
	int fd;
	int size;
	char path[256];
	char *buf;
	struct stat st;
	struct pv_state *s;

	if (rev < 0)
		sprintf(path, "%s/trails/current/state.json", pv_config_get_storage_mntpoint());
	else
		sprintf(path, "%s/trails/%d/.pvr/json", pv_config_get_storage_mntpoint(), rev);

	pv_log(INFO, "reading state from: '%s'", path);

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		pv_log(WARN, "unable to find state JSON for current step");
		return NULL;
	}

	stat(path, &st);
	size = st.st_size;

	buf = calloc(1, size+1);
	size = read(fd, buf, size);
	buf[size] = '\0';

	if (size < 0) {
		pv_log(ERROR, "unable to read device state");
		return NULL;
	}

	pv->step = buf;

	s = pv_state_parse(pv, buf, rev);
	close(fd);

	return s;
}

void pantavisor_init()
{
	int ret;
	struct pantavisor *pv;

	printf("Pantavisor (TM) (%s) - www.pantahub.com\n", pv_build_version);
	sprintf(pv_user_agent, PV_USER_AGENT_FMT, pv_build_arch, pv_build_version, pv_build_date);

	prctl(PR_SET_NAME, "pantavisor");
	pv = calloc(1, sizeof(struct pantavisor));
	if (pv)
		global_pv = pv;

	struct rlimit core_limit;
	core_limit.rlim_cur = RLIM_INFINITY;
	core_limit.rlim_max = RLIM_INFINITY;

	setrlimit(RLIMIT_CORE, &core_limit);

	char *core = "/storage/corepv";
	int fd = open("/proc/sys/kernel/core_pattern", O_WRONLY | O_SYNC);
	if (fd)
		write(fd, core, strlen(core));

	// Enter state machine
	ret = pv_controller_start(pv);

	// Clean exit -> reboot
	exit(ret);
}

static int pv_pantavisor_init(struct pv_init *this)
{
	struct pantavisor *pv = NULL;
	int ret = -1;

	pv = get_pv_instance();
	if (!pv)
		goto out;
	// Make sure this is initialized
	pv->state = NULL;
	pv->remote = NULL;
	pv->update = NULL;
	pv->last = -1;
	pv->online = false;
	ret = 0;
out:
	return 0;
}

struct pv_init pv_init_pantavisor = {
	.init_fn = pv_pantavisor_init,
	.flags = 0,
};

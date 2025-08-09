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
#include "pv_runc.h"
#include "pv_runc_container_status.h"

#include <limits.h>
#include <string.h>

#include "utils/fs.h"
#include "utils/tsh.h"

#define PV_VLOG __vlog
#define MODULE_NAME "pv_runc"
#define pv_log(level, msg, ...) __vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

struct pantavisor *(*__pv_get_instance)(void) = NULL;

void (*__vlog)(char *module, int level, const char *fmt, ...) = NULL;
void (*__pv_paths_pv_file)(char *, size_t, const char *) = NULL;
void (*__pv_paths_pv_log)(char *, size_t, const char *) = NULL;
void (*__pv_paths_pv_log_plat)(char *, size_t, const char *,
			       const char *) = NULL;
void (*__pv_paths_pv_log_file)(char *, size_t, const char *, const char *,
			       const char *) = NULL;
void (*__pv_paths_pv_usrmeta_key)(char *, size_t, const char *) = NULL;
void (*__pv_paths_pv_usrmeta_plat_key)(char *, size_t, const char *,
				       const char *) = NULL;
void (*__pv_paths_pv_devmeta_key)(char *, size_t, const char *) = NULL;
void (*__pv_paths_pv_devmeta_plat_key)(char *, size_t, const char *,
				       const char *) = NULL;
void (*__pv_paths_lib_hook)(char *, size_t, const char *) = NULL;
void (*__pv_paths_volumes_plat_file)(char *, size_t, const char *,
				     const char *) = NULL;
void (*__pv_paths_configs_file)(char *, size_t, const char *) = NULL;
void (*__pv_paths_lib_lxc_rootfs_mount)(char *, size_t) = NULL;
void (*__pv_paths_lib_lxc_lxcpath)(char *, size_t) = NULL;

struct _runc_container {
	pid_t pid;
	int logfd;
	char *containerid;
	char *bundlepath;
	char *rootpath;
};

struct _runc_state {
	char *ociversion;
	char *id;
	char *status;
	pid_t pid;
	char *bundle;
	// char *annotations[2];
};

void pv_set_pv_instance_fn(void *fn_pv_get_instance)
{
	__pv_get_instance = fn_pv_get_instance;
}

void pv_set_pv_paths_fn(
	void *fn_vlog, void *fn_pv_paths_pv_file, void *fn_pv_paths_pv_log,
	void *fn_pv_paths_pv_log_plat, void *fn_pv_paths_pv_log_file,
	void *fn_pv_paths_pv_usrmeta_key, void *fn_pv_paths_pv_usrmeta_plat_key,
	void *fn_pv_paths_pv_devmeta_key, void *fn_pv_paths_pv_devmeta_plat_key,
	void *fn_pv_paths_lib_hook, void *fn_pv_paths_volumes_plat_file,
	void *fn_pv_paths_configs_file, void *fn_pv_paths_lib_lxc_rootfs_mount,
	void *fn_pv_paths_lib_lxc_lxcpath)
{
	__vlog = fn_vlog;
	__pv_paths_pv_file = fn_pv_paths_pv_file;
	__pv_paths_pv_log = fn_pv_paths_pv_log;
	__pv_paths_pv_log_plat = fn_pv_paths_pv_log_plat;
	__pv_paths_pv_log_file = fn_pv_paths_pv_log_file;
	__pv_paths_pv_usrmeta_key = fn_pv_paths_pv_usrmeta_key;
	__pv_paths_pv_usrmeta_plat_key = fn_pv_paths_pv_usrmeta_plat_key;
	__pv_paths_pv_devmeta_key = fn_pv_paths_pv_devmeta_key;
	__pv_paths_pv_devmeta_plat_key = fn_pv_paths_pv_devmeta_plat_key;
	__pv_paths_lib_hook = fn_pv_paths_lib_hook;
	__pv_paths_volumes_plat_file = fn_pv_paths_volumes_plat_file;
	__pv_paths_configs_file = fn_pv_paths_configs_file;
	__pv_paths_lib_lxc_rootfs_mount = fn_pv_paths_lib_lxc_rootfs_mount;
	__pv_paths_lib_lxc_lxcpath = fn_pv_paths_lib_lxc_lxcpath;
}

void pv_set_pv_conf_loglevel_fn(int loglevel)
{
}

void pv_set_pv_conf_capture_fn(bool capture)
{
}

void *pv_start_container(struct pv_platform *p, const char *rev,
			 char *conf_file, int logfd, void *data)
{
	int wstatus = 0;

	char cmdcreate[PATH_MAX];
	char cmdstart[PATH_MAX];
	char overlaydir[PATH_MAX];
	const char *rootpath = "/run/runc";
	pv_runc_container_state cstate;

	char *statejsonpath = malloc(
		snprintf(NULL, 0, "%s/%s/state.json", rootpath, p->name) + 1);
	char *bundlepath = malloc(
		snprintf(NULL, 0, "/storage/trails/%s/%s", rev, p->name) + 1);

	sprintf(overlaydir, "/volumes/%s/lxc-overlay/upper", p->name);
	pv_fs_mkdir_p(overlaydir, 0777);

	sprintf(overlaydir, "/volumes/%s/lxc-overlay/work", p->name);
	pv_fs_mkdir_p(overlaydir, 0777);

	sprintf(statejsonpath, "%s/%s/state.json", rootpath, p->name);
	sprintf(bundlepath, "/storage/trails/%s/%s", rev, p->name);

	sprintf(cmdcreate,
		"/usr/bin/runc --debug --root %s create %s --no-pivot -b %s",
		rootpath, p->name, bundlepath);

	sprintf(cmdstart, "/usr/bin/runc --debug start %s", p->name);

	pv_log(ERROR, "Creating runc: %s", cmdcreate);

	int status = tsh_run_logserver(cmdcreate, &wstatus, "runc-create-out",
				       "runc-create-err");

	pv_log(ERROR, "Runc create finished status: %d", status);

	if (!pv_runc_parse_container_state_file(statejsonpath, &cstate)) {
		pv_log(WARN, "could not parse state json at %s", statejsonpath);
	}

	pv_log(DEBUG, "Starting runc: %s", cmdstart);
	
	status = tsh_run_logserver(cmdstart, &wstatus, "runc-start-out",
				   "runc-start-err");

	pv_log(DEBUG, "Started runc: %d", status);

	pv_log(DEBUG, "Started runc init: %d", cstate.pid);

	struct _runc_container *c = malloc(sizeof(struct _runc_container));
	c->logfd = 0;
	c->containerid = strdup(p->name);
	c->bundlepath = bundlepath;
	c->pid = cstate.pid;
	*((pid_t *)data) = cstate.pid;

	pv_log(DEBUG, "exiting with container id  %s and pid %d",
	       c->containerid, c->pid);
	return c;
}

void *pv_stop_container(struct pv_platform *p, char *conf_file, void *data)
{
	struct _runc_container *c = data;

	char cmd[PATH_MAX];
	int wstatus;

	sprintf(cmd, "/usr/bin/runc kill %s", p->name);

	int pid = tsh_run_logserver(cmd, &wstatus, p->name, p->name);
	fprintf(stderr, "STOPPED CONTAINER: %s\n", p->name);

	free(c->bundlepath);
	free(c->containerid);
	free(c);

	return NULL;
}

int pv_console_log_getfd(struct pv_platform_log *log, void *data)
{
	return -1;
}

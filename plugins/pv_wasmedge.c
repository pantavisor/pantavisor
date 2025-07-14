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
#include "pv_wasmedge.h"

#include <limits.h>
#include <string.h>
#include <errno.h>

#include "utils/fs.h"
#include "utils/system.h"
#include "utils/tsh.h"

#define PV_VLOG __vlog
#define MODULE_NAME "pv_wasmedge"
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
void (*__pv_paths_trail_wasm_file)(char *buf, size_t size, const char *rev,
				   const char *name) = NULL;

struct _wasmedge_container {
	pid_t pid;
	int logfd;
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
	void *fn_pv_paths_lib_lxc_lxcpath, void *fn_pv_paths_trail_wasm_file)
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
	__pv_paths_trail_wasm_file = fn_pv_paths_trail_wasm_file;
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

	char cmdrun[PATH_MAX];
	char wasmpath[PATH_MAX];
	char runtimepath[PATH_MAX];
	const char *rootpath = "/run/wasmedge";

	if (snprintf(runtimepath, PATH_MAX, "/run/wasmedge/%s", p->name) < 0) {
		pv_log(ERROR, "runtimepath cannot be constructed: %s",
		       strerror(errno));
		return NULL;
	}
	pv_fs_mkdir_p(runtimepath, 0777);

	__pv_paths_trail_wasm_file(wasmpath, PATH_MAX, rev, p->name);

	sprintf(cmdrun, "/usr/bin/wasmedge %s", wasmpath);
	pv_log(ERROR, "Running wasmedge: %s", cmdrun);

	pid_t pid = tsh_run_logserver_bg(cmdrun, &wstatus, "wasmedge-run-out",
				       "wasmedge-run-err");

	pv_log(ERROR, "Wasmedge run pid: %d", pid);

	struct _wasmedge_container *c =
		malloc(sizeof(struct _wasmedge_container));
	c->logfd = 0;
	c->pid = pid;
	p->init_pid = pid;
	pv_log(INFO, "started wasm app  %s with pid %d", p->name, c->pid);

	return c;
}

void *pv_stop_container(struct pv_platform *p, char *conf_file, void *data)
{
	struct _wasmedge_container *c = data;

	char cmd[PATH_MAX];
	int wstatus;

	if (p->init_pid <= 0) {
		pv_log(WARN, "Stop container called on platform without pid.");
		return;
	}

	wstatus = pv_system_kill_and_wait(p->init_pid);

	if (!wstatus) {
		// Successfully waited for the process
		// You can inspect 'status' using WIFEXITED, WEXITSTATUS, WIFSIGNALED, WTERMSIG etc.
		if (WIFEXITED(wstatus)) {
			pv_log(WARN,
			       "pv_system_kill_and_wait: Child %d exited with status %d.\n",
			       p->init_pid, WEXITSTATUS(wstatus));
		} else if (WIFSIGNALED(wstatus)) {
			pv_log(WARN,
			       "pv_system_kill_and_wait: Child %d terminated by signal %d.\n",
			       p->init_pid, WTERMSIG(wstatus));
		} else {
			pv_log(WARN,
			       "pv_system_kill_and_wait: Child %d ended with unexpected status 0x%x.\n",
			       p->init_pid, wstatus);
		}
	}
	free(c);

	return NULL;
}

int pv_console_log_getfd(struct pv_platform_log *log, void *data)
{
	return -1;
}

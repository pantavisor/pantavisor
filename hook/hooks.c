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

#include "hooks.h"
#include "utils/str.h"
#include "utils/json.h"
#include "utils/tsh.h"
#include "paths.h"
#include "storage.h"
#include "bootloader.h"
#include "init.h"

#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>
#include <linux/limits.h>
#include <sys/stat.h>

#define MODULE_NAME "hooks"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define PV_REV "PV_REV"
#define PV_TRY "PV_TRY"
#define PV_OP "PV_OP"
#define PV_TRYBOOT "PV_TRYBOOT"
#define PV_OBJ_STORAGE "PV_OBJ_STORAGE"
#define PV_TRAILS_STORAGE "PV_TRAILS_STORAGE"
#define PV_STATUS "PV_STATUS"

int pv_hooks_set_env(const char *env[][2], int size)
{
	for (int i = 0; i < size; i++) {
		if (pv_hooks_set_var(env[i][0], env[i][1]) != 0)
			return -1;
	}

	return 0;
}

int pv_hooks_set_var(const char *key, const char *value)
{
	if (!key || !value)
		return -1;

	if (setenv(key, value, 1) == -1) {
		pv_log(DEBUG, "couldn't set %s=%s", key, value);
		return -1;
	}
	pv_log(DEBUG, "set environment var %s=%s", key, value);
	return 0;
}

void pv_hooks_unset_var(const char *key)
{
	if (!key || !getenv(key))
		return;

	unsetenv(key);
	pv_log(DEBUG, "removing environment var %s", key);
}

void pv_hooks_unset_env(const char **env, int size)
{
	for (int i = 0; i < size * 2; i += 2)
		pv_hooks_unset_var(env[i]);
}

static char *get_current_status(const char *pv_rev, const char *pv_try)
{
	char *status = NULL;
	char *json = NULL;

	if (pv_try && strlen(pv_try) > 0)
		pv_storage_get_rev_progress(pv_try);
	else
		pv_storage_get_rev_progress(pv_rev);

	if (!json)
		return NULL;

	int tokc = 0;
	jsmntok_t *tokv = NULL;

	if (jsmnutil_parse_json(json, &tokv, &tokc) < 0)
		goto out;

	status = pv_json_get_value(json, "status", tokv, tokc);
out:
	if (json)
		free(json);
	if (tokv)
		free(tokv);

	return status;
}

void pv_hooks_set_default_env(const char *pv_op, const char *pv_rev,
			      const char *pv_try, const char *extra_env[][2],
			      int size)
{
	if (!pv_rev)
		pv_rev = pv_bootloader_get_rev();
	if (!pv_try)
		pv_try = pv_bootloader_get_try();

	if (!pv_rev)
		pv_rev = "";
	if (!pv_try)
		pv_try = "";

	pv_hooks_set_var(PV_REV, pv_rev);
	pv_hooks_set_var(PV_TRY, pv_try);
	pv_hooks_set_var(PV_OP, pv_op);

	char *tryboot = pv_bootloader_trying_update() ? "true" : "false";
	pv_hooks_set_var(PV_TRYBOOT, tryboot);

	char path[PATH_MAX] = { 0 };
	pv_paths_storage_object(path, sizeof(path), "");
	pv_hooks_set_var(PV_OBJ_STORAGE, path);

	memset(path, 0, sizeof(path));

	pv_paths_storage_trail(path, sizeof(path), pv_rev);
	pv_hooks_set_var(PV_TRAILS_STORAGE, path);

	char *status = get_current_status(pv_rev, pv_try);
	if (!status) {
		pv_log(DEBUG, "couldn't get the current rev status");
		pv_hooks_set_var(PV_STATUS, "");
	} else {
		pv_hooks_set_var(PV_STATUS, status);
		free(status);
	}

	if (extra_env)
		pv_hooks_set_env(extra_env, size);
}

void pv_hooks_unset_default_env(const char **extra_env, int size)
{
	if (extra_env)
		pv_hooks_unset_env(extra_env, size);

	pv_hooks_unset_var(PV_REV);
	pv_hooks_unset_var(PV_TRY);
	pv_hooks_unset_var(PV_OP);
	pv_hooks_unset_var(PV_OBJ_STORAGE);
	pv_hooks_unset_var(PV_TRAILS_STORAGE);
	pv_hooks_unset_var(PV_STATUS);
	pv_hooks_unset_var(PV_TRYBOOT);
}

int pv_hooks_run(const char *dirname, bool log)
{
	char base[PATH_MAX] = { 0 };
	pv_paths_pv_system_hooks(base, sizeof(base));

	char dir[PATH_MAX] = { 0 };
	SNPRINTF_WTRUNC(dir, sizeof(dir), "%s/%s", base, dirname);

	struct dirent **entry = NULL;
	int count = scandir(dir, &entry, NULL, alphasort);

	if (count < 0) {
		pv_log(DEBUG, "couldn't open directory %s: %s", dir,
		       strerror(errno));
		// if hooks directory is not found, we return 0 to avoid
		// blocks any process. So no directory means no hook to
		// execute
		return 0;
	}
	int ret = 0;
	int i = 0;
	for (; i < count; i++) {
		if (!strcmp(entry[i]->d_name, ".") ||
		    !strcmp(entry[i]->d_name, ".."))
			goto next;

		char path[PATH_MAX] = { 0 };
		SNPRINTF_WTRUNC(path, sizeof(path), "%s/%s", dir,
				entry[i]->d_name);

		struct stat st = { 0 };
		errno = 0;
		if (stat(path, &st) != 0) {
			pv_log(WARN, "couldn't stat hook %s: %s", path,
			       strerror(errno));
			goto next;
		}

		if (!S_ISREG(st.st_mode) || !(st.st_mode & S_IXUSR)) {
			pv_log(DEBUG, "skipping non-executable hook: %s", path);
			goto next;
		}

		pv_log(INFO, "running hook: %s", path);

#ifndef DISABLE_LOGSERVER
		if (log) {
			char err[PATH_MAX] = { 0 };
			snprintf(err, sizeof(err), "%s_err", entry[i]->d_name);
			ret = tsh_run_logserver(path, NULL, entry[i]->d_name,
						err);

			if (ret < 0) {
				pv_log(ERROR, "hook %s failed: %d", path, ret);
				goto out;
			}
		} else {
#endif
			int wstatus = 0;
			ret = tsh_run_io(path, 1, &wstatus, NULL, NULL, NULL);
			if (ret < 0) {
				pv_log(ERROR, "hook %s cannot run", path);
				ret = -1;
				goto out;
			} else if (WIFEXITED(wstatus) && WEXITSTATUS(wstatus)) {
				pv_log(ERROR, "hook %s failed status: %d", path,
				       WEXITSTATUS(wstatus));
				ret = -1;
				goto out;
			} else if (WIFEXITED(wstatus)) {
				pv_log(DEBUG, "hook %s succeeded", path);
				ret = 0;
			} else if (WIFSIGNALED(wstatus)) {
				pv_log(ERROR, "hook execution signaled %s: %d",
				       path, WTERMSIG(wstatus));
				ret = -1;
				goto out;
			} else {
				pv_log(ERROR, "hook %s failed with wstatus: %d",
				       path, wstatus);
				ret = -1;
				goto out;
			}

#ifndef DISABLE_LOGSERVER
		}
#endif

	next:
		free(entry[i]);
	}

out:
	// on error we redirect the control flow to this line, so we need
	// to free any pending entry.
	if (ret < 0) {
		for (; i < count; i++)
			free(entry[i]);
	}

	free(entry);

	return ret;
}

static int pv_hooks_early_hook(struct pv_init *init)
{
	pv_hooks_set_default_env("system-start", NULL, NULL, NULL, 0);
	int ret = pv_hooks_run("system.d", true);
	pv_hooks_unset_default_env(NULL, 0);

	if (ret < 0) {
		pv_log(ERROR, "hook system-start has failed");
		return -1;
	}

	return 0;
}

struct pv_init pv_init_hooks = {
	.init_fn = pv_hooks_early_hook,
	.flags = 0,
};

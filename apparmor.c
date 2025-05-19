/*
 * Copyright (c) 2023-2024 Pantacor Ltd.
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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <limits.h>

#include "apparmor.h"
#include "utils/tsh.h"
#include "config.h"
#include "paths.h"
#include "init.h"

#define MODULE_NAME "apparmor"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define PV_APPARMOR_PARSER_BIN "sbin/apparmor_parser"
#define PV_APPARMOR_PARSER_CMD "%s -r %s/%s"
#define PV_APPARMOR_PROFILES "apparmor.d"

static void run_apparmor_parser(const char *prof)
{
	char profiles_path[PATH_MAX] = { 0 };
	pv_paths_etc_file(profiles_path, PATH_MAX, PV_APPARMOR_PROFILES);

	char cmd_path[PATH_MAX] = { 0 };
	pv_paths_root_file(cmd_path, PATH_MAX, PV_APPARMOR_PARSER_BIN);

	char *cmd = NULL;
	asprintf(&cmd, PV_APPARMOR_PARSER_CMD, cmd_path, profiles_path, prof);
	if (!cmd) {
		pv_log(WARN, "could not allocate command for profile: %s",
		       prof);
		return;
	}

	int status = 0;
	tsh_run(cmd, 0, &status);
	if (status != 0) {
		pv_log(WARN, "could not load profile %s, code: %d", prof,
		       status);
	} else {
		pv_log(DEBUG, "apparmor profile %s loaded", prof);
	}

	free(cmd);
}

static void load_all_profiles()
{
	struct dirent **dir = NULL;
	char profiles_path[PATH_MAX] = { 0 };

	pv_paths_etc_file(profiles_path, PATH_MAX, PV_APPARMOR_PROFILES);
	int n = scandir(profiles_path, &dir, NULL, alphasort);

	for (int i = 0; i < n; ++i) {
		if (dir[i]->d_type == DT_REG || dir[i]->d_type == DT_LNK)
			run_apparmor_parser(dir[i]->d_name);
		free(dir[i]);
	}
	free(dir);
}

static void load_from_list(const char *prof)
{
	char *profiles = strdup(prof);
	if (!profiles) {
		pv_log(WARN, "could not load profiles, not enough memory");
		return;
	}

	char *tmp = NULL;

	for (char *p = strtok_r(profiles, ",", &tmp); p;
	     p = strtok_r(NULL, ",", &tmp)) {
		run_apparmor_parser(p);
	}
	free(profiles);
}

void pv_apparmor_load_profiles()
{
	char *profiles = pv_config_get_str(PV_SYSTEM_APPARMOR_PROFILES);
	if (!profiles)
		return;

	if (!strcmp(profiles, "all"))
		load_all_profiles();
	else
		load_from_list(profiles);
}

static int apparmor_init(struct pv_init *this)
{
	pv_apparmor_load_profiles();
	return 0;
}

struct pv_init pv_init_apparmor = { .init_fn = apparmor_init, .flags = 0 };

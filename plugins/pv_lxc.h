/*
 * Copyright (c) 2017-2022 Pantacor Ltd.
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
#ifndef PV_LXC_H
#define PV_LXC_H

#include "../pantavisor.h"
#include "../config.h"
#include "../platforms.h"

void pv_set_pv_instance_fn(void *fn_pv_get_instance);
void pv_set_pv_paths_fn(
	void *fn_vlog, void *fn_pv_paths_pv_file, void *fn_pv_paths_pv_log,
	void *fn_pv_paths_pv_log_plat, void *fn_pv_paths_pv_log_file,
	void *fn_pv_paths_pv_usrmeta_key, void *fn_pv_paths_pv_usrmeta_plat_key,
	void *fn_pv_paths_pv_devmeta_key, void *fn_pv_paths_pv_devmeta_plat_key,
	void *fn_pv_paths_lib_hook, void *fn_pv_paths_volumes_plat_file,
	void *fn_pv_paths_configs_file, void *fn_pv_paths_lib_lxc_rootfs_mount,
	void *fn_pv_paths_lib_lxc_lxcpath);

void pv_set_pv_conf_loglevel_fn(int loglevel);
void pv_set_pv_conf_capture_fn(bool capture);

void *pv_start_container(struct pv_platform *p, const char *rev,
			 char *conf_file, int logfd, void *data);
void *pv_stop_container(struct pv_platform *p, char *conf_file, void *data);
int pv_console_log_getfd(struct pv_platform_log *log, void *data);

#endif

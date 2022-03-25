/*
 * Copyright (c) 2021 Pantacor Ltd.
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
#include <unistd.h>
#include <errno.h>

#include <linux/limits.h>

#include "init.h"
#include "pantavisor.h"
#include "system.h"

#define MODULE_NAME		"system"
#define pv_log(level, msg, ...)		vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

static char *_path_tmp = 0;

static char *get_path_rel(char *base, char *target)
{
	if (!_path_tmp)
		_path_tmp = calloc(1, PATH_MAX);
	sprintf(_path_tmp, "%s%s", base, target);

	return _path_tmp;
}

char *pv_system_get_path_rundir(char *target)
{
	return get_path_rel(pv_system_get_instance()->rundir, target);
}

char *pv_system_get_path_etcdir(char *target)
{
	return get_path_rel(pv_system_get_instance()->etcdir, target);
}

char *pv_system_get_path_vardir(char *target)
{
	return get_path_rel(pv_system_get_instance()->vardir, target);
}

char *pv_system_get_path_datadir(char *target)
{
	return get_path_rel(pv_system_get_instance()->datadir, target);
}

char *pv_system_get_path_storage(char *target)
{
	return get_path_rel(pv_config_get_storage_mntpoint(), target);
}

char *pv_system_get_path_pluginsdir(char *target)
{
	return get_path_rel(pv_system_get_instance()->pluginsdir, target);
}

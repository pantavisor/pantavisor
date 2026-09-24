/*
 * Copyright (c) 2023 Pantacor Ltd.
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

#include "logserver_stdout.h"
#include "logserver/utils/logserver_utils.h"
#include "config.h"

#include <string.h>

static int pv_ls_stdout_add_log(struct pv_ls_out *out,
				const struct pv_ls_log *log)
{
	if (!strcmp(out->name, "stdout_containers") &&
	    !strncmp(log->plat, "pantavisor", strlen("pantavisor")))
		return 0;

	if (!strcmp(out->name, "stdout_pantavisor") &&
	    strncmp(log->plat, "pantavisor", strlen("pantavisor")))
		return 0;

	return pv_ls_utils_stdout(log);
}

struct pv_ls_out *pv_ls_stdout_new()
{
	return pv_ls_out_new(LOG_SERVER_OUTPUT_STDOUT, "stdout",
			     pv_ls_stdout_add_log, NULL, NULL);
}

struct pv_ls_out *pv_ls_stdout_containers_new()
{
	return pv_ls_out_new(LOG_SERVER_OUTPUT_STDOUT_CONTAINERS,
			     "stdout_containers", pv_ls_stdout_add_log, NULL,
			     NULL);
}

struct pv_ls_out *pv_ls_stdout_pantavisor_new()
{
	return pv_ls_out_new(LOG_SERVER_OUTPUT_STDOUT_PANTAVISOR,
			     "stdout_pantavisor", pv_ls_stdout_add_log, NULL,
			     NULL);
}

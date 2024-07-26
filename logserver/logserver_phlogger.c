/*
 * Copyright (c) 2024 Pantacor Ltd.
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

#include "logserver_singlefile.h"
#include "logserver_utils.h"
#include "config.h"
#include "phlogger/phlogger.h"
#include "pvctl_utils.h"
#include "utils/pvnanoid.h"

#include <linux/limits.h>
#include <string.h>
#include <stdlib.h>

struct phlogger_out {
	char sock[PATH_MAX];
	struct pv_nanoid nanoid;
};

static int add_log(struct logserver_out *out, const struct logserver_log *log)
{
	if (log->lvl > pv_config_get_int(PV_LOG_LEVEL))
		return 0;

	struct phlogger_out *phout = (struct phlogger_out *)out->opaque;
	char *id = pv_nanoid_id(&phout->nanoid);
	char *json = logserver_utils_jsonify_log(log, id);

	int written = pvctl_write_to_path(phout->sock, json, strlen(json));

	free(id);
	free(json);

	return written;
}

static void free_output(struct logserver_out *out)
{
	free((struct phlogger_out *)out->opaque);
}

struct logserver_out *logserver_singlefile_new()
{
	struct phlogger_out *phout = calloc(1, sizeof(struct phlogger_out));

	if (!phout)
		return NULL;

	phlogger_storage_path(phout->sock);

	return logserver_out_new(LOG_SERVER_OUTPUT_PHLOGGER, "phlogger",
				 add_log, free_output, phout);
}
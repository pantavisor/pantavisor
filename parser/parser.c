/*
 * Copyright (c) 2017 Pantacor Ltd.
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
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>

#define MODULE_NAME             "parser"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "pantavisor.h"
#include "utils.h"
#include "parser.h"
#include "state.h"

struct pv_state_parser parsers[SPEC_UNKNOWN] = {
	{
		.spec = "pantavisor-multi-platform@1",
		.parse = multi1_parse,
	},
	{
		.spec = "pantavisor-service-system@1",
		.parse = system1_parse,
	}
};

static struct pv_state_parser* _get_parser(char *spec)
{
	int i;

	for (i = 0; i < SPEC_UNKNOWN; i++)
		if (strcmp(parsers[i].spec, spec) == 0)
			return &parsers[i];

	return NULL;
}

state_spec_t pv_state_spec(struct pv_state *s)
{
	int i;

	for (i = 0; i < SPEC_UNKNOWN; i++)
		if (strcmp(parsers[i].spec, s->spec) == 0)
			return i;

	return SPEC_UNKNOWN;
}

struct pv_state* pv_state_parse(struct pantavisor *pv, char *buf, int rev)
{
	int tokc, ret;
	char *spec = 0;
	struct pv_state *state = 0;
	struct pv_state_parser *p;
	jsmntok_t *tokv;

	// Parse full state json
	ret = jsmnutil_parse_json(buf, &tokv, &tokc);
	if (ret < 0) {
		pv_log(WARN, "unable to parse state JSON");
		goto out;
	}

	spec = get_json_key_value(buf, "#spec", tokv, tokc);
	if (!spec) {
		pv_log(WARN, "step JSON has no valid #spec key");
		goto out;
	}

	p = _get_parser(spec);
	if (!p) {
		pv_log(WARN, "no parser plugin available for '%s' spec", spec);
		goto out;
	}

	state = pv_state_init(rev, spec);
	if (state) {
		if (!p->parse(pv, state, buf, rev)) {
			pv_state_free(state);
			state = NULL;
		}
	}
out:
	if (tokv)
		free(tokv);
	if (spec)
		free(spec);

	return state;
}

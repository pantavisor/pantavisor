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

#include <string.h>
#include <stdlib.h>

#include "cadence.h"

#include "config.h"
#include "utils/str.h"

#define MODULE_NAME "power"
#define pv_log(level, msg, ...)                                                \
	vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__,       \
	     ##__VA_ARGS__)
#include "log.h"

static const char *power_known_keys[] = { "interval", "min_awake", "max_awake",
					  "align", NULL };

static void _parse_field(const char *buf, jsmntok_t *tokv, int tokc,
			 const char *key, const char *ctx_name,
			 struct pv_power_field *out)
{
	char *raw = pv_json_get_value(buf, key, tokv, tokc);
	if (!raw)
		return;

	if (!strcmp(raw, "0")) {
		out->declared = true;
		out->seconds = 0;
		free(raw);
		return;
	}

	int secs;
	if (!pv_parse_duration(raw, &secs)) {
		pv_log(WARN, "%s: invalid power.%s value '%s'; ignoring",
		       ctx_name, key, raw);
		free(raw);
		return;
	}

	out->declared = true;
	out->seconds = secs;
	free(raw);
}

void pv_power_parse_json(const char *buf, jsmntok_t *tokv, int tokc,
			 struct pv_power_decl *out, const char *ctx_name)
{
	_parse_field(buf, tokv, tokc, "interval", ctx_name, &out->interval);
	_parse_field(buf, tokv, tokc, "min_awake", ctx_name, &out->min_awake);
	_parse_field(buf, tokv, tokc, "max_awake", ctx_name, &out->max_awake);
	_parse_field(buf, tokv, tokc, "align", ctx_name, &out->align);

	jsmntok_t **keys = jsmnutil_get_object_keys(buf, tokv);
	if (!keys)
		return;

	for (jsmntok_t **k = keys; *k; k++) {
		int n = (*k)->end - (*k)->start;
		bool known = false;
		for (const char **kk = power_known_keys; *kk; kk++) {
			if ((int)strlen(*kk) == n &&
			    !strncmp(buf + (*k)->start, *kk, n)) {
				known = true;
				break;
			}
		}
		if (!known)
			pv_log(WARN, "%s: unknown power.%.*s key; ignoring",
			       ctx_name, n, buf + (*k)->start);
	}

	jsmnutil_tokv_free(keys);
}

static long _resolve_field(const struct pv_power_field *container,
			   const struct pv_power_field *group,
			   config_index_t config_key, bool *out_set)
{
	if (container->declared) {
		if (out_set)
			*out_set = true;
		return container->seconds;
	}
	if (group->declared) {
		if (out_set)
			*out_set = true;
		return group->seconds;
	}

	long cfg = pv_config_get_int(config_key);
	if (out_set)
		*out_set = (cfg > 0);
	return cfg;
}

void pv_power_resolve(const struct pv_power_decl *container,
		      const struct pv_power_decl *group, bool mounted,
		      const char *ctx_name, struct pv_power_resolved *out)
{
	memset(out, 0, sizeof(*out));

	bool any_declared =
		container->interval.declared || container->min_awake.declared ||
		container->max_awake.declared || container->align.declared ||
		group->interval.declared || group->min_awake.declared ||
		group->max_awake.declared || group->align.declared;

	if (!any_declared)
		return;

	if (mounted) {
		pv_log(WARN,
		       "%s: power section ignored; status goal is MOUNTED",
		       ctx_name);
		return;
	}

	bool interval_set = false;
	long interval =
		_resolve_field(&container->interval, &group->interval,
			       PV_POWER_CONTAINER_INTERVAL, &interval_set);
	long min_awake =
		_resolve_field(&container->min_awake, &group->min_awake,
			       PV_POWER_CONTAINER_MIN_AWAKE, NULL);
	long max_awake =
		_resolve_field(&container->max_awake, &group->max_awake,
			       PV_POWER_CONTAINER_MAX_AWAKE, NULL);
	bool align_set = false;
	long align = _resolve_field(&container->align, &group->align,
				    PV_POWER_CONTAINER_ALIGN, &align_set);

	if (align_set && align > 0 && !interval_set) {
		pv_log(WARN,
		       "%s: power section ignored; align set without a resolved interval",
		       ctx_name);
		return;
	}

	if (min_awake > 0 && max_awake > 0 && min_awake > max_awake) {
		pv_log(WARN,
		       "%s: power section ignored; min_awake (%lds) > max_awake (%lds)",
		       ctx_name, min_awake, max_awake);
		return;
	}

	// clamp against system ceilings: warn, never fail
	long limit_max_awake = pv_config_get_int(PV_POWER_LIMIT_MAX_AWAKE);
	if (limit_max_awake > 0 && max_awake > limit_max_awake) {
		pv_log(WARN,
		       "%s: power.max_awake %lds clamped to system limit %lds",
		       ctx_name, max_awake, limit_max_awake);
		max_awake = limit_max_awake;
		out->clamped_max_awake = true;
	}
	long limit_interval = pv_config_get_int(PV_POWER_LIMIT_INTERVAL);
	if (interval_set && limit_interval > 0 && interval < limit_interval) {
		pv_log(WARN,
		       "%s: power.interval %lds clamped to system limit %lds",
		       ctx_name, interval, limit_interval);
		interval = limit_interval;
		out->clamped_interval = true;
	}

	out->active = interval_set && interval > 0;
	out->interval = interval;
	out->min_awake = min_awake;
	out->max_awake = max_awake;
	out->align = (align_set && align > 0) ? align : 0;
}

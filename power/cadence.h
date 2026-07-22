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
#ifndef POWER_CADENCE_H_
#define POWER_CADENCE_H_

#include <stdbool.h>

#include "utils/json.h"

// One field of the manifest "power" section at a single scope (container,
// group). `declared` distinguishes absent (inherit from the next scope) from
// an explicit value; seconds==0 with declared==true is the "disabled here,
// stop inheriting" sentinel (a group can enable a field, a container opts
// back out with an explicit 0).
struct pv_power_field {
	bool declared;
	long seconds;
};

struct pv_power_decl {
	struct pv_power_field interval;
	struct pv_power_field min_awake;
	struct pv_power_field max_awake;
	struct pv_power_field align;
};

// Fully resolved, post-inheritance, post-clamp values for one container.
struct pv_power_resolved {
	// a run window is scheduled for this container at all (a resolved
	// interval exists); false means every other field here is unused
	bool active;
	long interval;
	long min_awake;
	long max_awake;
	long align; // 0 = no alignment
	// clamp visibility for stats/devmeta
	bool clamped_interval;
	bool clamped_max_awake;
};

// Parse a "power" JSON object (buf/tokv/tokc as returned by
// jsmnutil_parse_json() on the extracted section) into a declaration.
// Unknown keys warn (forward compat) and are otherwise ignored; a malformed
// duration warns and leaves that one field undeclared (inherits normally).
void pv_power_parse_json(const char *buf, jsmntok_t *tokv, int tokc,
			 struct pv_power_decl *out, const char *ctx_name);

// Resolve one container's power section, per field: container > group >
// config power.container.* > built-in default; then clamp against
// power.limit.* (warn, never fail) and apply the phase-1 shape checks.
// `mounted` is whether the container's resolved status goal is MOUNTED.
// `ctx_name` is used only for log messages.
void pv_power_resolve(const struct pv_power_decl *container,
		      const struct pv_power_decl *group, bool mounted,
		      const char *ctx_name, struct pv_power_resolved *out);

#endif // POWER_CADENCE_H_

/*
 * Copyright (c) 2020 Pantacor Ltd.
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

#ifndef PV_STATE_H
#define PV_STATE_H

#include "pantavisor.h"
#include "group.h"

typedef enum { SPEC_MULTI1, SPEC_SYSTEM1, SPEC_UNKNOWN } state_spec_t;

struct pv_bsp {
	union {
		struct {
			char *kernel;
			char *fdt;
			char *initrd;
		} std;
		struct {
			char *fit;
		} ut;
	} img;
	char *firmware;
	char *modules;
	struct dl_list drivers; // pv_driver
};

struct pv_state {
	char *rev;
	state_spec_t spec;
	struct pv_bsp bsp;
	struct dl_list platforms; // pv_platform
	struct dl_list volumes; // pv_volume
	struct dl_list disks; // pv_disks
	struct dl_list addons; // pv_addon
	struct dl_list objects; //pv_object
	struct dl_list jsons; //pv_json
	struct dl_list groups; //pv_group
	struct dl_list conditions; // pv_condition
	char *json;
	int tryonce;
	bool local;
};

struct pv_state *pv_state_new(const char *rev, state_spec_t spec);
void pv_state_free(struct pv_state *s);

void pv_state_add_group(struct pv_state *s, struct pv_group *g);
void pv_state_add_condition(struct pv_state *s, struct pv_condition *c);

struct pv_group *pv_state_fetch_group(struct pv_state *s, const char *name);
struct pv_platform *pv_state_fetch_platform(struct pv_state *s,
					    const char *name);
struct pv_object *pv_state_fetch_object(struct pv_state *s, const char *name);
struct pv_json *pv_state_fetch_json(struct pv_state *s, const char *name);
struct pv_condition *pv_state_fetch_condition_value(struct pv_state *s,
						    const char *plat,
						    const char *key,
						    const char *eval_value);

state_spec_t pv_state_spec(struct pv_state *s);

void pv_state_validate(struct pv_state *s);
bool pv_state_validate_checksum(struct pv_state *s);

int pv_state_start(struct pv_state *s);
int pv_state_run(struct pv_state *s);
void pv_state_stop_lenient(struct pv_state *s);
int pv_state_stop_force(struct pv_state *s);

int pv_state_stop_platforms(struct pv_state *current, struct pv_state *pending);
void pv_state_transition(struct pv_state *pending, struct pv_state *current);

int pv_state_report_condition(struct pv_state *s, const char *plat,
			      const char *key, const char *value);
bool pv_state_check_conditions(struct pv_state *s);

void pv_state_print(struct pv_state *s);
char *pv_state_get_containers_json(struct pv_state *s);
char *pv_state_get_conditions_json(struct pv_state *s);

#endif

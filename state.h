/*
 * Copyright (c) 2020-2025 Pantacor Ltd.
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

#include "group.h"

typedef enum { SPEC_MULTI1, SPEC_SYSTEM1, SPEC_UNKNOWN } state_spec_t;

struct pv_bsp {
	char *config;
	union {
		struct {
			char *kernel;
			char *fdt;
			char *initrd;
		} std;
		struct {
			char *fit;
		} ut;
		struct {
			void *padding;
			char *bootimg;
		} rpiab;
	} img;
	char *firmware;
	char *modules;
	struct dl_list drivers; // pv_driver
};

struct pv_state {
	char *rev;
	plat_status_t status;
	state_spec_t spec;
	struct pv_bsp bsp;
	struct dl_list platforms; // pv_platform
	struct dl_list volumes; // pv_volume
	struct dl_list disks; // pv_disks
	struct dl_list addons; // pv_addon
	struct dl_list objects; //pv_object
	struct dl_list jsons; //pv_json
	struct dl_list groups; //pv_group
	bool using_runlevels;
	int tryonce;
	bool done;
};

struct pv_state *pv_state_new(const char *rev, state_spec_t spec);
void pv_state_free(struct pv_state *s);

void pv_state_add_group(struct pv_state *s, struct pv_group *g);

struct pv_group *pv_state_fetch_group(struct pv_state *s, const char *name);
struct pv_platform *pv_state_fetch_platform(struct pv_state *s,
					    const char *name);
struct pv_object *pv_state_fetch_object(struct pv_state *s, const char *name);
struct pv_object *pv_state_fetch_object_id(struct pv_state *s, const char *id);
struct pv_json *pv_state_fetch_json(struct pv_state *s, const char *name);

state_spec_t pv_state_spec(struct pv_state *s);

int pv_state_validate(struct pv_state *s);
bool pv_state_validate_checksum(struct pv_state *s);

int pv_state_prepare_run(struct pv_state *s);
int pv_state_start(struct pv_state *s);
int pv_state_run(struct pv_state *s);
void pv_state_stop_lenient(struct pv_state *s);
int pv_state_stop_force(struct pv_state *s);

int pv_state_stop_platforms(struct pv_state *current, struct pv_state *pending);
void pv_state_transition(struct pv_state *pending, struct pv_state *current);

void pv_state_eval_status(struct pv_state *s);
plat_goal_state_t pv_state_check_goals(struct pv_state *s);

int pv_state_interpret_signal(struct pv_state *s, const char *name,
			      const char *signal, const char *payload);

struct pv_volume *pv_state_search_volume(struct pv_state *s, const char *name);

void pv_state_set_object_metadata(struct pv_state *s, const char *sha256sum,
				  const char *geturl);
char **pv_state_get_unrecorded_objects(struct pv_state *s);
char **pv_state_get_unavailable_objects(struct pv_state *s);
bool pv_state_are_all_objects_recorded(struct pv_state *s);
bool pv_state_are_all_objects_installed(struct pv_state *s);
char *pv_state_get_object_geturl(struct pv_state *s, const char *sha256sum);

void pv_state_print(struct pv_state *s);
char *pv_state_get_containers_json(struct pv_state *s);
char *pv_state_get_groups_json(struct pv_state *s);

void pv_state_set_done(struct pv_state *s);
void pv_state_load_done(struct pv_state *s);
bool pv_state_is_done(struct pv_state *s);

#endif

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
#ifndef PV_SYSTEMC_H
#define PV_SYSTEMC_H

#include <stdbool.h>

#include "config.h"

#define DEVICE_UNCLAIMED	(1 << 0)

#define RUNLEVEL_ROOT 0
#define RUNLEVEL_PLATFORM 1
#define RUNLEVEL_APP 2

// pantavisor.h

char pv_user_agent[4096];

struct trail_remote;

#define PV_USER_AGENT_FMT	"Pantavisor/2 (Linux; %s) PV/%s Date/%s"

struct pantavisor {
	int last;
	char *step;
	struct pv_device *dev;
	struct pv_update *update;
	struct pv_state *state;
	struct pv_cmd_req *req;
	struct pantavisor_config config;
	struct trail_remote *remote;
	struct pv_metadata *metadata;
	bool online;
	int ctrl_fd;
	unsigned long flags;
	struct pv_connection *conn;
};

void pv_set_rev_done(struct pantavisor *pv, int rev);
int *pv_get_revisions(struct pantavisor *pv);
void pv_set_active(struct pantavisor *pv);
int pv_make_config(struct pantavisor *pv);
void pv_meta_set_objdir(struct pantavisor *pv);
int pv_meta_expand_jsons(struct pantavisor *pv, struct pv_state *s);
int pv_meta_link_boot(struct pantavisor *pv, struct pv_state *s);
void pv_meta_set_tryonce(struct pantavisor *pv, int value);
void pv_teardown(struct pantavisor *pv);
struct pv_state* pv_get_state(struct pantavisor *pv, int current);
char* pv_get_initrd_config_name(int rev);
void pantavisor_init(void);
struct pantavisor* get_pv_instance(void);

#endif

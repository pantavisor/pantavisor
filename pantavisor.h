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
#include <trail.h>
#include "config.h"

#define DEVICE_UNCLAIMED	(1 << 0)

// pantavisor.h

struct trail_remote;

enum update_state {
	UPDATE_QUEUED,
	UPDATE_DOWNLOADED,
	UPDATE_INSTALLED,
	UPDATE_TRY,
	UPDATE_REBOOT,
	UPDATE_DONE,
	UPDATE_FAILED,
	UPDATE_NO_DOWNLOAD,
	UPDATE_NO_PARSE
};

struct pv_update {
	enum update_state status;
	char *endpoint;
	int need_reboot;
	int need_finish;
	struct pv_state *pending;
};

struct pv_volume {
	char *name;
	char *mode;
	char *src;
	char *dest;
	int loop_fd;
	int file_fd;
	struct pv_volume *next;
};

struct pv_platform {
	char *name;
	char *type;
	char **configs;
	char *exec;
	unsigned long ns_share;
	void *data;
	bool running;
	bool done;
	struct pv_platform *next;
};

struct pv_object {
	char *name;
	char *id;
	char *geturl;
	char *objpath;
	char *relpath;
	off_t size;
	char *sha256;
	struct pv_object *next;
};

struct pv_state {
	int rev;
	char *kernel;
	char *firmware;
	char **initrd;
	struct pv_platform *platforms;
	struct pv_volume *volumes;
	struct pv_object *objects;
	char *json;
};

struct pantavisor {
	int last;
	char *step;
	struct pantavisor_config *config;
	struct trail_remote *remote;
	struct pv_update *update;
	struct pv_state *state;
	unsigned long flags;
};

int *pv_trail_get_revs(struct pantavisor *pv);
int pv_rev_is_done(struct pantavisor *pv, int rev);
void pv_set_current(struct pantavisor *pv, int rev);
int pv_get_rollback_rev(struct pantavisor *pv);
void pv_destroy(struct pantavisor *pv);
void pv_release_state(struct pantavisor *pv);
struct pv_state* pv_parse_state(struct pantavisor *pv, char *buf, int size, int rev);
struct pv_state* pv_parse_state_from_buf(struct pantavisor *pv, char *buf);
struct pv_state* pv_get_state(struct pantavisor *pv, int current);
struct pv_state* pv_get_current_state(struct pantavisor *pv);
void pv_state_free(struct pv_state *s);
int pv_start_platforms(struct pantavisor *pv);
int pantavisor_init(void);

#endif

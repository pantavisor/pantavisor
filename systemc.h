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
#ifndef SC_SYSTEMC_H
#define SC_SYSTEMC_H

#include <stdbool.h>
#include <trail.h>
#include "config.h"

#define DEVICE_UNCLAIMED	(1 << 0)

// systemc.h

struct trail_remote;

enum update_state {
	UPDATE_QUEUED,
	UPDATE_DOWNLOADED,
	UPDATE_INSTALLED,
	UPDATE_TRY,
	UPDATE_REBOOT,
	UPDATE_DONE,
	UPDATE_FAILED,
};

struct sc_update {
	enum update_state status;
	char *endpoint;
	int need_reboot;
	int need_finish;
	struct sc_state *pending;
};

struct sc_volume {
	char *name;
	char *mode;
	char *src;
	char *dest;
	int loop_fd;
	int file_fd;
	struct sc_volume *next;
};

struct sc_platform {
	char *name;
	char *type;
	char **configs;
	char *exec;
	unsigned long ns_share;
	void *data;
	bool running;
	struct sc_platform *next;
};

struct sc_object {
	char *name;
	char *id;
	char *geturl;
	char *objpath;
	char *relpath;
	int size;
	char *sha256;
	struct sc_object *next;
};

struct sc_state {
	int rev;
	char *kernel;
	char **initrd;
	struct sc_platform *platforms;
	struct sc_volume *volumes;
	struct sc_object *objects;
	char *json;
};

struct systemc {
	int last;
	char *step;
	struct systemc_config *config;
	struct trail_remote *remote;
	struct sc_update *update;
	struct sc_state *state;
	unsigned long flags;
};

void sc_set_current(struct systemc *sc, int rev);
int sc_get_rollback_rev(struct systemc *sc);
void sc_destroy(struct systemc *sc);
void sc_release_state(struct systemc *sc);
struct sc_state* sc_parse_state(struct systemc *sc, char *buf, int size, int rev);
struct sc_state* sc_parse_state_from_buf(struct systemc *sc, char *buf);
struct sc_state* sc_get_state(struct systemc *sc, int current);
struct sc_state* sc_get_current_state(struct systemc *sc);
void sc_state_free(struct sc_state *s);
int sc_start_platforms(struct systemc *sc);
int systemc_init(void);

#endif

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
#include <netinet/in.h>
#include "utils/list.h"

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

typedef enum {
	VOL_LOOPIMG,
	VOL_PERMANENT,
	VOL_REVISION,
	VOL_BOOT,
	VOL_UNKNOWN
} pv_volume_t;

struct pv_update {
	enum update_state status;
	char *endpoint;
	int need_reboot;
	int need_finish;
	struct pv_state *pending;
};

struct pv_addon {
	char *name;
	struct pv_addon *next;
};



struct pv_platform {
	char *name;
	char *type;
	char **configs;
	char *exec;
	unsigned long ns_share;
	void *data;
	char *json;
	pid_t init_pid;
	bool running;
	bool done;
	struct pv_platform *next;
	struct dl_list logger_list;
	/*
	 * To be freed once logger_list is setup.
	 * */
	struct dl_list logger_configs;
};

struct pv_volume {
	char *name;
	char *mode;
	char *src;
	char *dest;
	pv_volume_t type;
	int loop_fd;
	int file_fd;
	struct pv_platform *plat;
	struct pv_volume *next;
};

struct pv_object {
	char *name;
	char *id;
	char *geturl;
	char *objpath;
	char *relpath;
	off_t size;
	char *sha256;
	struct dl_list list;
};

struct pv_state {
	int rev;
	char *spec;
	char *kernel;
	char *firmware;
	char *modules;
	char *initrd;
	struct pv_platform *platforms;
	struct pv_volume *volumes;
	struct pv_addon *addons;
	struct pv_object *objects;
	struct dl_list obj_list;;
	char *json;
	int tryonce;
};

struct pv_usermeta {
	char *key;
	char *value;
	struct dl_list list;
};

struct pv_device {
	char *id;
	char *nick;
	char *owner;
	char *prn;
	struct dl_list metalist;
};

struct pv_connection {
	struct sockaddr sock;
	time_t since;
};

struct pantavisor {
	int last;
	char *step;
	struct pv_device *dev;
	struct pv_update *update;
	struct pv_state *state;
	struct pv_cmd_req *req;
	struct pantavisor_config *config;
	struct trail_remote *remote;
	int online;
	int ctrl_fd;
	unsigned long flags;
	bool signal_caught; /*For code too big for handlers*/
	struct pv_connection *conn;
};

int *pv_get_revisions(struct pantavisor *pv);
int pv_rev_is_done(struct pantavisor *pv, int rev);
void pv_set_active(struct pantavisor *pv);
void pv_set_current(struct pantavisor *pv, int rev);
int pv_get_rollback_rev(struct pantavisor *pv);
void pv_meta_set_objdir(struct pantavisor *pv);
int pv_meta_expand_jsons(struct pantavisor *pv, struct pv_state *s);
int pv_meta_link_boot(struct pantavisor *pv, struct pv_state *s);
int pv_meta_get_tryonce(struct pantavisor *pv);
void pv_meta_set_tryonce(struct pantavisor *pv, int value);
void pv_destroy(struct pantavisor *pv);
void pv_release_state(struct pantavisor *pv);
int pv_parse_usermeta(struct pantavisor *pv, char *buf);
struct pv_state* pv_get_state(struct pantavisor *pv, int current);
struct pv_state* pv_get_current_state(struct pantavisor *pv);
void pv_state_free(struct pv_state *s);
int pv_start_platforms(struct pantavisor *pv);
int pantavisor_init(bool do_fork);
struct pantavisor* get_pv_instance(void);
struct pv_log_info* pv_new_log(bool islxc, struct pv_logger_config *,const char *name);
const char* pv_get_log_config_item(struct pv_logger_config *config, const char *key);
#endif

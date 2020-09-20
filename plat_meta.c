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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <stdlib.h>
#include <errno.h>
#include <linux/limits.h>
#include "plat_meta.h"
#include "pantavisor.h"
#include "utils/list.h"
#include "pantahub.h"
#include "parser/parser_bundle.h"
#include "trestclient.h"

#define MODULE_NAME		"plat-meta"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#define BUFFER_SIZE 	(4 * 1024)
#define INOTIFY_SIZE \
	(sizeof(struct inotify_event) + NAME_MAX + 1)
static int epoll_fd = -1;
static int inotify_fd = -1;

struct plat_meta_internal {
	struct pv_plat_meta_watch *watch;
	int wd;
	struct dl_list list;
};

static DEFINE_DL_LIST(watch_list);
extern trest_ptr *client;
extern char *endpoint;
/*
 * don't use big stack variables here.
 */
int pv_plat_meta_watch_action(struct pv_plat_meta_watch *watch,
				struct inotify_event *ev)
{
	char *filename = NULL;
	char *buffer = NULL;
	int ret = -1;
	int fd = -1;
	ssize_t nr_read = 0;
	char *json_content = NULL;
	int json_len = 0;
	struct pv_platform *pv_platform = 
		container_of(watch, struct pv_platform, meta_watch);
	char *tmp_buff = NULL;
	struct pantavisor *pv = (struct pantavisor*)watch->opaque;

	filename = (char*) calloc(1, PATH_MAX);
	if (!filename)
		goto out;
	snprintf(filename, PATH_MAX, "%s/%s/%s", PV_PLAT_META_DIR, pv_platform->name, ev->name);
	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		pv_log(ERROR, "Unable to open file %s", filename);
		goto out;
	}
	buffer = (char*) calloc(1, BUFFER_SIZE);
	if (!buffer)
		goto out;
	nr_read = read_nointr(fd, buffer, BUFFER_SIZE);
	if (nr_read <= 0)
		goto out;
	/*
	 *We can't convert the null bytes properly.
	 */
	str_replace(buffer, nr_read, '\0', ' ');
	json_content = format_json(buffer, strlen(buffer));
	if (!json_content) {
		pv_log(WARN, "Couldn't convert content to json for %s", filename);
		goto out;
	}
	/*
	 * Re-use filename to create key for this update.
	 */
	snprintf(filename, PATH_MAX, "%s/%s", 
			pv_platform->name, ev->name);
	json_len = strlen(filename) + strlen(json_content)
			+ 2 /*start and end braces*/
			+ 4 /*2 pairs of quotes*/
			+ 2 /*one : and a NULL byte*/;
	tmp_buff = realloc(buffer, json_len);
	if (!tmp_buff) {
		pv_log(ERROR, "Couldn't extend json buffer for %s", filename);
		goto out;
	}
	buffer = tmp_buff;
	snprintf(buffer, json_len, "{\"%s\":\"%s\"}", filename, json_content);
	if (!pv)
		goto out;
	/*
	 * send it to PH.
	 */
	pv_log(INFO, "Sending %s for file %s", buffer, filename);
	ret = pv_ph_upload_metadata(pv, buffer);
	if (ret)
		ret = -1;
out:
	close(fd);
	if (json_content)
		free(json_content);
	if (filename)
		free(filename);
	if (buffer)
		free(buffer);
	return ret;
}

int pv_plat_meta_add_watch(struct pv_plat_meta_watch *watch, int flag)
{
	char path[PATH_MAX];
	struct pv_platform *plat = NULL;
	int wd = -1;
	int ret = 0;
	struct plat_meta_internal *new_watch = NULL;
	uint32_t inotify_mask = 0;

	plat = container_of(watch, struct pv_platform, meta_watch);
	snprintf(path, PATH_MAX, "%s/%s", PV_PLAT_META_DIR, plat->name);
	if (!(flag & PV_META_FLAG_NOCREATE))
		inotify_mask |= IN_CREATE;
	if (!(flag & PV_META_FLAG_NOMODIFY))
		inotify_mask |= IN_MODIFY;
	if (!(flag & PV_META_FLAG_NODELETE))
		inotify_mask |= IN_DELETE | IN_DELETE_SELF;
	if (!inotify_mask) {
		pv_log(WARN, "No inotify events defined for %s", path);
		ret = -1;
		goto out;
	}
	new_watch = (struct plat_meta_internal*)calloc (1, sizeof(*new_watch));
	if (!new_watch) {
		pv_log(WARN, "Couldn't allocate plat-meta watch for %s",
				path);
		ret = -1;
		goto out;
	}
	new_watch->watch = watch;
	wd = inotify_add_watch(inotify_fd, path, inotify_mask);
	if (wd < 0) {
		pv_log(WARN, "Couldn't add watch for %s - %s", path,
				strerror(errno));
		free(new_watch);
		ret = -1;
		goto out;
	}
	if (!(flag & PV_META_FLAG_NODEFACT))
		watch->action = pv_plat_meta_watch_action;
	new_watch->watch = watch;
	new_watch->wd = wd;
	dl_list_add(&watch_list, &new_watch->list);
	pv_log(INFO, "Watch added for %s", path);
out:
	return ret;
}

static struct pv_plat_meta_watch* pv_plat_meta_find_watch(int wd)
{
	struct plat_meta_internal *item, *tmp;
	
	if (dl_list_empty(&watch_list))
		return NULL;

	dl_list_for_each_safe(item, tmp, &watch_list,
				struct plat_meta_internal, list) {
		pv_log(INFO, "Checking wd = %d with %d", item->wd, wd);
		if (item->wd == wd)
			return item->watch;
	}
	return NULL;
}

static int plat_meta_device_meta_action(struct json_key_action *jka, char *value)
{
	struct pantavisor *pv = get_pv_instance();
	char json_buf[128];
	jsmntok_t *tokv = jka->tokv;
	char *fname = NULL;
	bool ispresent = true;
	struct pv_platform *plat_walker = 
		(struct pv_platform*)jka->opaque;

	if (tokv != NULL) {
		int keylen = tokv->end - tokv->start;
		struct stat st;
		char stat_path[PATH_MAX];

		fname = (char*)calloc (1, keylen + 1);
		if (!fname)
			goto out;
		snprintf(fname, keylen + 1, "%s",
				jka->buf + tokv->start);

		while (plat_walker) {
			snprintf(stat_path, sizeof(stat_path),
					"%s/", plat_walker->name);
			if (strncmp(fname, stat_path, strlen(stat_path)) == 0)
				break;
			plat_walker = plat_walker->next;
		}
		if (!plat_walker)
			goto out;
		snprintf(stat_path, PATH_MAX, "%s/%s", PV_PLAT_META_DIR, fname);
		if (stat(stat_path, &st))
			ispresent = false;
		else {
			if ((st.st_mode & S_IFMT) !=  S_IFREG)
				ispresent = false;
		}
	}
	if (!ispresent) {
		snprintf(json_buf, sizeof(json_buf), "{\"%s\":null}", fname);
		pv_log(INFO, "Clearing plat meta for %s", fname);
		pv_ph_upload_metadata(pv, json_buf);
	}
out:
	if (fname)
		free(fname);
	return 0;
}

static int plat_meta_key_action(struct json_key_action *jka, char *value)
{
	struct json_key_action jka_arr[] = {
		ADD_JKA_ENTRY_ITR("", JSMN_STRING, jka->opaque,
					plat_meta_device_meta_action, false),
		ADD_JKA_NULL_ENTRY()
	};
	return start_json_parsing_with_action(jka->buf, jka_arr, JSMN_OBJECT) ;
}

static int pv_plat_meta_cleanup(struct pantavisor *pv)
{
	static bool done = false;
	trest_request_ptr req = NULL;
	trest_response_ptr res = NULL;
	struct json_key_action jka[] = {
		ADD_JKA_ENTRY("device-meta", JSMN_OBJECT, pv->state->platforms, 
					plat_meta_key_action, false),
		ADD_JKA_NULL_ENTRY()
	};

	if (!pv || done)
		goto out;

	if (!ph_client_init(pv)) {
		pv_log(ERROR, "couldn't initialize ph_client");
		goto out;
	}

	req = trest_make_request(TREST_METHOD_GET,
			endpoint,
			0, 0, 0);
	res = trest_do_json_request(client, req);

	if (!res->body || res->code != THTTP_STATUS_OK) {
		pv_log(WARN, "error getting device details (code=%d)", res->code);
		goto out;
	}
	start_json_parsing_with_action(res->body, jka, JSMN_OBJECT);
	done = true;
out:
	if (req)
		trest_request_free(req);
	if (res)
		trest_response_free(res);
	return 0;
}

static int pv_plat_meta_init(struct pv_init *this)
{
	struct epoll_event ep_event;

	epoll_fd = epoll_create1(0);
	if (epoll_fd < 0) {
		pv_log(ERROR, "Couldn't create epoll fd for platform meta");
		goto out;
	}
	inotify_fd = inotify_init1(IN_NONBLOCK);
	if (inotify_fd < 0) {
		goto out;
	}
	/*Not really used*/
	ep_event.data.ptr = &watch_list;
	ep_event.events = EPOLLIN;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, inotify_fd, &ep_event)) {
		goto out;
	}
	pv_log(INFO, "Platform meta setup done.");
	return 0;
out:
	close(epoll_fd);
	close(inotify_fd);
	return -1;
}

int pv_plat_meta_upload()
{
	const int MAX_EVENTS = 1; /*only one inotify fd*/
	const int epoll_timeout = 2000; /*in millis*/
	const int MAX_INOTIFY_EVENTS = 10;
	struct epoll_event ep_event[MAX_EVENTS];
	char *inotify_ev = NULL;
	int ret = 0;
	int nr_uploaded = 0;

	pv_plat_meta_cleanup(get_pv_instance());
	ret = epoll_wait(epoll_fd, ep_event, MAX_EVENTS, epoll_timeout);
	if (ret < 0) {
		if (errno == EINTR)
			ret = 0;
		else
			ret = -1;
		goto out;
	}
	if (!ret)
		goto out;
	
	inotify_ev = (char*) calloc(MAX_INOTIFY_EVENTS, INOTIFY_SIZE);
	if (!inotify_ev) {
		ret = -1;
		pv_log(WARN, "Couldn't allocate events");
		goto out;
	}
	while (ret > 0) {
		struct pv_plat_meta_watch *watch = NULL;
		struct pv_platform *plat = NULL;
		int nr_read = -1;
	
		ret--;
		nr_read = read_nointr(inotify_fd, inotify_ev, 
					INOTIFY_SIZE * MAX_INOTIFY_EVENTS);
		if (nr_read > 0) {
			char *walker = NULL;
			struct inotify_event *inotify = NULL;

			for (walker = inotify_ev; walker < inotify_ev + nr_read;
					walker += sizeof(*inotify) + inotify->len) {
				inotify = (struct inotify_event*)walker;
				watch = pv_plat_meta_find_watch(inotify->wd);
				if (!watch)
					continue;

				plat = container_of(watch, struct pv_platform, meta_watch);
				if (watch->action && watch->action(watch, inotify)) {
					pv_log(WARN, "Error uploading meta data for platform %s - %s",
							plat->name, inotify->name);
				}
			}
		}
	}
	free(inotify_ev);
	pv_log(INFO, "ret = %d");
out:
	return ret < 0 ? ret : nr_uploaded;
}


struct pv_init pv_init_plat_meta = {
	.init_fn = pv_plat_meta_init,
	.flags = PV_INIT_FLAG_CANFAIL
};

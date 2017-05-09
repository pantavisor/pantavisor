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
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/statfs.h>
#include <fcntl.h>
#include <errno.h>
#include <mtd/mtd-user.h>

#include <thttp.h>

#define MODULE_NAME			"updater"
#define sc_log(level, msg, ...)		vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "utils.h"

#include "objects.h"
#include "updater.h"
#include "bootloader.h"
#include "pantahub.h"
#include "storage.h"

static struct trail_object *head;
static struct trail_object *last;

typedef void (*token_iter_f) (void *d1, void *d2, char *buf, jsmntok_t* tok, int c);

// takes an allocated buffer
static char *unescape_utf8_to_ascii(char *buf, char *code, char c)
{
	char *p = 0;
	char *new = 0;
	char *old;
	int pos = 0, replaced = 0;
	char *tmp;

	tmp = malloc(strlen(buf) + strlen(code) + 1);
	strcpy(tmp, buf);
	strcat(tmp, code);
	old = tmp;

	p = strstr(tmp, code);
	while (p) {
		*p = '\0';
		new = realloc(new, pos + strlen(tmp) + 2);
		strcpy(new+pos, tmp);
		pos = pos + strlen(tmp);
		new[pos] = c;
		pos += 1;
		new[pos] = '\0';
		replaced += 1;
		tmp = p+strlen(code);
		p = strstr(tmp, code);
	}

	if (new[strlen(new)-1] == c)
		new[strlen(new)-1] = '\0';

	if (old)
		free(old);
	if (buf)
		free(buf);

	return new;
}

// is good for getting elements of any array type token. Just point tok+t to the
// token of type array and it will iterate the direct children of that token
// through travesal the depth first token array.
static int _iterate_json_array(char *buf, jsmntok_t* tok, int t, token_iter_f func, void *d1, void *d2)
{
	int i;
	int c;
	if (tok[t].type != JSMN_ARRAY) {
		sc_log(INFO, "iterare_json_array: token not array");
		return -1;
	}

	c = t;
	for(i=0; i < tok->size; i++) {
		func(d1, d2, buf, tok, c+1);
		c = traverse_token (buf, tok, c+1);
	}

	return 0;
}

static void _add_pending_step(void *d1, void *d2, char *buf, jsmntok_t *tok, int c)
{
	int n = ((tok+c)->end - (tok+c)->start) + 1;
	int tokc, ret, rev = 0;
	char *s = malloc (sizeof (char) * n+1);
	char *rev_s = NULL;
	char *value = NULL;
	struct sc_state **steps = (struct sc_state **) d1;
	struct systemc *sc = (struct systemc *) d2;
	jsmntok_t **keys = NULL, **keys_i = NULL;
	jsmntok_t *tokv = NULL;

	strncpy(s, buf + (tok+c)->start, n);
	s[n] = '\0';

	while (*steps)
		steps++;

	ret = jsmnutil_parse_json (s, &tokv, &tokc);
	keys = jsmnutil_get_object_keys(s, tokv);
	keys_i = keys;
	while (*keys_i) {
		if (!strncmp(s+(*keys_i)->start, "rev", strlen("rev"))) {
			n = (*keys_i+1)->end - (*keys_i+1)->start;
			rev_s = malloc(n+1);
			rev_s[n] = '\0';
			strncpy(rev_s, s+(*keys_i+1)->start, n);
			rev = atoi(rev_s);
		} else if (!strncmp(s+(*keys_i)->start, "state", strlen("state"))) {
			n = (*keys_i+1)->end - (*keys_i+1)->start;
			value = malloc(n + 2);
			strncpy(value, s+(*keys_i+1)->start, n);
			value[n] = '\0';
		}
		keys_i++;
	}
	jsmnutil_tokv_free(keys);

	*steps = sc_parse_state(sc, value, strlen(value), rev);
	sc_log(DEBUG, "adding rev=%d, step = '%s'", rev, (*steps)->json);

	if (value)
		free(value);
	if (tokv)
		free(tokv);

	free(s);
}

static struct sc_state* _pending_get_first(struct sc_state **p)
{
	int min;
	struct sc_state *r;

	if (*p == NULL)
		return NULL;

	min = (*p)->rev;
	r = *p;

	while (*p) {
		if ((*p)->rev < min) {
			min = (*p)->rev;
			r = *p;
		}
		p++;
	}

	return r;
}

static int trail_get_new_steps(struct systemc *sc)
{
	int size;
	struct trail_remote *r = sc->remote;
	trest_request_ptr req = 0;
	trest_response_ptr res = 0;
	struct sc_state **steps = 0, **iter = 0;

	if (!r)
		return -1;

	req = trest_make_request(TREST_METHOD_GET,
				 r->endpoint,
				 0, 0, 0);

	res = trest_do_json_request(r->client, req);

	if (!res) {
		sc_log(INFO, "unable to do trail request");
		size = -1;
		goto out;
	}

	size = jsmnutil_array_count(res->body, res->json_tokv);
	sc_log(DEBUG, "steps found in NEW state = '%d'", size);

	if (!size)
		goto out;

	steps = malloc(sizeof (struct sc_state*) * (size + 1));
	iter = steps;
	memset(steps, 0, sizeof(struct sc_state*) * (size + 1));
        _iterate_json_array (res->body, res->json_tokv, 0,
			    (token_iter_f) _add_pending_step, steps, sc);
	steps[size] = NULL;
	r->pending = _pending_get_first(steps);

	// free all but pending
	while (*iter) {
		if (*iter != r->pending) {
			free((*iter)->json);
			sc_state_free((*iter));
		}
		iter++;
	}

	sc_log(INFO, "first pending found to be rev = %d", r->pending->rev);

out:
	if (req)
		trest_request_free(req);
	if (res)
		trest_response_free(res);
	if (steps)
		free(steps);

	return size;
}


static int trail_is_available(struct trail_remote *r)
{
	trest_request_ptr req;
	trest_response_ptr res;
	int size = 0;

	if (!r)
		return -1;

	req = trest_make_request(TREST_METHOD_GET,
				 "/trails/",
				 0, 0, 0);

	res = trest_do_json_request(r->client, req);

	if (!res) {
		sc_log(INFO, "unable to do trail request");
		size = -1;
		goto out;
	}

	if (res->body == NULL) {
		size = -1;
		goto out;
	}

	size = jsmnutil_array_count(res->body, res->json_tokv);
	if (size)
		sc_log(DEBUG, "trail found, using remote");

out:
	if (req)
		trest_request_free(req);
	if (res)
		trest_response_free(res);

	return size;
}

static int trail_first_boot(struct systemc *sc)
{
	int ret;
	trest_request_ptr req;
	trest_response_ptr res;
	trest_auth_status_enum status = TREST_AUTH_STATUS_NOTAUTH;

	status = trest_update_auth(sc->remote->client);
	if (status != TREST_AUTH_STATUS_OK) {
		sc_log(INFO, "cannot update auth token");
		return -1;
	}

	req = trest_make_request(TREST_METHOD_POST, "/trails/", 0, 0, sc->step);
	res = trest_do_json_request(sc->remote->client, req);

	if (!res) {
		sc_log(ERROR, "unable to push initial trail on first boot");
		ret = -1;
		goto out;
	}
	sc_log(INFO, "initial trail pushed ok");
	ret = 0;

out:
	sleep(5);
	if (req)
		trest_request_free(req);
	if (res)
		trest_response_free(res);

	return ret;
}

static int trail_remote_init(struct systemc *sc)
{
	struct trail_remote *remote = NULL;
	const char **cafiles;
	trest_auth_status_enum status = TREST_AUTH_STATUS_NOTAUTH;
	trest_ptr client = 0;

	// Make sure values are reasonable
	if ((strcmp(sc->config->creds.id, "") == 0) ||
	    (strcmp(sc->config->creds.prn, "") == 0))
		return 0;

	cafiles = sc_ph_get_certs(sc);
	if (!cafiles) {
		sc_log(ERROR, "unable to assemble cert list");
		goto err;
	}

	// Create client
	client = trest_new_tls_from_userpass(
		sc->config->creds.host,
		sc->config->creds.port,
		sc->config->creds.prn,
		sc->config->creds.secret,
		(const char **) cafiles
		);

	if (!client) {
		sc_log(INFO, "unable to create device client");
		goto err;
	}

	// FIXME: Crash here if unable to auth
	status = trest_update_auth(client);
	if (status != TREST_AUTH_STATUS_OK) {
		sc_log(INFO, "unable to auth device client");
		goto err;
	}

	remote = malloc(sizeof(struct trail_remote));
	remote->client = client;
	remote->endpoint = malloc((sizeof(DEVICE_TRAIL_ENDPOINT_FMT)
				   + strlen(sc->config->creds.id)) * sizeof(char));
	sprintf(remote->endpoint, DEVICE_TRAIL_ENDPOINT_FMT, sc->config->creds.id);

	sc->remote = remote;

	return 0;

err:
	if (client)
		free(client);
	if (remote)
		free(remote);

	return -1;
}

/* API */

int sc_trail_check_for_updates(struct systemc *sc)
{
	int ret;
	trest_auth_status_enum auth_status;

	if (!sc->remote)
		trail_remote_init(sc);

	// Offline
	if (!sc->remote)
		return 0;

	auth_status = trest_update_auth(sc->remote->client);
	if (auth_status != TREST_AUTH_STATUS_OK) {
		sc_log(INFO, "cannot authenticate to cloud");
		return 0;
	}

	ret = trail_is_available(sc->remote);
	if (ret == 0)
		return trail_first_boot(sc);
	else if (ret > 0)
		return trail_get_new_steps(sc);
	else
		return 0;
}

static int trail_remote_set_status(struct systemc *sc, enum update_state status)
{
	int ret = 0;
	struct sc_update *u = sc->update;
	trest_request_ptr req;
	trest_response_ptr res;
	char json[1024];

	if (!sc->remote)
		trail_remote_init(sc);

	switch (status) {
	case UPDATE_QUEUED:
		sprintf(json, DEVICE_STEP_STATUS_FMT, 
			"QUEUED", "Update queued", 0);
		break;
	case UPDATE_DOWNLOADED:
		sprintf(json, DEVICE_STEP_STATUS_FMT,
			"INPROGRESS", "Update objects downloaded", 40);
		break;
	case UPDATE_INSTALLED:
		sprintf(json, DEVICE_STEP_STATUS_FMT,
			"INPROGRESS", "Update installed", 80);
		break;
	case UPDATE_TRY:
		sprintf(json, DEVICE_STEP_STATUS_FMT,
			"INPROGRESS", "Starting updated version", 90);
		break;
	case UPDATE_REBOOT:
		sprintf(json, DEVICE_STEP_STATUS_FMT,
			"INPROGRESS", "Rebooting", 95);
		break;
	case UPDATE_DONE:
		sprintf(json, DEVICE_STEP_STATUS_FMT,
			"DONE", "Update finished", 100);
		break;
	default:
		sprintf(json, DEVICE_STEP_STATUS_FMT,
			"ERROR", "Error during update", 0);
		break;
	}

	req = trest_make_request(TREST_METHOD_PUT,
				 u->endpoint,
				 0, 0,
				 json);

	res = trest_do_json_request(sc->remote->client, req);

	if (!res) {
		sc_log(INFO, "unable to do trail request");
		ret = -1;
		goto out;
	}

	sc_log(INFO, "remote state updated to %s", res->body);
out:
	if (req)
		trest_request_free(req);
	if (res)
		trest_response_free(res);

	return ret;
}

int sc_trail_update_start(struct systemc *sc, int offline)
{
	int c;
	int ret = 0;
	int rev = sc->state->rev;
	struct sc_update *u = calloc(sizeof(struct sc_update), 1);

	head = NULL;
	last = NULL;

	// Offline update
	if (!sc->remote && offline) {
		rev = sc->state->rev;
	} else {
		u->pending = sc->remote->pending;
		rev = u->pending->rev;
	}

	// to construct endpoint
	c = get_digit_count(rev);
	u->endpoint = malloc((sizeof(DEVICE_STEP_ENDPOINT_FMT)
		          + (strlen(sc->config->creds.id)) + c) * sizeof(char));
	sprintf(u->endpoint, DEVICE_STEP_ENDPOINT_FMT,
		sc->config->creds.id, rev);

	u->need_reboot = 0;
	u->need_finish = 0;
	sc->update = u;

	if (!offline) {
		ret = trail_remote_set_status(sc, UPDATE_QUEUED);
		if (ret < 0)
			sc_log(INFO, "failed to update cloud status, possibly offline");
	}

	return 0;
}

int sc_trail_update_finish(struct systemc *sc)
{
	int ret = 0;

	switch (sc->update->status) {
	case UPDATE_DONE:
		ret = trail_remote_set_status(sc, UPDATE_DONE);
		goto out;
		break;
	case UPDATE_REBOOT:
		sc_log(INFO, "update requires reboot, cleaning up...");
		goto out;
		break;
	case UPDATE_FAILED:
		ret = trail_remote_set_status(sc, UPDATE_FAILED);
		sc_log(ERROR, "update has failed");
		goto out;
	default:
		ret = -1;
		goto out;
		break;
	}

out:
	if (sc->update->pending)
		sc_state_free(sc->update->pending);
	if (sc->update->endpoint)
		free(sc->update->endpoint);

	free(sc->update);

	sc->update = NULL;
	return ret;
}

static int trail_download_get_meta(struct systemc *sc, struct sc_object *o)
{
	int ret = 0;
	char *endpoint = 0;
	char *url = 0;
	char *prn;
	trest_request_ptr req = 0;
	trest_response_ptr res = 0;

	if (!o)
		goto out;

	prn = o->id;

	endpoint = malloc((sizeof(TRAIL_OBJECT_DL_FMT) + strlen(prn)) * sizeof(char));
	sprintf(endpoint, TRAIL_OBJECT_DL_FMT, prn);

	sc_log(INFO, "requesting obj='%s'", endpoint);

	req = trest_make_request(TREST_METHOD_GET,
				 endpoint,
				 0, 0, 0);

	res = trest_do_json_request(sc->remote->client, req);

	if (!res) {
		sc_log(INFO, "unable to do trail request");
		goto out;
	}

	o->size = atoi(get_json_key_value(res->body, "size",
				 res->json_tokv, res->json_tokc));
	o->sha256 = get_json_key_value(res->body, "sha256sum",
				 res->json_tokv, res->json_tokc);

	url = get_json_key_value(res->body, "signed-geturl",
				 res->json_tokv, res->json_tokc);

	if (!url) {
		sc_log(ERROR, "unable to get download url for object");
		goto out;
	}
	url = unescape_utf8_to_ascii(url, "\\u0026", '&');
	o->geturl = url;

	// FIXME:
	// if (verify_url(url)) ret = 1;
	ret = 1;

out:
	if (req)
		trest_request_free(req);
	if (res)
		trest_response_free(res);
	if (endpoint)
		free(endpoint);

	return ret;
}

static int obj_is_kernel_pvk(struct systemc *sc, struct sc_object *obj)
{
	if (strcmp(sc->state->kernel, obj->name))
		return 0;

	if (sc->config->bl_type == UBOOT_PVK)
		return 1;

	return 0;
}

static int copy_and_close(int s_fd, int d_fd)
{
	int bytes_r = 0, bytes_w = 0;
	char buf[4096];

	lseek(s_fd, 0, SEEK_SET);
	lseek(d_fd, 0, SEEK_SET);

	while (bytes_r = read(s_fd, buf, sizeof(buf)), bytes_r > 0)
		bytes_w += write(d_fd, buf, bytes_r);

	close(s_fd);

	sc_log(DEBUG, "  bytes_r=%d bytes_w=%d", bytes_r, bytes_w);

	return bytes_r;
}

static int trail_download_object(struct systemc *sc, struct sc_object *obj, const char **crtfiles)
{
	int ret = 0;
	int tmp_fd, obj_fd, fd;
	int bytes, n;
	int is_kernel_pvk;
	int use_temp = 0;
	char *host = 0;
	thttp_response_t* res = 0;
	thttp_request_tls_t* tls_req = 0;
	thttp_request_t* req = 0;
	char *start = 0, *port = 0, *end = 0;
	char tobj[] = "/tmp/object-XXXXXX";
	struct stat st;

	if (!obj)
		goto out;

	tls_req = thttp_request_tls_new_0 ();
	tls_req->crtfiles = (char ** )crtfiles;

	req = (thttp_request_t*) tls_req;

	req->method = THTTP_METHOD_GET;
	req->proto = THTTP_PROTO_HTTP;
	req->proto_version = THTTP_PROTO_VERSION_10;

	is_kernel_pvk = obj_is_kernel_pvk(sc, obj);

	if (!is_kernel_pvk && stat(obj->objpath, &st) == 0) {
		sc_log(INFO, "file exists (%s)", obj->objpath);
		ret = 1;
		goto out;
	}

	if (obj->geturl == NULL) {
		sc_log(INFO, "there is no get url defined");
		goto out;
	}

	// FIXME: This breaks with non https urls...
	if (strncmp(obj->geturl, "https://", 8) != 0) {
		sc_log(INFO, "object url (%s) is invalid", obj->geturl);
		goto out;
	}

	// SSL is default
	req->port = 443;

	// FIXME: should check sha256, need to rework geturl() for that
	// FIXME: can use sha256.h from mbedtls mbedtls_sha256()
	start = obj->geturl + 8;
	port = strchr(start, ':');
	if (port) {
		int p = strtol (++port, &end, 0);
		if (p > 0)
		req->port = p;
	} else {
		end = strchr(start, '/');
	}

	n = (unsigned long) end - (unsigned long) start;
	host = malloc((n+1) * sizeof(char));
	strncpy(host, start, n);
	host[n] = '\0';

	req->host = host;

	req->path = obj->geturl;
	req->headers = 0;

	if (!strcmp(sc->config->storage.fstype, "jffs2") ||
	    !strcmp(sc->config->storage.fstype, "ubifs"))
		use_temp = 1;

	mktemp(tobj);
	obj_fd = open(obj->objpath, O_CREAT | O_WRONLY, 0644);
	tmp_fd = open(tobj, O_CREAT | O_RDWR, 0644);

	if (use_temp)
		fd = tmp_fd;
	else
		fd = obj_fd;

	if (is_kernel_pvk) {
		fsync(obj_fd);
		close(obj_fd);
		fd = tmp_fd;
	}

	// download to tmp
	lseek(fd, 0, SEEK_SET);
	sc_log(INFO, "downloading object (%s)", obj->objpath);
	res = thttp_request_do_file (req, fd);

	if (use_temp) {
		sc_log(INFO, "copying %s to %s", tobj, obj->objpath);
		bytes = copy_and_close(tmp_fd, obj_fd);
	}
	sc_log(INFO, "downloaded object (%s)", obj->objpath);

	fsync(obj_fd);
	close(obj_fd);

	if (is_kernel_pvk)
		sc_bl_install_kernel(sc, tobj);

	syncdir(obj->objpath);

	// FIXME: must verify file downloaded correctly
	sc_log(INFO, "downloaded object (%s)", obj->objpath);

out:
	if (host)
		free(host);
	if (req)
		thttp_request_free(req);
	if (res)
		thttp_response_free(res);

	return ret;
}

static int trail_link_objects(struct systemc *sc)
{
	int err = 0;
	struct sc_object *obj = sc->update->pending->objects;
	char *c, *tmp;

	while (obj) {
		tmp = strdup(obj->relpath);
		c = strrchr(tmp, '/');
		*c = '\0';
		mkdir_p(tmp, 0644);
		free(tmp);
		if (link(obj->objpath, obj->relpath) < 0) {
			if (errno != EEXIST)
				err++;
			sc_log(ERROR, "unable to link %s, errno=%d",
				obj->relpath, errno);
		} else {
			syncdir(obj->objpath);
			sc_log(INFO, "linked %s to %s",
				obj->relpath, obj->objpath);
		}
		obj = obj->next;
	}

	return -err;
}

static int get_update_size(struct sc_update *u)
{
	int size = 0;
	struct stat st;
	struct sc_object *o = u->pending->objects;

	while (o) {
		if (stat(o->objpath, &st) < 0) {
			size += o->size;
			sc_log(INFO, "id=%s, name=%s, size=%d", o->id, o->name, o->size);
		}
		o = o->next;
	}

	sc_log(DEBUG, "update_size: %d bytes", size);

	return size;
}

static int trail_download_objects(struct systemc *sc)
{
	int ret = 0;
	struct sc_object *k_new, *k_old;
	struct sc_update *u = sc->update;
	struct sc_object *o = u->pending->objects;
	const char **crtfiles = sc_ph_get_certs(sc);

	while (o) {
		if (!trail_download_get_meta(sc, o))
			goto out;
		o = o->next;
	}

	// Run GC as last resort
	if (sc_storage_get_free(sc) < get_update_size(u))
		sc_storage_gc_run(sc);

	// Check again
	if (sc_storage_get_free(sc) < get_update_size(u)) {
		sc_log(WARN, "not enough space to process update");
		goto out;
	}

	k_new = sc_objects_get_by_name(u->pending,
			u->pending->kernel);
	k_old = sc_objects_get_by_name(sc->state,
			sc->state->kernel);

	if (strcmp(k_new->id, k_old->id))
		u->need_reboot = 1;

	// Reset ret
	ret = 0;

	o = u->pending->objects;
	while (o) {
		if (!trail_download_object(sc, o, crtfiles))
			goto out;
		o = o->next;
	}

	// All done
	ret = 1;

out:
	return ret;
}

int sc_trail_update_install(struct systemc *sc)
{
	int ret, fd;
	struct sc_state *pending = sc->update->pending;
	char state_path[1024];

	if (!sc->remote)
		trail_remote_init(sc);

	sc_log(INFO, "applying update...");

	ret = trail_download_objects(sc);
	if (ret < 0) {
		sc_log(ERROR, "unable to download objects");
		sc->update->status = UPDATE_FAILED;
		goto out;
	}

	trail_remote_set_status(sc, UPDATE_DOWNLOADED);

	ret = trail_link_objects(sc);
	if (ret < 0) {
		sc_log(ERROR, "unable to link objects to relative path (failed=%d)", ret);
		sc->update->status = UPDATE_FAILED;
		goto out;
	}

	// install state.json for new rev
	sprintf(state_path, "%s/trails/%d.json", sc->config->storage.mntpoint, pending->rev);
	fd = open(state_path, O_CREAT | O_WRONLY | O_SYNC, 0644);
	if (fd < 0) {
		sc_log(ERROR, "unable to write state.json file for update");
		ret = -1;
		goto out;
	}
	write(fd, pending->json, strlen(pending->json));
	close(fd);

	trail_remote_set_status(sc, UPDATE_INSTALLED);

	sleep(2);
	sc->update->status = UPDATE_TRY;
	ret = pending->rev;

	if (sc->update->need_reboot) {
		sc->update->status = UPDATE_REBOOT;
		sc_bl_set_try(sc, ret);
	}

out:
	trail_remote_set_status(sc, sc->update->status);

	return ret;
}

void sc_trail_remote_destroy(struct systemc *sc)
{
	if (!sc->remote)
		return;

	free(sc->remote->client);
	free(sc->remote->endpoint);
	free(sc->remote);
}

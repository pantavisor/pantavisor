#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <mtd/mtd-user.h>

#include <thttp.h>
#include <jsmn/jsmnutil.h>

#define MODULE_NAME			"updater"
#define sc_log(level, msg, ...)		vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "utils.h"

#include "updater.h"

static struct trail_object *head;
static struct trail_object *last;

typedef void (*token_iter_f) (void *data, char *buf, jsmntok_t* tok, int c);

static void uboot_set_try_rev(struct systemc *sc, int rev)
{
	int fd;
	char s[256];
	erase_info_t ei;

	fd = open("/dev/mtd2", O_RDWR | O_SYNC);
	ei.start = 0;
	ioctl(fd, MEMUNLOCK, &ei);
	ioctl(fd, MEMERASE, &ei);

	lseek(fd, 0, SEEK_SET);
	sprintf(s, "sc_try=%d\0", rev);
	write(fd, &s, strlen(s) + 1);
	
	close(fd);
	
	return;	
}

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

	if (old)
		free(old);
	if (buf)
		free(buf);

	return new;
}

static char* get_json_key_value(char *buf, char *key, jsmntok_t* tok, int tokc)
{
	int i;
	int t=-1;

	for(i=0; i<tokc; i++) {
		int n = tok[i].end - tok[i].start;
		if (tok[i].type == JSMN_STRING
		    && !strncmp(buf + tok[i].start, key, n)) {
			t=1;
		} else if (t==1) {
			char *idval = malloc(n+1);
			idval[n] = 0;
			strncpy(idval, buf + tok[i].start, n);
			return idval;
		} else if (t==1) {
			sc_log(WARN, "json does not have 'key' string");
			return NULL;
		}
	}
	return NULL;
}

static int traverse_token (char *buf, jsmntok_t* tok, int t)
{
	int i;
	int c;
	c=t;
	for (i=0; i < tok[t].size; i++) {
		c = traverse_token (buf, tok, c+1);
	}
	return c;
}

// is good for getting elements of any array type token. Just point tok+t to the
// token of type array and it will iterate the direct children of that token
// through travesal the depth first token array.
static int _iterate_json_array(char *buf, jsmntok_t* tok, int t, token_iter_f func, void *data)
{
	int i;
	int c;
	if (tok[t].type != JSMN_ARRAY) {
		sc_log(WARN, "iterare_json_array: token not array");
		return -1;
	}

	c = t;
	for(i=0; i < tok->size; i++) {
		func(data, buf, tok, c+1);
		c = traverse_token (buf, tok, c+1);
	}

	return 0;
}

static void _add_pending_step(void *data, char *buf, jsmntok_t *tok, int c)
{
	int n = ((tok+c)->end - (tok+c)->start) + 1;
	int tokc, ret;
	char *s = malloc (sizeof (char) * n+1);
	char *value = NULL;
	struct trail_step **steps = (struct trail_step **) data;
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
		if (!strncmp("state", s+(*keys_i)->start, strlen("state"))) {
			int n = (*keys_i+1)->end - (*keys_i+1)->start;
			value = malloc(n + 2);
			strncpy(value, s+(*keys_i+1)->start, n+1);
			value[n] = '\0';
			break;
		}
		keys_i++;
	}
	jsmnutil_tokv_free(keys);

	*steps = malloc(sizeof(struct trail_step));	
	(*steps)->state = trail_parse_state(value, strlen(value));
	(*steps)->json = strdup(value);
	sc_log(DEBUG, "adding step = '%s'", (*steps)->json);
	
	if (value)
		free(value);
	if (tokv)
		free(tokv);

	free(s);
}

static struct trail_step* _pending_get_first(struct trail_step **p)
{
	int min;
	struct trail_step *r;

	if (*p == NULL)
		return NULL;

	min = (*p)->state->rev;
	r = *p;

	while (*p) {
		if ((*p)->state->rev < min) {
			min = (*p)->state->rev;
			r = *p;
		}
		p++;	
	}

	return r;
}

static int trail_get_new_steps(struct trail_remote *r)
{
	int size;
	trest_request_ptr req = 0;
	trest_response_ptr res = 0;
	struct trail_step **steps = 0, **iter = 0;

	if (!r)
		return -1;

	req = trest_make_request(TREST_METHOD_GET,
				 r->endpoint,
				 0, 0, 0);
	
	res = trest_do_json_request(r->client, req);

	if (!res) {
		sc_log(WARN, "unable to do trail request");
		size = -1;
		goto out;
	}

	size = jsmnutil_array_count(res->body, res->json_tokv);
	sc_log(DEBUG, "steps found in NEW state = '%d'", size);

	if (!size)
		goto out;

	steps = malloc(sizeof (struct trail_step*) * (size + 1));
	iter = steps;
	memset(steps, 0, sizeof(struct trail_step*) * (size + 1));
        _iterate_json_array (res->body, res->json_tokv, 0,
			    (token_iter_f) _add_pending_step, steps);
	steps[size] = NULL;
	r->pending = _pending_get_first(steps);

	// free all but pending
	while (*iter) {
		if (*iter != r->pending) {
			free((*iter)->json);
			trail_state_free((*iter)->state);
			free(*iter);
		}
		iter++;
	}

	sc_log(INFO, "first pending found to be rev = %d", r->pending->state->rev);

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
				 "/api/trails/",
				 0, 0, 0);

	res = trest_do_json_request(r->client, req);

	if (!res) {
		sc_log(WARN, "unable to do trail request");
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
		sc_log(WARN, "cannot update auth token");
		return -1;
	}

	req = trest_make_request(TREST_METHOD_POST, "/api/trails/", 0, 0, sc->step);
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
	trest_auth_status_enum status = TREST_AUTH_STATUS_NOTAUTH;
	trest_ptr client;

	// Make sure values are reasonable
	if ((strcmp(sc->config->creds.id, "") == 0) ||
	    (strcmp(sc->config->creds.abrn, "") == 0))
		return 0;

	// Create client
	client = trest_new_from_userpass(
		sc->config->creds.host,
		sc->config->creds.port,
		sc->config->creds.abrn,
		sc->config->creds.secret
		);

	if (!client) {
		sc_log(WARN, "unable to create device client");
		goto err;
	}

	status = trest_update_auth(client);
	if (status != TREST_AUTH_STATUS_OK) {
		sc_log(WARN, "unable to auth device client");
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
	
	auth_status = trest_update_auth(sc->remote->client);
	if (auth_status != TREST_AUTH_STATUS_OK) {
		sc_log(WARN, "cannot authenticate to cloud");
		return 0;
	}

	ret = trail_is_available(sc->remote);
	if (ret == 0)
		return trail_first_boot(sc);
	else if (ret > 0)
		return trail_get_new_steps(sc->remote);
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
			"QUEUED", "Step seen, queued locally", 0);
		break;
	case UPDATE_DOWNLOADED:
		sprintf(json, DEVICE_STEP_STATUS_FMT,
			"INPROGRESS", "Objects downloaded", 40);
		break;
	case UPDATE_INSTALLED:
		sprintf(json, DEVICE_STEP_STATUS_FMT,
			"INPROGRESS", "Step committed to disk", 80);
		break;
	case UPDATE_TRY:
		sprintf(json, DEVICE_STEP_STATUS_FMT,
			"INPROGRESS", "Attempting to start step", 90);
		break;
	case UPDATE_REBOOT:
		sprintf(json, DEVICE_STEP_STATUS_FMT,
			"INPROGRESS", "Rebooting device", 95);
		break;
	case UPDATE_DONE:
		sprintf(json, DEVICE_STEP_STATUS_FMT,
			"DONE", "Step started correctly", 100);
		break;
	default:
		sprintf(json, DEVICE_STEP_STATUS_FMT,
			"ERROR", "Failed to install step", 0);
		break;
	}
				
	req = trest_make_request(TREST_METHOD_PUT,
				 u->endpoint,
				 0, 0,
				 json);

	res = trest_do_json_request(sc->remote->client, req);

	if (!res) {
		sc_log(WARN, "unable to do trail request");
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

static int get_digit_count(int number)
{
	int c = 0;

	while (number) {
		number /= 10;
		c++;
	}
	c++;

	return c;
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
		rev = u->pending->state->rev;
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
			sc_log(WARN, "failed to update cloud status, possibly offline");
	}

	return 0;
}

int sc_bl_get_update(struct systemc *sc, int *update)
{
	int ret = -1;
	int fd, t;
	char *rev = 0;
	char *buf = 0;

	// FIXME: systemc env partition should come from config
	// FIXME: in fact it should be smart and have multiple backends
	fd = open("/dev/mtd2", O_RDONLY);
	if (fd < 0) {
		sc_log(ERROR, "unable to read bootloader update buffer");
		goto out;
	}

	lseek(fd, 0, SEEK_SET);
	buf = calloc(1, 64 * sizeof(char));
	read(fd, buf, 64 * sizeof(char));
	buf[63] = '\0';
	sc_log(INFO, "read %s from bootloader update buffer", buf);
	close(fd);

	rev = strtok(buf, "=");
	if (!rev)
		goto out;

	if (strcmp(rev, "sc_update") != 0) {
		sc_log(WARN, "no update information from bootloader");
		goto out;
	}

	rev = strtok(NULL, "=");
	t = atoi(rev);

	if (t <= 0) {
		sc_log(ERROR, "wrong update revision from bootloader");
		goto out;
	}

	*update = t;
	ret = 1;

out:
	if (buf)
		free(buf);

	return ret;
}

int sc_bl_clear_update(struct systemc *sc)
{
	int fd;
	char buf[64] = { 0 };

	fd = open("/dev/mtd2", O_RDONLY);
	if (fd < 0) {
		sc_log(ERROR, "unable to clear bootloader update buffer");
		return -1;
	}

	lseek(fd, 0, SEEK_SET);
	write(fd, &buf, sizeof(buf));
	sc_log(INFO, "cleared bootloader update buffer");
	close(fd);

	return 0;
}

int sc_trail_update_finish(struct systemc *sc)
{
	int ret = 0;
	struct trail_object *tmp;
	struct trail_object *obj = head;

	switch (sc->update->status) {
	case UPDATE_DONE:
		ret = trail_remote_set_status(sc, UPDATE_DONE);
		goto out;
		break;
	case UPDATE_REBOOT:
		sc_log(WARN, "update requires reboot, cleaning up...");
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
	if (sc->update->pending) {
		if (sc->update->pending->state)
			trail_state_free(sc->update->pending->state);
		free(sc->update->pending->json);
		free(sc->update->pending);
	}
	if (sc->update->objects)
		free(sc->update->objects);
	if (sc->update->endpoint)
		free(sc->update->endpoint);

	free(sc->update);

	while (obj) {
		free(obj->objpath);	
		free(obj->relpath);	
		free(obj->id);	
		free(obj->geturl);
		tmp = obj->next;
		free(obj);
		obj = tmp;
	}

	head = NULL;
	last = NULL;

	sc->update = NULL;
	return ret;
}

static char* trail_download_geturl(struct systemc *sc, char *abrn)
{
	char *endpoint;
	char *url = 0;
	trest_request_ptr req;
	trest_response_ptr res;

	endpoint = malloc((sizeof(TRAIL_OBJECT_DL_FMT) + strlen(abrn)) * sizeof(char));
	sprintf(endpoint, TRAIL_OBJECT_DL_FMT, abrn);

	sc_log(INFO, "requesting obj='%s'", endpoint);
	
	req = trest_make_request(TREST_METHOD_GET,
				 endpoint,
				 0, 0, 0);

	res = trest_do_json_request(sc->remote->client, req);

	if (!res) {
		sc_log(WARN, "unable to do trail request");
		goto out;
	}

	url = (char *) get_json_key_value(res->body, "signed-geturl",
				 res->json_tokv, res->json_tokc);

	if (!url) {
		sc_log(ERROR, "unable to get download url for object");
		goto out;
	}
	url = unescape_utf8_to_ascii(url, "\\u0026", '&');

out:
	if (req)
		trest_request_free(req);
	if (res)
		trest_response_free(res);
	if (endpoint)
		free(endpoint);

	return url;
}

static char *trail_get_objpath(struct systemc *sc, char *abrn)
{
	struct systemc_config *c = sc->config;
	char *path;

	if (!abrn)
		return NULL;

	path = malloc((strlen(c->storage.mntpoint) +
			 strlen(abrn) + sizeof(TRAIL_OBJPATH_FMT)) * sizeof(char));
	sprintf(path, TRAIL_OBJPATH_FMT, c->storage.mntpoint, abrn);

	return path;
}

static int trail_add_object(struct systemc *sc, char *abrn, char *rpath)
{
	struct trail_object *obj = malloc(sizeof(struct trail_object));

	if (head == NULL)
		head = obj;
	else
		last->next = obj;

	obj->id = strdup(abrn);
	obj->geturl = trail_download_geturl(sc, abrn);
	obj->objpath = trail_get_objpath(sc, abrn);
	obj->relpath = rpath;

	sc_log(DEBUG, "new obj id: '%s', url: '%s,' objpath: '%s', relpath: '%s'",
		 obj->id, obj->geturl, obj->objpath, obj->relpath);

	obj->next = NULL;
	last = obj;

	return 0;
}

static char *trail_get_relpath(struct systemc *sc, char *fmt, int rev, char *filename, char *parent)
{
	int size;
	int rsize = get_digit_count(rev);
	char *rpath;
	struct systemc_config *c = sc->config;

	size = (strlen(fmt) + strlen(c->storage.mntpoint) +
		strlen(filename) + rsize); 

	if (parent)
		size += strlen(parent);

	rpath = malloc(size * sizeof(char));

	if (!parent)
		sprintf(rpath, fmt, c->storage.mntpoint, rev, filename);
	else
		sprintf(rpath, fmt, c->storage.mntpoint, rev, parent, filename);

	return rpath;
}

static int trail_download_object(struct trail_object *obj)
{
	int fd, ret, n;
	char *host = 0;
	thttp_request_t* req = 0;
	thttp_response_t* res = 0;
	char *start = 0, *end = 0;

	req = thttp_request_new_0 ();

	req->method = THTTP_METHOD_GET;
	req->proto = THTTP_PROTO_HTTP;
	req->proto_version = THTTP_PROTO_VERSION_10;

	if (obj->geturl && strncmp(obj->geturl, "https://", 8) != 0) {
		sc_log(WARN, "object url (%s) is invalid", obj->geturl);
		ret = -1;
		goto out;
	}

	// FIXME: should check sha256, need to rework geturl() for that
	// FIXME: can use sha256.h from mbedtls mbedtls_sha256()

	struct stat st;
	if (stat(obj->objpath, &st) == 0) {
		sc_log(INFO, "file exists (%s)", obj->objpath);
		ret = 0;
		goto out;
	}
	
	start = obj->geturl + 8;
	end = strchr(start, '/');
	n = (unsigned long) end - (unsigned long) start;
	host = malloc((n+1) * sizeof(char));
	strncpy(host, start, n);
	host[n] = '\0';

	req->host = host;
	req->port = 80;
	req->path = obj->geturl;
	req->headers = 0;

	fd = open(obj->objpath, O_CREAT | O_RDWR, 0644);

	res = thttp_request_do_file (req, fd);

	close (fd);
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
	struct trail_object *obj;
	char *c, *tmp;

	for (obj = head; obj != NULL; obj = obj->next) {
		tmp = strdup(obj->relpath);
		c = strrchr(tmp, '/');
		*c = '\0';
		mkdir_p(tmp, 0644);
		free(tmp);
		if (link(obj->objpath, obj->relpath) < 0) {
			sc_log(ERROR, "unable to link %s, errno=%d",
				obj->relpath, errno);
			if (errno != EEXIST)
				err++;
		} else {
			sc_log(INFO, "linked %s to %s",
				obj->relpath, obj->objpath);
		}
	}

	return -err;
}


static int trail_download_objects(struct systemc *sc)
{
	struct stat st;
	struct sc_update *u = sc->update;
	systemc_state *p = u->pending->state;
        systemc_object **basev_i = p->basev;
        systemc_volobject **volumesv_i = p->volumesv;
        systemc_platform **platformsv_i = p->platformsv;

	// build list of objects to download
	trail_add_object(sc, p->kernel->abrn,
			trail_get_relpath(sc, TRAIL_KERNEL_FMT, p->rev,
				p->kernel->filename, 0));

	// Check if update includes new kernel
	if (strcmp(sc->state->kernel->abrn, p->kernel->abrn) != 0)
		u->need_reboot = 1;

	while(*basev_i) {
		trail_add_object(sc, (*basev_i)->abrn,
			trail_get_relpath(sc, TRAIL_SYSTEMC_FMT, p->rev,
				(*basev_i)->filename, 0));

		// Check if new base object
		if (stat(trail_get_objpath(sc, (*basev_i)->abrn), &st) < 0)
			u->need_reboot = 1;

		basev_i++;
	}

	while(*volumesv_i) {
		trail_add_object(sc, (*volumesv_i)->abrn,
			 trail_get_relpath(sc, TRAIL_VOLUMES_FMT, p->rev,
				(*volumesv_i)->filename, 0));
		volumesv_i++;
	}

	while(*platformsv_i) {
		systemc_object **configs_i;
		configs_i = (*platformsv_i)->configs;
		while (*configs_i) {
			trail_add_object(sc, (*configs_i)->abrn,
				trail_get_relpath(sc, TRAIL_PLAT_CFG_FMT, p->rev,
					  (*configs_i)->filename, (*platformsv_i)->name));
			configs_i++;
		}
		platformsv_i++;
	}

	for (struct trail_object *obj = head; obj != NULL; obj = obj->next)
		trail_download_object(obj);

	return 0;
}

int sc_trail_update_install(struct systemc *sc)
{
	int ret, fd;
	struct trail_step *step;
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
	step = sc->update->pending;
	sprintf(state_path, "%s/trails/%d/state.json", sc->config->storage.mntpoint, step->state->rev);
	fd = open(state_path, O_CREAT | O_WRONLY);
	if (fd < 0) {
		sc_log(ERROR, "unable to write state.json file for update");
		ret = -1;
		goto out;
	}
	write(fd, step->json, strlen(step->json));
	close(fd);

	trail_remote_set_status(sc, UPDATE_INSTALLED);

	sleep(2);
	sc->update->status = UPDATE_TRY;
	ret = step->state->rev;

	if (sc->update->need_reboot) {
		sc->update->status = UPDATE_REBOOT;
		uboot_set_try_rev(sc, ret);
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

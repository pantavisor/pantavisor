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
#include <mbedtls/sha256.h>

#define MODULE_NAME			"updater"
#define pv_log(level, msg, ...)		vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "utils.h"

#include "objects.h"
#include "updater.h"
#include "bootloader.h"
#include "pantahub.h"
#include "storage.h"
#include "wdt.h"

static struct trail_object *head;
static struct trail_object *last;

typedef int (*token_iter_f) (void *d1, void *d2, char *buf, jsmntok_t* tok, int c);

// takes an allocated buffer
static char *unescape_utf8_to_apvii(char *buf, char *code, char c)
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

static int trail_remote_init(struct pantavisor *pv)
{
	struct trail_remote *remote = NULL;
	const char **cafiles;
	trest_auth_status_enum status = TREST_AUTH_STATUS_NOTAUTH;
	trest_ptr client = 0;

	// Make sure values are reasonable
	if ((strcmp(pv->config->creds.id, "") == 0) ||
	    (strcmp(pv->config->creds.prn, "") == 0))
		return 0;

	cafiles = pv_ph_get_certs(pv);
	if (!cafiles) {
		pv_log(ERROR, "unable to assemble cert list");
		goto err;
	}

	// Create client
	client = trest_new_tls_from_userpass(
		pv->config->creds.host,
		pv->config->creds.port,
		pv->config->creds.prn,
		pv->config->creds.secret,
		(const char **) cafiles
		);

	if (!client) {
		pv_log(INFO, "unable to create device client");
		goto err;
	}

	// FIXME: Crash here if unable to auth
	status = trest_update_auth(client);
	if (status != TREST_AUTH_STATUS_OK) {
		pv_log(INFO, "unable to auth device client");
		goto err;
	}

	remote = malloc(sizeof(struct trail_remote));
	remote->client = client;
	remote->endpoint = malloc((sizeof(DEVICE_TRAIL_ENDPOINT_FMT)
				   + strlen(pv->config->creds.id)) * sizeof(char));
	sprintf(remote->endpoint, DEVICE_TRAIL_ENDPOINT_FMT, pv->config->creds.id);

	pv->remote = remote;

	return 0;

err:
	if (client)
		free(client);
	if (remote)
		free(remote);

	return -1;
}

static int trail_remote_set_status(struct pantavisor *pv, int rev, enum update_state status)
{
	int ret = 0;
	struct pv_update *u = pv->update;
	trest_request_ptr req;
	trest_response_ptr res;
	char json[1024];
	char *endpoint;

	if (!u) {
		endpoint = malloc(sizeof(DEVICE_STEP_ENDPOINT_FMT) +
			strlen(pv->config->creds.id) + get_digit_count(rev));
		sprintf(endpoint, DEVICE_STEP_ENDPOINT_FMT, pv->config->creds.id, rev);
	} else {
		endpoint = u->endpoint;
	}

	if (!pv->remote)
		trail_remote_init(pv);

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
	case UPDATE_NO_DOWNLOAD:
		sprintf(json, DEVICE_STEP_STATUS_FMT,
			"WONTGO", "Unable to download and/or install update", 0);
		break;
	case UPDATE_NO_PARSE:
		sprintf(json, DEVICE_STEP_STATUS_FMT,
			"WONTGO", "Remote state cannot be parsed", 0);
		break;
	default:
		sprintf(json, DEVICE_STEP_STATUS_FMT,
			"ERROR", "Error during update", 0);
		break;
	}

	req = trest_make_request(TREST_METHOD_PUT,
				 endpoint,
				 0, 0,
				 json);

	res = trest_do_json_request(pv->remote->client, req);

	if (!res) {
		pv_log(INFO, "unable to do trail request");
		ret = -1;
		goto out;
	}

	if (res->code == THTTP_STATUS_OK) {
		pv_log(INFO, "remote state updated to %s", res->body);
	} else {
		pv_log(WARN, "unable to update remote status, http code %d", res->code);
	}

out:
	if (!u && endpoint)
		free(endpoint);
	if (req)
		trest_request_free(req);
	if (res)
		trest_response_free(res);

	return ret;
}

static int trail_get_new_steps(struct pantavisor *pv)
{
	int size = 0, tokc = 0, rev;
	char *state = 0, *rev_s = 0;
	struct trail_remote *r = pv->remote;
	trest_request_ptr req = 0;
	trest_response_ptr res = 0;
	jsmntok_t *tokv = 0;

	if (!r)
		return 0;

	req = trest_make_request(TREST_METHOD_GET,
				 r->endpoint,
				 0, 0, 0);

	res = trest_do_json_request(r->client, req);

	if (!res) {
		pv_log(INFO, "unable to do trail request");
		goto out;
	}
	if (res->code != THTTP_STATUS_OK) {
		pv_log(WARN, "http error (%d) on trail request", res->code);
		goto out;
	}

	size = jsmnutil_array_count(res->body, res->json_tokv);
	pv_log(DEBUG, "steps found in NEW state = '%d'", size);

	if (!size)
		goto out;

	if (jsmnutil_parse_json (res->body, &tokv, &tokc) < 0)
		goto out;

	rev_s = get_json_key_value(res->body, "rev",
		res->json_tokv, res->json_tokc);
	state = get_json_key_value(res->body, "state",
		res->json_tokv, res->json_tokc);

	if (!rev_s || !state) {
		pv_log(WARN, "invalid data found on trail, ignoring");
		goto out;
	}

	// parse state
	rev = atoi(rev_s);
	r->pending = pv_parse_state(pv, state, strlen(state), rev);

	if (!r->pending) {
		pv_log(INFO, "invalid rev (%d) found on remote", rev);
		trail_remote_set_status(pv, rev, UPDATE_NO_PARSE);
		size = 0;
	} else {
		pv_log(DEBUG, "adding rev (%d), state = '%s'", rev, state);
		pv_log(DEBUG, "first pending found to be rev = %d", r->pending->rev);
	}

out:
	if (rev_s)
		free(rev_s);
	if (state)
		free(state);
	if (tokv)
		free(tokv);
	if (req)
		trest_request_free(req);
	if (res)
		trest_response_free(res);

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
		pv_log(INFO, "unable to do trail request");
		size = -1;
		goto out;
	}

	if (res->code != THTTP_STATUS_OK || res->body == NULL) {
		size = -1;
		goto out;
	}

	size = jsmnutil_array_count(res->body, res->json_tokv);
	if (size)
		pv_log(DEBUG, "trail found, using remote");

out:
	if (req)
		trest_request_free(req);
	if (res)
		trest_response_free(res);

	return size;
}

static int trail_put_object(struct pantavisor *pv, struct pv_object *o, const char **crtfiles)
{
	int ret = 0;
	int fd, bytes;
	int size, pos, i;
	char *signed_puturl;
	char sha_str[128];
	char body[512];
	unsigned char buf[4096];
	unsigned char local_sha[32];
	struct stat st;
	trest_request_ptr treq = 0;
	trest_response_ptr tres = 0;
	thttp_request_t *req = 0;
	thttp_request_tls_t *tls_req = 0;
	thttp_response_t *res = 0;

	fd = open(o->objpath, O_RDONLY);
	if (fd < 0)
		return -1;

	stat(o->objpath, &st);
	size = st.st_size;

	mbedtls_sha256_context sha256_ctx;

	mbedtls_sha256_init(&sha256_ctx);
	mbedtls_sha256_starts(&sha256_ctx, 0);

	while ((bytes = read(fd, buf, 4096)) > 0) {
		mbedtls_sha256_update(&sha256_ctx, buf, bytes);
	}

	mbedtls_sha256_finish(&sha256_ctx, local_sha);
	mbedtls_sha256_free(&sha256_ctx);

	pos = 0;
	i = 0;
	while(i < 32) {
		pos += sprintf(sha_str+pos, "%02x", local_sha[i]);
		i++;
	}

	sprintf(body,
		"{ \"objectname\": \"%s\","
		" \"size\": \"%d\","
		" \"sha256sum\": \"%s\""
		" }",
		o->name,
		size,
		sha_str);

	pv_log(INFO, "syncing '%s'", o->id, body);

	if (strcmp(o->id,sha_str)) {
		pv_log(INFO, "sha256 mismatch, probably writable image, skipping", o->objpath);
		goto out;
	}

	treq = trest_make_request(TREST_METHOD_POST,
				"/objects/",
				0,
				0,
				body);

	tres = trest_do_json_request(pv->remote->client, treq);
	if (!tres) {
		ret = -1;
		goto out;
	}

	if (tres->code == THTTP_STATUS_CONFLICT) {
		pv_log(INFO, "'%s' already owned by user, skipping", o->id, tres->code);
		goto out;
	}
	pv_log(INFO, "'%s' does not exist, uploading", o->id, tres->code);

	signed_puturl = get_json_key_value(tres->body,
				"signed-puturl",
				tres->json_tokv,
				tres->json_tokc);

	tls_req = (thttp_request_tls_t*) thttp_request_tls_new_0 ();
	tls_req->crtfiles = (char ** )crtfiles;
	req = (thttp_request_t*) tls_req;
	req->is_tls = 1;

	req->method = THTTP_METHOD_PUT;
	req->proto = THTTP_PROTO_HTTP;
	req->proto_version = THTTP_PROTO_VERSION_10;
	req->host = pv->config->creds.host;
	req->port = pv->config->creds.port;

	req->path = strstr(signed_puturl, "/local-s3");

	req->headers = 0;
	req->body_content_type = "application/json";
	lseek(fd, 0, SEEK_SET);
	req->fd = fd;
	req->len = size;

	res = thttp_request_do(req);

	if (!res) {
		ret = -1;
		goto out;
	}

	if (tres->code != THTTP_STATUS_OK) {
		pv_log(ERROR, "'%s' could not be uploaded, code=%d", o->id, tres->code);
		ret = -1;
		goto out;
	}

	pv_log(INFO, "'%s' uploaded correctly, size=%d, code=%d", o->id, size, res->code);

out:
	if (treq)
		trest_request_free(treq);
	if (tres)
		trest_response_free(tres);
	if (req)
		thttp_request_free(req);
	if (res)
		thttp_response_free(res);

	return ret;
}

static int trail_put_objects(struct pantavisor *pv)
{
	int ret = 0;
	struct pv_object *o = pv->state->objects;
	const char **crtfiles = pv_ph_get_certs(pv);

	// count
	while (o) {
		ret++;
		o = o->next;
	}

	o = pv->state->objects;
	pv_log(DEBUG, "first boot: %d objects found, syncing", ret);

	// push all
	while (o) {
		if (trail_put_object(pv, o, crtfiles) < 0)
			break;
		ret--;
		o = o->next;
	}

	return ret;
}

static int trail_first_boot(struct pantavisor *pv)
{
	int ret = 0;
	trest_request_ptr req;
	trest_response_ptr res;
	trest_auth_status_enum status = TREST_AUTH_STATUS_NOTAUTH;

	status = trest_update_auth(pv->remote->client);
	if (status != TREST_AUTH_STATUS_OK) {
		pv_log(INFO, "cannot update auth token");
		return -1;
	}

	// first upload all objects
	if (trail_put_objects(pv) > 0) {
		pv_log(DEBUG, "error syncing objects on first boot");
		return -1;
	}

	req = trest_make_request(TREST_METHOD_POST, "/trails/", 0, 0, pv->step);
	res = trest_do_json_request(pv->remote->client, req);

	if (!res) {
		pv_log(ERROR, "error on first boot json request");
		ret = -1;
		goto out;
	}

	if (res->code != THTTP_STATUS_OK) {
		pv_log(ERROR, "http request error (%d) for initial trail", res->code);
		ret = -1;
		goto out;
	}

	pv_log(INFO, "factory revision (base trail) pushed to remote correctly");
	ret = 0;

out:
	if (req)
		trest_request_free(req);
	if (res)
		trest_response_free(res);

	return ret;
}

/* API */

int pv_check_for_updates(struct pantavisor *pv)
{
	int ret;
	trest_auth_status_enum auth_status;

	if (!pv->remote)
		trail_remote_init(pv);

	// Offline
	if (!pv->remote)
		return 0;

	auth_status = trest_update_auth(pv->remote->client);
	if (auth_status != TREST_AUTH_STATUS_OK) {
		pv_log(INFO, "cannot authenticate to cloud");
		return 0;
	}

	ret = trail_is_available(pv->remote);
	if (ret == 0)
		return trail_first_boot(pv);
	else if (ret > 0)
		return trail_get_new_steps(pv);
	else
		return 0;
}

int pv_update_set_status(struct pantavisor *pv, enum update_state status)
{
	if (!pv) {
		pv_log(WARN, "uninitialized pantavisor object");
		return 0;
	}

	if (!pv->update) {
		pv_log(WARN, "invalid update in current state");
		return 0;
	}

	pv->update->status = status;

	return 1;
}

int pv_update_start(struct pantavisor *pv, int offline)
{
	int c;
	int ret = -1, rev = -1;
	struct pv_update *u;

	if (!pv) {
		pv_log(WARN, "uninitialized pantavisor object");
		goto out;
	}

	if (!pv->state) {
		pv_log(WARN, "invalid pantavisor state");
		goto out;
	}

	u = calloc(sizeof(struct pv_update), 1);

	head = NULL;
	last = NULL;

	// Offline update
	if (!pv->remote && offline) {
		rev = pv->state->rev;
	} else {
		u->pending = pv->remote->pending;
		rev = u->pending->rev;
	}

	// to construct endpoint
	c = get_digit_count(rev);
	u->endpoint = malloc((sizeof(DEVICE_STEP_ENDPOINT_FMT)
		          + (strlen(pv->config->creds.id)) + c) * sizeof(char));
	sprintf(u->endpoint, DEVICE_STEP_ENDPOINT_FMT,
		pv->config->creds.id, rev);

	// FIXME: currently we only support strict (always rebot) updates
	u->need_reboot = 1;
	u->need_finish = 0;
	pv->update = u;

	// all done up to here for offline
	ret = 0;

	if (!offline) {
		ret = trail_remote_set_status(pv, -1, UPDATE_QUEUED);
		if (ret < 0)
			pv_log(INFO, "failed to update cloud status, possibly offline");
	}

out:
	return ret;
}

int pv_update_finish(struct pantavisor *pv)
{
	int ret = 0;

	switch (pv->update->status) {
	case UPDATE_DONE:
		ret = trail_remote_set_status(pv, -1, UPDATE_DONE);
		goto out;
		break;
	case UPDATE_REBOOT:
		pv_log(INFO, "update requires reboot, cleaning up...");
		goto out;
		break;
	case UPDATE_FAILED:
		ret = trail_remote_set_status(pv, -1, UPDATE_FAILED);
		pv_log(ERROR, "update has failed");
		goto out;
	default:
		ret = -1;
		goto out;
		break;
	}

out:
	if (pv->update->pending)
		pv_state_free(pv->update->pending);
	if (pv->update->endpoint)
		free(pv->update->endpoint);

	free(pv->update);

	pv->update = NULL;
	return ret;
}

static int trail_download_get_meta(struct pantavisor *pv, struct pv_object *o)
{
	int ret = 0;
	char *endpoint = 0;
	char *url = 0;
	char *prn, *size;
	trest_request_ptr req = 0;
	trest_response_ptr res = 0;

	if (!o)
		goto out;

	prn = o->id;

	endpoint = malloc((sizeof(TRAIL_OBJECT_DL_FMT) + strlen(prn)) * sizeof(char));
	sprintf(endpoint, TRAIL_OBJECT_DL_FMT, prn);

	pv_log(DEBUG, "requesting obj='%s'", endpoint);

	req = trest_make_request(TREST_METHOD_GET,
				 endpoint,
				 0, 0, 0);

	res = trest_do_json_request(pv->remote->client, req);
	if (!res) {
		pv_log(WARN, "unable to do trail request");
		goto out;
	}
	if (res->code != THTTP_STATUS_OK) {
		pv_log(WARN, "http request error (%d) on object metadata", res->code);
		goto out;
	}

	size = get_json_key_value(res->body, "size",
			res->json_tokv, res->json_tokc);
	if (size)
		o->size = atoll(size);

	o->sha256 = get_json_key_value(res->body, "sha256sum",
				 res->json_tokv, res->json_tokc);

	url = get_json_key_value(res->body, "signed-geturl",
				 res->json_tokv, res->json_tokc);
	if (!url) {
		pv_log(ERROR, "unable to get download url for object");
		goto out;
	}
	url = unescape_utf8_to_apvii(url, "\\u0026", '&');
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

static int obj_is_kernel_pvk(struct pantavisor *pv, struct pv_object *obj)
{
	if (strcmp(pv->state->kernel, obj->name))
		return 0;

	if (pv->config->bl.type == BL_UBOOT_PVK)
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

	pv_log(INFO, "  bytes_r=%d bytes_w=%d", bytes_r, bytes_w);

	return bytes_r;
}

static int trail_update_has_new_initrd(struct pantavisor *pv)
{
	char *old = 0, *new = 0;
	struct pv_object *o_new = 0, *o_old = 0;

	if (!pv)
		return 0;

	if (pv->state)
		old = pv->state->initrd;

	if (pv->update && pv->update->pending)
		new = pv->update->pending->initrd;

	if (!old || !new)
		return 0;

	if (strcmp(old, new))
		return 1;

	o_new = pv_objects_get_by_name(pv->update->pending, new);
	o_old = pv_objects_get_by_name(pv->state, old);
	if (!o_new || !o_old)
		return 1;

	if (strcmp(o_new->id, o_old->id))
		return 1;

	return 0;
}

static int trail_download_object(struct pantavisor *pv, struct pv_object *obj, const char **crtfiles)
{
	int ret = 0;
	int volatile_tmp_fd = -1, fd = -1, obj_fd = -1;
	int bytes, n;
	int is_kernel_pvk;
	int use_volatile_tmp = 0;
	char *tmp_sha;
	char *host = 0;
	char *start = 0, *port = 0, *end = 0;
	char mmc_tmp_obj_path [PATH_MAX];
	char volatile_tmp_obj_path[] = VOLATILE_TMP_OBJ_PATH;
	unsigned char buf[4096];
	unsigned char cloud_sha[32];
	unsigned char local_sha[32];
	struct stat st;
	mbedtls_sha256_context sha256_ctx;
	thttp_response_t* res = 0;
	thttp_request_tls_t* tls_req = 0;
	thttp_request_t* req = 0;

	if (!obj)
		goto out;

	tls_req = thttp_request_tls_new_0 ();
	tls_req->crtfiles = (char ** )crtfiles;

	req = (thttp_request_t*) tls_req;

	req->method = THTTP_METHOD_GET;
	req->proto = THTTP_PROTO_HTTP;
	req->proto_version = THTTP_PROTO_VERSION_10;

	is_kernel_pvk = obj_is_kernel_pvk(pv, obj);
	if (!is_kernel_pvk && stat(obj->objpath, &st) == 0) {
		pv_log(DEBUG, "file exists (%s)", obj->objpath);
		ret = 1;
		goto out;
	}

	if (obj->geturl == NULL) {
		pv_log(INFO, "there is no get url defined");
		goto out;
	}

	// SSL is mandatory
	if (strncmp(obj->geturl, "https://", 8) != 0) {
		pv_log(INFO, "object url (%s) is invalid", obj->geturl);
		goto out;
	}
	req->port = 443;

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

	if (!strcmp(pv->config->storage.fstype, "jffs2") ||
	    !strcmp(pv->config->storage.fstype, "ubifs"))
		use_volatile_tmp = 1;

	// temporary path where we will store the file until validated
	sprintf(mmc_tmp_obj_path, MMC_TMP_OBJ_FMT, obj->objpath);
	obj_fd = open(mmc_tmp_obj_path, O_CREAT | O_RDWR, 0644);

	if (use_volatile_tmp) {
		mktemp(volatile_tmp_obj_path);
		volatile_tmp_fd = open(volatile_tmp_obj_path, O_CREAT | O_RDWR, 0644);
		fd = volatile_tmp_fd;
	} else {
		fd = obj_fd;
	}

	if (is_kernel_pvk) {
		fsync(obj_fd);
		close(obj_fd);
		fd = volatile_tmp_fd;
	}

	// download to tmp
	lseek(fd, 0, SEEK_SET);
	pv_log(INFO, "downloading object to tmp path (%s)", mmc_tmp_obj_path);
	res = thttp_request_do_file (req, fd);
	if (!res) {
		pv_log(WARN, "no response from server");
		remove(mmc_tmp_obj_path);
		goto out;
	} else if (res->code != THTTP_STATUS_OK) {
		pv_log(WARN, "error response from server, http code %d", res->code);
		remove(mmc_tmp_obj_path);
		goto out;
	}

	if (use_volatile_tmp) {
		pv_log(INFO, "copying %s to tmp path (%s)", volatile_tmp_obj_path, mmc_tmp_obj_path);
		bytes = copy_and_close(volatile_tmp_fd, obj_fd);
		fd = obj_fd;
	}
	pv_log(INFO, "downloaded object to tmp path (%s)", mmc_tmp_obj_path);
	fsync(fd);

	// verify file downloaded correctly before syncing to disk
	lseek(fd, 0, SEEK_SET);
	mbedtls_sha256_init(&sha256_ctx);
	mbedtls_sha256_starts(&sha256_ctx, 0);

	while ((bytes = read(fd, buf, 4096)) > 0) {
		mbedtls_sha256_update(&sha256_ctx, buf, bytes);
	}

	mbedtls_sha256_finish(&sha256_ctx, local_sha);
	mbedtls_sha256_free(&sha256_ctx);

	tmp_sha = obj->sha256;
	for (int i = 0, j = 0; i < (int) strlen(tmp_sha); i=i+2, j++) {
		char byte[3];
		strncpy(byte, tmp_sha+i, 2);
		byte[2] = 0;
		cloud_sha[j] = strtoul(byte, NULL, 16);
	}

	// compare hashes FIXME: retry if fail
	for (int i = 0; i < 32; i++) {
		if (cloud_sha[i] != local_sha[i]) {
			pv_log(WARN, "sha256 mismatch with local object");
			remove(mmc_tmp_obj_path);
			goto out;
		}
	}
	syncdir(mmc_tmp_obj_path);

	pv_log(INFO, "verified object (%s), renaming from (%s)", obj->objpath, mmc_tmp_obj_path);
	rename(mmc_tmp_obj_path, obj->objpath);

	if (is_kernel_pvk)
		pv_bl_install_kernel(pv, volatile_tmp_obj_path);

	ret = 1;

out:
	if (fd)
		close(fd);
	if (host)
		free(host);
	if (req)
		thttp_request_free(req);
	if (res)
		thttp_response_free(res);

	return ret;
}

static int trail_link_objects(struct pantavisor *pv)
{
	int err = 0;
	struct pv_object *obj = pv->update->pending->objects;
	char *c, *tmp, *ext;

	while (obj) {
		tmp = strdup(obj->relpath);
		c = strrchr(tmp, '/');
		*c = '\0';
		mkdir_p(tmp, 0644);
		free(tmp);
	        ext = strrchr(obj->relpath, '.');
		if (ext && (strcmp(ext, ".bind") == 0)) {
			int s_fd, d_fd;
			s_fd = open(obj->objpath, O_RDONLY);
			d_fd = open(obj->relpath, O_CREAT | O_WRONLY | O_SYNC, 0644);
			pv_log(INFO, "copying bind volume '%s' from '%s'", obj->relpath, obj->objpath);
			copy_and_close(s_fd, d_fd);
			obj = obj->next;
			continue;
		}
		if (link(obj->objpath, obj->relpath) < 0) {
			if (errno != EEXIST)
				err++;
			pv_log(ERROR, "unable to link %s, errno=%d",
				obj->relpath, errno);
		} else {
			syncdir(obj->objpath);
			pv_log(INFO, "linked %s to %s",
				obj->relpath, obj->objpath);
		}
		obj = obj->next;
	}

	err += pv_meta_link_boot(pv, pv->update->pending);

	return -err;
}

static int get_update_size(struct pv_update *u)
{
	int size = 0;
	struct stat st;
	struct pv_object *o = u->pending->objects;

	while (o) {
		if (stat(o->objpath, &st) < 0)
			size += o->size;
		o = o->next;
	}

	pv_log(INFO, "update size: %d bytes", size);

	return size;
}

static int trail_download_objects(struct pantavisor *pv)
{
	int ret = -1;
	struct pv_object *k_new, *k_old;
	struct pv_update *u = pv->update;
	struct pv_object *o = u->pending->objects;
	const char **crtfiles = pv_ph_get_certs(pv);

	while (o) {
		if (!trail_download_get_meta(pv, o))
			goto out;
		o = o->next;
	}

	// Run GC as last resort
	if (!pv_storage_get_free(pv, get_update_size(u)))
		pv_storage_gc_run(pv);

	// Check again
	if (!pv_storage_get_free(pv, get_update_size(u))) {
		pv_log(WARN, "not enough space to process update");
		goto out;
	}

	k_new = pv_objects_get_by_name(u->pending,
			u->pending->kernel);
	k_old = pv_objects_get_by_name(pv->state,
			pv->state->kernel);

	if (k_new && k_old && strcmp(k_new->id, k_old->id))
		u->need_reboot = 1;

	o = u->pending->objects;
	while (o) {
		if (!trail_download_object(pv, o, crtfiles))
			goto out;
		o = o->next;
	}

	ret = 0;

out:
	return ret;
}

int pv_update_install(struct pantavisor *pv)
{
	int ret, fd;
	struct pv_state *pending = pv->update->pending;
	char path[PATH_MAX];

	if (!pv->remote)
		trail_remote_init(pv);

	if (!pending) {
		ret = -1;
		pv_log(ERROR, "update data is invalid");
		goto out;
	}

	pv_log(INFO, "applying update...");
	ret = trail_download_objects(pv);

	if (ret < 0) {
		pv_log(ERROR, "unable to download objects");
		pv->update->status = UPDATE_NO_DOWNLOAD;
		goto out;
	}

	trail_remote_set_status(pv, -1, UPDATE_DOWNLOADED);

	if (trail_update_has_new_initrd(pv))
		pv->update->need_reboot = 1;

	// make sure target directories exist
	sprintf(path, "%s/trails/%d/.pvr", pv->config->storage.mntpoint, pending->rev);
	mkdir_p(path, 0644);
	sprintf(path, "%s/trails/%d/.pv", pv->config->storage.mntpoint, pending->rev);
	mkdir_p(path, 0644);

	ret = trail_link_objects(pv);
	if (ret < 0) {
		pv_log(ERROR, "unable to link objects to relative path (failed=%d)", ret);
		pv->update->status = UPDATE_FAILED;
		goto out;
	}

	// install state.json for new rev
	sprintf(path, "%s/trails/%d/.pvr/json", pv->config->storage.mntpoint, pending->rev);
	fd = open(path, O_CREAT | O_WRONLY | O_SYNC, 0644);
	if (fd < 0) {
		pv_log(ERROR, "unable to write state.json file for update");
		ret = -1;
		goto out;
	}
	write(fd, pending->json, strlen(pending->json));
	close(fd);

	if (!pv_meta_expand_jsons(pv, pending)) {
		pv_log(ERROR, "unable to install platform and pantavisor jsons");
		ret = -1;
		goto out;
	}

	trail_remote_set_status(pv, -1, UPDATE_INSTALLED);

	sleep(2);
	pv->update->status = UPDATE_TRY;
	ret = pending->rev;

	if (pv->update->need_reboot) {
		pv->update->status = UPDATE_REBOOT;
		pv_bl_set_try(pv, ret);
	}

out:
	trail_remote_set_status(pv, -1, pv->update->status);
	if (pending && (ret < 0))
		pv_storage_rm_rev(pv, pending->rev);

	return ret;
}

void pv_remote_destroy(struct pantavisor *pv)
{
	if (!pv->remote)
		return;

	free(pv->remote->client);
	free(pv->remote->endpoint);
	free(pv->remote);
}

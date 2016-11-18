#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <jsmn/jsmnutil.h>

#include "updater.h"

typedef void (*token_iter_f) (void *data, char *buf, jsmntok_t* tok, int c);

static int
traverse_token (char *buf, jsmntok_t* tok, int t)
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
		printf("iterare_json_array: token not array");
		return -1;
	}

	c = t;
	for(i=0; i < tok->size; i++) {
		func(data, buf, tok, c+1);
		c = traverse_token (buf, tok, c+1);
	}

	return 0;
}

static char* _get_json_key_value(char *buf, char *key, jsmntok_t* tok, int tokc)
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
			printf ("ERROR: json does not have 'key' string\n");
			return NULL;
		}
	}
	return NULL;
}

static void _add_pending_step(void *data, char *buf, jsmntok_t *tok, int c)
{
	int n = (tok+c)->end - (tok+c)->start;
	int tokc, ret;
	char *s = malloc (sizeof (char) * n+2);
	char *value = NULL;
	systemc_state **state = (systemc_state **) data;
	jsmntok_t **key = NULL;
	jsmntok_t *tokv = NULL;

	buf[n+1]=0;
	strncpy(s, buf + (tok+c)->start, n+2);

	while (*state) {
		printf("%s():%d\n", __func__, __LINE__);
		state++;
	}
	
	printf("%s():%d -- s=%s\n", __func__, __LINE__, s);
	ret = jsmnutil_parse_json (s, &tokv, &tokc);
	printf("%s():%d\n", __func__, __LINE__);
	key = jsmnutil_get_object_keys(s, tokv);
	while (*key) {
		if (!strncmp("state", s+(*key)->start, strlen("state"))) {
			int n = (*key+1)->end - (*key+1)->start;
			value = malloc(n + 1);
			strncpy(value, s+(*key+1)->start, n);
			value[n] = '\0';
			printf("SYSTEMC:TRAIL Adding step = '%s'\n", value);
			break;
		}
		key++;
	}
		
	printf("%s():%d\n", __func__, __LINE__);
	// external -- this has to match allocated size
	*state = trail_parse_state(value, strlen(value));
	printf("%s():%d added to state=0x%08lx, rev=%d\n", __func__, __LINE__, (*state), (*state)->rev);
	if (value)
		free(value);

	free(s);
}

static systemc_state* _pending_get_first(systemc_state **p)
{
	int min;
	systemc_state *r;

	if (*p == NULL)
		return NULL;

	min = (*p)->rev;
	r = *p;

	printf("p=0x%08lx, r=0x%08lx, max=%d\n", p, r, r->rev);
	while (*p) {
		printf("   p=0x%08lx\n", *p);
		if ((*p)->rev < min) {
			min = (*p)->rev;
			r = *p;
		}
		p++;	
	}

	printf("p=0x%08lx *p=0x%08lx r=0x%08lx\n", p, *p, r);
	printf("pending rev=%d\n", r->rev);
	return r;
}

// FIXME: Make it download trail states each -- add to state array
static int trail_get_new_steps(struct trail_remote *r)
{
	trest_request_ptr req;
	trest_response_ptr res;
	int size;
	systemc_state **steps; 

	if (!r)
		return -1;

	req = trest_make_request(TREST_METHOD_GET,
				 r->endpoint,
				 0, 0, 0);

	res = trest_do_json_request(r->client, req);

	if (!res) {
		printf("SYSTEMC: TRAIL: Unable to do trail request\n");
		size = -1;
		goto out;
	}

	size = jsmnutil_array_count(res->body, res->json_tokv);
	printf("SYSTEMC: TRAIL: Steps found in NEW state = '%d'\n", size);

	if (!size)
		goto out;

	steps = malloc(sizeof (systemc_state*) * size + 1);
	memset(steps, 0, sizeof(systemc_state*) * size);
        _iterate_json_array (res->body, res->json_tokv, 0,
			    (token_iter_f) _add_pending_step, steps);
	steps[size] = NULL;

	printf("%s():%d size\n", __func__, __LINE__);
	r->pending = _pending_get_first(steps);
	printf("%s():%d\n", __func__, __LINE__);

	// free all but pending
	printf("%s():%d\n", __func__, __LINE__);
	while (*steps) {
		if (*steps != r->pending) {
			trail_state_free(*steps);
		}
		steps++;
	}

	printf("SYSTEM: TRAIL: First pending found to be rev = %d\n", r->pending->rev);

out:
	if (req)
		free(req);
	if (res)
		free(res);

	return size;
}


static int trail_is_available(struct trail_remote *r)
{
	trest_request_ptr req;
	trest_response_ptr res;
	int size = 0;

	if (!r)
		return -1;

	printf("%s():%d\n", __func__, __LINE__);
	req = trest_make_request(TREST_METHOD_GET,
				 "/api/trails/",
				 0, 0, 0);

	printf("%s():%d\n", __func__, __LINE__);
	res = trest_do_json_request(r->client, req);

	printf("%s():%d\n", __func__, __LINE__);
	if (!res) {
		printf("SYSTEMC: TRAIL: Unable to do trail request\n");
		size = -1;
		goto out;
	}

	printf("%s():%d\n", __func__, __LINE__);
	size = jsmnutil_array_count(res->body, res->json_tokv);
	if (size)
		printf("SYSTEMC: TRAIL: Trail found, using remote\n");

	printf("%s():%d\n", __func__, __LINE__);
out:
	if (req)
		free(req);
	if (res)
		free(res);

	printf("%s():%d\n", __func__, __LINE__);
	return size;
}

static int trail_first_boot(struct systemc *sc)
{
	int ret;
	trest_request_ptr req;
	trest_response_ptr res;
	trest_auth_status_enum status = TREST_AUTH_STATUS_NOTAUTH;

	printf("%s():%d\n", __func__, __LINE__);
	status = trest_update_auth(sc->remote->client);
	if (status != TREST_AUTH_STATUS_OK) {
		printf("Authorization expired, exit\n");
		return -1;
	}

	printf("%s():%d\n", __func__, __LINE__);
	req = trest_make_request(TREST_METHOD_POST, "/api/trails/", 0, 0, sc->step);
	res = trest_do_json_request(sc->remote->client, req);	

	printf("%s():%d\n", __func__, __LINE__);
	if (!res) {
		printf("SYSTEMC: TRAIL: Unable to push initial trail on first boot\n");
		ret = -1;
		goto out;
	}
	printf("SYSTEMC: TRAIL: Initial trail pushed OK\n");
	printf("SYSTEMC: Response: \n\n'%s'\n\n", res->body);
	ret = 0;

out:
	sleep(5);
	if (req)
		free(req);
	if (res)
		free(res);

	return ret;
}

static int trail_remote_init(struct systemc *sc)
{
	struct trail_remote *remote = NULL;
	trest_auth_status_enum status = TREST_AUTH_STATUS_NOTAUTH;
	trest_ptr client;

	printf("%s():%d\n", __func__, __LINE__);
	// Make sure values are reasonable
	if ((strcmp(sc->config->creds.id, "") == 0) ||
	    (strcmp(sc->config->creds.abrn, "") == 0))
		return 0;

	printf("%s():%d\n", __func__, __LINE__);
	// Create client
	client = trest_new_from_userpass(
		sc->config->creds.host,
		sc->config->creds.port,
		sc->config->creds.abrn,
		sc->config->creds.secret
		);

	printf("%s():%d\n", __func__, __LINE__);
	if (!client) {
		printf("SYSTEMC: TRAIL: Unable to create device client\n");
		goto err;
	}

	printf("%s():%d\n", __func__, __LINE__);
	status = trest_update_auth(client);
	if (status != TREST_AUTH_STATUS_OK) {
		printf("SYSTEMC: TRAIL: Unable to auth device client\n");
		goto err;
	}

	printf("%s():%d\n", __func__, __LINE__);
	remote = malloc(sizeof(struct trail_remote));
	remote->client = client;
	remote->endpoint = malloc((sizeof(DEVICE_TRAIL_ENDPOINT_FMT)
				   + strlen(sc->config->creds.id)) * sizeof(char));
	sprintf(remote->endpoint, DEVICE_TRAIL_ENDPOINT_FMT, sc->config->creds.id);	
	printf("%s():%d\n", __func__, __LINE__);

	sc->remote = remote;

	printf("%s():%d\n", __func__, __LINE__);
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
	printf("%s():%d\n", __func__, __LINE__);
	if (!sc->remote)
		trail_remote_init(sc);
	
	printf("%s():%d\n", __func__, __LINE__);
	if (!trail_is_available(sc->remote))
		return trail_first_boot(sc);
	else
		return trail_get_new_steps(sc->remote);
}

static int trail_remote_queue(struct systemc *sc)
{
	int ret = 0;
	struct sc_update *u = sc->update;
	trest_request_ptr req;
	trest_response_ptr res;

	printf("%s():%d\n", __func__, __LINE__);
	req = trest_make_request(TREST_METHOD_PUT,
				 u->endpoint,
				 0, 0,
				 "{ \"status\" : \"QUEUED\" }");

	printf("%s():%d\n", __func__, __LINE__);
	res = trest_do_json_request(sc->remote->client, req);

	printf("%s():%d\n", __func__, __LINE__);
	if (!res) {
		printf("SYSTEMC: TRAIL: Unable to do trail request\n");
		ret = -1;
		goto out;
	}

	printf("RESPONSE: body=%s\n", res->body);
	printf("%s():%d\n", __func__, __LINE__);

out:
	return ret;
}

static int trail_remote_finish(struct systemc *sc)
{
	int ret = 0;
	struct sc_update *u = sc->update;
	trest_request_ptr req;
	trest_response_ptr res;

	req = trest_make_request(TREST_METHOD_PUT,
				 u->endpoint,
				 0, 0,
				 "{ \"status\" : \"DONE\" }");

	res = trest_do_json_request(sc->remote->client, req);

	if (!res) {
		printf("SYSTEMC: TRAIL: Unable to do trail request\n");
		ret = -1;
		goto out;
	}

	u->status = UPDATE_QUEUED;
	printf("RESPONSE: body=%s\n", res->body);

out:
	return ret;
}

int sc_trail_update_start(struct systemc *sc)
{
	int l = 0, c = 0;
	int ret = 0;
	struct sc_update *u = malloc(sizeof(struct sc_update));
	
	printf("%s():%d\n", __func__, __LINE__);
	u->pending = sc->remote->pending;
	
	// to construct endpoint
	l = u->pending->rev;
	while (l) {
		l /= 10;
		c++;
	}
	c++;
	
	printf("%s():%d\n", __func__, __LINE__);
	u->endpoint = malloc((sizeof(DEVICE_STEP_ENDPOINT_FMT)
		          + (strlen(sc->config->creds.id)) + c) * sizeof(char));
	sprintf(u->endpoint, DEVICE_STEP_ENDPOINT_FMT, sc->config->creds.id, l);

	sc->update = u;

	printf("%s():%d\n", __func__, __LINE__);
	ret = trail_remote_queue(sc);
	if (ret < 0) {
		printf("SYSTEMC: TRAIL: Failed to queue update\n");
		return -1;
	}

	printf("%s():%d\n", __func__, __LINE__);
	// FIXME: commit state to disk for reboot and friends
	// commit();

	printf("%s():%d\n", __func__, __LINE__);

	return 0;
}

int sc_trail_update_finish(struct systemc *sc)
{
	int ret;

	switch (sc->update->status) {
	case UPDATE_DONE:
		ret = trail_remote_finish(sc);
		if (ret < 0) {
			printf("SYSTEMC: TRAIL: Unable to post completion, keep alive\n");
		}
		break;
	case UPDATE_FAILED:
		printf("SYSTEMC: TRAIL: Update failed, error\n");
	default:
		ret = -1;
		goto out;
		break;
	}

	free(sc->update);
	sc->update = NULL;

out:
	free(sc->update->endpoint);
	return ret;
}

int sc_trail_update_install(struct systemc *sc)
{
	printf("%s():%d\n", __func__, __LINE__);
	if (!sc->remote)
		trail_remote_init(sc);

	printf("%s():%d\n", __func__, __LINE__);
	printf("SYSTEMC: TRAIL: Applying update...\n");

	// FIXME: Commit to server before stepping to new step, otherwise wait

	// diff and info from on-disk to new trail
	// download new objects
	// place on disk structure
	// return new-rev	
	
	return 0;
}

void sc_trail_remote_destroy(struct systemc *sc)
{
	if (!sc->remote)
		return;

	free(sc->remote->client);
	free(sc->remote->endpoint);
	free(sc->remote);
}

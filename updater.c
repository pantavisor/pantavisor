#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <jsmn/jsmnutil.h>

#include "updater.h"

static int trail_get_new_steps(struct trail_remote *r)
{
	trest_request_ptr req;
	trest_response_ptr res;
	int size = 0;

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

	req = trest_make_request(TREST_METHOD_GET,
				 "/api/trails/",
				 0, 0, 0);

	res = trest_do_json_request(r->client, req);

	if (!res) {
		printf("SYSTEMC: TRAIL: Unable to do trail request\n");
		size = -1;
		goto out;
	}

	size = jsmnutil_array_count(res->body, res->json_tokv);
	if (size)
		printf("SYSTEMC: TRAIL: Trail found, using remote\n");

out:
	if (req)
		free(req);
	if (res)
		free(res);

	return size;
}

struct trest_request {
        int type;
        int method;

        char *endpoint_path;
        char **queries;
        char **headers;
        char *json_body;
};


static int trail_first_boot(struct systemc *sc)
{
	int ret;
	trest_request_ptr req;
	trest_response_ptr res;
	trest_auth_status_enum status = TREST_AUTH_STATUS_NOTAUTH;

	status = trest_update_auth(sc->remote->client);
	if (status != TREST_AUTH_STATUS_OK) {
		printf("Authorization expired, exit\n");
		return -1;
	}

	req = trest_make_request(TREST_METHOD_POST, "/api/trails/", 0, 0, sc->step);
	res = trest_do_json_request(sc->remote->client, req);	

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
		printf("SYSTEMC: TRAIL: Unable to create device client\n");
		goto err;
	}

	status = trest_update_auth(client);
	if (status != TREST_AUTH_STATUS_OK) {
		printf("SYSTEMC: TRAIL: Unable to auth device client\n");
		goto err;
	}

	remote = malloc(sizeof(struct trail_remote));
	remote->endpoint = malloc((sizeof(DEVICE_TRAIL_ENDPOINT_FMT)
				   + strlen(sc->config->creds.id)) * sizeof(char));
	remote->client = client;
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
	if (!sc->remote)
		trail_remote_init(sc);
	
	if (!trail_is_available(sc->remote))
		return trail_first_boot(sc);
	else
		return trail_get_new_steps(sc->remote);
}

int sc_trail_do_update(struct systemc *sc)
{
	printf("%s():%d\n", __func__, __LINE__);
	if (!sc->remote)
		trail_remote_init(sc);

	printf("%s():%d\n", __func__, __LINE__);
	printf("SYSTEMC: TRAIL: Applying update...\n");

	// diff and info from on-disk to new trail
	// download new objects
	// place on disk structure
	// return new-rev	
	
	return sc->state->rev;
}

void sc_trail_remote_destroy(struct systemc *sc)
{
	if (!sc->remote)
		return;

	free(sc->remote->client);
	free(sc->remote->endpoint);
	free(sc->remote);
}

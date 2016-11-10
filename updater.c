#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <jsmn/jsmnutil.h>

#include "updater.h"

static int trail_get_size(struct trail_remote *r)
{
	trest_request_ptr req;
	trest_response_ptr res;
	int size = 0;

	req = trest_make_request(TREST_METHOD_GET,
				 r->endpoint,
				 0, 0, 0);

	res = trest_do_json_request(r->client, req);

	if (!res) {
		printf("SYSTEMC: TRAIL: Unable get trail size\n");
		size = -1;
		goto out;
	}

	size = jsmnutil_array_count(res->body, res->json_tokv);
	printf("SYSTEMC: TRAIL: Remote trail size = '%d'\n", size);

out:
	if (req)
		free(req);
	if (res)
		free(res);

	return size;
}

static int trail_first_boot(struct trail_remote *r)
{
	printf("SYSTEMC: TRAIL: Initial trail first boot DO_PUSH()\n");

	sleep(5);

	return 0;
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
	printf("%s():%d\n", __func__, __LINE__);
	if (status != TREST_AUTH_STATUS_OK) {
		printf("SYSTEMC: TRAIL: Unable to auth device client\n");
		goto err;
	}
	printf("%s():%d\n", __func__, __LINE__);

	remote = malloc(sizeof(struct trail_remote));
	printf("%s():%d\n", __func__, __LINE__);
	remote->endpoint = malloc((sizeof(DEVICE_TRAIL_ENDPOINT_FMT)
				   + strlen(sc->config->creds.id)) * sizeof(char));
	printf("%s():%d\n", __func__, __LINE__);
	remote->client = client;
	printf("%s():%d\n", __func__, __LINE__);
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
	int ret;

	printf("%s():%d\n", __func__, __LINE__);
	if (!sc->remote)
		trail_remote_init(sc);

	printf("%s():%d\n", __func__, __LINE__);
	ret = trail_get_size(sc->remote);
	if (ret == 0) {
		return trail_first_boot(sc->remote);
	} else {
		return ret;
	}
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

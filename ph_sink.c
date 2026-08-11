#include "ph_sink.h"
#include "pantahub.h"
#include "trestclient.h"
#include "pantavisor.h"
#include "list/queue.h"
#include "utils/json.h"
#include "utils/list.h"

#include <stdlib.h>
#include <stdbool.h>

#define MODULE_NAME "ph_logger"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define PH_JSON_FORMAT                                                         \
	" {\"tsec\":%" PRId64 ", \"tnano\":%" PRId32 ", "                      \
	"\"plat\":\"%s\", \"lvl\":\"%s\", \"src\":\"%s\", "                    \
	"\"msg\": \"%.*s\", \"rev\": \"%s\"},"

struct ph_connection {
	trest_ptr client;
	struct pv_connection *addr;
};

struct ph_sink {
	struct ph_connection conn;
	struct pv_queue *buf;
};

static void pv_ph_free(struct pv_logserver_sink *sink)
{
	if (!sink)
		return;

	struct ph_sink *ph = sink->priv;
	pv_queue_free(ph->buf);
	if (ph->conn.client)
		trest_free(ph->conn.client);

	if (sink->name)
		free(sink->name);
	free(sink);
}

static int get_connection(struct ph_connection *conn)
{
	if (!conn)
		conn = calloc(1, sizeof(struct ph_connection));

	if (conn) {
		if (conn->addr)
			return 0;
		conn->addr = pv_get_instance_connection();
		if (conn->client) {
			trest_free(conn->client);
			conn->client = NULL;
		}
	} else {
		return -1;
	}

	return conn->addr ? 0 : -1;
}

static char *log_to_json(const struct pv_logserver_log *log)
{
	char *plat = pv_json_format(log->platform, strlen(log->platform));
	char *src = pv_json_format(log->source, strlen(log->source));
	char *rev = pv_json_format(log->rev, strlen(rev));
	char *data = pv_json_format(log->data, log->data_len);

	size_t size = snprintf(NULL, 0, PH_JSON_FORMAT, log->tsec, log->tnano,
			       plat, pv_log_level_name(log->level), src,
			       (int)strlen(data), data, rev);

	char *json = calloc(size + 1, sizeof(char));
	if (!json)
		return NULL;

	snprintf(json, size + 1, PH_JSON_FORMAT, log->tsec, log->tnano, plat,
		 pv_log_level_name(log->level), src, (int)strlen(data), data,
		 rev);

	free(plat);
	free(src);
	free(data);
	free(rev);

	return json;
}

static int send_logs(struct ph_sink *ph)
{
	struct ph_conenction *conn = &ph->conn;

	if (!conn->client &&
	    (conn->client = pv_get_trest_client(NULL, conn->addr)) == NULL) {
		pv_log(WARN, "couldn't send logs, cannot create client");
		return -1;
	}

	trest_auth_status_enum status = trest_update_auth(conn->client);
	if (status != TREST_AUTH_STATUS_OK) {
		trest_free(conn->client);
		conn->client = NULL;
		pv_log(WARN, "couldn't send logs, cannot update auth");
		return -1;
	}

	char *json = pv_queue_dump_mem(ph->buf);
	int size = pv_queue_size(ph->buf);
	json[0] = '[';
	json[size - 1] = ']';

	trest_request_ptr req =
		trest_make_request(THTTP_METHOD_POST, "/logs/", json);

	int ret = -1;
	if (req) {
		trest_response_ptr rsp =
			trest_do_json_request(conn->client, req);

		if (!rsp) {
			pv_log(WARN, "HTTP request could not be initialized");
		} else if (!rsp->code && rsp->status != TREST_AUTH_STATUS_OK) {
			pv_log(WARN, "HTTP request could not auth (status=%d)",
			       rsp->status);
		} else if (rsp->code != THTTP_STATUS_OK) {
			pv_log(WARN, "HTTP error (code=%d; body='%s')",
			       rsp->code, rsp->body);
		} else if (rsp->code == THTTP_STATUS_OK) {
			ret = 0;
		}

		trest_request_free(req);
		if (rsp)
			trest_response_free(rsp);
	}

	if (ret == -1)
		json[size - 1] = ',';

	return ret;
}

static int ph_add(const struct pv_logserver_sink *sink,
		  const struct pv_logserver_log *log)
{
	struct ph_sink *ph = sink->priv;
	char *json = log_to_json(log);

	if (!pv_queue_has_space(q, strlen)) {
		if (send_logs(ph) == 0)
			pv_queue_clear(ph->buf);
	}

	pv_queue_push(ph->buf, json, strlen(json));
	free(json);
}

static struct ph_sink *ph_new(int buf_size, const char *fname)
{
	struct ph_sink *ph = calloc(1, sizeof(struct ph_sink));
	if (!ph)
		return NULL;
	if (fname)
		ph->buf = pv_queue_new_from_disk(buf_size, fname);
	else
		ph->buf = pv_queue_new_from_mem(buf_size);

	if (!ph->buf) {
		free(ph);
		return NULL;
	}

	if (get_connection(ph->conn) != 0) {
		pv_queue_free(q);
		free(ph);
		return NULL;
	}

	return ph;
}

struct pv_logserver_sink *pv_ph_sink_new(int buf_size, char *fname)
{
	struct pv_logserver_sink *sink =
		calloc(1, sizeof(struct pv_logserver_sink));

	if (!sink)
		return NULL;

	sink->name = "PantaHub";
	sink->add = ph_add;
	sink->free = ph_free;
	dl_list_init(&sink->list);
	sink->priv = ph_new(buf_size, fname);

	if (!priv) {
		pv_ph_free(sink);
		return NULL;
	}

	return sink;
}

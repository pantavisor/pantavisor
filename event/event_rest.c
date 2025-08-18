/*
 * Copyright (c) 2025 Pantacor Ltd.
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
#include <dirent.h>
#include <string.h>

#include <event2/bufferevent_ssl.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/http.h>

#include <mbedtls/error.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#include "event_rest.h"

#include "event.h"
#include "paths.h"

#include "utils/str.h"

#define MODULE_NAME "event_rest"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

static mbedtls_x509_crt cacert;
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_entropy_context entropy;
static mbedtls_ssl_config config;

int pv_event_rest_init(void)
{
	mbedtls_x509_crt_init(&cacert);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);
	mbedtls_ssl_config_init(&config);

	mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
			      (const unsigned char *)"pantavisor",
			      sizeof("pantavisor"));
	mbedtls_ssl_config_defaults(&config, MBEDTLS_SSL_IS_CLIENT,
				    MBEDTLS_SSL_TRANSPORT_STREAM,
				    MBEDTLS_SSL_PRESET_DEFAULT);
	mbedtls_ssl_conf_rng(&config, mbedtls_ctr_drbg_random, &ctr_drbg);

	char path[PATH_MAX];
	pv_paths_cert(path, PATH_MAX, "");

	mbedtls_ssl_conf_authmode(&config, MBEDTLS_SSL_VERIFY_NONE);
	int res;
	res = mbedtls_x509_crt_parse_path(&cacert, path);
	if (res != 0) {
		pv_log(ERROR, "mbedtls_x509_crt_parse_file returned code %d",
		       res);
		pv_event_rest_cleanup();
		return -1;
	}
	mbedtls_ssl_conf_ca_chain(&config, &cacert, NULL);

	pv_log(DEBUG, "HTTP REST initialized");

	return 0;
}

void pv_event_rest_cleanup(void)
{
	mbedtls_x509_crt_free(&cacert);
	mbedtls_ssl_config_free(&config);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	pv_log(DEBUG, "HTTP REST cleaned up");
}

static const char *_op_string(enum evhttp_cmd_type op)
{
	switch (op) {
	case EVHTTP_REQ_GET:
		return "GET";
	case EVHTTP_REQ_POST:
		return "POST";
	case EVHTTP_REQ_HEAD:
		return "HEAD";
	case EVHTTP_REQ_PUT:
		return "PUT";
	case EVHTTP_REQ_DELETE:
		return "DELETE";
	case EVHTTP_REQ_OPTIONS:
		return "OPTIONS";
	case EVHTTP_REQ_TRACE:
		return "TRACE";
	case EVHTTP_REQ_CONNECT:
		return "CONNECT";
	case EVHTTP_REQ_PATCH:
		return "PATCH";
	default:
		return "UNKNOWN";
	}

	return "UNKNOWN";
}

// event_rest super verbose logging to inspect HTTP protocol
static void _debug_log(int level, const char *fmt, ...)
{
	if (!pv_config_get_bool(PV_LIBEVENT_DEBUG_MODE))
		return;

	va_list args;
	va_start(args, fmt);

	char *msg = NULL;
	int n = vasprintf(&msg, fmt, args);
	va_end(args);

	if (n < 0) {
		free(msg);
		goto out;
	}

	pv_log(level, "%s", msg);

out:
	if (msg)
		free(msg);
}

static void _add_header(struct evkeyvalq *output_headers, const char *key,
			const char *value)
{
	_debug_log(DEBUG, "%s: %s", key, value);
	evhttp_add_header(output_headers, key, value);
}

static void _print_error_cb(enum evhttp_request_error error, void *mbedtls_ctx)
{
	switch (error) {
	case EVREQ_HTTP_TIMEOUT:
		pv_log(WARN, "timeout reached");
		break;
	case EVREQ_HTTP_EOF:
		pv_log(WARN, "EOF reached");
		break;
	case EVREQ_HTTP_INVALID_HEADER:
		pv_log(WARN, "error while reading header or invalid header");
		break;
	case EVREQ_HTTP_BUFFER_ERROR:
		pv_log(WARN, "error encountered while reading or writing");
		break;
	case EVREQ_HTTP_REQUEST_CANCEL:
		pv_log(WARN, "evhttp_cancel_request() called on this request");
		break;
	case EVREQ_HTTP_DATA_TOO_LONG:
		pv_log(WARN,
		       "body is greated than evhttp_connection_set_max_body_size()");
		break;
	default:
		pv_log(WARN, "libevent returned an unknown error %d", error);
		break;
	}
}

int pv_event_rest_send(enum evhttp_cmd_type op, const char *uri,
		       const char *token, const char *body,
		       void (*cb)(struct evhttp_request *, void *))
{
	if (!pv_event_get_base())
		return -1;

	_debug_log(DEBUG, "%s %s HTTP/1.1", _op_string(op), uri);

	mbedtls_dyncontext *ssl;
	ssl = bufferevent_mbedtls_dyncontext_new(&config);

	char *host = pv_config_get_str(PH_CREDS_HOST);
	mbedtls_ssl_set_hostname(ssl, host);

	struct bufferevent *bev;
	bev = bufferevent_mbedtls_socket_new(
		pv_event_get_base(), -1, ssl, BUFFEREVENT_SSL_CONNECTING,
		BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	if (!bev) {
		pv_log(ERROR, "bufferevent_mbedtls_socket_new failed");
		goto error;
	}

	bufferevent_mbedtls_set_allow_dirty_shutdown(bev, 1);

	int port = pv_config_get_int(PH_CREDS_PORT);
	struct evhttp_connection *evcon;
	evcon = evhttp_connection_base_bufferevent_new(pv_event_get_base(),
						       NULL, bev, host, port);
	if (!evcon) {
		pv_log(ERROR, "evhttp_connection_base_bufferevent_new failed");
		goto error;
	}

	// libevent will manage its resourcess so we only have to free our own context
	evhttp_connection_free_on_completion(evcon);

	evhttp_connection_set_family(evcon, AF_INET);

	int retries = pv_config_get_int(PH_LIBEVENT_HTTP_RETRIES);
	evhttp_connection_set_retries(evcon, retries);

	int timeout = pv_config_get_int(PH_LIBEVENT_HTTP_TIMEOUT);
	evhttp_connection_set_timeout(evcon, timeout);

	const struct timeval time = { timeout, 0 };
	evhttp_connection_set_timeout_tv(evcon, &time);
	evhttp_connection_set_connect_timeout_tv(evcon, &time);
	evhttp_connection_set_read_timeout_tv(evcon, &time);
	evhttp_connection_set_write_timeout_tv(evcon, &time);

	struct evhttp_request *req;
	req = evhttp_request_new(cb, bev);
	if (!req) {
		pv_log(ERROR, "evhttp_request_new failed");
		goto error;
	}

	evhttp_request_set_error_cb(req, _print_error_cb);

	struct evkeyvalq *output_headers;
	output_headers = evhttp_request_get_output_headers(req);

	_add_header(output_headers, "Host", host);
	_add_header(output_headers, "Connection", "close");
	_add_header(output_headers, "User-Agent", pv_user_agent);

	if (token) {
		char bearer[1024];
		memset(bearer, 0, sizeof(bearer));
		snprintf(bearer, sizeof(bearer), "Bearer %s", token);

		_add_header(output_headers, "Authorization", bearer);
	}

	if (body) {
		size_t len = strlen(body);
		_debug_log(DEBUG, "");
		_debug_log(DEBUG, "%s", body);

		struct evbuffer *output_buffer;
		output_buffer = evhttp_request_get_output_buffer(req);
		evbuffer_add(output_buffer, body, len);

		char buf[64];
		evutil_snprintf(buf, sizeof(buf) - 1, "%zu", len);
		_add_header(output_headers, "Content-Length", buf);
		_add_header(output_headers, "Content-Type", "application/json");
	}

	int res;
	res = evhttp_make_request(evcon, req, op, uri);
	if (res != 0) {
		pv_log(ERROR, "evhttp_make_request returned code %d", res);
		goto error;
	}

	pv_log(DEBUG, "add event: type='rest' cb=%p req='%s %s HTTP/1.1'",
	       (void *)cb, _op_string(op), uri);

	return 0;
error:
	// this should free bev, evcon and ssl
	if (evcon)
		evhttp_connection_free(evcon);

	return -1;
}

int pv_event_rest_recv(struct evhttp_request *req, void *ctx, char **buf,
		       size_t max_len)
{
	int ret = -1;

	struct bufferevent *bev = (struct bufferevent *)ctx;
	if (!bev) {
		pv_log(WARN, "response got no buffer event");
		return ret;
	}

	if (!req || !evhttp_request_get_response_code(req)) {
		unsigned long oslerr;
		int printed_err = 0;
		int errcode = EVUTIL_SOCKET_ERROR();

		pv_log(WARN, "request failed");
		while ((oslerr = bufferevent_get_mbedtls_error(bev))) {
			pv_log(WARN,
			       "bufferevent_get_mbedtls_error returned code %d",
			       oslerr);
			printed_err = 1;
		}
		if (!printed_err)
			pv_log(WARN, "socket error %d: %s", errcode,
			       evutil_socket_error_to_string(errcode));
		goto out;
	}

	ret = evhttp_request_get_response_code(req);
	_debug_log(DEBUG, "HTTP/1.1 %d %s", ret,
		   evhttp_request_get_response_code_line(req));

	struct evbuffer *evbuf;
	evbuf = evhttp_request_get_input_buffer(req);

	size_t to_read;
	to_read = evbuffer_get_length(evbuf);
	if (to_read > max_len) {
		pv_log(WARN, "body length %zu bigger than max allowed %zu",
		       to_read, max_len);
		goto out;
	}

	char *tmp;
	tmp = calloc(to_read + 1, sizeof(char));
	if (!tmp)
		goto out;

	*buf = tmp;

	int nread = 0, i = 0;
	while ((nread = evbuffer_remove(evbuf, tmp, max_len - i)) > 0) {
		tmp += nread;
		i += nread;
	}

	_debug_log(DEBUG, "");
	_debug_log(DEBUG, "%s", buf);

out:

	return ret;
}

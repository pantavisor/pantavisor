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

#include "pantahub/pantahub_rest.h"

#include "paths.h"

#define MODULE_NAME "pantahub_rest"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

typedef struct {
	struct bufferevent *bev;
	struct evhttp_connection *evcon;
	mbedtls_dyncontext *ssl;
	mbedtls_ssl_config config;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;
	mbedtls_x509_crt cacert;
} mbedtls_ctx_t;

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

const char **_get_certs()
{
	struct dirent **files;
	char **cafiles;
	char path[PATH_MAX];
	int n = 0, i = 0, size = 0;

	pv_paths_cert(path, PATH_MAX, "");
	n = scandir(path, &files, NULL, alphasort);
	if (n < 0) {
		pv_log(WARN, "%s could not be scanned", path);
		return NULL;
	} else if (n == 0) {
		pv_log(WARN, "%s is empty", path);
		free(files);
		return NULL;
	}

	// Always n-1 due to . and .., and need one extra
	cafiles = calloc(n - 1, sizeof(char *));

	while (n--) {
		if (!strncmp(files[n]->d_name, ".", 1)) {
			free(files[n]);
			continue;
		}

		pv_paths_cert(path, PATH_MAX, files[n]->d_name);
		size = strlen(path);
		cafiles[i] = malloc((size + 1) * sizeof(char));
		memcpy(cafiles[i], path, size);
		cafiles[i][size] = '\0';
		i++;
		free(files[n]);
	}

	free(files);

	return (const char **)cafiles;
}

static void _add_header(struct evkeyvalq *output_headers, const char *key,
			const char *value)
{
	pv_log(TRACE, "%s: %s", key, value);
	evhttp_add_header(output_headers, key, value);
}

int pv_pantahub_rest_send(struct event_base *base, enum evhttp_cmd_type op,
			  const char *uri, const char *token, const char *body,
			  void (*cb)(struct evhttp_request *, void *))
{
	mbedtls_ctx_t *ctx = calloc(1, sizeof(mbedtls_ctx_t));
	if (!ctx)
		return -1;

	pv_log(TRACE, "%s %s HTTP/1.1", _op_string(op), uri);

	ctx->ssl = NULL;
	mbedtls_x509_crt_init(&ctx->cacert);
	mbedtls_ctr_drbg_init(&ctx->ctr_drbg);
	mbedtls_entropy_init(&ctx->entropy);
	mbedtls_ssl_config_init(&ctx->config);

	mbedtls_ctr_drbg_seed(&ctx->ctr_drbg, mbedtls_entropy_func,
			      &ctx->entropy,
			      (const unsigned char *)"pantavisor",
			      sizeof("pantavisor"));
	mbedtls_ssl_config_defaults(&ctx->config, MBEDTLS_SSL_IS_CLIENT,
				    MBEDTLS_SSL_TRANSPORT_STREAM,
				    MBEDTLS_SSL_PRESET_DEFAULT);
	mbedtls_ssl_conf_rng(&ctx->config, mbedtls_ctr_drbg_random,
			     &ctx->ctr_drbg);

	const char **crts = _get_certs();
	int res;
	res = mbedtls_x509_crt_parse_file(&ctx->cacert, *crts);
	if (res != 0) {
		pv_log(ERROR, "mbedtls_x509_crt_parse_file returned code %d",
		       res);
		goto error;
	}
	mbedtls_ssl_conf_ca_chain(&ctx->config, &ctx->cacert, NULL);

	ctx->ssl = bufferevent_mbedtls_dyncontext_new(&ctx->config);

	char *host = pv_config_get_str(PH_CREDS_HOST);
	mbedtls_ssl_set_hostname(ctx->ssl, host);

	ctx->bev = bufferevent_mbedtls_socket_new(
		base, -1, ctx->ssl, BUFFEREVENT_SSL_CONNECTING,
		BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	if (!ctx->bev) {
		pv_log(ERROR, "bufferevent_mbedtls_socket_new failed");
		goto error;
	}

	bufferevent_mbedtls_set_allow_dirty_shutdown(ctx->bev, 1);

	int port = pv_config_get_int(PH_CREDS_PORT);
	ctx->evcon = evhttp_connection_base_bufferevent_new(
		base, NULL, ctx->bev, host, port);
	if (!ctx->evcon) {
		pv_log(ERROR, "evhttp_connection_base_bufferevent_new failed");
		goto error;
	}
	evhttp_connection_set_family(ctx->evcon, AF_INET);

	int retries = pv_config_get_int(PH_HTTP_RETRIES);
	evhttp_connection_set_retries(ctx->evcon, retries);

	int timeout = pv_config_get_int(PH_HTTP_TIMEOUT);
	evhttp_connection_set_timeout(ctx->evcon, timeout);

	struct evhttp_request *req;
	req = evhttp_request_new(cb, ctx);
	if (!req) {
		pv_log(ERROR, "evhttp_request_new failed");
		goto error;
	}

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
		pv_log(TRACE, "");
		pv_log(TRACE, "%s", body);

		struct evbuffer *output_buffer;
		output_buffer = evhttp_request_get_output_buffer(req);
		evbuffer_add(output_buffer, body, len);

		char buf[64];
		evutil_snprintf(buf, sizeof(buf) - 1, "%zu", len);
		_add_header(output_headers, "Content-Length", buf);
		_add_header(output_headers, "Content-Type", "application/json");
	}

	res = evhttp_make_request(ctx->evcon, req, op, uri);
	if (res != 0) {
		pv_log(ERROR, "evhttp_make_request returned code %d", res);
		goto error;
	}

	return 0;
error:
	if (ctx->evcon)
		evhttp_connection_free(ctx->evcon);
	mbedtls_ssl_config_free(&ctx->config);
	mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
	mbedtls_x509_crt_free(&ctx->cacert);
	free(ctx);

	return -1;
}

int pv_pantahub_rest_recv(struct evhttp_request *req, void *mbedtls_ctx,
			  char *out, int max_len)
{
	int ret = -1;

	mbedtls_ctx_t *ctx = (mbedtls_ctx_t *)mbedtls_ctx;
	if (!ctx) {
		pv_log(WARN, "response got no context");
		return ret;
	}

	if (!req || !evhttp_request_get_response_code(req)) {
		unsigned long oslerr;
		int printed_err = 0;
		int errcode = EVUTIL_SOCKET_ERROR();

		pv_log(WARN, "request failed");
		while ((oslerr = bufferevent_get_mbedtls_error(ctx->bev))) {
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
	pv_log(TRACE, "HTTP/1.1 %d %s", ret,
	       evhttp_request_get_response_code_line(req));

	int nread = 0, i = 0;
	while ((nread = evbuffer_remove(evhttp_request_get_input_buffer(req),
					out, max_len - i)) > 0) {
		out += nread;
		i += nread;
	}

out:
	if (ctx->evcon)
		evhttp_connection_free(ctx->evcon);
	mbedtls_ssl_config_free(&ctx->config);
	mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
	mbedtls_x509_crt_free(&ctx->cacert);
	//free(ctx);

	return ret;
}

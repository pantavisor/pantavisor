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
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

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

#include "event/event_rest.h"
#include "event/event.h"

#include "config.h"
#include "metadata.h"
#include "pantavisor.h"
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

static void _print_error_cb(enum evhttp_request_error error, void *ctx)
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

#include <arpa/inet.h>

static int _header_cb(struct evhttp_request *req, void *ctx)
{
	struct evhttp_connection *evcon;
	const struct sockaddr *sa;
	struct sockaddr_in6 *addr_in6;
	struct sockaddr_in *addr_in;
	char ip[INET6_ADDRSTRLEN];
	char addr[64];
	int port;

	if (!req)
		return 0;

	evcon = evhttp_request_get_connection(req);
	if (!evcon) {
		pv_log(WARN, "could not retreive connection");
		return 0;
	}

	sa = evhttp_connection_get_addr(evcon);

	if (sa->sa_family == AF_INET) {
		addr_in = (struct sockaddr_in *)sa;
		inet_ntop(AF_INET, &(addr_in->sin_addr), ip, INET_ADDRSTRLEN);
		port = ntohs(addr_in->sin_port);
	} else if (sa->sa_family == AF_INET6) {
		addr_in6 = (struct sockaddr_in6 *)sa;
		inet_ntop(AF_INET6, &(addr_in6->sin6_addr), ip,
			  INET6_ADDRSTRLEN);
		port = ntohs(addr_in6->sin6_port);
	} else {
		pv_log(WARN, "unsupported family");
	}
	SNPRINTF_WTRUNC(addr, 64, "%s:%d", ip, port);

	pv_metadata_add_devmeta(DEVMETA_KEY_PH_ADDRESS, addr);

	return 0;
}

int pv_event_rest_send_by_components(
	enum evhttp_cmd_type op, const char *host, int port,
	const char *endpoint, const char *token, const char *body,
	void (*chunk_cb)(struct evhttp_request *, void *),
	void (*done_cb)(struct evhttp_request *, void *), void *ctx)
{
	if (!pv_event_get_base())
		return -1;

	_debug_log(DEBUG, "%s %s HTTP/1.1", _op_string(op), endpoint);

	mbedtls_dyncontext *ssl;
	ssl = bufferevent_mbedtls_dyncontext_new(&config);

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
	req = evhttp_request_new(done_cb, ctx);
	if (!req) {
		pv_log(ERROR, "evhttp_request_new failed");
		goto error;
	}

	if (chunk_cb)
		evhttp_request_set_chunked_cb(req, chunk_cb);
	evhttp_request_set_error_cb(req, _print_error_cb);
	evhttp_request_set_header_cb(req, _header_cb);

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
	res = evhttp_make_request(evcon, req, op, endpoint);
	if (res != 0) {
		pv_log(ERROR, "evhttp_make_request returned code %d", res);
		goto error;
	}

	pv_log(DEBUG,
	       "add event: type='rest' chunk_cb=%p done_cb=%p req='%s %s HTTP/1.1'",
	       (void *)chunk_cb, (void *)done_cb, _op_string(op), endpoint);

	return 0;
error:
	// this should free bev, evcon and ssl
	if (evcon)
		evhttp_connection_free(evcon);

	return -1;
}

int pv_event_rest_send_by_url(enum evhttp_cmd_type op, const char *url,
			      void (*chunk_cb)(struct evhttp_request *, void *),
			      void (*done_cb)(struct evhttp_request *, void *),
			      void *ctx)
{
	int ret = -1, port;
	const char *scheme, *host, *path;
	struct evhttp_uri *http_uri = NULL;

	http_uri = evhttp_uri_parse(url);
	if (!http_uri) {
		pv_log(WARN, "could not parse URL");
		goto out;
	}

	scheme = evhttp_uri_get_scheme(http_uri);
	if (!scheme) {
		pv_log(WARN, "could not get scheme");
		goto out;
	}

	if (!pv_str_matches(scheme, strlen(scheme), "https", strlen("https"))) {
		pv_log(WARN, "https is mandatory");
		goto out;
	}

	host = evhttp_uri_get_host(http_uri);
	if (!host) {
		pv_log(WARN, "could not get host");
		goto out;
	}

	port = evhttp_uri_get_port(http_uri);
	if (port < 0)
		port = 443;

	path = evhttp_uri_get_path(http_uri);
	if (!path || !strlen(path))
		path = "/";

	pv_event_rest_send_by_components(op, host, port, path, NULL, NULL,
					 chunk_cb, done_cb, ctx);

	ret = 0;
out:
	if (http_uri)
		evhttp_uri_free(http_uri);

	return ret;
}

int _recv_status_line(struct evhttp_request *req)
{
	int ret = -1;

	if (!req || !evhttp_request_get_response_code(req)) {
		int errcode = EVUTIL_SOCKET_ERROR();
		pv_log(WARN, "socket error %d: %s", errcode,
		       evutil_socket_error_to_string(errcode));
		return -1;
	}

	ret = evhttp_request_get_response_code(req);
	_debug_log(DEBUG, "HTTP/1.1 %d %s", ret,
		   evhttp_request_get_response_code_line(req));

	return ret;
}

int pv_event_rest_recv_buffer(struct evhttp_request *req, char **buf,
			      size_t max_len)
{
	int ret;
	struct evbuffer *evbuf;

	ret = _recv_status_line(req);
	if (ret < 0) {
		pv_log(WARN, "could not receive status line");
		return -1;
	}

	evbuf = evhttp_request_get_input_buffer(req);

	size_t to_read;
	to_read = evbuffer_get_length(evbuf);
	if (to_read > max_len) {
		pv_log(WARN, "body length %zu bigger than max allowed %zu",
		       to_read, max_len);
		return -1;
	}

	char *tmp;
	tmp = calloc(to_read + 1, sizeof(char));
	if (!tmp)
		return -1;

	*buf = tmp;

	int nread = 0, i = 0;
	while ((nread = evbuffer_remove(evbuf, tmp, max_len - i)) > 0) {
		tmp += nread;
		i += nread;
	}

	_debug_log(DEBUG, "");
	_debug_log(DEBUG, "%s", buf);

	return ret;
}

int pv_event_rest_recv_chunk_path(struct evhttp_request *req, const char *path)
{
	int fd;
	size_t total_written = 0, blen;
	struct evbuffer *evbuf;

	evbuf = evhttp_request_get_input_buffer(req);

	fd = open(path, O_CREAT | O_RDWR | O_APPEND, 0644);
	if (fd < 0) {
		pv_log(WARN, "could not open '%s': %s", path, strerror(errno));
		return -1;
	}

	blen = evbuffer_get_length(evbuf);
	while (evbuffer_get_length(evbuf) > 0) {
		ssize_t n = evbuffer_write(evbuf, fd);

		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN) {
				// Temporary error, retry
				continue;
			}
			// Actual error
			pv_log(WARN, "could not write '%s': %s", path,
			       strerror(errno));
			close(fd);
			return -1;
		}

		if (n == 0) {
			break;
		}

		total_written += n;
		if (total_written != blen)
			pv_log(DEBUG,
			       "successfully wrote part of %d bytes to file %s",
			       total_written, path);
	}
	pv_log(DEBUG,
	       "success: wrote %d bytes from %d bytes buffer to file %s",
	       total_written, blen, path);

	close(fd);

	return 0;
}

int pv_event_rest_recv_done_path(struct evhttp_request *req, const char *path)
{
	int ret;
	off_t size;

	ret = _recv_status_line(req);
	if (ret == 200) {
		size = pv_fs_path_get_size(path);
		pv_log(DEBUG, "successfully wrote %jd bytes to '%s'", size,
		       path);
	} else {
		pv_log(WARN, "file transfer to '%s' failed", path);
		pv_fs_path_remove(path, false);
	}

	if (ret < 0) {
		pv_log(WARN, "could not receive status line");
		return -1;
	}

	return ret;
}

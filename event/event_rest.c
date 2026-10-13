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
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
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

#include "utils/fs.h"
#include "utils/list.h"
#include "utils/str.h"

#define MODULE_NAME "event_rest"
#define HTTP_DOWNLOAD_READ_HIGHWATER (128 * 1024)
#define HTTP_UPLOAD_CHUNK (128 * 1024)
#define pv_log(level, msg, ...)                                                \
	vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__,       \
	     ##__VA_ARGS__)
#include "log.h"

static mbedtls_x509_crt cacert;
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_entropy_context entropy;
static mbedtls_ssl_config config;

// test-only download pacer; libevent's token bucket is a no-op on mbedtls
struct pv_rest_pacer {
	struct evhttp_request *req; // key for the per-chunk lookup
	void *ctx; // request's cb_arg; key for the completion-cb lookup
	void (*done_cb)(struct evhttp_request *, void *); // real done_cb
	struct bufferevent *bev; // never freed here, libevent owns it
	struct event *timer; // one-shot, re-enables EV_READ
	size_t rate; // bytes/sec
	struct dl_list list;
};

static struct dl_list pacers;

static struct pv_rest_pacer *_pacer_find_by_req(struct evhttp_request *req)
{
	struct pv_rest_pacer *p;

	dl_list_for_each(p, &pacers, struct pv_rest_pacer, list)
	{
		if (p->req == req)
			return p;
	}

	return NULL;
}

static struct pv_rest_pacer *_pacer_find_by_ctx(void *ctx)
{
	struct pv_rest_pacer *p;

	dl_list_for_each(p, &pacers, struct pv_rest_pacer, list)
	{
		if (p->ctx == ctx)
			return p;
	}

	return NULL;
}

static void _pacer_init(struct pv_rest_pacer *pacer, struct evhttp_request *req,
			struct bufferevent *bev,
			void (*done_cb)(struct evhttp_request *, void *),
			void *ctx)
{
	pacer->req = req;
	pacer->ctx = ctx;
	pacer->done_cb = done_cb;
	pacer->bev = bev;
	dl_list_add(&pacers, &pacer->list);
}

static void _pacer_free(struct pv_rest_pacer *pacer)
{
	// event_free() also removes a still-pending timer
	event_free(pacer->timer);
	dl_list_del(&pacer->list);
	free(pacer);
}

static void _pacer_resume_cb(evutil_socket_t fd, short what, void *arg)
{
	(void)fd;
	(void)what;
	struct pv_rest_pacer *pacer = arg;

	bufferevent_enable(pacer->bev, EV_READ);
}

// rides done_cb since on_complete_cb never fires for client requests; req
// is NULL on error, hence the lookup by ctx
static void _pacer_done_cb(struct evhttp_request *req, void *ctx)
{
	struct pv_rest_pacer *pacer = _pacer_find_by_ctx(ctx);
	void (*done_cb)(struct evhttp_request *, void *) = NULL;

	if (pacer) {
		done_cb = pacer->done_cb;
		_pacer_free(pacer);
	}

	if (done_cb)
		done_cb(req, ctx);
}

struct pv_rest_feeder {
	struct evhttp_request *req; // key for the cancel lookup
	void *ctx; // request's cb_arg; key for the completion-cb lookup
	void (*done_cb)(struct evhttp_request *, void *); // real done_cb
	struct bufferevent *bev; // never freed here, libevent owns it
	struct evbuffer *output; // bev's output, refilled on drain
	int fd;
	off_t offset; // next byte to queue
	off_t size;
	struct dl_list list;
};

static struct dl_list feeders;

static struct pv_rest_feeder *_feeder_find_by_req(struct evhttp_request *req)
{
	struct pv_rest_feeder *f;

	dl_list_for_each(f, &feeders, struct pv_rest_feeder, list)
	{
		if (f->req == req)
			return f;
	}

	return NULL;
}

static struct pv_rest_feeder *_feeder_find_by_ctx(void *ctx)
{
	struct pv_rest_feeder *f;

	dl_list_for_each(f, &feeders, struct pv_rest_feeder, list)
	{
		if (f->ctx == ctx)
			return f;
	}

	return NULL;
}

static struct pv_rest_feeder *_feeder_find_by_output(struct evbuffer *output,
						     void *arg)
{
	struct pv_rest_feeder *f;

	dl_list_for_each(f, &feeders, struct pv_rest_feeder, list)
	{
		if (f == arg && f->output == output)
			return f;
	}

	return NULL;
}

static void _feeder_free(struct pv_rest_feeder *feeder)
{
	dl_list_del(&feeder->list);
	close(feeder->fd);
	free(feeder);
}

static int _feeder_read(struct pv_rest_feeder *feeder, struct evbuffer *buf)
{
	struct evbuffer_iovec v;
	size_t len;
	ssize_t n;

	len = feeder->size - feeder->offset;
	if (len > HTTP_UPLOAD_CHUNK)
		len = HTTP_UPLOAD_CHUNK;
	if (len <= 0)
		return 0;

	if (evbuffer_reserve_space(buf, len, &v, 1) < 1)
		return -1;

	do {
		n = pread(feeder->fd, v.iov_base, len, feeder->offset);
	} while (n < 0 && errno == EINTR);
	if (n <= 0) {
		pv_log(WARN, "could not read upload body at byte %jd: %s",
		       (intmax_t)feeder->offset,
		       n < 0 ? strerror(errno) : "unexpected end of file");
		return -1;
	}

	v.iov_len = n;
	if (evbuffer_commit_space(buf, &v, 1))
		return -1;

	feeder->offset += n;

	return 0;
}

static void _feeder_drain_cb(struct evbuffer *buf,
			     const struct evbuffer_cb_info *info, void *arg)
{
	struct pv_rest_feeder *feeder;

	if (!info->n_deleted)
		return;

	// the drain callback stays on the connection's buffer, which can outlive the
	// feeder, so it is looked up instead of trusting the callback argument
	feeder = _feeder_find_by_output(buf, arg);
	if (!feeder || feeder->offset >= feeder->size)
		return;

	// failed and cancelled requests stop writing before their buffers are
	// drained
	if (!(bufferevent_get_enabled(feeder->bev) & EV_WRITE))
		return;

	if (evbuffer_get_length(buf) >= HTTP_UPLOAD_CHUNK)
		return;

	_feeder_read(feeder, buf);
}

static void _feeder_attach(struct pv_rest_feeder *feeder,
			   struct bufferevent *bev)
{
	feeder->bev = bev;
	feeder->output = bufferevent_get_output(bev);
	if (!evbuffer_add_cb(feeder->output, _feeder_drain_cb, feeder))
		pv_log(WARN, "could not watch upload body drain");
}

static void _feeder_init(struct pv_rest_feeder *feeder,
			 struct evhttp_request *req, struct bufferevent *bev,
			 void (*done_cb)(struct evhttp_request *, void *),
			 void *ctx)
{
	feeder->req = req;
	feeder->ctx = ctx;
	feeder->done_cb = done_cb;
	dl_list_add(&feeders, &feeder->list);
	if (bev)
		_feeder_attach(feeder, bev);
}

static void _feeder_done_cb(struct evhttp_request *req, void *ctx)
{
	struct pv_rest_feeder *feeder = _feeder_find_by_ctx(ctx);
	void (*done_cb)(struct evhttp_request *, void *) = NULL;

	if (feeder) {
		done_cb = feeder->done_cb;
		_feeder_free(feeder);
	}

	if (done_cb)
		done_cb(req, ctx);
}

int pv_event_rest_init(void)
{
	dl_list_init(&pacers);
	dl_list_init(&feeders);

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
	struct pv_rest_pacer *p, *ptmp;
	struct pv_rest_feeder *f, *ftmp;

	dl_list_for_each_safe(p, ptmp, &pacers, struct pv_rest_pacer, list)
		_pacer_free(p);
	dl_list_for_each_safe(f, ftmp, &feeders, struct pv_rest_feeder, list)
		_feeder_free(f);

	mbedtls_x509_crt_free(&cacert);
	mbedtls_ssl_config_free(&config);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	pv_log(DEBUG, "HTTP REST cleaned up");
}

void pv_event_rest_cancel_request(struct evhttp_request *req)
{
	struct pv_rest_pacer *pacer = _pacer_find_by_req(req);
	struct pv_rest_feeder *feeder = _feeder_find_by_req(req);

	if (pacer)
		_pacer_free(pacer);
	if (feeder)
		_feeder_free(feeder);

	evhttp_cancel_request(req);
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

static void _add_header(struct evkeyvalq *output_headers, const char *key,
			const char *value)
{
	pv_log(TRACE, "%s: %s", key, value);
	evhttp_add_header(output_headers, key, value);
}

static void _print_error_cb(enum evhttp_request_error error, void *ctx)
{
	pv_log(TRACE, "run event: cb=%p", (void *)_print_error_cb);

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
	pv_log(TRACE, "run event: cb=%p", (void *)_header_cb);

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
		SNPRINTF_WTRUNC(addr, 64, "%s:%d", ip, port);
		pv_metadata_add_devmeta(DEVMETA_KEY_PH_ADDRESS, addr);
	} else if (sa->sa_family == AF_INET6) {
		addr_in6 = (struct sockaddr_in6 *)sa;
		inet_ntop(AF_INET6, &(addr_in6->sin6_addr), ip,
			  INET6_ADDRSTRLEN);
		port = ntohs(addr_in6->sin6_port);
		SNPRINTF_WTRUNC(addr, 64, "%s:%d", ip, port);
		pv_metadata_add_devmeta(DEVMETA_KEY_PH_ADDRESS, addr);
	} else {
		pv_log(WARN, "unsupported address family: %d", sa->sa_family);
	}

	return 0;
}

static void _setup_connection(struct evhttp_connection *evcon)
{
	// libevent will manage its resourcess so we only have to free our own context
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
}

static struct bufferevent *_new_tls_bev(const char *host)
{
	mbedtls_dyncontext *ssl;
	struct bufferevent *bev;

	ssl = bufferevent_mbedtls_dyncontext_new(&config);
	if (!ssl) {
		pv_log(ERROR, "bufferevent_mbedtls_dyncontext_new failed");
		return NULL;
	}

	mbedtls_ssl_set_hostname(ssl, host);

	bev = bufferevent_mbedtls_socket_new(
		pv_event_get_base(), -1, ssl, BUFFEREVENT_SSL_CONNECTING,
		BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	if (!bev) {
		pv_log(ERROR, "could not create TLS bufferevent");
		bufferevent_mbedtls_dyncontext_free(ssl);
		return NULL;
	}

	bufferevent_mbedtls_set_allow_dirty_shutdown(bev, 1);
	/* Bound buffered read data so large downloads don't starve the event loop. */
	bufferevent_setwatermark(bev, EV_READ, 0, HTTP_DOWNLOAD_READ_HIGHWATER);

	return bev;
}

static int _make_request(struct evhttp_connection *evcon,
			 struct evhttp_request *req, enum evhttp_cmd_type op,
			 const char *uri)
{
	int res = evhttp_make_request(evcon, req, op, uri);
	if (res != 0) {
		pv_log(ERROR, "evhttp_make_request returned code %d", res);
		return -1;
	}
	evhttp_connection_free_on_completion(evcon);

	pv_log(TRACE, "add event: type='rest' req='%s %s HTTP/1.1'",
	       _op_string(op), uri);

	return 0;
}

static int _send(enum evhttp_cmd_type op, const char *host, int port,
		 const char *endpoint, const char *autotok, const char *token,
		 const char *body, int body_fd, off_t body_size,
		 void (*chunk_cb)(struct evhttp_request *, void *),
		 void (*done_cb)(struct evhttp_request *, void *), void *ctx,
		 struct evhttp_request **out_req,
		 size_t rate_limit_bytes_per_sec, off_t resume_from)
{
	struct pv_rest_pacer *pacer = NULL;
	struct pv_rest_feeder *feeder = NULL;
	struct bufferevent *bev = NULL;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;
	void (*req_done_cb)(struct evhttp_request *, void *) = done_cb;

	if (!pv_event_get_base())
		goto error;

	pv_log(TRACE, "%s %s HTTP/1.1", _op_string(op), endpoint);

	// a disabled knob must cost nothing: no pacer, no hooks
	if (rate_limit_bytes_per_sec > 0) {
		pacer = calloc(1, sizeof(*pacer));
		if (!pacer) {
			pv_log(WARN, "could not allocate download pacer");
		} else {
			dl_list_init(&pacer->list);
			pacer->rate = rate_limit_bytes_per_sec;
			pacer->timer = evtimer_new(pv_event_get_base(),
						   _pacer_resume_cb, pacer);
			if (!pacer->timer) {
				pv_log(WARN, "could not create pacer timer");
				free(pacer);
				pacer = NULL;
			}
		}
	}

	if (body_fd >= 0) {
		feeder = calloc(1, sizeof(*feeder));
		if (!feeder) {
			pv_log(ERROR, "could not allocate upload feeder");
			goto error;
		}
		dl_list_init(&feeder->list);
		feeder->fd = body_fd;
		body_fd = -1;
		feeder->size = body_size;
	}

	if (pacer)
		req_done_cb = _pacer_done_cb;
	else if (feeder)
		req_done_cb = _feeder_done_cb;

	bev = _new_tls_bev(host);
	if (!bev)
		goto error;

	evcon = evhttp_connection_base_bufferevent_new(pv_event_get_base(),
						       NULL, bev, host, port);
	if (!evcon) {
		pv_log(ERROR, "evhttp_connection_base_bufferevent_new failed");
		goto error;
	}
	_setup_connection(evcon);

	req = evhttp_request_new(req_done_cb, ctx);
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

	if (autotok && strlen(autotok))
		_add_header(output_headers, "Pantahub-Devices-Auto-Token-V1",
			    autotok);

	if (token) {
		char bearer[1024];
		memset(bearer, 0, sizeof(bearer));
		snprintf(bearer, sizeof(bearer), "Bearer %s", token);

		_add_header(output_headers, "Authorization", bearer);
	}

	if (resume_from > 0) {
		char range[64];
		snprintf(range, sizeof(range), "bytes=%jd-",
			 (intmax_t)resume_from);

		_add_header(output_headers, "Range", range);
	}

	struct evbuffer *output_buffer;
	output_buffer = evhttp_request_get_output_buffer(req);
	char len_str[64];

	if (body) {
		size_t len = strlen(body);
		pv_log(TRACE, "");
		pv_log(TRACE, "%s", body);

		evbuffer_add(output_buffer, body, len);

		evutil_snprintf(len_str, sizeof(len_str) - 1, "%zu", len);
		_add_header(output_headers, "Content-Length", len_str);
		_add_header(output_headers, "Content-Type", "application/json");
	} else if (feeder) {
		// the rest is queued as the connection drains this first chunk
		if (_feeder_read(feeder, output_buffer))
			goto error;

		evutil_snprintf(len_str, sizeof(len_str) - 1, "%jd",
				(intmax_t)body_size);
		_add_header(output_headers, "Content-Length", len_str);
		_add_header(output_headers, "Content-Type",
			    "application/octet-stream");
	}

	// linked before sending, so a failure can find them
	if (feeder)
		_feeder_init(feeder, req, bev, done_cb, ctx);
	if (pacer)
		_pacer_init(pacer, req, bev, feeder ? _feeder_done_cb : done_cb,
			    ctx);

	if (_make_request(evcon, req, op, endpoint)) {
		// req is now tied to evcon, freed along with it
		req = NULL;
		goto error;
	}

	pv_log(TRACE, "chunk_cb=%p done_cb=%p", (void *)chunk_cb,
	       (void *)done_cb);

	if (out_req)
		*out_req = req;

	return 0;
error:
	if (body_fd >= 0)
		close(body_fd);
	if (req)
		evhttp_request_free(req);
	if (pacer)
		_pacer_free(pacer);
	if (feeder)
		_feeder_free(feeder);
	if (evcon) {
		evhttp_connection_free(evcon);
	} else if (bev) {
		bufferevent_free(bev);
	}

	return -1;
}

int pv_event_rest_send_by_components(
	enum evhttp_cmd_type op, const char *host, int port,
	const char *endpoint, const char *autotok, const char *token,
	const char *body, void (*chunk_cb)(struct evhttp_request *, void *),
	void (*done_cb)(struct evhttp_request *, void *), void *ctx,
	struct evhttp_request **out_req, size_t rate_limit_bytes_per_sec,
	off_t resume_from)
{
	return _send(op, host, port, endpoint, autotok, token, body, -1, 0,
		     chunk_cb, done_cb, ctx, out_req, rate_limit_bytes_per_sec,
		     resume_from);
}

static int _parse_url(const char *url, char *host, size_t host_size, int *port,
		      char *endpoint, size_t endpoint_size)
{
	int ret = -1;
	const char *scheme, *h, *path, *query;
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

	h = evhttp_uri_get_host(http_uri);
	if (!h) {
		pv_log(WARN, "could not get host");
		goto out;
	}
	SNPRINTF_WTRUNC(host, host_size, "%s", h);

	*port = evhttp_uri_get_port(http_uri);
	if (*port < 0)
		*port = 443;

	path = evhttp_uri_get_path(http_uri);
	if (!path || !strlen(path))
		path = "/";

	query = evhttp_uri_get_query(http_uri);
	if (query)
		SNPRINTF_WTRUNC(endpoint, endpoint_size, "%s?%s", path, query);
	else
		SNPRINTF_WTRUNC(endpoint, endpoint_size, "%s", path);

	ret = 0;
out:
	if (http_uri)
		evhttp_uri_free(http_uri);

	return ret;
}

int pv_event_rest_send_by_url(enum evhttp_cmd_type op, const char *url,
			      void (*chunk_cb)(struct evhttp_request *, void *),
			      void (*done_cb)(struct evhttp_request *, void *),
			      void *ctx, struct evhttp_request **out_req,
			      size_t rate_limit_bytes_per_sec,
			      off_t resume_from)
{
	char host[256], endpoint[PATH_MAX];
	int port;

	if (_parse_url(url, host, sizeof(host), &port, endpoint,
		       sizeof(endpoint)))
		return -1;

	return _send(op, host, port, endpoint, NULL, NULL, NULL, -1, 0,
		     chunk_cb, done_cb, ctx, out_req, rate_limit_bytes_per_sec,
		     resume_from);
}

int pv_event_rest_send_file_by_url(const char *url, const char *path,
				   off_t size,
				   void (*done_cb)(struct evhttp_request *,
						   void *),
				   void *ctx, struct evhttp_request **out_req)
{
	char host[256], endpoint[PATH_MAX];
	int port, fd;

	if (_parse_url(url, host, sizeof(host), &port, endpoint,
		       sizeof(endpoint)))
		return -1;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		pv_log(WARN, "could not open '%s': %s", path, strerror(errno));
		return -1;
	}

	return _send(EVHTTP_REQ_PUT, host, port, endpoint, NULL, NULL, NULL, fd,
		     size, NULL, done_cb, ctx, out_req, 0, 0);
}

int _recv_status_line(struct evhttp_request *req)
{
	if (!req) {
		pv_log(WARN, "null request");
		return -1;
	}

	int ret = evhttp_request_get_response_code(req);
	if (ret == 0) {
		int errcode = EVUTIL_SOCKET_ERROR();
		pv_log(WARN, "socket error %d: %s", errcode,
		       evutil_socket_error_to_string(errcode));
		return -1;
	}

	pv_log(TRACE, "HTTP/1.1 %d %s", ret,
	       evhttp_request_get_response_code_line(req));

	return ret;
}

int pv_event_rest_recv_buffer(struct evhttp_request *req, char **buf,
			      size_t max_len)
{
	int ret;
	struct evbuffer *evbuf;

	*buf = NULL;

	ret = _recv_status_line(req);
	if (ret < 0) {
		pv_log(WARN, "could not receive status line");
		return -1;
	}

	evbuf = evhttp_request_get_input_buffer(req);

	size_t to_read = evbuffer_get_length(evbuf);
	if (to_read > max_len) {
		pv_log(WARN, "body length %zu bigger than max allowed %zu",
		       to_read, max_len);
		return -1;
	}

	char *tmp = calloc(to_read + 1, sizeof(char));
	if (!tmp)
		return -1;

	*buf = tmp;

	int nread = 0;
	size_t total = 0;
	while (total < to_read &&
	       (nread = evbuffer_remove(evbuf, tmp + total, to_read - total)) >
		       0) {
		total += nread;
	}

	if (total != to_read) {
		pv_log(WARN, "incomplete read: got %zu bytes, expected %zu",
		       total, to_read);
		free(*buf);
		*buf = NULL;
		return -1;
	}

	pv_log(TRACE, "");
	pv_log(TRACE, "%s", *buf);

	return ret;
}

int pv_event_rest_recv_chunk_path(struct evhttp_request *req, const char *path,
				  size_t *written)
{
	int fd;
	size_t total_written = 0, blen;
	struct evbuffer *evbuf;

	if (written)
		*written = 0;

	// connection failures run done_cb without a request
	if (!req)
		return -1;

	evbuf = evhttp_request_get_input_buffer(req);
	blen = evbuffer_get_length(evbuf);
	pv_log(TRACE, "recv chunk '%s': %zu bytes", path, blen);

	fd = open(path, O_CREAT | O_RDWR | O_APPEND, 0644);
	if (fd < 0) {
		pv_log(WARN, "could not open '%s': %s", path, strerror(errno));
		return -1;
	}

	while (evbuffer_get_length(evbuf) > 0) {
		ssize_t n = evbuffer_write(evbuf, fd);

		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN) {
				pv_log(TRACE,
				       "recv chunk '%s': temp error (%s), retrying",
				       path, strerror(errno));
				continue;
			}
			pv_log(WARN, "could not write '%s': %s", path,
			       strerror(errno));
			close(fd);
			return -1;
		}

		if (n == 0) {
			pv_log(TRACE,
			       "recv chunk '%s': zero-write, exiting loop",
			       path);
			break;
		}

		total_written += n;
		if (total_written < blen)
			pv_log(TRACE, "recv chunk '%s': partial write %zu/%zu",
			       path, total_written, blen);
	}

	pv_log(TRACE, "recv chunk '%s': wrote %zu/%zu bytes", path,
	       total_written, blen);
	close(fd);
	if (written)
		*written = total_written;

	// O(1) when no download is paced: check list emptiness before the lookup
	if (!dl_list_empty(&pacers) && total_written > 0) {
		struct pv_rest_pacer *pacer = _pacer_find_by_req(req);

		if (pacer) {
			uint64_t usec = (uint64_t)total_written * 1000000ULL /
					pacer->rate;
			if (usec < 1000)
				usec = 1000; // minimum 1 ms
			struct timeval tv = { .tv_sec = usec / 1000000,
					      .tv_usec = usec % 1000000 };

			bufferevent_disable(pacer->bev, EV_READ);
			evtimer_add(pacer->timer, &tv);
		}
	}

	return 0;
}

int pv_event_rest_recv_done_path(struct evhttp_request *req, const char *path,
				 size_t *written)
{
	int ret;
	off_t size;

	if (pv_event_rest_recv_chunk_path(req, path, written)) {
		pv_log(WARN, "could not finish transfer to path %s", path);
		return -1;
	}

	ret = _recv_status_line(req);
	if (ret == 200 || ret == 206) {
		size = pv_fs_path_get_size(path);
		pv_log(DEBUG,
		       "successfully downloaded file with size %jd bytes at '%s' (status %d)",
		       (intmax_t)size, path, ret);
	} else {
		// caller decides whether the partial file at 'path' is kept
		// around for a resumed retry or discarded
		pv_log(WARN, "file transfer to '%s' failed with status %d",
		       path, ret);
	}

	if (ret < 0) {
		pv_log(WARN, "could not receive status line");
		return -1;
	}

	return ret;
}

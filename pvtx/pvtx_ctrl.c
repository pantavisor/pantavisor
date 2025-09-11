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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "utils/fs.h"
#include "pvtx_ctrl.h"
#include "pvtx_buffer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define PVTX_CTRL_ROOT_SOCK "/pv/pv-ctrl"
#define PVTX_CTRL_CONTAINER_SOCK "/pantavisor/pv-ctrl"

#define PVTX_CTRL_GET_HEAD "GET %s HTTP/1.1\r\nHost: localhost\r\n\r\n\r\n"
#define PVTX_CTRL_PUT_HEAD                                                     \
	"PUT %s HTTP/1.1\r\nHost: localhost\r\nContent-type: %s\r\nContent-length: %jd\r\n\r\n"
#define PVTX_CTRL_BUFF_ENV "PVTX_CTRL_BUF_SIZE"
// 16K
#define PVTX_CTRL_BUFF_MIN (16384)
// 10M
#define PVTX_CTRL_BUFF_MAX (10485760)
// common size on many web servers
#define PVTX_CTRL_HEADER_SIZE (8192)

enum pvtx_ctrl_method {
	PVTX_CTRL_METHOD_UNSET,
	PVTX_CTRL_METHOD_GET,
	PVTX_CTRL_METHOD_PUT,
};

struct pv_pvtx_ctrl_header {
	enum pvtx_ctrl_method method;
	char path[PATH_MAX];
	const char *ctype;
	off_t clen;
};

struct pv_pvtx_buffer *get_buffer(struct pv_pvtx_error *err)
{
	struct pv_pvtx_buffer *buf =
		pv_pvtx_buffer_from_env(PVTX_CTRL_BUFF_ENV, PVTX_CTRL_BUFF_MIN,
					PVTX_CTRL_BUFF_MAX, 512);
	if (!buf && err)
		PVTX_ERROR_SET(err, -1, "couldn't get buffer");

	return buf;
}

static char *concatenate_header(const char *tmpl, ...)
{
	va_list list;
	va_start(list, tmpl);

	char *head = NULL;

	int len = vasprintf(&head, tmpl, list);
	va_end(list);

	if (len == -1)
		return NULL;

	return head;
}

static char *header_to_str(struct pv_pvtx_ctrl_header *head)
{
	const char *tmpl = NULL;
	if (head->method == PVTX_CTRL_METHOD_GET)
		tmpl = PVTX_CTRL_GET_HEAD;
	else
		tmpl = PVTX_CTRL_PUT_HEAD;

	return concatenate_header(tmpl, head->path, head->ctype, head->clen);
}

void pv_pvtx_ctrl_free(struct pv_pvtx_ctrl *ctrl)
{
	if (!ctrl)
		return;

	if (ctrl->sock)
		close(ctrl->sock);
	free(ctrl);
}

static int connect_sock(struct pv_pvtx_ctrl *ctrl, const char *path)
{
	pv_pvtx_error_clear(&ctrl->error);

	if (!path) {
		// checking both paths
		if (pv_fs_path_exist(PVTX_CTRL_ROOT_SOCK))
			path = PVTX_CTRL_ROOT_SOCK;
		else if (pv_fs_path_exist(PVTX_CTRL_CONTAINER_SOCK))
			path = PVTX_CTRL_CONTAINER_SOCK;
		else {
			PVTX_ERROR_SET(&ctrl->error, -1,
				       "couldn't locate socket");
			return -1;
		}
	}

	int retries = 5;
	int wait = 2;
	bool ok = false;

	ctrl->sock = -1;
	do {
		if (ctrl->sock > -1) {
			close(ctrl->sock);
			sleep(wait);
		}

		ctrl->sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

		if (ctrl->sock < 0) {
			PVTX_ERROR_SET(&ctrl->error, errno,
				       "couldn't open socket");
			return -1;
		}

		struct sockaddr_un addr = { .sun_family = AF_UNIX };
		strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

		struct sockaddr *ptr = (struct sockaddr *)&addr;

		ok = (connect(ctrl->sock, ptr, sizeof(addr)) == 0);

		retries--;

	} while (!ok && retries > 0);

	if (!ok || ctrl->sock < 0) {
		PVTX_ERROR_SET(&ctrl->error, -1,
			       "couldn't connect, all atteps failed");
		return -1;
	}

	return 0;
}

struct pv_pvtx_ctrl *pv_pvtx_ctrl_new(const char *path)
{
	struct pv_pvtx_ctrl *ctrl = calloc(1, sizeof(struct pv_pvtx_ctrl));
	if (!ctrl)
		return NULL;

	if (connect_sock(ctrl, path) != 0) {
		free(ctrl);
		return NULL;
	}

	return ctrl;
}

static int send_header(struct pv_pvtx_ctrl *ctrl,
		       struct pv_pvtx_ctrl_header *head)
{
	pv_pvtx_error_clear(&ctrl->error);

	const char *err = NULL;

	char *head_str = header_to_str(head);
	if (!head_str) {
		PVTX_ERROR_SET(&ctrl->error, -1,
			       "couldn't allocate header string");
		return -1;
	}
	pv_fs_file_write_nointr(ctrl->sock, head_str, strlen(head_str));
	free(head_str);

	return 0;
}

const char *pvtx_ctrl_get_data(const char *data, size_t size)
{
	char *p = strstr(data, "\r\n\r\n");
	if (!p)
		return NULL;

	if ((p - data) > size)
		return NULL;

	// return pointer after the delimiter
	return p + 4;
}

static void check_error(struct pv_pvtx_buffer *buf, struct pv_pvtx_error *err)
{
	if (!buf || !buf->data || buf->size < 1)
		return;

	pv_pvtx_error_clear(err);

	const char *ptr = strchr(buf->data, ' ');
	if (!ptr) {
		PVTX_ERROR_SET(err, -1,
			       "couldn't parse header, error check failed");
		return;
	}

	// get http code
	char n_str[4] = { 0 };
	memcpy(n_str, ptr + 1, 3);
	long code = strtol(n_str, NULL, 10);

	if (code < 300 && code > 199)
		return;

	char *end = strstr(buf->data, "\r\n");
	if (!end) {
		PVTX_ERROR_SET(err, -1, "couldn't parse header");
		return;
	}

	char base_err[PV_PVTX_ERROR_MAX_LEN] = { 0 };
	memcpy(base_err, ptr + 1, end - (ptr + 1));

	ptr = pvtx_ctrl_get_data(buf->data, buf->size);

	char *error_str = NULL;
	if (asprintf(&error_str, "%s\nResponse: %s", base_err, ptr) == -1) {
		PVTX_ERROR_SET(err, -1, "couldn't get the complete err: %s",
			       base_err);
		return;
	}

	PVTX_ERROR_SET(err, -code, error_str);
	free(error_str);
}

static ssize_t get_content_length(const char *data)
{
	const char *header = "content-length:";
	const char *sep = "\r\n";

	char *beg = strcasestr(data, header);
	if (!beg)
		return -1;
	beg += strlen(header);

	char *end = strstr(beg, sep);
	if (!end)
		return -1;

	struct pv_pvtx_buffer *buf = pv_pvtx_buffer_new(end - beg + 1);
	if (!buf)
		return -1;

	memccpy(buf->data, beg, '\r', end - beg);
	ssize_t len = strtol(buf->data, NULL, 10);
	pv_pvtx_buffer_free(buf);

	if (errno == ERANGE)
		return -ERANGE;

	return len;
}

static struct pv_pvtx_buffer *read_data(struct pv_pvtx_ctrl *ctrl)
{
	pv_pvtx_error_clear(&ctrl->error);

	struct pv_pvtx_buffer *buf = pv_pvtx_buffer_new(PVTX_CTRL_HEADER_SIZE);
	if (!buf)
		return NULL;

	ssize_t cur_read =
		pv_fs_file_read_nointr(ctrl->sock, buf->data, buf->size - 1);

	ssize_t len = get_content_length(buf->data);
	if (len < 0)
		goto out;

	size_t new_size = cur_read + len;
	if (pv_pvtx_buffer_realloc(buf, new_size) != 0) {
		PVTX_ERROR_SET(&ctrl->error, -1, "couldn't reallocate buffer");
		goto out;
	}

	if (cur_read < new_size)
		pv_fs_file_read_nointr(ctrl->sock, buf->data + cur_read,
				       new_size - cur_read);

out:
	if (ctrl->error.code != 0) {
		memset(buf->data, 0, buf->size);
		buf->size = 0;
	}

	return buf;
}

char *pv_pvtx_ctrl_steps_get(struct pv_pvtx_ctrl *ctrl, const char *rev,
			     size_t *size)
{
	pv_pvtx_error_clear(&ctrl->error);

	struct pv_pvtx_ctrl_header head = {
		.method = PVTX_CTRL_METHOD_GET,
	};
	snprintf(head.path, PATH_MAX, "/steps/%s", rev);

	if (send_header(ctrl, &head) != 0) {
		goto out;
	}

	struct pv_pvtx_buffer *buf = read_data(ctrl);

	check_error(buf, &ctrl->error);

	const char *data_ptr = pvtx_ctrl_get_data(buf->data, buf->size);
	char *data = strdup(data_ptr);
	*size = strlen(data);

	pv_pvtx_buffer_free(buf);

out:
	return data;
}

int pv_pvtx_ctrl_steps_put(struct pv_pvtx_ctrl *ctrl, const char *data,
			   size_t size, const char *rev)
{
	struct pv_pvtx_ctrl_header head = {
		.method = PVTX_CTRL_METHOD_PUT,
		.ctype = "application/json",
		.clen = size,
	};
	snprintf(head.path, PATH_MAX, "/steps/%s", rev);

	send_header(ctrl, &head);
	if (pv_fs_file_write_nointr(ctrl->sock, data, size) < 0)
		return -1;

	struct pv_pvtx_buffer *buf = read_data(ctrl);
	check_error(buf, &ctrl->error);

	pv_pvtx_buffer_free(buf);

	return -ctrl->error.code;
}

int pv_pvtx_ctrl_obj_put(struct pv_pvtx_ctrl *ctrl,
			 struct pv_pvtx_tar_content *con)
{
	struct pv_pvtx_ctrl_header head = {
		.method = PVTX_CTRL_METHOD_PUT,
		.ctype = "application/octet-stream",
		.clen = con->size,
	};
	snprintf(head.path, PATH_MAX, "/%s", con->name);

	send_header(ctrl, &head);
	struct pv_pvtx_buffer *buf = get_buffer(&ctrl->error);

	if (!buf) {
		PVTX_ERROR_SET(&ctrl->error, -1, "couldn't allocate buffer");
		return -1;
	}

	ssize_t written = 0;
	while (written < con->size) {
		ssize_t cur = pv_pvtx_tar_content_read_block(con, buf->data,
							     buf->size);
		if (cur <= 0)
			break;

		ssize_t to_write = cur;
		if ((written + cur) > con->size)
			to_write = con->size - written;
		written += pv_fs_file_write_nointr(ctrl->sock, buf->data,
						   to_write);
		memset(buf->data, 0, buf->size);
	}

	struct pv_pvtx_buffer *buf_data = read_data(ctrl);
	check_error(buf_data, &ctrl->error);

	pv_pvtx_buffer_free(buf_data);
	pv_pvtx_buffer_free(buf);

	return -ctrl->error.code;
}
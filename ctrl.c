/*
 * Copyright (c) 2017-2021 Pantacor Ltd.
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
#include <unistd.h>
#include <inttypes.h>
#include <stdint.h>
#include <errno.h>
#include <picohttpparser.h>
#include <fcntl.h>

#include <sys/time.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

#include <linux/limits.h>

#include "ctrl.h"
#include "utils.h"
#include "pvlogger.h"
#include "state.h"
#include "init.h"
#include "storage.h"

#define MODULE_NAME             "ctrl"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#define ENDPOINT_COMMANDS "/commands"
#define ENDPOINT_OBJECTS "/objects"

#define HTTP_RES_OK "HTTP/1.1 200 OK\r\n\r\n"
#define HTTP_RES_CONT "HTTP/1.1 100 Continue\r\n\r\n"
#define HTTP_RES_BAD_REQ "HTTP/1.1 400 Bad Request\r\n\r\n"

static const int HTTP_REQ_BUFFER_SIZE = 4096;
static const int HTTP_REQ_NUM_HEADERS = 8;

static int pv_ctrl_socket_open(char *path)
{
	int fd;
	struct sockaddr_un addr;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		pv_log(ERROR, "unable to open control socket");
		goto out;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, path);

	if (bind(fd, (const struct sockaddr *) &addr, sizeof(addr)) < 0) {
		pv_log(ERROR, "unable to bind control socket fd=%d", fd);
		close(fd);
		fd = -1;
		goto out;
	}

	// queue 15 commands
	listen(fd, 15);

out:
	return fd;
}

void pv_ctrl_socket_close(int ctrl_fd)
{
	if (ctrl_fd > 0) {
		pv_log(DEBUG, "closing ctrl socket");
		close(ctrl_fd);
	}
}

static struct pv_cmd* pv_ctrl_parse_command(char *buf)
{
	int tokc;
	uint8_t ret = -1;
	jsmntok_t *tokv;
	char *op_string = NULL;
	struct pv_cmd* cmd = NULL;

	cmd = calloc(1, sizeof(struct pv_cmd));
	if (!cmd) {
		pv_log(ERROR, "cmd could not be allocated");
		goto out;
	}

	jsmnutil_parse_json(buf, &tokv, &tokc);

	op_string = get_json_key_value(buf, "op", tokv, tokc);
	if(!op_string) {
		pv_log(WARN, "unable to get op value from command");
		goto err;
	}

	cmd->op = pv_ctrl_int_cmd_operation(op_string, strlen(op_string));
	if (!cmd->op) {
		pv_log(WARN, "op from command unknown");
		goto err;
	}

	cmd->payload = get_json_key_value(buf, "payload", tokv, tokc);
	if (!cmd->payload) {
		pv_log(WARN, "unable to get payload value from command");
		goto err;
	}

	ret = 0;

	goto out;

err:
	pv_ctrl_free_cmd(cmd);
	cmd = NULL;

out:
	if (tokv)
		free(tokv);
	if (op_string)
		free(op_string);

	return cmd;
}

static int pv_ctrl_process_cmd(int req_fd, size_t content_length, struct pv_cmd** cmd)
{
	char req[HTTP_REQ_BUFFER_SIZE];

	memset(req, 0, sizeof(req));

	pv_log(DEBUG, "reading and parsing command...");

	if (content_length > HTTP_REQ_BUFFER_SIZE) {
		pv_log(WARN, "cmd request too long");
		goto err;
	}

	// read request
	if (read(req_fd, req, content_length) <= 0) {
		pv_log(ERROR, "cmd request could not be received from ctrl socket");
		goto err;
	}

	*cmd = pv_ctrl_parse_command(req);
	if (!*cmd)
		goto err;

	return 0;

err:
	return -1;
}

static int pv_ctrl_process_put_object(int req_fd, size_t content_length, char* object_name)
{
	int obj_fd, read_length, write_length, ret = -1;
	char object_path[PATH_MAX];
	char req[HTTP_REQ_BUFFER_SIZE];

	sprintf(object_path, "%s/objects/%s", pv_config_get_storage_mntpoint(), object_name);
	memset(req, 0, sizeof(req));

	pv_log(INFO, "reading object from endpoint and putting it in %s...", object_path);

	if (write(req_fd, HTTP_RES_CONT, sizeof(HTTP_RES_CONT)-1) <= 0)
		pv_log(ERROR, "HTTP Continue response could not be sent to ctrl socket");

	obj_fd = open(object_path, O_CREAT | O_WRONLY, 0644);
	if (obj_fd <= 0) {
		pv_log(ERROR, "%s could not be created", object_path);
		goto out;
	}

	// read and save
	while (content_length > 0) {
		if (content_length > HTTP_REQ_BUFFER_SIZE)
			read_length = HTTP_REQ_BUFFER_SIZE;
		else
			read_length = content_length;

		write_length = read(req_fd, req, read_length);
		if (write_length <= 0) {
			pv_log(ERROR, "read failed");
			goto sha;
		}

		if (write(obj_fd, req, write_length) <= 0) {
			pv_log(ERROR, "write failed");
			goto sha;
		}

		content_length-=write_length;
	}

sha:
	fsync(obj_fd);
	close(obj_fd);

	if (pv_storage_validate_file_checksum(object_path, object_name)) {
		pv_log(DEBUG, "removing %s...", object_path);
		remove(object_path);
		syncdir(object_path);
		goto out;
	}

	ret = 0;

out:
	return ret;
}

static void pv_ctrl_read_parse_get_object(int req_fd)
{
	pv_log(DEBUG, "GET OBJECT NOT IMPLEMENTED");
}

static int pv_ctrl_read_parse_request_header(int req_fd,
											char *buf,
											int buf_index,
											const char **method,
											size_t *method_len,
											const char **path,
											size_t *path_len,
											struct phr_header *headers,
											size_t *num_headers)
{
	int minor_version;

	// read from socket until end of HTTP header
	while ((buf_index < HTTP_REQ_BUFFER_SIZE) &&
			(1 == read(req_fd, &buf[buf_index], 1))) {
		if ((buf[buf_index-3] == '\r') &&
			(buf[buf_index-2] == '\n') &&
			(buf[buf_index-1] == '\r') &&
			(buf[buf_index] == '\n')) {
			break;
		}
		buf_index++;
	}

	// parse HTTP header
	return phr_parse_request(buf,
							buf_index+1,
							method,
							method_len,
							path,
							path_len,
							&minor_version,
							headers,
							num_headers,
							0);
}

static size_t pv_ctrl_get_value_header_int(struct phr_header *headers,
										size_t num_headers,
										char* name)
{
	for (size_t header_index = 0; header_index < num_headers; header_index++)
		if (!strncmp(headers[header_index].name, name, headers[header_index].name_len))
			return atoi(headers[header_index].value);

	return -1;
}

static void pv_ctrl_process_get_object(int req_fd, char* object_name)
{
	int obj_fd, read_length;
	char object_path[PATH_MAX];
	char buf[4096];

	memset(buf, 0, sizeof(buf));

	sprintf(object_path, "%s/objects/%s", pv_config_get_storage_mntpoint(), object_name);

	pv_log(INFO, "reading object from %s and sending it to endpoint...", object_path);

	obj_fd = open(object_path, O_RDONLY);
	if (obj_fd <= 0) {
		pv_log(ERROR, "%s could not be opened for read", object_path);
		goto out;
	}

	if (write(req_fd, HTTP_RES_OK, sizeof(HTTP_RES_OK)-1) < 0)
		pv_log(ERROR, "HTTP OK response could not be sent to ctrl socket");

	// read and send
	while ((read_length = read(obj_fd, buf, 4096)) > 0) {
		if (write(req_fd, buf, read_length) != read_length) {
			pv_log(ERROR, "write failed");
			goto out;
		}
	}

out:
	close(obj_fd);
}

static char* pv_ctrl_get_object_name(const char* path, int buf_index, size_t path_len)
{
	char* object_name;

	if ((path_len - buf_index) != 64)
		return NULL;

	object_name = calloc(1, 64 * sizeof(char));
	if (!object_name)
		return NULL;

	strncpy(object_name, &path[buf_index], 64);

	return object_name;
}

static struct pv_cmd* pv_ctrl_read_parse_request(int req_fd)
{
	char buf[HTTP_REQ_BUFFER_SIZE];
	int buf_index = 0, res = -1;
	const char *method, *path;
	size_t method_len, path_len, num_headers = HTTP_REQ_NUM_HEADERS, content_length;
	struct phr_header headers[HTTP_REQ_NUM_HEADERS];
	struct pv_cmd *cmd = NULL;
	char* object_name = NULL;

	// read first character to see if the request is a non-HTTP legacy one
	if (read(req_fd, &buf[0], 1) < 0)
		goto out;
	buf_index++;

	// if character is 3 (old code for json command), it is non-HTTP
	if (buf[0] == 3) {
		res = pv_ctrl_process_cmd(req_fd, HTTP_REQ_BUFFER_SIZE, &cmd);
		goto out;
	}

	// at this point, the request can only be either HTTP or bad formatted
	buf_index = pv_ctrl_read_parse_request_header(req_fd,
												buf,
												buf_index,
												&method,
												&method_len,
												&path,
												&path_len,
												headers,
												&num_headers);
	if (buf_index < 0) {
		pv_log(WARN, "HTTP request recived has bad format");
		goto out;
	}

	content_length = pv_ctrl_get_value_header_int(headers, num_headers, "Content-Length");
	if (content_length <= 0) {
		pv_log(WARN, "HTTP request received has empty body");
		goto out;
	}

	// read and parse rest of message
	if (!strncmp(ENDPOINT_COMMANDS, path, sizeof(ENDPOINT_COMMANDS)-1)) {
		if (!strncmp("POST", method, method_len)) {
			res = pv_ctrl_process_cmd(req_fd, content_length, &cmd);
		}
	} else if (!strncmp(ENDPOINT_OBJECTS, path, sizeof(ENDPOINT_OBJECTS)-1)) {
		object_name = pv_ctrl_get_object_name(path, sizeof(ENDPOINT_OBJECTS), path_len);
		if (!object_name) {
			pv_log(WARN, "HTTP request has bad object name");
			goto out;
		}

		if (!strncmp("PUT", method, method_len)) {
			res = pv_ctrl_process_put_object(req_fd, content_length, object_name);
		} else if (!strncmp("GET", method, method_len)) {
			pv_ctrl_process_get_object(req_fd, object_name);
			goto out;
		}
	}

	// write response
	if (res < 0) {
		if (write(req_fd, HTTP_RES_BAD_REQ, sizeof(HTTP_RES_BAD_REQ)-1) <= 0)
			pv_log(ERROR, "HTTP Bad Request response could not be sent to ctrl socket");
	} else {
		if (write(req_fd, HTTP_RES_OK, sizeof(HTTP_RES_OK)-1) < 0)
			pv_log(ERROR, "HTTP OK response could not be sent to ctrl socket");
	}

out:
	if (object_name)
		free(object_name);

	return cmd;
}

struct pv_cmd* pv_ctrl_socket_wait(int ctrl_fd, int timeout)
{
	int req_fd = 0, ret;
	fd_set fdset;
	struct timeval tv;
	struct pv_cmd *cmd = NULL;

	if (ctrl_fd < 0) {
		pv_log(ERROR, "control socket not setup");
		goto out;
	}

	FD_ZERO(&fdset);
	FD_SET(ctrl_fd, &fdset);
	tv.tv_sec = timeout;
	tv.tv_usec = 0;

	// select with blocking time
	ret = select(ctrl_fd + 1, &fdset, 0, 0, &tv);
	if (!ret)
		goto out;
	else if (ret < 0) {
		pv_log(ERROR, "select wait failed");
		goto out;
	}

	// create dedicated fd
	req_fd = accept(ctrl_fd, 0, 0);
	if (req_fd <= 0) {
		pv_log(ERROR, "accept connection failed");
		goto out;
	}

	cmd = pv_ctrl_read_parse_request(req_fd);

	close(req_fd);
out:
	return cmd;
}

void pv_ctrl_free_cmd(struct pv_cmd *cmd)
{
	if (!cmd)
		return;

	if (cmd->payload)
		free(cmd->payload);

	free(cmd);
}

static int pv_ctrl_init(struct pv_init *this)
{
	struct pantavisor *pv = get_pv_instance();

	pv->ctrl_fd = pv_ctrl_socket_open("/pv/pv-ctrl");
	if (pv->ctrl_fd <= 0) {
		pv_log(ERROR, "ctrl socket could not be initialized");
		return -1;
	}

	return 0;
}

struct pv_init pv_init_ctrl = {
	.init_fn = pv_ctrl_init,
	.flags = 0,
};

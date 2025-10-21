/*
 * Copyright (c) 2017-2024 Pantacor Ltd.
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
#include <sys/sendfile.h>

#include <linux/limits.h>

#include <jsmn/jsmnutil.h>

#include "ctrl.h"
#include "utils/math.h"
#include "utils/str.h"
#include "json.h"
#include "pvlogger.h"
#include "state.h"
#include "init.h"
#include "objects.h"
#include "storage.h"
#include "metadata.h"
#include "version.h"
#include "platforms.h"
#include "drivers.h"
#include "paths.h"
#include "utils/math.h"
#include "utils/fs.h"
#include "utils/socket.h"

#define MODULE_NAME "ctrl"
#define pv_log(level, msg, ...)                                                \
	vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__,       \
	     ##__VA_ARGS__)
#include "log.h"

#define ENDPOINT_CONTAINERS "/containers"
#define ENDPOINT_GROUPS "/groups"
#define ENDPOINT_SIGNAL "/signal"
#define ENDPOINT_COMMANDS "/commands"
#define ENDPOINT_OBJECTS "/objects"
#define ENDPOINT_STEPS "/steps"
#define ENDPOINT_PROGRESS "/progress"
#define ENDPOINT_COMMITMSG "/commitmsg"
#define ENDPOINT_USER_META "/user-meta"
#define ENDPOINT_DEVICE_META "/device-meta"
#define ENDPOINT_BUILDINFO "/buildinfo"
#define ENDPOINT_CONFIG "/config"
#define ENDPOINT_CONFIG2 "/config2"
#define ENDPOINT_DRIVERS "/drivers"

#define HTTP_RES_OK "HTTP/1.1 200 OK\r\n\r\n"
#define HTTP_RES_OK_SIZE "HTTP/1.1 200 \r\nContent-Length: %zd\r\n\r\n"
#define HTTP_RES_CONT "HTTP/1.1 100 Continue\r\n\r\n"

#define HTTP_RESPONSE                                                          \
	"HTTP/1.1 %s \r\nContent-Length: %zd\r\nContent-Type: application/json; charset=utf-8\r\n\r\n{\"Error\":\"%s\"}"

#define UNSUPPORTED_LOG_COMMAND_FMT                                            \
	"ERROR: unsupported legacy 'log command' command; use new REST API instead\n"

static const size_t HTTP_REQ_BUFFER_SIZE = 4096;
static const unsigned int HTTP_REQ_NUM_HEADERS = 8;

static const unsigned int HTTP_ERROR_RESPONSE_MSG_SIZE = 256;

typedef enum {
	HTTP_STATUS_BAD_REQ,
	HTTP_STATUS_FORBIDDEN,
	HTTP_STATUS_NOT_FOUND,
	HTTP_STATUS_CONFLICT,
	HTTP_STATUS_UNPROCESSABLE_ENTITY,
	HTTP_STATUS_ERROR,
	HTTP_STATUS_INSUFF_STORAGE,
} pv_http_status_code_t;

static const char *pv_ctrl_string_http_status_code(pv_http_status_code_t code)
{
	static const char *strings[] = { "400 Bad Request",
					 "403 Forbidden",
					 "404 Not Found",
					 "409 Conflict",
					 "422 Unprocessable Entity",
					 "500 Internal Server Error",
					 "507 Insufficient Storage" };
	return strings[code];
}

static int pv_ctrl_socket_open()
{
	int fd, flags;
	struct sockaddr_un addr;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		pv_log(ERROR, "ctrl socket open error: %s", strerror(errno));
		return -1;
	}

	// Set the socket to non-blocking mode
	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		pv_log(ERROR, "could not get flags from ctrl socket: %s",
		       strerror(errno));
		goto out;
	}
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		pv_log(ERROR, "could not set flags to ctrl socket: %s",
		       strerror(errno));
		goto out;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	pv_paths_pv_file(addr.sun_path, sizeof(addr.sun_path) - 1,
			 PVCTRL_FNAME);

	// sometimes, the socket file still exists after reboot
	unlink(addr.sun_path);

	if (bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
		pv_log(ERROR, "ctrl socket with fd %d open error: %s", fd,
		       strerror(errno));
		goto out;
	}

	// queue 15 commands
	if (listen(fd, 15)) {
		pv_log(ERROR, "ctrl socket with fd %d listen error: %s", fd,
		       strerror(errno));
		goto out;
	}

	return fd;
out:
	close(fd);
	return -1;
}

void pv_ctrl_socket_close(int ctrl_fd)
{
	char path[PATH_MAX];

	if (ctrl_fd >= 0) {
		pv_paths_pv_file(path, PATH_MAX, PVCTRL_FNAME);
		pv_log(DEBUG, "closing %s with fd %d", path, ctrl_fd);
		close(ctrl_fd);
		unlink(path);
	}
}

static void pv_ctrl_parse_signal(char *buf, char **signal, char **payload)
{
	int tokc;
	jsmntok_t *tokv;

	jsmnutil_parse_json(buf, &tokv, &tokc);

	*signal = pv_json_get_value(buf, "type", tokv, tokc);
	if (!signal) {
		pv_log(WARN, "unable to get type value from signal");
	}

	*payload = pv_json_get_value(buf, "payload", tokv, tokc);
	if (!payload) {
		pv_log(WARN, "unable to get payload value from signal");
	}

	if (tokv)
		free(tokv);
}

static int pv_ctrl_wait_recv(int req_fd, char *buf, size_t length)
{
	int res;
	fd_set fdset;
	struct timeval tv;

	FD_ZERO(&fdset);
	FD_SET(req_fd, &fdset);

	// for now, we wait for 1s max
	tv.tv_sec = 1;
	tv.tv_usec = 0;

	res = select(req_fd + 1, &fdset, 0, 0, &tv);
	if (res == 0) {
		pv_log(WARN, "request timed out");
		goto out;
	} else if (res < 0) {
		pv_log(WARN, "could not select socket with fd %d: %s", req_fd,
		       strerror(errno));
		goto out;
	}

	res = recv(req_fd, buf, length, MSG_DONTWAIT);

out:
	return res;
}

static void pv_ctrl_consume_req(int req_fd, size_t content_length)
{
	char buf[HTTP_REQ_BUFFER_SIZE];
	size_t total_rec = 0;
	ssize_t rec;

	while ((rec = read(req_fd, buf, content_length - total_rec)) > 0) {
		if (rec < 0)
			return;

		total_rec += rec;
	}
}

static int pv_ctrl_process_signal(int req_fd, size_t content_length,
				  char **signal, char **payload)
{
	int res;
	char req[HTTP_REQ_BUFFER_SIZE];

	memset(req, 0, sizeof(req));

	pv_log(DEBUG, "reading and parsing signal...");

	if (content_length >= HTTP_REQ_BUFFER_SIZE) {
		pv_ctrl_consume_req(req_fd, content_length);
		pv_log(WARN, "signal request too long");
		goto err;
	}

	// read request
	res = pv_ctrl_wait_recv(req_fd, req, content_length);
	if (res == 0) {
		pv_log(WARN, "nothing to read from signal request");
		goto err;
	} else if (res < 0) {
		pv_log(WARN,
		       "signal request could not be read from ctrl socket with fd %d: %s",
		       req_fd, strerror(errno));
		goto err;
	}

	req[content_length] = 0;

	pv_ctrl_parse_signal(req, signal, payload);
	if (!signal || !payload)
		goto err;

	return 0;

err:
	return -1;
}

static struct pv_cmd *pv_ctrl_parse_command(char *buf)
{
	int tokc;
	jsmntok_t *tokv = NULL;
	char *op_string = NULL;
	struct pv_cmd *cmd = NULL;

	cmd = calloc(1, sizeof(struct pv_cmd));
	if (!cmd) {
		pv_log(ERROR, "cmd could not be allocated");
		goto out;
	}

	jsmnutil_parse_json(buf, &tokv, &tokc);

	op_string = pv_json_get_value(buf, "op", tokv, tokc);
	if (!op_string) {
		pv_log(WARN, "unable to get op value from command");
		goto err;
	}

	cmd->op = pv_ctrl_int_cmd_operation(op_string, strlen(op_string));
	if (!cmd->op) {
		pv_log(WARN, "op from command unknown");
		goto err;
	}

	cmd->payload = pv_json_get_value(buf, "payload", tokv, tokc);
	if (!cmd->payload) {
		pv_log(WARN, "unable to get payload value from command");
		goto err;
	}

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

static int pv_ctrl_process_cmd(int req_fd, size_t content_length,
			       struct pv_cmd **cmd)
{
	int res;
	char req[HTTP_REQ_BUFFER_SIZE];

	memset(req, 0, sizeof(req));

	pv_log(DEBUG, "reading and parsing command...");

	if (content_length >= HTTP_REQ_BUFFER_SIZE) {
		pv_ctrl_consume_req(req_fd, content_length);
		pv_log(WARN, "cmd request too long");
		goto err;
	}

	// read request
	res = pv_ctrl_wait_recv(req_fd, req, content_length);
	if (res == 0) {
		pv_log(WARN, "nothing to read from cmd request");
		goto err;
	} else if (res < 0) {
		pv_log(WARN,
		       "cmd request could not be read from ctrl socket with fd %d: %s",
		       req_fd, strerror(errno));
		goto err;
	}

	req[content_length] = 0;

	*cmd = pv_ctrl_parse_command(req);
	if (!*cmd)
		goto err;

	return 0;

err:
	return -1;
}

static int pv_ctrl_send_all(int req_fd, const char *message, size_t size)
{
	size_t total_sent = 0;
	ssize_t size_sent;

	while (total_sent < size) {
		size_sent = send(req_fd, message + total_sent,
				 size - total_sent, MSG_NOSIGNAL);
		if (size_sent < 0)
			return size_sent;
		total_sent += size_sent;
	}

	return total_sent;
}

static void pv_ctrl_write_cont_response(int req_fd)
{
	int res;

	res = pv_ctrl_send_all(req_fd, HTTP_RES_CONT, strlen(HTTP_RES_CONT));
	if (res < 0) {
		pv_log(WARN,
		       "HTTP CONTINUE response could not be sent to ctrl socket with fd %d: %s",
		       req_fd, strerror(errno));
	} else if (res != strlen(HTTP_RES_CONT)) {
		pv_log(WARN, "HTTP CONTINUE response was not sent");
	}
}

static void pv_ctrl_write_ok_response(int req_fd)
{
	int res;

	res = pv_ctrl_send_all(req_fd, HTTP_RES_OK, strlen(HTTP_RES_OK));
	if (res < 0) {
		pv_log(WARN,
		       "HTTP OK response could not be written to ctrl socket with fd %d: %s",
		       req_fd, strerror(errno));
	} else if (res != strlen(HTTP_RES_OK)) {
		pv_log(WARN, "HTTP OK response was not sent");
	}
}

static void pv_ctrl_write_ok_response_size(int req_fd, ssize_t size)
{
	char *header = NULL;
	int len = asprintf(&header, HTTP_RES_OK_SIZE, size);
	if (len == -1) {
		pv_log(WARN, "HTTP OK response could not be allocated");
		return;
	}

	int res = pv_ctrl_send_all(req_fd, header, strlen(header));
	free(header);

	if (res < 0) {
		pv_log(WARN,
		       "HTTP OK response could not be written to ctrl socket with fd %d: %s",
		       req_fd, strerror(errno));
	} else if (res != len) {
		pv_log(WARN, "HTTP OK response was not sent");
	}
}

static void pv_ctrl_write_error_response(int req_fd, pv_http_status_code_t code,
					 const char *message)
{
	ssize_t res;
	size_t content_len, response_len;
	char *response = NULL;

	content_len = 15 + // {\"Error\":\"%s\"}\0
		      strlen(message);

	response_len = 93 + // HTTP/1.1...
		       strlen(pv_ctrl_string_http_status_code(code)) +
		       get_digit_count(content_len) + strlen(message);
	if (response_len > HTTP_REQ_BUFFER_SIZE) {
		pv_log(ERROR, "HTTP response too long");
		goto out;
	}

	response = calloc(response_len + 1, sizeof(char));
	if (!response) {
		pv_log(ERROR, "HTTP response cannot be allocated");
		goto out;
	}

	SNPRINTF_WTRUNC(response, response_len, HTTP_RESPONSE,
			pv_ctrl_string_http_status_code(code), content_len,
			message);

	res = pv_ctrl_send_all(req_fd, response, response_len);
	if (res < 0) {
		pv_log(WARN,
		       "HTTP response could not be written to ctrl socket with fd %d: %s",
		       req_fd, strerror(errno));
	} else if ((size_t)res != response_len) {
		pv_log(WARN, "HTTP error response was not sent");
	}

out:
	if (response)
		free(response);
}

static int pv_ctrl_process_put_file(int req_fd, size_t content_length,
				    bool expect_continue, char *file_path)
{
	int obj_fd = -1, read_length, write_length, ret = -1;
	char req[HTTP_REQ_BUFFER_SIZE];
	size_t free_space = (size_t)pv_storage_get_free();

	if (content_length > free_space) {
		pv_ctrl_consume_req(req_fd, content_length);
		pv_log(WARN,
		       "%zu B needed but only %zu B available. Cannot create file",
		       content_length, free_space);
		pv_ctrl_write_error_response(req_fd, HTTP_STATUS_INSUFF_STORAGE,
					     "Not enough disk space available");
		return ret;
	}

	pv_log(DEBUG,
	       "reading file with size %zu from endpoint and putting it in %s",
	       content_length, file_path);

	if (expect_continue)
		pv_ctrl_write_cont_response(req_fd);

	obj_fd = open(file_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (obj_fd < 0) {
		pv_ctrl_consume_req(req_fd, content_length);
		pv_log(ERROR, "'%s' could not be created: %s", file_path,
		       strerror(errno));
		pv_ctrl_write_error_response(req_fd, HTTP_STATUS_ERROR,
					     "Cannot create file");
		goto clean;
	}

	memset(req, 0, sizeof(req));

	// read and save
	while (content_length > 0) {
		if (content_length > HTTP_REQ_BUFFER_SIZE)
			read_length = HTTP_REQ_BUFFER_SIZE;
		else
			read_length = content_length;

		write_length = pv_ctrl_wait_recv(req_fd, req, read_length);
		if (write_length <= 0) {
			pv_log(WARN,
			       "HTTP PUT content could not be read from ctrl socket with fd %d: %s",
			       req_fd, strerror(errno));
			pv_ctrl_write_error_response(req_fd, HTTP_STATUS_ERROR,
						     "Cannot read from socket");
			goto clean;
		}

		if (write(obj_fd, req, write_length) <= 0) {
			pv_log(WARN,
			       "HTTP PUT content could not be written from ctrl socket with fd %d: %s",
			       req_fd, strerror(errno));
			pv_ctrl_write_error_response(req_fd, HTTP_STATUS_ERROR,
						     "Cannot write into file");
			goto clean;
		}

		content_length -= write_length;
	}

	ret = 0;
	goto out;

clean:
	pv_log(DEBUG, "removing '%s'...", file_path);
	pv_fs_path_remove(file_path, false);
out:
	if (obj_fd >= 0) {
		fsync(obj_fd);
		close(obj_fd);
	}

	pv_fs_path_sync(file_path);

	return ret;
}

static int pv_ctrl_read_parse_request_header(
	int req_fd, char *buf, unsigned int buf_index, const char **method,
	size_t *method_len, const char **path, size_t *path_len,
	struct phr_header *headers, size_t *num_headers)
{
	int minor_version, res = -1;

	// read from socket until end of HTTP header
	do {
		res = pv_ctrl_wait_recv(req_fd, &buf[buf_index], 1);
		if (res < 0) {
			pv_log(ERROR,
			       "HTTP request header could not read from fd %d: %s",
			       req_fd, strerror(errno));
			goto out;
		}
		if ((buf_index > 3) && (buf[buf_index - 3] == '\r') &&
		    (buf[buf_index - 2] == '\n') &&
		    (buf[buf_index - 1] == '\r') && (buf[buf_index] == '\n')) {
			break;
		}
		buf_index++;
		if (buf_index >= HTTP_REQ_BUFFER_SIZE) {
			pv_log(WARN, "HTTP request received longer than %d",
			       HTTP_REQ_BUFFER_SIZE);
			goto out;
		}
	} while (res == 1);

	// parse HTTP header
	res = phr_parse_request(buf, buf_index + 1, method, method_len, path,
				path_len, &minor_version, headers, num_headers,
				0);
	if (res < 0) {
		pv_log(WARN, "HTTP request received has bad format");
	}

out:
	return res;
}

static size_t pv_ctrl_get_value_header_int(struct phr_header *headers,
					   size_t num_headers, const char *name)
{
	size_t ret = 0;
	char *value = NULL;

	for (size_t header_index = 0; header_index < num_headers;
	     header_index++) {
		if (pv_str_matches_case(headers[header_index].name,
					headers[header_index].name_len, name,
					strlen(name))) {
			value = calloc(headers[header_index].value_len,
				       sizeof(char));
			strncpy(value, headers[header_index].value,
				headers[header_index].value_len);
			ret = strtoul(value, NULL, 10);
			free(value);
		}
	}

	return ret;
}

static bool pv_ctrl_check_header_value(struct phr_header *headers,
				       size_t num_headers, const char *header,
				       const char *value)
{
	bool ret = false;

	for (size_t header_index = 0; header_index < num_headers;
	     header_index++) {
		if (pv_str_matches_case(headers[header_index].name,
					headers[header_index].name_len, header,
					strlen(header)) &&
		    pv_str_matches_case(headers[header_index].value,
					headers[header_index].value_len, value,
					strlen(value)))
			ret = true;
	}

	return ret;
}

static void pv_ctrl_process_get_file(int req_fd, char *file_path)
{
	int obj_fd = -1;
	ssize_t sent, file_size = pv_fs_path_get_size(file_path);
	off_t offset = 0;

	pv_log(DEBUG, "reading file from %s and sending it to endpoint",
	       file_path);

	obj_fd = open(file_path, O_RDONLY);
	if (obj_fd < 0) {
		pv_log(ERROR, "%s could not be opened for read", file_path);
		goto error;
	}

	pv_ctrl_write_ok_response_size(req_fd, file_size);

	// read and send
	for (size_t to_send = file_size; to_send > 0;) {
		sent = sendfile(req_fd, obj_fd, &offset, to_send);
		if (sent < 0)
			pv_log(WARN,
			       "HTTP GET file could not be written to ctrl socket with fd %d: %s",
			       req_fd, strerror(errno));

		if (sent <= 0)
			goto out;

		to_send -= sent;
	}

	goto out;

error:
	pv_ctrl_write_error_response(req_fd, HTTP_STATUS_NOT_FOUND,
				     "Resource does not exist");
out:
	if (obj_fd >= 0)
		close(obj_fd);
}

static char *pv_ctrl_get_file_name(const char *path, size_t buf_index,
				   size_t path_len)
{
	int len;
	char *file_name;

	if (buf_index > path_len)
		return NULL;

	len = path_len - buf_index;

	file_name = calloc(len + 1, sizeof(char));
	if (!file_name)
		return NULL;

	strncpy(file_name, &path[buf_index], len);

	return file_name;
}

static void pv_ctrl_process_get_string(int req_fd, char *buf)
{
	int res, buf_len;

	pv_log(DEBUG,
	       "converting data to string and sending it to endpoint...");

	buf_len = strlen(buf);

	pv_ctrl_write_ok_response_size(req_fd, buf_len);

	res = pv_ctrl_send_all(req_fd, buf, buf_len);
	if (res < 0) {
		pv_log(WARN,
		       "HTTP GET content could not be written to ctrl socket with fd %d: %s",
		       req_fd, strerror(errno));
	} else if (res != buf_len) {
		pv_log(WARN, "HTTP GET response was not sent");
	}

	if (buf)
		free(buf);
}

static char *pv_ctrl_get_body(int req_fd, size_t content_length)
{
	int res;
	char *req = NULL;

	if (content_length >= HTTP_REQ_BUFFER_SIZE) {
		pv_ctrl_consume_req(req_fd, content_length);
		pv_log(WARN, "body too long");
		goto err;
	}

	req = calloc(content_length + 1, sizeof(char));

	// read request
	res = pv_ctrl_wait_recv(req_fd, req, content_length);
	if (res == 0) {
		pv_log(WARN, "nothing to read from HTTP GET body");
		goto err;
	} else if (res < 0) {
		pv_log(WARN,
		       "HTTP GET body could not be read to ctrl socket with fd %d: %s",
		       req_fd, strerror(errno));
		goto err;
	}
	req[content_length] = 0;

	return req;

err:
	if (req)
		free(req);

	return NULL;
}

static int pv_ctrl_check_command(int req_fd, struct pv_cmd **cmd)
{
	if (!cmd || !(*cmd))
		return -1;

	struct pantavisor *pv = pv_get_instance();

	if (!pv->remote_mode && ((*cmd)->op == CMD_UPDATE_METADATA)) {
		pv_ctrl_write_error_response(
			req_fd, HTTP_STATUS_CONFLICT,
			"Cannot do this operation while on local mode");
		goto error;
	}

	if (pv->update && (((*cmd)->op == CMD_REBOOT_DEVICE) ||
			   ((*cmd)->op == CMD_POWEROFF_DEVICE) ||
			   ((*cmd)->op == CMD_LOCAL_RUN) ||
			   ((*cmd)->op == CMD_LOCAL_RUN_COMMIT) ||
			   ((*cmd)->op == CMD_MAKE_FACTORY))) {
		pv_ctrl_write_error_response(
			req_fd, HTTP_STATUS_CONFLICT,
			"Cannot do this operation while update is ongoing");
		goto error;
	}

	if (!pv->unclaimed && ((*cmd)->op == CMD_MAKE_FACTORY)) {
		pv_ctrl_write_error_response(
			req_fd, HTTP_STATUS_CONFLICT,
			"Cannot do this operation if device is already claimed");
		goto error;
	}

	if (!pv_config_get_bool(PV_CONTROL_REMOTE) &&
	    ((*cmd)->op == CMD_GO_REMOTE)) {
		pv_ctrl_write_error_response(
			req_fd, HTTP_STATUS_CONFLICT,
			"Cannot do this operation when remote mode is disabled by config");
		goto error;
	}

	if (!pv_config_get_bool(PV_DEBUG_SHELL) &&
	    ((*cmd)->op == CMD_DEFER_REBOOT)) {
		pv_ctrl_write_error_response(
			req_fd, HTTP_STATUS_CONFLICT,
			"Cannot do this operation when debug shell is not active");
		pv_log(WARN,
		       "Cannot do this operation when debug shell is not active");

		goto error;
	}

	if (pv->remote_mode && ((*cmd)->op == CMD_GO_REMOTE)) {
		pv_ctrl_write_error_response(req_fd, HTTP_STATUS_CONFLICT,
					     "Already in remote mode");
		goto error;
	}

	if (pv->cmd) {
		pv_ctrl_write_error_response(
			req_fd, HTTP_STATUS_CONFLICT,
			"A command is already in progress. Try again");
		goto error;
	}

	return 0;

error:
	pv_ctrl_free_cmd(*cmd);
	*cmd = NULL;
	return -1;
}

static char *pv_ctrl_get_sender_pname(int req_fd)
{
	pid_t sender_pid;
	sender_pid = pv_socket_get_sender_pid(req_fd);

	if (sender_pid < 0) {
		pv_log(WARN, "could not get pid from sender: %s",
		       strerror(errno));
		return NULL;
	}

	return pv_cgroup_get_process_name(sender_pid);
}

static struct pv_platform *pv_ctrl_get_sender_plat(const char *pname)
{
	struct pantavisor *pv = pv_get_instance();
	struct pv_platform *plat;

	plat = pv_state_fetch_platform(pv->state, pname);
	if (!plat)
		pv_log(WARN, "could not find platform %s in current state",
		       pname);

	return plat;
}

static bool pv_ctrl_check_sender_privileged(const char *pname)
{
	// if this is from root context we are privileged
	if (!strcmp(pname, "_pv_"))
		return true;

	struct pv_platform *plat = pv_ctrl_get_sender_plat(pname);

	return plat ? pv_platform_has_role(plat, PLAT_ROLE_MGMT) : false;
}

static struct pv_cmd *
pv_ctrl_process_endpoint_and_reply(int req_fd, const char *method,
				   size_t method_len, const char *path,
				   size_t path_len, size_t content_length,
				   bool expect_continue, char *pname)
{
	bool mgmt;
	struct pv_cmd *cmd = NULL;
	struct pantavisor *pv = pv_get_instance();
	char *file_name = NULL;
	char file_path_parent[PATH_MAX] = { 0 }, file_path[PATH_MAX] = { 0 },
	     file_path_tmp[PATH_MAX] = { 0 };
	char *signal = NULL, *payload = NULL;
	char *metakey = NULL, *metavalue = NULL;
	char *driverkey = NULL, *drivervalue = NULL;
	char *drivername = NULL;
	char *driverop = NULL;
	char msg[HTTP_ERROR_RESPONSE_MSG_SIZE];
	struct pv_platform *p = pv_ctrl_get_sender_plat(pname);
	struct stat st;

	mgmt = pv_ctrl_check_sender_privileged(pname);

	if (pv_str_matches(ENDPOINT_CONTAINERS, strlen(ENDPOINT_CONTAINERS),
			   path, path_len)) {
		if (!strncmp("GET", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			pv_ctrl_process_get_string(
				req_fd,
				pv_state_get_containers_json(pv->state));
		} else
			goto err_me;
	} else if (pv_str_matches(ENDPOINT_GROUPS, strlen(ENDPOINT_GROUPS),
				  path, path_len)) {
		if (!strncmp("GET", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			pv_ctrl_process_get_string(
				req_fd, pv_state_get_groups_json(pv->state));
		} else
			goto err_me;
	} else if (pv_str_matches(ENDPOINT_SIGNAL, strlen(ENDPOINT_SIGNAL),
				  path, path_len)) {
		if (!strncmp("POST", method, method_len)) {
			if (pv_ctrl_process_signal(req_fd, content_length,
						   &signal, &payload)) {
				pv_ctrl_write_error_response(
					req_fd, HTTP_STATUS_BAD_REQ,
					"Signal has bad format");
				goto out;
			}
			if (pv_state_interpret_signal(pv->state, pname, signal,
						      payload)) {
				pv_ctrl_write_error_response(
					req_fd, HTTP_STATUS_ERROR,
					"Signal not expected from this platform");
				goto out;
			}
			pv_ctrl_write_ok_response(req_fd);
		} else
			goto err_me;
	} else if (pv_str_startswith(ENDPOINT_COMMANDS,
				     strlen(ENDPOINT_COMMANDS), path)) {
		if (!strncmp("POST", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			if (pv_ctrl_process_cmd(req_fd, content_length, &cmd) <
			    0) {
				pv_ctrl_write_error_response(
					req_fd, HTTP_STATUS_BAD_REQ,
					"Command has bad format");
				goto out;
			}
			if (pv_ctrl_check_command(req_fd, &cmd) < 0)
				goto out;
			pv_ctrl_write_ok_response(req_fd);
		} else
			goto err_me;
	} else if (pv_str_matches(ENDPOINT_OBJECTS, strlen(ENDPOINT_OBJECTS),
				  path, path_len)) {
		if (!strncmp("GET", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			pv_ctrl_process_get_string(
				req_fd, pv_objects_get_list_string());
		} else
			goto err_me;
	} else if (pv_str_startswith(ENDPOINT_OBJECTS, strlen(ENDPOINT_OBJECTS),
				     path)) {
		file_name = pv_ctrl_get_file_name(
			path, sizeof(ENDPOINT_OBJECTS), path_len);
		pv_paths_storage_object(file_path, PATH_MAX, file_name);
		pv_paths_tmp(file_path_tmp, PATH_MAX, file_path);
		// sha must have 64 characters
		if (!file_name || (strlen(file_name) != 64)) {
			pv_log(WARN, "HTTP request has bad object name %s",
			       file_name);
			pv_ctrl_write_error_response(
				req_fd, HTTP_STATUS_BAD_REQ,
				"Request has bad object name");
			goto out;
		}

		if (!strncmp("PUT", method, method_len)) {
			if (!mgmt) {
				pv_ctrl_consume_req(req_fd, content_length);
				goto err_pr;
			}
			if (pv_ctrl_process_put_file(req_fd, content_length,
						     expect_continue,
						     file_path_tmp) < 0)
				goto out;
			if (pv_fs_path_exist(file_path) &&
			    !pv_storage_validate_file_checksum(file_path,
							       file_name)) {
				pv_log(WARN,
				       "object %s already exists and is valid; discarding new object upload",
				       file_path_tmp);
				pv_fs_path_remove(file_path_tmp, false);

			} else if (pv_storage_validate_file_checksum(
					   file_path_tmp, file_name) < 0) {
				pv_log(WARN, "object %s has bad checksum",
				       file_path_tmp);
				pv_ctrl_write_error_response(
					req_fd,
					HTTP_STATUS_UNPROCESSABLE_ENTITY,
					"Object has bad checksum");
				goto out;
			} else {
				pv_log(DEBUG, "renaming %s to %s",
				       file_path_tmp, file_path);
				if (pv_fs_path_rename(file_path_tmp,
						      file_path) < 0) {
					pv_log(ERROR, "could not rename: %s",
					       strerror(errno));
					pv_ctrl_write_error_response(
						req_fd, HTTP_STATUS_ERROR,
						"Cannot rename object");
					goto out;
				}
			}
			pv_storage_gc_defer_run_threshold();
			pv_ctrl_write_ok_response(req_fd);
		} else if (!strncmp("GET", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			pv_ctrl_process_get_file(req_fd, file_path);
		} else
			goto err_me;
	} else if (pv_str_matches(ENDPOINT_STEPS, strlen(ENDPOINT_STEPS), path,
				  path_len)) {
		if (!strncmp("GET", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			pv_ctrl_process_get_string(
				req_fd, pv_storage_get_revisions_string());
		} else
			goto err_me;
	} else if (pv_str_startswith(ENDPOINT_STEPS, strlen(ENDPOINT_STEPS),
				     path) &&
		   pv_str_endswith(ENDPOINT_PROGRESS, strlen(ENDPOINT_PROGRESS),
				   path, path_len)) {
		file_name = pv_ctrl_get_file_name(
			path, sizeof(ENDPOINT_STEPS),
			path_len - strlen(ENDPOINT_PROGRESS));
		pv_paths_storage_trail_pv_file(file_path, PATH_MAX, file_name,
					       PROGRESS_FNAME);

		if (!file_name) {
			pv_log(WARN, "HTTP request has bad step name %s",
			       file_name);
			pv_ctrl_write_error_response(
				req_fd, HTTP_STATUS_BAD_REQ,
				"Request has bad step name");
			goto out;
		}

		if (!strncmp("GET", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			pv_ctrl_process_get_file(req_fd, file_path);
		} else
			goto err_me;
	} else if (pv_str_startswith(ENDPOINT_STEPS, strlen(ENDPOINT_STEPS),
				     path) &&
		   pv_str_endswith(ENDPOINT_COMMITMSG,
				   strlen(ENDPOINT_COMMITMSG), path,
				   path_len)) {
		file_name = pv_ctrl_get_file_name(
			path, sizeof(ENDPOINT_STEPS),
			path_len - strlen(ENDPOINT_COMMITMSG));
		pv_paths_storage_trail_pv_file(file_path_parent, PATH_MAX,
					       file_name, "");
		pv_paths_storage_trail_pv_file(file_path, PATH_MAX, file_name,
					       COMMITMSG_FNAME);
		pv_paths_tmp(file_path_tmp, PATH_MAX, file_path);

		if (!file_name) {
			pv_log(WARN, "HTTP request has bad step name %s",
			       file_name);
			pv_ctrl_write_error_response(
				req_fd, HTTP_STATUS_BAD_REQ,
				"Request has bad step name");
			goto out;
		}

		if (!strncmp("PUT", method, method_len)) {
			if (!mgmt) {
				pv_ctrl_consume_req(req_fd, content_length);
				goto err_pr;
			}

			pv_fs_mkdir_p(file_path_parent, 0755);
			if (pv_ctrl_process_put_file(req_fd, content_length,
						     expect_continue,
						     file_path_tmp) < 0)
				goto out;
			pv_log(DEBUG, "renaming %s to %s", file_path_tmp,
			       file_path);
			if (pv_fs_path_rename(file_path_tmp, file_path) < 0) {
				pv_log(ERROR, "could not rename: %s",
				       strerror(errno));
				pv_ctrl_write_error_response(
					req_fd, HTTP_STATUS_ERROR,
					"Cannot rename commitmsg");
				goto out;
			}
			pv_ctrl_write_ok_response(req_fd);
		} else
			goto err_me;
	} else if (pv_str_startswith(ENDPOINT_STEPS, strlen(ENDPOINT_STEPS),
				     path)) {
		file_name = pv_ctrl_get_file_name(path, sizeof(ENDPOINT_STEPS),
						  path_len);
		pv_paths_storage_trail_pvr_file(file_path_parent, PATH_MAX,
						file_name, "");
		pv_paths_storage_trail_pvr_file(file_path, PATH_MAX, file_name,
						JSON_FNAME);

		if (!file_name) {
			pv_log(WARN, "HTTP request has bad step name %s",
			       file_name);
			pv_ctrl_write_error_response(
				req_fd, HTTP_STATUS_BAD_REQ,
				"Request has bad step name");
			goto out;
		}

		if (!strncmp("PUT", method, method_len)) {
			if (!mgmt) {
				pv_ctrl_consume_req(req_fd, content_length);
				goto err_pr;
			}
			if (!pv_storage_is_revision_local(file_name)) {
				pv_ctrl_consume_req(req_fd, content_length);
				pv_log(ERROR, "wrong local step name %s",
				       file_name);
				pv_ctrl_write_error_response(
					req_fd, HTTP_STATUS_BAD_REQ,
					"Step name has bad name");
				goto out;
			}
			pv_fs_mkdir_p(file_path_parent, 0755);
			if (pv_ctrl_process_put_file(req_fd, content_length,
						     expect_continue,
						     file_path) < 0)
				goto out;
			if (!pv_storage_verify_state_json(
				    file_name, msg,
				    HTTP_ERROR_RESPONSE_MSG_SIZE)) {
				pv_log(ERROR, "state verification went wrong");
				pv_ctrl_write_error_response(
					req_fd,
					HTTP_STATUS_UNPROCESSABLE_ENTITY, msg);
				pv_storage_rm_rev(file_name);
				goto out;
			}
			pv_ctrl_write_ok_response(req_fd);
		} else if (!strncmp("GET", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			pv_ctrl_process_get_file(req_fd, file_path);
		} else
			goto err_me;
	} else if (pv_str_matches(ENDPOINT_USER_META,
				  strlen(ENDPOINT_USER_META), path, path_len)) {
		if (!strncmp("GET", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			pv_ctrl_process_get_string(
				req_fd, pv_metadata_get_user_meta_string());
		} else
			goto err_me;
	} else if (pv_str_matches(ENDPOINT_DEVICE_META,
				  strlen(ENDPOINT_DEVICE_META), path,
				  path_len)) {
		if (!strncmp("GET", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			pv_ctrl_process_get_string(
				req_fd, pv_metadata_get_device_meta_string());
		} else
			goto err_me;
	} else if (pv_str_matches(ENDPOINT_BUILDINFO,
				  strlen(ENDPOINT_BUILDINFO), path, path_len)) {
		if (!strncmp("GET", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			pv_ctrl_process_get_string(req_fd,
						   strdup(pv_build_manifest));
		} else
			goto err_me;
	} else if (pv_str_startswith(ENDPOINT_USER_META,
				     strlen(ENDPOINT_USER_META), path)) {
		metakey = pv_ctrl_get_file_name(
			path, sizeof(ENDPOINT_USER_META), path_len);

		if (!metakey) {
			pv_log(WARN, "HTTP request has bad meta name %s",
			       metakey);
			pv_ctrl_write_error_response(
				req_fd, HTTP_STATUS_BAD_REQ,
				"Request has bad metadata key name");
			goto out;
		}

		if (!strncmp("PUT", method, method_len)) {
			if (!mgmt) {
				pv_ctrl_consume_req(req_fd, content_length);
				goto err_pr;
			}
			metavalue = pv_ctrl_get_body(req_fd, content_length);
			if (pv_metadata_add_usermeta(metakey, metavalue) < 0)
				pv_ctrl_write_error_response(
					req_fd, HTTP_STATUS_ERROR,
					"Cannot add or update user meta");
			pv_ctrl_write_ok_response(req_fd);
		} else if (!strncmp("DELETE", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			if (pv_metadata_rm_usermeta(metakey) < 0)
				pv_ctrl_write_error_response(
					req_fd, HTTP_STATUS_NOT_FOUND,
					"User meta does not exist");
			pv_ctrl_write_ok_response(req_fd);
		} else
			goto err_me;
	} else if (pv_str_startswith(ENDPOINT_DEVICE_META,
				     strlen(ENDPOINT_DEVICE_META), path)) {
		metakey = pv_ctrl_get_file_name(
			path, sizeof(ENDPOINT_DEVICE_META), path_len);

		if (!metakey) {
			pv_log(WARN, "HTTP request has bad meta name %s",
			       metakey);
			pv_ctrl_write_error_response(
				req_fd, HTTP_STATUS_BAD_REQ,
				"Request has bad metadata key name");
			goto out;
		}

		if (!strncmp("PUT", method, method_len)) {
			if (!mgmt) {
				pv_ctrl_consume_req(req_fd, content_length);
				goto err_pr;
			}
			metavalue = pv_ctrl_get_body(req_fd, content_length);
			if (pv_metadata_add_devmeta(metakey, metavalue) < 0)
				pv_ctrl_write_error_response(
					req_fd, HTTP_STATUS_ERROR,
					"Cannot add or update device meta");
			pv_ctrl_write_ok_response(req_fd);
		} else if (!strncmp("DELETE", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			if (pv_metadata_rm_devmeta(metakey) < 0)
				pv_ctrl_write_error_response(
					req_fd, HTTP_STATUS_NOT_FOUND,
					"Device meta does not exist");
			pv_ctrl_write_ok_response(req_fd);
		} else
			goto err_me;
	} else if (pv_str_matches(ENDPOINT_DRIVERS, strlen(ENDPOINT_DRIVERS),
				  path, path_len)) {
		if (!strncmp("GET", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			pv_ctrl_process_get_string(req_fd,
						   pv_drivers_state_all(p));
		} else
			goto err_me;
	} else if (pv_str_startswith(ENDPOINT_DRIVERS, strlen(ENDPOINT_DRIVERS),
				     path)) {
		driverkey = pv_ctrl_get_file_name(
			path, sizeof(ENDPOINT_DRIVERS), path_len);

		if (!driverkey) {
			pv_log(WARN, "HTTP request has bad driver alias");
			pv_ctrl_write_error_response(
				req_fd, HTTP_STATUS_BAD_REQ,
				"Request has bad driver key name");
			goto out;
		}

		if (!strncmp("PUT", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			if (!strchr(driverkey, '/')) {
				if (!p) {
					pv_log(WARN,
					       "HTTP request has bad sender");
					pv_ctrl_write_error_response(
						req_fd, HTTP_STATUS_BAD_REQ,
						"Request comes from wrong sender");
				}
				if (!strcmp(driverkey, "load")) {
					if (pv_platform_load_drivers(
						    p, NULL, DRIVER_MANUAL) >=
					    0)
						pv_ctrl_write_ok_response(
							req_fd);
					else
						pv_ctrl_write_error_response(
							req_fd,
							HTTP_STATUS_BAD_REQ,
							"Error loading drivers");
				} else if (!strcmp(driverkey, "unload")) {
					pv_platform_unload_drivers(
						p, NULL, DRIVER_MANUAL);
					pv_ctrl_write_ok_response(req_fd);
				} else {
					pv_ctrl_write_error_response(
						req_fd, HTTP_STATUS_BAD_REQ,
						"Request has bad driver key name");
				}
				goto out;
			}
			drivername = strtok(driverkey, "/");
			driverop = strtok(NULL, "/");
			if (driverop && !strcmp(driverop, "load"))
				pv_platform_load_drivers(p, drivername,
							 DRIVER_MANUAL);
			else if (driverop && !strcmp(driverop, "unload"))
				pv_platform_unload_drivers(p, drivername,
							   DRIVER_MANUAL);
			else if (!driverop)
				pv_ctrl_write_error_response(
					req_fd, HTTP_STATUS_BAD_REQ,
					"no driver name provided in PUT");
			else {
				pv_ctrl_write_error_response(
					req_fd, HTTP_STATUS_BAD_REQ,
					"no valid driver operation provided in PUT; should be load or unload");
				goto out;
			}

			pv_ctrl_write_ok_response(req_fd);
		} else if (!strncmp("GET", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			if (driverkey) {
				pv_ctrl_process_get_string(
					req_fd, strdup(pv_drivers_state_str(
							driverkey)));
			}
		} else
			goto err_me;
	} else if (pv_str_matches(ENDPOINT_CONFIG, strlen(ENDPOINT_CONFIG),
				  path, path_len)) {
		if (!strncmp("GET", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			pv_ctrl_process_get_string(req_fd,
						   pv_config_get_alias_json());
		} else
			goto err_me;
	} else if (pv_str_matches(ENDPOINT_CONFIG2, strlen(ENDPOINT_CONFIG2),
				  path, path_len)) {
		if (!strncmp("GET", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			pv_ctrl_process_get_string(req_fd,
						   pv_config_get_json());
		} else
			goto err_me;
	} else {
		goto err_ep;
	}
	goto out;

err_ep:
	pv_log(WARN, "HTTP request received has unknown endpoint");
	pv_ctrl_write_error_response(req_fd, HTTP_STATUS_BAD_REQ,
				     "Unknown endpoint");
	goto out;

err_me:
	pv_log(WARN, "HTTP method not supported for this endpoint");
	pv_ctrl_write_error_response(req_fd, HTTP_STATUS_BAD_REQ,
				     "Method not supported for this endpoint");
	goto out;

err_pr:
	pv_log(WARN, "request not sent from mgmt platform");
	pv_ctrl_write_error_response(req_fd, HTTP_STATUS_FORBIDDEN,
				     "Request not sent from mgmt platform");

out:
	if (!stat(file_path_tmp, &st)) {
		pv_log(DEBUG, "removing %s", file_path_tmp);
		pv_fs_path_remove(file_path_tmp, false);
	}
	if (pname)
		free(pname);
	if (file_name)
		free(file_name);
	if (signal)
		free(signal);
	if (payload)
		free(payload);
	if (metakey)
		free(metakey);
	if (metavalue)
		free(metavalue);
	if (driverkey)
		free(driverkey);
	if (drivervalue)
		free(drivervalue);

	return cmd;
}

static struct pv_cmd *pv_ctrl_read_parse_request(int req_fd)
{
	char buf[HTTP_REQ_BUFFER_SIZE];
	char *pname;
	int buf_index = 0;
	const char *method, *path;
	size_t method_len, path_len, num_headers = HTTP_REQ_NUM_HEADERS,
				     content_length;
	struct phr_header headers[HTTP_REQ_NUM_HEADERS];
	struct pv_cmd *cmd = NULL;
	bool expect_continue = false;

	memset(buf, 0, sizeof(buf));

	pname = pv_ctrl_get_sender_pname(req_fd);
	if (!pname) {
		pv_log(WARN, "could not find a sender platform name");
		goto out;
	}

	pv_log(DEBUG, "request received from platform %s", pname);

	// legacy commands are only for mgmt platforms
	if (pv_ctrl_check_sender_privileged(pname)) {
		// read first character to see if the request is a non-HTTP legacy one
		if (pv_ctrl_wait_recv(req_fd, &buf[0], 1) < 0) {
			pv_log(WARN,
			       "could not read first character from socket with fd %d: %s",
			       req_fd, strerror(errno));
			goto out;
		}
		buf_index++;

		// if character is 3 (old code for json command), it is non-HTTP
		if (buf[0] == 3) {
			pv_ctrl_process_cmd(req_fd, HTTP_REQ_BUFFER_SIZE - 1,
					    &cmd);
			goto out;
		} else if (buf[0] == 2) {
			write(req_fd, UNSUPPORTED_LOG_COMMAND_FMT,
			      sizeof(UNSUPPORTED_LOG_COMMAND_FMT));
			// not supported log command ... just return.
			goto out;
		}
	}

	// at this point, the request can only be either HTTP or bad formatted
	buf_index = pv_ctrl_read_parse_request_header(req_fd, buf, buf_index,
						      &method, &method_len,
						      &path, &path_len, headers,
						      &num_headers);
	if (buf_index < 0) {
		pv_ctrl_write_error_response(req_fd, HTTP_STATUS_BAD_REQ,
					     "Request has bad format");
		goto out;
	}

	pv_log(DEBUG, "HTTP request received: %.*s %.*s", method_len, method,
	       path_len, path);

	content_length = pv_ctrl_get_value_header_int(headers, num_headers,
						      "content-length");
	expect_continue = pv_ctrl_check_header_value(headers, num_headers,
						     "expect", "100-continue");

	cmd = pv_ctrl_process_endpoint_and_reply(req_fd, method, method_len,
						 path, path_len, content_length,
						 expect_continue, pname);
out:
	return cmd;
}

void pv_ctrl_socket_read(int fd, short event, void *arg)
{
	pv_log(DEBUG, "run event: cb=%p", (void *)pv_ctrl_socket_read);

	int req_fd = 0, ret;

	struct pantavisor *pv = pv_get_instance();
	if (!pv)
		return;

	if (fd < 0) {
		pv_log(ERROR, "control socket not setup");
		return;
	}

	// create dedicated fd
	req_fd = accept(fd, 0, 0);
	if (req_fd < 0) {
		pv_log(WARN, "could not accept ctrl socket with fd %d: %s", fd,
		       strerror(errno));
		return;
	}

	struct pv_cmd *cmd;
	cmd = pv_ctrl_read_parse_request(req_fd);
	// we don't want to queue any command if one is already being processed
	if (!pv->cmd)
		pv->cmd = cmd;

	close(req_fd);
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
	struct pantavisor *pv = pv_get_instance();

	pv->ctrl_fd = pv_ctrl_socket_open();
	if (pv->ctrl_fd < 0) {
		pv_log(ERROR, "ctrl socket could not be initialized");
		return -1;
	}

	pv_log(DEBUG, "ctrl socket initialized with fd %d", pv->ctrl_fd);

	return 0;
}

struct pv_init pv_init_ctrl = {
	.init_fn = pv_ctrl_init,
	.flags = 0,
};

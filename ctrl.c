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
#include "json.h"
#include "str.h"
#include "pvlogger.h"
#include "state.h"
#include "init.h"
#include "objects.h"
#include "storage.h"
#include "metadata.h"

#define MODULE_NAME             "ctrl"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#define CTRL_SOCKET_PATH "/pv/pv-ctrl"

#define ENDPOINT_COMMANDS "/commands"
#define ENDPOINT_OBJECTS "/objects"
#define ENDPOINT_STEPS "/steps"
#define ENDPOINT_PROGRESS "/progress"
#define ENDPOINT_USER_META "/user-meta"
#define ENDPOINT_DEVICE_META "/device-meta"

#define PATH_OBJECTS "%s/objects/%s"
#define PATH_TRAILS_PARENT "%s/trails/%s/.pvr"
#define PATH_TRAILS "%s/trails/%s/.pvr/json"
#define PATH_TRAILS_PROGRESS "%s/trails/%s/.pv/progress"

#define HTTP_RES_OK "HTTP/1.1 200 OK\r\n\r\n"
#define HTTP_RES_CONT "HTTP/1.1 100 Continue\r\n\r\n"
#define HTTP_RES_BAD_REQ "HTTP/1.1 400 Bad Request\r\n\r\n"
#define HTTP_RES_ERROR "HTTP/1.1 500 Internal Server Error\r\n\r\n"

static const unsigned int HTTP_REQ_BUFFER_SIZE = 4096;
static const unsigned int HTTP_REQ_NUM_HEADERS = 8;

static int pv_ctrl_socket_open(char *path)
{
	int fd;
	struct sockaddr_un addr;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		pv_log(ERROR, "ctrl socket open error: %s", strerror(errno));
		goto out;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, path);

	if (bind(fd, (const struct sockaddr *) &addr, sizeof(addr)) < 0) {
		pv_log(ERROR, "ctrl socket with fd %d open error: %s", fd, strerror(errno));
		close(fd);
		fd = -1;
		goto out;
	}

	// queue 15 commands
	if (listen(fd, 15)) {
		pv_log(ERROR, "ctrl socket with fd %d listen error: %s", fd, strerror(errno));
		return -1;
	}

out:
	return fd;
}

void pv_ctrl_socket_close(int ctrl_fd)
{
	if (ctrl_fd >= 0) {
		pv_log(DEBUG, "closing ctrl socket with fd %d", ctrl_fd);
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

	op_string = pv_json_get_value(buf, "op", tokv, tokc);
	if(!op_string) {
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
		pv_log(INFO, "cmd request could not be read from ctrl socket with fd %d: %s",
			req_fd, strerror(errno));
		goto err;
	}

	*cmd = pv_ctrl_parse_command(req);
	if (!*cmd)
		goto err;

	return 0;

err:
	return -1;
}

static int pv_ctrl_process_put_file(int req_fd, size_t content_length, char* file_path)
{
	int obj_fd, read_length, write_length, ret = -1;
	char req[HTTP_REQ_BUFFER_SIZE];

	memset(req, 0, sizeof(req));

	pv_log(INFO, "reading file from endpoint and putting it in %s...", file_path);

	if (write(req_fd, HTTP_RES_CONT, sizeof(HTTP_RES_CONT)-1) <= 0)
		pv_log(INFO, "HTTP CONTINUE response could not be sent to ctrl socket with fd %d: %s",
			req_fd, strerror(errno));

	// open will fail if the file exist so we do not overwrite it
	obj_fd = open(file_path, O_CREAT | O_EXCL | O_WRONLY, 0644);
	if (obj_fd < 0) {
		pv_log(ERROR, "%s could not be created", file_path);
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
			pv_log(INFO, "HTTP PUT content could not be read from ctrl socket with fd %d: %s",
				req_fd, strerror(errno));
			goto out;
		}

		if (write(obj_fd, req, write_length) <= 0) {
			pv_log(INFO, "HTTP PUT content could not be written from ctrl socket with fd %d: %s",
				req_fd, strerror(errno));
			goto out;
		}

		content_length-=write_length;
	}

	ret = 0;

out:
	fsync(obj_fd);
	close(obj_fd);

	return ret;
}

static int pv_ctrl_validate_object_checksum(char *file_path, char *sha)
{
	if (pv_storage_validate_file_checksum(file_path, sha)) {
		pv_log(DEBUG, "removing %s...", file_path);
		remove(file_path);
		syncdir(file_path);
		return -1;
	}

	return 0;
}

static int pv_ctrl_read_parse_request_header(int req_fd,
											char *buf,
											unsigned int buf_index,
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
		if ((buf_index > 3) &&
			(buf[buf_index-3] == '\r') &&
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

static void pv_ctrl_process_get_file(int req_fd, char *file_path)
{
	int obj_fd, read_length;
	char buf[HTTP_REQ_BUFFER_SIZE];

	memset(buf, 0, sizeof(buf));

	pv_log(INFO, "reading file from %s and sending it to endpoint...", file_path);

	obj_fd = open(file_path, O_RDONLY);
	if (obj_fd < 0) {
		pv_log(ERROR, "%s could not be opened for read", file_path);
		goto error;
	}

	if (write(req_fd, HTTP_RES_OK, sizeof(HTTP_RES_OK)-1) <= 0)
		pv_log(INFO, "HTTP OK response could not be written to ctrl socket with fd %d: %s",
			req_fd, strerror(errno));

	// read and send
	while ((read_length = read(obj_fd, buf, HTTP_REQ_BUFFER_SIZE)) > 0) {
		if (write(req_fd, buf, read_length) != read_length) {
			pv_log(INFO, "HTTP GET content could not be written to ctrl socket with fd %d: %s",
				req_fd, strerror(errno));
			goto out;
		}
	}

	goto out;

error:
	if (write(req_fd, HTTP_RES_ERROR, sizeof(HTTP_RES_ERROR)-1) <= 0)
		pv_log(ERROR, "HTTP Internal Server Error response could not be sent to ctrl socket");
out:
	close(obj_fd);
}

static char* pv_ctrl_get_file_name(const char* path, int buf_index, size_t path_len)
{
	int len;
	char* file_name;

	len = path_len - buf_index;

	file_name = calloc(1, (len + 1) * sizeof(char));
	if (!file_name)
		return NULL;

	strncpy(file_name, &path[buf_index], len);

	return file_name;
}

static char* pv_ctrl_get_file_path(const char* path, const char* file_name)
{
	int len;
	char* file_path;

	len = strlen(path) + strlen(pv_config_get_storage_mntpoint()) + strlen(file_name) + 1;
	file_path = calloc(1, len * sizeof(char*));
	if (!file_path)
		return NULL;
	snprintf(file_path, len, path, pv_config_get_storage_mntpoint(), file_name);

	return file_path;
}

static void pv_ctrl_process_get_string(int req_fd, char* buf)
{
	int buf_len;

	pv_log(INFO, "converting data to string and sending it to endpoint...");

	buf_len = strlen(buf);

	if (write(req_fd, HTTP_RES_OK, sizeof(HTTP_RES_OK)-1) <= 0)
		pv_log(INFO, "HTTP OK response could not be written to ctrl socket with fd %d: %s",
			req_fd, strerror(errno));

	if (write(req_fd, buf, buf_len) != buf_len)
		pv_log(INFO, "HTTP GET content could not be written to ctrl socket with fd %d: %s",
			req_fd, strerror(errno));

	if (buf)
		free(buf);
}

static char *pv_ctrl_get_body(int req_fd, size_t content_length)
{
	char *req = NULL;

	if (content_length > HTTP_REQ_BUFFER_SIZE) {
		pv_log(WARN, "body too long");
		goto err;
	}

	req = calloc(1, content_length);

	// read request
	if (read(req_fd, req, content_length) <= 0) {
		pv_log(INFO, "HTTP GET body could not be read to ctrl socket with fd %d: %s",
			req_fd, strerror(errno));
		goto err;
	}

	return req;

err:
	if (req)
		free(req);

	return NULL;
}

static struct pv_cmd* pv_ctrl_read_parse_request(int req_fd)
{
	char buf[HTTP_REQ_BUFFER_SIZE];
	int buf_index = 0, res = -1;
	const char *method, *path;
	size_t method_len, path_len, num_headers = HTTP_REQ_NUM_HEADERS, content_length;
	struct phr_header headers[HTTP_REQ_NUM_HEADERS];
	struct pv_cmd *cmd = NULL;
	char *file_name = NULL, *file_path_parent = NULL, *file_path = NULL;
	char *metakey = NULL, *metavalue = NULL;

	memset(buf, 0, sizeof(buf));

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
		goto bad_request;
	}

	content_length = pv_ctrl_get_value_header_int(headers, num_headers, "Content-Length");
	if (content_length <= 0) {
		pv_log(WARN, "HTTP request received has empty body");
		goto bad_request;
	}

	// read and parse rest of message
	if (pv_str_startswith(ENDPOINT_COMMANDS, strlen(ENDPOINT_COMMANDS), path)) {
		if (!strncmp("POST", method, method_len)) {
			res = pv_ctrl_process_cmd(req_fd, content_length, &cmd);
		}
	} else if (pv_str_matches(ENDPOINT_OBJECTS, strlen(ENDPOINT_OBJECTS), path, path_len)) {
		if (!strncmp("GET", method, method_len)) {
			pv_ctrl_process_get_string(req_fd, pv_objects_get_list_string());
			goto out;
		}
	} else if (pv_str_startswith(ENDPOINT_OBJECTS, strlen(ENDPOINT_OBJECTS), path)) {
		file_name = pv_ctrl_get_file_name(path, sizeof(ENDPOINT_OBJECTS), path_len);
		file_path = pv_ctrl_get_file_path(PATH_OBJECTS, file_name);

		// sha must have 64 characters
		if (!file_name || !file_path || (strlen(file_name) != 64)) {
			pv_log(WARN, "HTTP request has bad object name %s", file_name);
			goto response;
		}

		if (!strncmp("PUT", method, method_len)) {
			res = pv_ctrl_process_put_file(req_fd, content_length, file_path);
			if (!res)
				res = pv_ctrl_validate_object_checksum(file_path, file_name);
		} else if (!strncmp("GET", method, method_len)) {
			pv_ctrl_process_get_file(req_fd, file_path);
			goto out;
		}
	} else if (pv_str_matches(ENDPOINT_STEPS, strlen(ENDPOINT_STEPS), path, path_len)) {
		if (!strncmp("GET", method, method_len)) {
			pv_ctrl_process_get_string(req_fd, pv_storage_get_revisions_string());
			goto out;
		}
	} else if (pv_str_startswith(ENDPOINT_STEPS, strlen(ENDPOINT_STEPS), path) &&
		pv_str_endswith(ENDPOINT_PROGRESS, strlen(ENDPOINT_PROGRESS), path, path_len)) {
		file_name = pv_ctrl_get_file_name(path, sizeof(ENDPOINT_STEPS), path_len - strlen(ENDPOINT_PROGRESS));
		file_path = pv_ctrl_get_file_path(PATH_TRAILS_PROGRESS, file_name);

		if (!file_name || !file_path) {
			pv_log(WARN, "HTTP request has bad object name %s", file_name);
			goto response;
		}

		if (!strncmp("GET", method, method_len)) {
			pv_ctrl_process_get_file(req_fd, file_path);
		}
		goto out;
	} else if (pv_str_startswith(ENDPOINT_STEPS, strlen(ENDPOINT_STEPS), path)) {
		file_name = pv_ctrl_get_file_name(path, sizeof(ENDPOINT_STEPS), path_len);
		file_path_parent = pv_ctrl_get_file_path(PATH_TRAILS_PARENT, file_name);
		file_path = pv_ctrl_get_file_path(PATH_TRAILS, file_name);

		if (!file_name || !file_path_parent || !file_path) {
			pv_log(WARN, "HTTP request has bad step name %s", file_name);
			goto response;
		}

		if (!strncmp("PUT", method, method_len)) {
			if (pv_storage_is_revision_local(file_name)) {
				mkdir_p(file_path_parent, 0755);
				res = pv_ctrl_process_put_file(req_fd, content_length, file_path);
			}
		} else if (!strncmp("GET", method, method_len)) {
			pv_ctrl_process_get_file(req_fd, file_path);
			goto out;
		}
	} else if (pv_str_matches(ENDPOINT_USER_META, strlen(ENDPOINT_USER_META), path, path_len)) {
		if (!strncmp("GET", method, method_len)) {
			pv_ctrl_process_get_string(req_fd, pv_metadata_get_user_meta_string());
			goto out;
		}
	} else if (pv_str_matches(ENDPOINT_DEVICE_META, strlen(ENDPOINT_DEVICE_META), path, path_len)) {
		if (!strncmp("GET", method, method_len)) {
			pv_ctrl_process_get_string(req_fd, pv_metadata_get_device_meta_string());
			goto out;
		}
	} else if (pv_str_startswith(ENDPOINT_USER_META, strlen(ENDPOINT_USER_META), path)) {
		if (pv_config_get_control_remote()) {
			pv_log(WARN, "HTTP resquest cannot be done while on remote revision");
			goto response;
		}

		metakey = pv_ctrl_get_file_name(path, sizeof(ENDPOINT_USER_META), path_len);

		if (!metakey) {
			pv_log(WARN, "HTTP request has bad step name %s", file_name);
			goto response;
		}

		if (!strncmp("PUT", method, method_len)) {
			metavalue = pv_ctrl_get_body(req_fd, content_length);
			pv_metadata_add_usermeta(metakey, metavalue);
		} else if (!strncmp("DELETE", method, method_len))
			pv_metadata_rm_usermeta(metakey);
	} else
		pv_log(WARN, "HTTP request received has bad endpoint");

response:
	if (res < 0) {
		if (write(req_fd, HTTP_RES_ERROR, strlen(HTTP_RES_ERROR)) <= 0)
			pv_log(INFO, "HTTP ERROR response could not be written to ctrl socket with fd %d: %s",
				req_fd, strerror(errno));
	} else {
		if (write(req_fd, HTTP_RES_OK, strlen(HTTP_RES_OK)) <= 0)
			pv_log(INFO, "HTTP OK response could not be written to ctrl socket with fd %d: %s",
				req_fd, strerror(errno));
	}
	goto out;

bad_request:
	if (write(req_fd, HTTP_RES_BAD_REQ, strlen(HTTP_RES_BAD_REQ)) <= 0)
		pv_log(INFO, "HTTP BAD REQUEST response could not be written to ctrl socket with fd %d: %s",
			req_fd, strerror(errno));

out:
	if (file_name)
		free(file_name);
	if (file_path_parent)
		free(file_path_parent);
	if (file_path)
		free(file_path);
	if (metakey)
		free(metakey);
	if (metavalue)
		free(metavalue);

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
		pv_log(WARN, "could not select ctrl socket with fd %d: %s",
			ctrl_fd, strerror(errno));
		goto out;
	}

	// create dedicated fd
	req_fd = accept(ctrl_fd, 0, 0);
	if (req_fd < 0) {
		pv_log(WARN, "could not accept ctrl socket with fd %d: %s",
			ctrl_fd, strerror(errno));
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
	struct pantavisor *pv = pv_get_instance();

	pv->ctrl_fd = pv_ctrl_socket_open(CTRL_SOCKET_PATH);
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

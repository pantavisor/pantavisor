/*
 * Copyright (c) 2017-2022 Pantacor Ltd.
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
#define _GNU_SOURCE
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
#include "updater.h"
#include "drivers.h"
#include "paths.h"
#include "utils/math.h"
#include "utils/fs.h"

#define MODULE_NAME             "ctrl"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#define ENDPOINT_CONTAINERS "/containers"
#define ENDPOINT_COMMANDS "/commands"
#define ENDPOINT_OBJECTS "/objects"
#define ENDPOINT_STEPS "/steps"
#define ENDPOINT_PROGRESS "/progress"
#define ENDPOINT_COMMITMSG "/commitmsg"
#define ENDPOINT_USER_META "/user-meta"
#define ENDPOINT_DEVICE_META "/device-meta"
#define ENDPOINT_BUILDINFO "/buildinfo"
#define ENDPOINT_CONDITIONS "/conditions"
#define ENDPOINT_CONFIG "/config"
#define ENDPOINT_DRIVERS "/drivers"

#define HTTP_RES_OK "HTTP/1.1 200 OK\r\n\r\n"
#define HTTP_RES_CONT "HTTP/1.1 100 Continue\r\n\r\n"

#define HTTP_RESPONSE "HTTP/1.1 %s \r\nContent-Length: %d\r\nContent-Type: application/json; charset=utf-8\r\n\r\n{\"Error\":\"%s\"}\r\n"

static const unsigned int HTTP_REQ_BUFFER_SIZE = 4096;
static const unsigned int HTTP_REQ_NUM_HEADERS = 8;

typedef enum {
	HTTP_STATUS_BAD_REQ,
	HTTP_STATUS_FORBIDDEN,
	HTTP_STATUS_NOT_FOUND,
	HTTP_STATUS_CONFLICT,
	HTTP_STATUS_UNPROCESSABLE_ENTITY,
	HTTP_STATUS_ERROR,
	HTTP_STATUS_INSUFF_STORAGE,
} pv_http_status_code_t;

static const char* pv_ctrl_string_http_status_code(pv_http_status_code_t code)
{
	static const char *strings[] = {
		"400 Bad Request",
		"403 Forbidden",
		"404 Not Found",
		"409 Conflict",
		"422 Unprocessable Entity",
		"500 Internal Server Error",
		"507 Insufficient Storage"};
	return strings[code];
}

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
	char path[PATH_MAX];

	if (ctrl_fd >= 0) {
		pv_paths_pv_file(path, PATH_MAX, PVCTRL_FNAME);
		pv_log(DEBUG, "closing %s with fd %d", path, ctrl_fd);
		close(ctrl_fd);
		unlink(path);
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

	if (content_length >= HTTP_REQ_BUFFER_SIZE) {
		pv_log(WARN, "cmd request too long");
		goto err;
	}

	// read request
	if (read(req_fd, req, content_length) <= 0) {
		pv_log(WARN, "cmd request could not be read from ctrl socket with fd %d: %s",
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

static void pv_ctrl_write_cont_response(int req_fd)
{
	if (write(req_fd, HTTP_RES_CONT, sizeof(HTTP_RES_CONT)-1) <= 0)
		pv_log(WARN, "HTTP CONTINUE response could not be sent to ctrl socket with fd %d: %s",
			req_fd, strerror(errno));
}

static void pv_ctrl_write_ok_response(int req_fd)
{
	if (write(req_fd, HTTP_RES_OK, strlen(HTTP_RES_OK)) <= 0)
		pv_log(WARN, "HTTP OK response could not be written to ctrl socket with fd %d: %s",
			req_fd, strerror(errno));
}

static void pv_ctrl_write_error_response(int req_fd,
								pv_http_status_code_t code,
								const char* message)
{
	unsigned int content_len, response_len;
	char* response = NULL;


	content_len = 12 + // {\"Error\":\"%s\"}
		strlen(message);

	response_len = 93 + // HTTP/1.1...
		strlen(pv_ctrl_string_http_status_code(code)) +
		get_digit_count(content_len) +
		strlen(message);
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
				pv_ctrl_string_http_status_code(code), content_len, message);

	if (write(req_fd, response, response_len) <= 0) {
		pv_log(ERROR, "HTTP response could not be written to ctrl socket with fd %d: %s",
				req_fd, strerror(errno));
	}

out:
	if (response)
		free(response);
}

static int pv_ctrl_process_put_file(int req_fd, size_t content_length, char* file_path)
{
	int obj_fd, read_length, write_length, ret = -1;
	char req[HTTP_REQ_BUFFER_SIZE];
	size_t free_space = pv_storage_get_free();

	if (content_length > free_space) {
		pv_log(WARN, "%"PRIu64" B needed but only %"PRIu64" B available. Cannot create file",
			content_length,
			free_space);
		pv_ctrl_write_error_response(req_fd, HTTP_STATUS_INSUFF_STORAGE, "Not enough disk space available");
		return ret;
	}

	pv_log(DEBUG, "reading file with size %zu from endpoint and putting it in %s",
		content_length,
		file_path);

	pv_ctrl_write_cont_response(req_fd);

	obj_fd = open(file_path, O_CREAT | O_EXCL | O_WRONLY | O_TRUNC | O_SYNC, 0644);
	if (obj_fd < 0) {
		pv_log(ERROR, "%s could not be created: %s", file_path, strerror(errno));
		pv_ctrl_write_error_response(req_fd, HTTP_STATUS_ERROR, "Cannot create file");
		// skip clean if the error was about the file already existing
		if (errno == EEXIST)
			goto out;
		else
			goto clean;
	}

	memset(req, 0, sizeof(req));

	// read and save
	while (content_length > 0) {
		if (content_length > HTTP_REQ_BUFFER_SIZE)
			read_length = HTTP_REQ_BUFFER_SIZE;
		else
			read_length = content_length;

		write_length = read(req_fd, req, read_length);
		if (write_length <= 0) {
			pv_log(WARN, "HTTP PUT content could not be read from ctrl socket with fd %d: %s",
				req_fd, strerror(errno));
			pv_ctrl_write_error_response(req_fd, HTTP_STATUS_ERROR, "Cannot read from socket");
			goto clean;
		}

		if (write(obj_fd, req, write_length) <= 0) {
			pv_log(WARN, "HTTP PUT content could not be written from ctrl socket with fd %d: %s",
				req_fd, strerror(errno));
			pv_ctrl_write_error_response(req_fd, HTTP_STATUS_ERROR, "Cannot write into file");
			goto clean;
		}

		content_length-=write_length;
	}

	ret = 0;
	goto out;

 clean:
	remove(file_path);
	pv_fs_path_sync(file_path);

 out:
	fsync(obj_fd);
	close(obj_fd);

	return ret;
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
	int minor_version, res = -1;

	// read from socket until end of HTTP header
	while (1 == read(req_fd, &buf[buf_index], 1)) {
		if ((buf_index > 3) &&
			(buf[buf_index-3] == '\r') &&
			(buf[buf_index-2] == '\n') &&
			(buf[buf_index-1] == '\r') &&
			(buf[buf_index] == '\n')) {
			break;
		}
		buf_index++;
		if (buf_index >= HTTP_REQ_BUFFER_SIZE) {
			pv_log(WARN, "HTTP request received longer than %d", HTTP_REQ_BUFFER_SIZE);
			goto out;
		}
	}

	// parse HTTP header
	res = phr_parse_request(buf,
							buf_index+1,
							method,
							method_len,
							path,
							path_len,
							&minor_version,
							headers,
							num_headers,
							0);
	if (res < 0) {
		pv_log(WARN, "HTTP request received has bad format");
	}

out:
	return res;
}

static size_t pv_ctrl_get_value_header_int(struct phr_header *headers,
										size_t num_headers,
										const char* name)
{
	int ret = 0;
	char *value = NULL;

	for (size_t header_index = 0; header_index < num_headers; header_index++) {
		if (pv_str_matches_case(headers[header_index].name,
				headers[header_index].name_len,
				name,
				strlen(name))) {
			value = calloc(headers[header_index].value_len, sizeof(char));
			strncpy(value, headers[header_index].value, headers[header_index].value_len);
			ret = strtol(value, NULL, 10);
		}
	}

	if (value)
		free(value);
	return ret;
}

static void pv_ctrl_process_get_file(int req_fd, char *file_path)
{
	int obj_fd;
	ssize_t sent, file_size = pv_fs_path_get_size(file_path);
	off_t offset = 0;

	pv_log(DEBUG, "reading file from %s and sending it to endpoint", file_path);

	obj_fd = open(file_path, O_RDONLY);
	if (obj_fd < 0) {
		pv_log(ERROR, "%s could not be opened for read", file_path);
		goto error;
	}

	pv_ctrl_write_ok_response(req_fd);

	// read and send
	for (size_t to_send = file_size; to_send > 0; ) {
		sent = sendfile(req_fd, obj_fd, &offset, to_send);
		if (sent < 0)
			pv_log(WARN, "HTTP GET file could not be written to ctrl socket with fd %d: %s",
				req_fd, strerror(errno));

		if (sent <= 0)
			goto out;

		to_send -= sent;
	}

	goto out;

error:
	pv_ctrl_write_error_response(req_fd, HTTP_STATUS_NOT_FOUND, "Resource does not exist");
out:
	close(obj_fd);
}

static char* pv_ctrl_get_file_name(const char* path, int buf_index, size_t path_len)
{
	int len;
	char* file_name;

	len = path_len - buf_index;

	file_name = calloc(len + 1, sizeof(char));
	if (!file_name)
		return NULL;

	strncpy(file_name, &path[buf_index], len);

	return file_name;
}

static void pv_ctrl_process_get_string(int req_fd, char* buf)
{
	int buf_len;

	pv_log(DEBUG, "converting data to string and sending it to endpoint...");

	buf_len = strlen(buf);

	pv_ctrl_write_ok_response(req_fd);

	if (write(req_fd, buf, buf_len) != buf_len)
		pv_log(WARN, "HTTP GET content could not be written to ctrl socket with fd %d: %s",
			req_fd, strerror(errno));

	if (buf)
		free(buf);
}

static char *pv_ctrl_get_body(int req_fd, size_t content_length)
{
	char *req = NULL;

	if (content_length >= HTTP_REQ_BUFFER_SIZE) {
		pv_log(WARN, "body too long");
		goto err;
	}

	req = calloc(content_length + 1, sizeof(char));

	// read request
	if (read(req_fd, req, content_length) <= 0) {
		pv_log(WARN, "HTTP GET body could not be read to ctrl socket with fd %d: %s",
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

	if (!pv->remote_mode &&
		((*cmd)->op == CMD_UPDATE_METADATA)) {
		pv_ctrl_write_error_response(req_fd,
			HTTP_STATUS_CONFLICT,
			"Cannot do this operation while on local mode");
		goto error;
	}

	if (pv->update && pv->update->status != UPDATE_APPLIED &&
		(((*cmd)->op == CMD_REBOOT_DEVICE) ||
		 ((*cmd)->op == CMD_POWEROFF_DEVICE) ||
		 ((*cmd)->op == CMD_LOCAL_RUN) ||
		 ((*cmd)->op == CMD_LOCAL_APPLY) ||
		 ((*cmd)->op == CMD_MAKE_FACTORY))) {
		pv_ctrl_write_error_response(req_fd,
			HTTP_STATUS_CONFLICT,
			"Cannot do this operation while update is ongoing");
		goto error;
	}

	if (!pv->unclaimed &&
		((*cmd)->op == CMD_MAKE_FACTORY)) {
		pv_ctrl_write_error_response(req_fd,
			HTTP_STATUS_CONFLICT,
			"Cannot do this operation if device is already claimed");
		goto error;
	}

	return 0;

error:
	pv_ctrl_free_cmd(*cmd);
	*cmd = NULL;
	return -1;
}

static char* pv_ctrl_get_sender_pname(int req_fd)
{
	char *pvcg, *pname = NULL;
	struct ucred ucred;
	socklen_t ucred_len = sizeof(ucred);
	char path[PATH_MAX], buf[128];
	FILE *fd;
	int len;

	// get sender PID
	if (getsockopt(req_fd, SOCK_STREAM, SO_PEERCRED, &ucred, &ucred_len) < 0) {
		pv_log(WARN, "could not get pid from sender: %s", strerror(errno));
		goto out;
	}

	// get container name from sender PID
	len = strlen("/proc/%d/cgroup") + get_digit_count(ucred.pid) + 1;
	snprintf(path, len, "/proc/%d/cgroup", ucred.pid);

	fd = fopen(path,"r");
	if (!fd) {
		pv_log(WARN, "could not open %s: %s", path, strerror(errno));
		goto out;
	}

	while (fgets(buf, 128, fd)) {
		pvcg = strstr(buf, ":name=pantavisor:/lxc/");
		if (pvcg) {
			pvcg += strlen(":name=pantavisor:/lxc/");
			pvcg[strlen(pvcg) - 1] = '\0';
			pname = strdup(pvcg);
			break;
		}
	}

	fclose(fd);

out:
	return pname;
}

static struct pv_platform* pv_ctrl_get_sender_plat(const char *pname)
{
	struct pantavisor *pv = pv_get_instance();
	struct pv_platform *plat;

	plat = pv_state_fetch_platform(pv->state, pname);
	if (!plat)
		pv_log(WARN, "could not find platform %s in current state", pname);

	return plat;
}

static bool pv_ctrl_check_sender_privileged(const char *pname)
{
	struct pv_platform *plat = pv_ctrl_get_sender_plat(pname);

	return plat ? pv_platform_has_role(plat, PLAT_ROLE_MGMT) : false;
}

static struct pv_cmd* pv_ctrl_process_endpoint_and_reply(int req_fd,
														const char *method,
														size_t method_len,
														const char *path,
														size_t path_len,
														size_t content_length,
														char *pname)
{
	bool mgmt;
	struct pv_cmd *cmd = NULL;
	struct pantavisor *pv = pv_get_instance();
	char *file_name = NULL;
	char file_path_parent[PATH_MAX] = { 0 }, file_path[PATH_MAX] = { 0 }, file_path_tmp[PATH_MAX] = { 0 };
	char *metakey = NULL, *metavalue = NULL;
	char *condkey = NULL, *condvalue = NULL;
	char *driverkey = NULL, *drivervalue = NULL;
	char *drivername = NULL; char *driverop = NULL;
	struct pv_platform *p = pv_ctrl_get_sender_plat(pname);
	struct stat st;

	mgmt = pv_ctrl_check_sender_privileged(pname);

	if (pv_str_matches(ENDPOINT_CONTAINERS, strlen(ENDPOINT_CONTAINERS), path, path_len)) {
		if (!strncmp("GET", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			pv_ctrl_process_get_string(req_fd, pv_state_get_containers_json(pv->state));
		} else
			goto err_me;
	} else if (pv_str_startswith(ENDPOINT_COMMANDS, strlen(ENDPOINT_COMMANDS), path)) {
		if (!strncmp("POST", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			if (pv_ctrl_process_cmd(req_fd, content_length, &cmd) < 0) {
				pv_ctrl_write_error_response(req_fd, HTTP_STATUS_BAD_REQ, "Command has bad format");
				goto out;
			}
			if (pv_ctrl_check_command(req_fd, &cmd) < 0)
				goto out;
			pv_ctrl_write_ok_response(req_fd);
		} else
			goto err_me;
	} else if (pv_str_matches(ENDPOINT_OBJECTS, strlen(ENDPOINT_OBJECTS), path, path_len)) {
		if (!strncmp("GET", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			pv_ctrl_process_get_string(req_fd, pv_objects_get_list_string());
		} else
			goto err_me;
	} else if (pv_str_startswith(ENDPOINT_OBJECTS, strlen(ENDPOINT_OBJECTS), path)) {
		file_name = pv_ctrl_get_file_name(path, sizeof(ENDPOINT_OBJECTS), path_len);
		pv_paths_storage_object(file_path, PATH_MAX, file_name);
		pv_paths_tmp(file_path_tmp, PATH_MAX, file_path);
		// sha must have 64 characters
		if (!file_name || (strlen(file_name) != 64)) {
			pv_log(WARN, "HTTP request has bad object name %s", file_name);
			pv_ctrl_write_error_response(req_fd, HTTP_STATUS_BAD_REQ, "Request has bad object name");
			goto out;
		}

		if (!strncmp("PUT", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			if (pv_ctrl_process_put_file(req_fd, content_length, file_path_tmp) < 0)
				goto out;
			if (pv_storage_validate_file_checksum(file_path_tmp, file_name) < 0) {
				pv_log(WARN, "object %s has bad checksum", file_path_tmp);
				pv_ctrl_write_error_response(req_fd, HTTP_STATUS_UNPROCESSABLE_ENTITY, "Object has bad checksum");
				goto out;
			}
			pv_log(DEBUG, "renaming %s to %s", file_path_tmp, file_path);
			if (pv_fs_path_rename(file_path_tmp, file_path) < 0) {
				pv_log(ERROR, "could not rename: %s", strerror(errno));
				pv_ctrl_write_error_response(req_fd, HTTP_STATUS_ERROR, "Cannot rename object");
				goto out;
			}
			pv_storage_gc_defer_run_threshold();
			pv_ctrl_write_ok_response(req_fd);
		} else if (!strncmp("GET", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			pv_ctrl_process_get_file(req_fd, file_path);
		} else
			goto err_me;
	} else if (pv_str_matches(ENDPOINT_STEPS, strlen(ENDPOINT_STEPS), path, path_len)) {
		if (!strncmp("GET", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			pv_ctrl_process_get_string(req_fd, pv_storage_get_revisions_string());
		} else
			goto err_me;
	} else if (pv_str_startswith(ENDPOINT_STEPS, strlen(ENDPOINT_STEPS), path) &&
		pv_str_endswith(ENDPOINT_PROGRESS, strlen(ENDPOINT_PROGRESS), path, path_len)) {
		file_name = pv_ctrl_get_file_name(path, sizeof(ENDPOINT_STEPS), path_len - strlen(ENDPOINT_PROGRESS));
		pv_paths_storage_trail_pv_file(file_path, PATH_MAX, file_name, PROGRESS_FNAME);

		if (!file_name) {
			pv_log(WARN, "HTTP request has bad step name %s", file_name);
			pv_ctrl_write_error_response(req_fd, HTTP_STATUS_BAD_REQ, "Request has bad step name");
			goto out;
		}

		if (!strncmp("GET", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			pv_ctrl_process_get_file(req_fd, file_path);
		} else
			goto err_me;
	} else if (pv_str_startswith(ENDPOINT_STEPS, strlen(ENDPOINT_STEPS), path) &&
		pv_str_endswith(ENDPOINT_COMMITMSG, strlen(ENDPOINT_COMMITMSG), path, path_len)) {
		file_name = pv_ctrl_get_file_name(path, sizeof(ENDPOINT_STEPS), path_len - strlen(ENDPOINT_COMMITMSG));
		pv_paths_storage_trail_pv_file(file_path_parent, PATH_MAX, file_name, "");
		pv_paths_storage_trail_pv_file(file_path, PATH_MAX, file_name, COMMITMSG_FNAME);
		pv_paths_tmp(file_path_tmp, PATH_MAX, file_path);

		if (!file_name) {
			pv_log(WARN, "HTTP request has bad step name %s", file_name);
			pv_ctrl_write_error_response(req_fd, HTTP_STATUS_BAD_REQ, "Request has bad step name");
			goto out;
		}

		if (!strncmp("PUT", method, method_len)) {
			if (!mgmt)
				goto err_pr;

			mkdir(file_path_parent, 0755);
			if (pv_ctrl_process_put_file(req_fd, content_length, file_path_tmp) < 0)
				goto out;
			pv_log(DEBUG, "renaming %s to %s", file_path_tmp, file_path);
			if (pv_fs_path_rename(file_path_tmp, file_path) < 0) {
				pv_log(ERROR, "could not rename: %s", strerror(errno));
				pv_ctrl_write_error_response(req_fd, HTTP_STATUS_ERROR, "Cannot rename commitmsg");
				goto out;
			}
			pv_ctrl_write_ok_response(req_fd);
		} else
			goto err_me;
	} else if (pv_str_startswith(ENDPOINT_STEPS, strlen(ENDPOINT_STEPS), path)) {
		file_name = pv_ctrl_get_file_name(path, sizeof(ENDPOINT_STEPS), path_len);
		pv_paths_storage_trail_pvr_file(file_path_parent, PATH_MAX, file_name, "");
		pv_paths_storage_trail_pvr_file(file_path, PATH_MAX, file_name, JSON_FNAME);

		if (!file_name) {
			pv_log(WARN, "HTTP request has bad step name %s", file_name);
			pv_ctrl_write_error_response(req_fd, HTTP_STATUS_BAD_REQ, "Request has bad step name");
			goto out;
		}

		if (!strncmp("PUT", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			if (!pv_storage_is_revision_local(file_name)) {
				pv_log(ERROR, "wrong local step name %s", file_name);
				pv_ctrl_write_error_response(req_fd, HTTP_STATUS_BAD_REQ, "Step name has bad name");
				goto out;
			}
			pv_fs_mkdir_p(file_path_parent, 0755);
			if (pv_ctrl_process_put_file(req_fd, content_length, file_path) < 0)
				goto out;
			if (!pv_storage_verify_state_json(file_name)) {
				pv_log(ERROR, "state verification went wrong");
				pv_ctrl_write_error_response(req_fd, HTTP_STATUS_UNPROCESSABLE_ENTITY, "State verification has failed");
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
	} else if (pv_str_matches(ENDPOINT_USER_META, strlen(ENDPOINT_USER_META), path, path_len)) {
		if (!strncmp("GET", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			pv_ctrl_process_get_string(req_fd, pv_metadata_get_user_meta_string());
		} else
			goto err_me;
	} else if (pv_str_matches(ENDPOINT_DEVICE_META, strlen(ENDPOINT_DEVICE_META), path, path_len)) {
		if (!strncmp("GET", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			pv_ctrl_process_get_string(req_fd, pv_metadata_get_device_meta_string());
		} else
			goto err_me;
	} else if (pv_str_matches(ENDPOINT_BUILDINFO, strlen(ENDPOINT_BUILDINFO), path, path_len)) {
		if (!strncmp("GET", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			pv_ctrl_process_get_string(req_fd, strdup(pv_build_manifest));
		} else
			goto err_me;
	} else if (pv_str_startswith(ENDPOINT_USER_META, strlen(ENDPOINT_USER_META), path)) {
		metakey = pv_ctrl_get_file_name(path, sizeof(ENDPOINT_USER_META), path_len);

		if (!metakey) {
			pv_log(WARN, "HTTP request has bad meta name %s", metakey);
			pv_ctrl_write_error_response(req_fd, HTTP_STATUS_BAD_REQ, "Request has bad metadata key name");
			goto out;
		}

		if (!strncmp("PUT", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			metavalue = pv_ctrl_get_body(req_fd, content_length);
			if (pv_metadata_add_usermeta(metakey, metavalue) < 0)
				pv_ctrl_write_error_response(req_fd, HTTP_STATUS_ERROR, "Cannot add or update user meta");
			pv_ctrl_write_ok_response(req_fd);
		} else if (!strncmp("DELETE", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			if (pv_metadata_rm_usermeta(metakey) < 0)
				pv_ctrl_write_error_response(req_fd, HTTP_STATUS_NOT_FOUND, "User meta does not exist");
			pv_ctrl_write_ok_response(req_fd);
		} else
			goto err_me;
	} else if (pv_str_startswith(ENDPOINT_DEVICE_META, strlen(ENDPOINT_DEVICE_META), path)) {
		metakey = pv_ctrl_get_file_name(path, sizeof(ENDPOINT_DEVICE_META), path_len);

		if (!metakey) {
			pv_log(WARN, "HTTP request has bad meta name %s", metakey);
			pv_ctrl_write_error_response(req_fd, HTTP_STATUS_BAD_REQ, "Request has bad metadata key name");
			goto out;
		}

		if (!strncmp("PUT", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			metavalue = pv_ctrl_get_body(req_fd, content_length);
			if (pv_metadata_add_devmeta(metakey, metavalue) < 0)
				pv_ctrl_write_error_response(req_fd, HTTP_STATUS_ERROR, "Cannot add or update device meta");
			pv_ctrl_write_ok_response(req_fd);
		} else if (!strncmp("DELETE", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			if (pv_metadata_rm_devmeta(metakey) < 0)
				pv_ctrl_write_error_response(req_fd, HTTP_STATUS_NOT_FOUND, "Device meta does not exist");
			pv_ctrl_write_ok_response(req_fd);
		} else
			goto err_me;
	} else if (pv_str_matches(ENDPOINT_DRIVERS, strlen(ENDPOINT_DRIVERS), path, path_len)) {
		if (!strncmp("GET", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			pv_ctrl_process_get_string(req_fd,
				pv_drivers_state_all(p));
		} else
			goto err_me;
	} else if (pv_str_startswith(ENDPOINT_DRIVERS, strlen(ENDPOINT_DRIVERS), path)) {
		driverkey = pv_ctrl_get_file_name(path, sizeof(ENDPOINT_DRIVERS), path_len);

		if (!driverkey) {
			pv_log(WARN, "HTTP request has bad driver alias");
			pv_ctrl_write_error_response(req_fd, HTTP_STATUS_BAD_REQ, "Request has bad driver key name");
			goto out;
		}

		if (!strncmp("PUT", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			if(!strchr(driverkey, '/')) {
				if (!p) {
					pv_log(WARN, "HTTP request has bad sender");
					pv_ctrl_write_error_response(req_fd, HTTP_STATUS_BAD_REQ, "Request comes from wrong sender");
				}
				if (!strcmp(driverkey, "load")) {
					if (pv_platform_load_drivers(p, NULL, DRIVER_MANUAL) >= 0)
						pv_ctrl_write_ok_response(req_fd);
					else
						pv_ctrl_write_error_response(req_fd, HTTP_STATUS_BAD_REQ, "Error loading drivers");
				} else if (!strcmp(driverkey, "unload")) {
					pv_platform_unload_drivers(p, NULL, DRIVER_MANUAL);
					pv_ctrl_write_ok_response(req_fd);
				} else {
					pv_ctrl_write_error_response(req_fd, HTTP_STATUS_BAD_REQ, "Request has bad driver key name");
				}
				goto out;
			}
			drivername = strtok(driverkey, "/");
			driverop = strtok(NULL, "/");
			if (driverop && !strcmp(driverop, "load"))
				pv_platform_load_drivers(p, drivername, DRIVER_MANUAL);
			else if (driverop && !strcmp(driverop, "unload"))
				pv_platform_unload_drivers(p, drivername, DRIVER_MANUAL);
			else if (!driverop)
				pv_ctrl_write_error_response(req_fd, HTTP_STATUS_BAD_REQ, "no driver name provided in PUT");
			else {
				pv_ctrl_write_error_response(req_fd, HTTP_STATUS_BAD_REQ, "no valid driver operation provided in PUT; should be load or unload");
				goto out;
			}

			pv_ctrl_write_ok_response(req_fd);
		} else if (!strncmp("GET", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			if (driverkey) {
				pv_ctrl_process_get_string(req_fd,
					strdup(pv_drivers_state_str(driverkey)));
			}
		} else
			goto err_me;
	} else if (pv_str_matches(ENDPOINT_CONDITIONS, strlen(ENDPOINT_CONDITIONS), path, path_len)) {
		if (!strncmp("GET", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			pv_ctrl_process_get_string(req_fd, pv_state_get_conditions_json(pv->state));
		} else
			goto err_me;
	} else if (pv_str_startswith(ENDPOINT_CONDITIONS, strlen(ENDPOINT_CONDITIONS), path)) {
		condkey = pv_ctrl_get_file_name(path, sizeof(ENDPOINT_CONDITIONS), path_len);

		if (!condkey) {
			pv_log(WARN, "HTTP request has bad condition name %s", condkey);
			pv_ctrl_write_error_response(req_fd, HTTP_STATUS_BAD_REQ, "Request has bad condition key name");
			goto out;
		}

		if (!strncmp("PUT", method, method_len)) {
			condvalue = pv_ctrl_get_body(req_fd, content_length);
			if (pv_state_report_condition(pv->state, pname, condkey, condvalue))
				pv_ctrl_write_error_response(req_fd, HTTP_STATUS_ERROR, "Cannot report condition");
			pv_ctrl_write_ok_response(req_fd);
		} else
			goto err_me;
	} else if (pv_str_matches(ENDPOINT_CONFIG, strlen(ENDPOINT_CONFIG), path, path_len)) {
		if (!strncmp("GET", method, method_len)) {
			if (!mgmt)
				goto err_pr;
			pv_ctrl_process_get_string(req_fd, pv_config_get_json());
		} else
			goto err_me;
	} else {
		goto err_ep;
	}
	goto out;

err_ep:
	pv_log(WARN, "HTTP request received has unknown endpoint");
	pv_ctrl_write_error_response(req_fd, HTTP_STATUS_BAD_REQ, "Unknown endpoint");
	goto out;

err_me:
	pv_log(WARN, "HTTP method not supported for this endpoint");
	pv_ctrl_write_error_response(req_fd, HTTP_STATUS_BAD_REQ, "Method not supported for this endpoint");
	goto out;

err_pr:
	pv_log(WARN, "request not sent from mgmt platform");
	pv_ctrl_write_error_response(req_fd, HTTP_STATUS_FORBIDDEN, "Request not sent from mgmt platform");

out:
	if (!stat(file_path_tmp, &st)) {
		pv_log(DEBUG, "removing %s", file_path_tmp);
		pv_fs_path_remove(file_path_tmp, false);
	}
	if (pname)
		free(pname);
	if (file_name)
		free(file_name);
	if (metakey)
		free(metakey);
	if (metavalue)
		free(metavalue);
	if (condkey)
		free(condkey);
	if (condvalue)
		free(condvalue);
	if (driverkey)
		free(driverkey);
	if (drivervalue)
		free(drivervalue);

	return cmd;
}

static struct pv_cmd* pv_ctrl_read_parse_request(int req_fd)
{
	char buf[HTTP_REQ_BUFFER_SIZE];
	char *pname;
	int buf_index = 0, res = -1;
	const char *method, *path;
	size_t method_len, path_len, num_headers = HTTP_REQ_NUM_HEADERS, content_length;
	struct phr_header headers[HTTP_REQ_NUM_HEADERS];
	struct pv_cmd *cmd = NULL;

	memset(buf, 0, sizeof(buf));

	pname = pv_ctrl_get_sender_pname(req_fd);
	if (!pname) {
		pv_log(WARN, "could not find a sender platform name");
		goto out;
	}

	pv_log(DEBUG, "request received from platform %s", pname)

	// legacy commands are only for mgmt platforms
	if (pv_ctrl_check_sender_privileged(pname)) {
		// read first character to see if the request is a non-HTTP legacy one
		if (read(req_fd, &buf[0], 1) < 0)
			goto out;
		buf_index++;

		// if character is 3 (old code for json command), it is non-HTTP
		if (buf[0] == 3) {
			res = pv_ctrl_process_cmd(req_fd, HTTP_REQ_BUFFER_SIZE - 1, &cmd);
			goto out;
		}
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
		pv_ctrl_write_error_response(req_fd, HTTP_STATUS_BAD_REQ, "Request has bad format");
		goto out;
	}

	pv_log(DEBUG, "HTTP request received: %.*s %.*s", method_len, method, path_len, path);

	content_length = pv_ctrl_get_value_header_int(headers, num_headers, "content-length");

	cmd = pv_ctrl_process_endpoint_and_reply(req_fd,
											method,
											method_len,
											path,
											path_len,
											content_length,
											pname);
out:
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
	char path[PATH_MAX];

	pv_paths_pv_file(path, PATH_MAX, PVCTRL_FNAME);
	pv->ctrl_fd = pv_ctrl_socket_open(path);
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

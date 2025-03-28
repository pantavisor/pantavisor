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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/un.h>

#include "phclient/local.h"
#include "phclient/log.h"

#define SOCKET_PATH "/pantavisor/pv-ctrl"

int ph_local_get_creds(char *out, size_t max_len)
{
	int sockfd;
	struct sockaddr_un server_addr;
	ssize_t bytes_read;

	// Create a UNIX domain socket
	if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		ph_log(ERROR, "socket: %s", strerror(errno));
		return -1;
	}

	// Configure the server address
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sun_family = AF_UNIX;
	strncpy(server_addr.sun_path, SOCKET_PATH,
		sizeof(server_addr.sun_path) - 1);

	// Connect to the server
	if (connect(sockfd, (struct sockaddr *)&server_addr,
		    sizeof(server_addr)) < 0) {
		ph_log(ERROR, "connect: %s", strerror(errno));
		close(sockfd);
		return -1;
	}

	// Send an HTTP GET request
	const char *http_request =
		"GET /config2 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
	if (send(sockfd, http_request, strlen(http_request), 0) < 0) {
		ph_log(ERROR, "send: %s", strerror(errno));
		close(sockfd);
		return -1;
	}

	// Read the response header
	char buf[256];
	memset(buf, 0, 256);
	size_t len = 0;
	while (recv(sockfd, &buf[len], 1, 0) > 0) {
		if ((len >= 4) && (buf[len - 3] == '\r') &&
		    (buf[len - 2] == '\n') && (buf[len - 1] == '\r') &&
		    (buf[len] == '\n')) {
			ph_log(DEBUG, "response header '%s'", buf);
			break;
		}
		len++;
		if (len >= 256)
			break;
	}

	// Read the response body
	len = 0;
	while ((bytes_read = recv(sockfd, out, max_len + len - 1, 0)) > 0) {
		out[len + bytes_read] = '\0';
		len += bytes_read;
	}

	if (bytes_read < 0) {
		ph_log(ERROR, "recv: %s", strerror(errno));
	}

	// Close the socket
	close(sockfd);

	return 0;
}

int ph_local_get_devmeta(char *out, size_t max_len)
{
	int sockfd;
	struct sockaddr_un server_addr;
	ssize_t bytes_read;

	// Create a UNIX domain socket
	if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		ph_log(ERROR, "socket: %s", strerror(errno));
		return -1;
	}

	// Configure the server address
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sun_family = AF_UNIX;
	strncpy(server_addr.sun_path, SOCKET_PATH,
		sizeof(server_addr.sun_path) - 1);

	// Connect to the server
	if (connect(sockfd, (struct sockaddr *)&server_addr,
		    sizeof(server_addr)) < 0) {
		ph_log(ERROR, "connect: %s", strerror(errno));
		close(sockfd);
		return -1;
	}

	// Send an HTTP GET request
	const char *http_request =
		"GET /device-meta HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
	if (send(sockfd, http_request, strlen(http_request), 0) < 0) {
		ph_log(ERROR, "send: %s", strerror(errno));
		close(sockfd);
		return -1;
	}

	// Read the response header
	char buf[256];
	memset(buf, 0, 256);
	size_t len = 0;
	while (recv(sockfd, &buf[len], 1, 0) > 0) {
		if ((len >= 4) && (buf[len - 3] == '\r') &&
		    (buf[len - 2] == '\n') && (buf[len - 1] == '\r') &&
		    (buf[len] == '\n')) {
			ph_log(DEBUG, "response header '%s'", buf);
			break;
		}
		len++;
		if (len >= 256)
			break;
	}

	// Read the response body
	len = 0;
	while ((bytes_read = recv(sockfd, out, max_len + len - 1, 0)) > 0) {
		out[len + bytes_read] = '\0';
		len += bytes_read;
	}

	if (bytes_read < 0) {
		ph_log(ERROR, "recv: %s", strerror(errno));
	}

	// Close the socket
	close(sockfd);

	return 0;
}

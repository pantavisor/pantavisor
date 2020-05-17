/*
 * Copyright (c) 2020 Pantacor Ltd.
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
#include <unistd.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <trest.h>
#include <thttp.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <libgen.h>
#include <string.h>
#include <dirent.h>
#include <stdio.h>
#include "../utils.h"
#include "../pantavisor.h"
#include "../config.h"
#include "../pantahub.h"
#include "../version.h"
#include "../utils/list.h"
#include "../pvctl_utils.h"

#define MODULE_NAME             "ph_logger"
#include "../log.h"
#include "ph_logger.h"
#include "ph_logger_v1.h"

#define PH_LOGGER_POS_FILE 	"/pv/.ph_logger"
#define PH_LOGGER_SKIP_FILE	".ph_logger_skip_list"
#define PH_LOGGER_LOGDIR 	"/pv/logs"
#define PH_LOGGER_BACKLOG	(20)
#define PH_LOGGER_LOGFILE 	"/ph_logger.log"

#define PH_LOGGER_FLAG_STOP 	(1<<0)
#define USER_AGENT_LEN 		(128)

#ifdef pv_log
#undef pv_log
#endif

static void pv_log(int level, char *msg, ...)
{
	struct ph_logger_msg *ph_logger_msg = NULL;
	char *buffer = NULL;
	char *logger_buffer = NULL;
	va_list args;
	int len = 0;
	int max_size = 0;
	char *shrinked = NULL;

	buffer = (char*)calloc(1, BUF_CHUNK * 3);

	if (!buffer)
		return;
	va_start(args, msg);
	vsnprintf(buffer, BUF_CHUNK * 3, msg, args);
	va_end(args);
	len = strlen(buffer);
	shrinked = realloc(buffer, len + 1);

	if (shrinked)
		buffer = shrinked;

	max_size = (len + 1) + strlen(MODULE_NAME) + strlen(PH_LOGGER_LOGFILE) + 
		6/*6 digits for revision*/ + 4/*null*/;
	logger_buffer = (char*)calloc(1 , sizeof(*ph_logger_msg) + max_size);

	if (!logger_buffer)
		goto out;
	ph_logger_msg = (struct ph_logger_msg*)logger_buffer;
	ph_logger_msg->version = PH_LOGGER_V1;
	ph_logger_msg->len = sizeof(*ph_logger_msg) + max_size;

	ph_logger_write_bytes(ph_logger_msg, buffer, level, 
			MODULE_NAME, PH_LOGGER_LOGFILE, len + 1);
	pvctl_write_to_path(LOG_CTRL_PATH, logger_buffer, ph_logger_msg->len + sizeof(*ph_logger_msg));
	free(logger_buffer);
out:
	free(buffer);
}
/*
 * Include after defining MODULE_NAME.
 */
#define PH_LOGGER_MAX_EPOLL_FD 	(50)

static struct pantavisor *pv_global;

struct ph_logger_fragment {
	struct dl_list list;
	char *json_frag;
};

struct ph_logger_skip_prefix {
	struct dl_list list;
	char *prefix;
};

static DEFINE_DL_LIST(frag_list);
/*
 * This is a private struct.
 */
struct ph_logger {
	int sock_fd;
	int flags;
	int epoll_fd;
	int revision;
	trest_ptr *client;
	struct pv_connection *pv_conn;
	char user_agent[USER_AGENT_LEN];
	struct dl_list skip_list;
};

static struct ph_logger ph_logger = {
	.epoll_fd = -1,
	.sock_fd = -1,
	.pv_conn = NULL,
	.client = NULL
};

static ph_logger_handler_t read_handler[] = {
	[PH_LOGGER_V1] = ph_logger_read_handler_v1
};

static ph_logger_handler_t write_handler[] = {
	[PH_LOGGER_V1] = ph_logger_write_handler_v1
};

static ph_logger_file_rw_handler_t file_rw_handler[] = {
	[PH_LOGGER_V1] = ph_logger_write_to_file_handler_v1
};

static struct ph_logger_skip_prefix* ph_logger_skip_prefix(char *prefix)
{
	struct ph_logger_skip_prefix *skip_prefix = NULL;
	
	if (!prefix || !strlen(prefix))
		return NULL;

	skip_prefix = (struct ph_logger_skip_prefix*) calloc(1, sizeof(*skip_prefix));
	if (skip_prefix) {
		skip_prefix->prefix = strdup(prefix);
		if (!skip_prefix->prefix) {
			free(skip_prefix);
			skip_prefix = NULL;
		}
	}
	return skip_prefix;
}

static bool ph_logger_add_skip_prefix(struct ph_logger *ph_logger, char *prefix)
{
	struct ph_logger_skip_prefix *new_prefix = NULL;
	bool added = false;

	if (!ph_logger)
		return added;

	new_prefix = ph_logger_skip_prefix(prefix);
	if (new_prefix) {
		dl_list_add(&ph_logger->skip_list, &new_prefix->list);
		added = true;
	}
	return added;
}

static bool ph_logger_contains_skip_prefix(struct ph_logger *ph_logger, const char *prefix)
{
	struct ph_logger_skip_prefix *item, *tmp;

	if (dl_list_empty(&ph_logger->skip_list) || !prefix || !strlen(prefix))
		return false;

	dl_list_for_each_safe(item, tmp, &ph_logger->skip_list,
				struct ph_logger_skip_prefix, list) {
		if (!strcmp(prefix, item->prefix))
			return true;
	}
	return false;
}

static void ph_logger_clear_skip_prefix(struct ph_logger *ph_logger)
{
	struct ph_logger_skip_prefix *item, *tmp;

	if (dl_list_empty(&ph_logger->skip_list))
		return;
	dl_list_for_each_safe(item, tmp, &ph_logger->skip_list,
				struct ph_logger_skip_prefix, list) {
		dl_list_del(&item->list);
		free(item->prefix);
		free(item);
	}
}

/*
 * Add skip prefixes from the filename.
 */
static bool ph_logger_add_skip_prefixes(struct ph_logger *ph_logger, const char *filename)
{
	FILE *fp = fopen(filename, "r");
	char *line = NULL;
	size_t line_len = 0;
	bool added = false;

	if (fp) {
		while (!feof(fp)) {
			ssize_t ret = 0;

			ret = getline(&line, &line_len, fp);
			if (ret > 0) {
				char *new_line_at = strstr(line,"\n");

				if (new_line_at)
					*new_line_at='\0';
				if (!ph_logger_contains_skip_prefix(ph_logger, line))
					added = ph_logger_add_skip_prefix(ph_logger, line) || added;
			} else {
				break;
			}
		}
		if (line)
			free(line);
		fclose(fp);
		return added;
	}
	return false;
}

static struct ph_logger_fragment* __ph_logger_alloc_frag(char *json_frag, bool do_frag_dup) 
{
	struct ph_logger_fragment *frag = NULL;

	if (!json_frag)
		return NULL;
	frag = (struct ph_logger_fragment*) calloc(1, sizeof(*frag));
	if (frag) {
		if (do_frag_dup)
			frag->json_frag = strdup(json_frag);
		else
			frag->json_frag = json_frag;
		if (!frag->json_frag) {
			free(frag);
			frag = NULL;
		}
	}
	return frag;

}
static struct ph_logger_fragment* ph_logger_alloc_frag(char *json_frag)
{
	return __ph_logger_alloc_frag(json_frag, false);
}

static ph_logger_file_rw_handler_t get_file_rw_handler(int version)
{
	if (version < PH_LOGGER_V1 || version >= PH_LOGGER_MAX_HANDLERS)
		return NULL;

	return file_rw_handler[version];
}

static ph_logger_handler_t get_read_handler(int version)
{
	if (version < PH_LOGGER_V1 || version >= PH_LOGGER_MAX_HANDLERS)
		return NULL;
	
	return read_handler[version];
}

static ph_logger_handler_t get_write_handler(int version)
{
	if (version < PH_LOGGER_V1 || version >= PH_LOGGER_MAX_HANDLERS)
		return NULL;
	
	return write_handler[version];
}


static int __ph_logger_get_connection(struct ph_logger *ph_logger,
					struct pantavisor_config *config,
					bool force_free)
{
	if (force_free) {
		if (ph_logger->pv_conn) {
			free(ph_logger->pv_conn);
			ph_logger->pv_conn = NULL;
		}
		if (ph_logger->client) {
			trest_free(ph_logger->client);
			ph_logger->client = NULL;
		}
	}
	if (ph_logger->pv_conn && !connect_try(&ph_logger->pv_conn->sock))
		goto out;

	if (ph_logger->pv_conn)
		free(ph_logger->pv_conn);
	ph_logger->pv_conn = pv_get_pv_connection(config);
	if (ph_logger->client) {
		trest_free(ph_logger->client);
		ph_logger->client = NULL;
	}
out:
	return !!ph_logger->pv_conn;;

}
static int ph_logger_get_connection(struct ph_logger *ph_logger, struct pantavisor_config *config)
{
	return __ph_logger_get_connection(ph_logger, config, false);
}

static int ph_logger_open_socket(const char *path) 
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
		close(fd);
		fd = -1;
		goto out;
	}

	// queue upto PH_LOGGER_BACKLOG commands
	listen(fd, PH_LOGGER_BACKLOG);
out:
	return fd;
}
static int __ph_logger_init_basic(struct ph_logger *ph_logger) {
	sprintf(ph_logger->user_agent, PV_USER_AGENT_FMT, pv_build_arch, pv_build_version, pv_build_date);
	dl_list_init(&ph_logger->skip_list);
	return 0;
}

static int ph_logger_init(const char *sock_path, char *log_path)
{
	struct epoll_event ep_event;

	ph_logger.sock_fd = ph_logger_open_socket(sock_path);
	ph_logger.epoll_fd = epoll_create1(0);
	
	if (ph_logger.epoll_fd < 0 || ph_logger.sock_fd < 0) {
#ifdef DEBUG
		printf("ph_logger epoll_fd = %d\n",ph_logger.epoll_fd);
		printf("ph_logger sock_fd = %d\n",ph_logger.sock_fd);
		printf("errno  =%d\n", errno);
#endif
		goto out;
	}

	ep_event.events = EPOLLIN;
	ep_event.data.fd = ph_logger.sock_fd;
	__ph_logger_init_basic(&ph_logger);
	if (epoll_ctl(ph_logger.epoll_fd, EPOLL_CTL_ADD, ep_event.data.fd, &ep_event))
		goto out;
	return 0;
out:
	close(ph_logger.sock_fd);
	close(ph_logger.epoll_fd);
	return -1;
}

static void sigterm_handler(int signum)
{
	ph_logger.flags = PH_LOGGER_FLAG_STOP;
}

static void sigchld_handler(int signum)
{
	/*
	 * Reap the child procs.
	 */
	while(waitpid(-1, NULL, WNOHANG) > 0)
		;	
}

static int ph_logger_push_logs(	struct ph_logger *ph_logger,
				struct pantavisor_config *config,
				char *logs)
{
	int ret = 0;
        trest_auth_status_enum status = TREST_AUTH_STATUS_NOTAUTH;
	trest_request_ptr req = NULL;
	trest_response_ptr res = NULL;

	if (ph_logger->client)
		goto auth;

	if (!config->creds.prn || strcmp(config->creds.prn, "") == 0) {
			ret = -1;
			goto out;
	}
	ph_logger->client = trest_new_tls_from_userpass(
			config->creds.host,
			config->creds.port,
			config->creds.prn,
			config->creds.secret,
			pv_ph_get_certs(NULL),
			ph_logger->user_agent,
			&ph_logger->pv_conn->sock);
	
	if (!ph_logger->client) {
		ret = -1;
		goto out;
	}
auth:
	status = trest_update_auth(ph_logger->client);
	if (status != TREST_AUTH_STATUS_OK) {
		ret = -1;
		goto out;
	}
	req = trest_make_request(TREST_METHOD_POST,
				 "/logs/",
				 0, 0,
				 logs);
	if (!req) {
		ret = -1;
		goto out;
	}
	res = trest_do_json_request(ph_logger->client, req);
	if (!res) {
		ret = -1;
		goto out;
	}
	if (!res->body || res->code != THTTP_STATUS_OK) {
		pv_log(DEBUG, "logs upload status = %d, body = '%s'", 
				res->code, (res->body ? res->body : ""));
		if (res->code == THTTP_STATUS_BAD_REQUEST)
			ret = -1;
		goto out;
	}
out:
	if (req)
		trest_request_free(req);
	if (res)
		trest_response_free(res);

	return ret;
}

static char *strnchr(char *src, char ch, int len)
{
	int idx = 0;

	if (!src || len <= 0)
		return NULL;
	for (idx = 0 ; idx < len && src[idx] ; idx++) {
		if (src[idx] == ch)
			return src + idx;
	}
	return NULL;
}

/*
 * The log files contains each line ending in a '\n'
 * Read 4K block of filename, seek to the last saved position in
 * xattr of the filename and push the log line to PH.
 * If a new line isn't found, it's probably not written yet so wait
 * for it to appear and try again later.
 */
static int ph_logger_push_from_file(const char *filename, char *platform, char *source, int rev)
{
	int ret = 0;
	char buff[32] = {0};
	char *dst = buff;
	off_t pos = 0;
	int offset = 0;
	off_t read_pos = 0;
	struct stat st;
	int fd = -1;
	char buf[BUF_CHUNK];
	int bytes_read = 0;
	int nr_frags = 0;
	int len_frags = 0;

	ret = get_xattr_on_file(filename, PH_LOGGER_POS_XATTR, &dst, NULL);
	if (ret > 0) {
		sscanf(dst, "%" PRId64, &pos);
	} else {
		pv_log(DEBUG, "XATTR %s errno = %d .Start position of file %s is %lld\n",
				PH_LOGGER_POS_XATTR, -ret, filename, pos);
	}
	ret = -1;
#ifdef DEBUG
	if (!dl_list_empty(&frag_list)) {
		printf("BUG!! .Frag list must be empty\n");
	}
#endif
	dl_list_init(&frag_list);
	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		pv_log(ERROR, "Unable to open file %s\n", filename);
		goto out;
	}

	if (lseek(fd, pos, SEEK_SET) == (off_t) -1) {
		pv_log(ERROR, "Unable to seek to position %lld for %s\n", pos, filename);
		goto close_fd;
	}

	read_pos = lseek(fd, 0, SEEK_CUR);

	if (!fstat(fd, &st)) {
		/*
		 * The stored position was larger
		 * then the current size of the file.
		 * We assume it was truncated hence read from the
		 * beginning.
		 */
		if (st.st_size < read_pos) {
			lseek(fd, 0, SEEK_SET);
			read_pos = 0;
		}
	}

	bytes_read = read_nointr(fd, buf, sizeof(buf));
	/*
	 * we've to get rid of all NULL bytes in buf
	 * otherwise the format_json won't really work as it'll
	 * see the length of the string short.
	 */
	str_replace(buf, bytes_read, '\0',' ');
	while(bytes_read > 0) {
		char *newline_at = NULL;
		char *src = buf + offset;
		char *formatted_json = NULL;
		/*
		 * add 1 for holding a null byte.
		 * */
		char json_holder[sizeof(buf)  + 1];

		newline_at = strnchr(src, '\n', bytes_read);
		if (newline_at) {
			int len = newline_at - src + 1;
			/*
			 * Use json_holder temporarily to
			 * get the source name and platform 
			 * name.
			 */
			sprintf(json_holder, "%.*s", len - 1, src);
			offset += len;
			bytes_read -= offset;
			json_holder[len - 1] = '\0';
		} else {
			/* No new line found, there can be 2 cases here,
			 * either we've read a full BUF_CHUNK and found no newline
			 * in which case there's nothing else we can do but dump
			 * it. But if bytes_read are != BUF_CHUNK then we can
			 * safely assume we might get a new line later and in this
			 * case we simply bail out.
			 */
			if (bytes_read == sizeof(buf)) {
				sprintf(json_holder, "%.*s", bytes_read, src);
				offset += bytes_read;
				json_holder[bytes_read] = '\0';
				bytes_read = 0;
			} else {
				/*
				 * A small file will not be pushed out
				 * if it doesn't contain a '\n'. Similarly a large file's
				 * last chunk(BUF_CHUNK) size may not be pushed out as it's
				 * similar to the case of small file.
				 * The reason being we can't differentiate between a slow
				 * growing file and a file that doesn't grow at all.
				 */
				bytes_read = 0;
				break;
			}
		}
#ifdef DEBUG
		pv_log(DEBUG, "buf strlen = %d for file %s\n", strlen(json_holder), filename);
#endif
		formatted_json = format_json(json_holder, strlen(json_holder));
		if (formatted_json) {
			char __rev_str[8];
			struct ph_logger_fragment *frag = NULL;
			char *__json_frag = NULL;
			int frag_len = 0;
			
			snprintf(__rev_str, sizeof(__rev_str), "%d", rev);
			frag_len = sizeof(PH_LOGGER_JSON_FORMAT) + 
					strlen(pv_log_level_name(INFO)) +
					strlen(source) +
					strlen(platform) +
					strlen(__rev_str) +
					strlen(formatted_json) +
					/*largest 64 bit is 19 digits*/
					19 +
					/*largest 32 bit is 10 digits.
					 * sizeof accomodates for null
					 */
					10;
			__json_frag = (char*)calloc(1, frag_len);
			if (__json_frag) {
				char *shrinked = NULL;

				snprintf(__json_frag, frag_len, PH_LOGGER_JSON_FORMAT,
						(uint64_t)0, (uint32_t)0, pv_log_level_name(INFO), source,
						platform, __rev_str, formatted_json);
				shrinked = realloc(__json_frag, strlen(__json_frag) + 1);
				if (shrinked)
					__json_frag = shrinked;
				frag = ph_logger_alloc_frag(__json_frag);
				dl_list_add_tail(&frag_list, &frag->list);
				nr_frags++;
				len_frags += strlen(frag->json_frag);
				pos = read_pos + offset;
			} else {
				/*Bail out on the first error*/
				bytes_read = 0;
			}
			free(formatted_json);
		} else if (strlen(json_holder)){ /*we actually failed to create json*/
			/*
			 * Dont' try for next block if this block
			 * couldn't be json escaped.
			 */
#ifdef DEBUG
			pv_log(WARN, "json_format failed for %s", filename);
#endif
			bytes_read = 0;
		} else {
			/*
			 * We got a new line at the beginning of our
			 * data buffer. Make sure we store the position
			 * in xattr otherwise we'll just keep looping in
			 * this block without reading the file further if
			 * this block contains only new lines.
			 *
			 * If we got some text after this newline, then the
			 * offset above would take place so no need to re-init
			 * offset after writing it here.
			 */
			char value[20];

			pos = read_pos + offset;
			snprintf(value, sizeof(value), "%"PRId64, pos);
			set_xattr_on_file(filename, PH_LOGGER_POS_XATTR, value);
		}
	}
close_fd:
	close(fd);
	if (!dl_list_empty(&frag_list)) {
		struct ph_logger_fragment *item, *tmp;
		char *json_frag_array = NULL;
		int off = 0;
		int avail = 0;
		int written = 0;
		/*
		 * Each fragment will need to be separated by ',' thus
		 * we'll need nr_frags - 1 bytes in addition to size
		 * of each of the frags. The whole bundle needs to be
		 * inside '[' ']'. Thus
		 * bytes_reqd = nr_frags - 1 + 2 + len_frags + 1 (for null).
		 */
		avail =  nr_frags + len_frags + 2;
		json_frag_array = (char*) calloc(1, avail);
		if (json_frag_array) {
			off = sprintf(json_frag_array, "[");
			avail -= off;
		}

		dl_list_for_each_safe(item, tmp, &frag_list, 
				struct ph_logger_fragment, list) {
			if (json_frag_array) {
				written = snprintf(json_frag_array + off, avail, "%s",
						item->json_frag);
				avail -= written;
				off += written;
			}
			dl_list_del(&item->list);
			/*
			 * Is there another item if so add , in
			 * json.
			 */
			if (!dl_list_empty(&frag_list) && json_frag_array) {
				written = snprintf(json_frag_array + off, avail, ",");
				avail -= written;
				off += written;
			}
			free(item->json_frag);
			free(item);
		}
		if (json_frag_array) {
			snprintf(json_frag_array + off, avail, "]");
			/*
			 * We've something to send. Mark that with
			 * ret = 0. Though we may fail to push things
			 * upstream recording the fact that there was
			 * indeed something to send counts.
			 * This is required so that pusher service for other
			 * revisions doesn't exit.
			 */
			ret = 0;
#ifdef DEBUG
			{
				int to_send = strlen(json_frag_array);
				int __send_off = 0;

				printf("sending for filename %s: \n %s\n==\n", filename, json_frag_array);

				while (to_send > 0) {
					pv_log(INFO, "Sending json as , len = %d,\n: %.*s", to_send,
							BUF_CHUNK * 3  - 100,
							json_frag_array + __send_off);
					to_send -= BUF_CHUNK * 3 - 100;
					__send_off += BUF_CHUNK *3 - 100;
				}
			}
#endif
			if (!ph_logger_push_logs(&ph_logger, pv_global->config, json_frag_array)) {
				char value[20];

				sprintf(value, "%"PRId64, pos);
				set_xattr_on_file(filename, PH_LOGGER_POS_XATTR, value);
			}
			free(json_frag_array);
		}
	}
out:
	return ret;
}

static int ph_logger_write_to_log_file(struct ph_logger_msg  *ph_logger_msg)
{
	char *log_dir = PH_LOGGER_LOGDIR;
	int rev = ph_logger.revision;
	ph_logger_file_rw_handler_t  file_handler = NULL;
	int ret = 0;

	file_handler = get_file_rw_handler(ph_logger_msg->version);
	if (file_handler)
		ret = file_handler(ph_logger_msg, log_dir, rev);
	return ret;
}

static int ph_logger_read_write(struct ph_logger *ph_logger)
{
	struct epoll_event ep_event[PH_LOGGER_MAX_EPOLL_FD];
	int ret = 0;
	int nr_logs = 0;
again:
	ret = epoll_wait(ph_logger->epoll_fd, ep_event, PH_LOGGER_MAX_EPOLL_FD, -1);
	if (ret < 0) {
		if (errno == EINTR)
			goto again;
		else {
			perror("pantahub logger service error in epoll_wait: ");
			return -1;
		}
	}
	while(ret > 0) {
		int work_fd;
		/* Only one way comm.*/
		struct sockaddr __unused;
		/* index into event array*/
		ret -= 1; 
		work_fd = ep_event[ret].data.fd;

		if (work_fd == ph_logger->sock_fd) {
			socklen_t sock_size;
			int client_fd = -1;
accept_again:
			client_fd = accept(ph_logger->sock_fd, &__unused, &sock_size);
			if (client_fd > 0) {
				/* reuse ep_event to add the new client_fd
				 * to epoll.
				 */
				memset(&ep_event[ret], 0, sizeof(ep_event[ret]));
				ep_event[ret].events = EPOLLIN;
				ep_event[ret].data.fd = client_fd;

				if (epoll_ctl(ph_logger->epoll_fd, EPOLL_CTL_ADD, client_fd, &ep_event[ret]))
					close(client_fd);/*So client would know*/

			} else if (client_fd < 0 && errno == EINTR)
				goto accept_again;
		} else {
			/* We've data to read.*/
			char buf[BUF_CHUNK + sizeof(struct ph_logger_msg)];
			int nr_read = 0;
			struct ph_logger_msg *msg = (struct ph_logger_msg*)buf;

			nr_read = read_nointr(work_fd, buf, sizeof(buf));
			if (nr_read > 0) {
				ph_logger_write_to_log_file(msg);
				nr_logs++;
			}
			epoll_ctl(ph_logger->epoll_fd, EPOLL_CTL_DEL, work_fd, &ep_event[ret]);
			close(work_fd);
		}
	}
	return nr_logs;
}

static void ph_logger_load_config(struct pantavisor *pv)
{
	char ph_path[PATH_MAX];

	if (pv_config_from_file(PV_CONFIG_FILENAME, pv->config)) {
		WARN_ONCE("Error starting pantahub logger service."
				"Unable to parse pantavisor config.\n");
	}
	/* Load PH config. */
	sprintf(ph_path, "%s/config/pantahub.config", pv->config->storage.mntpoint);

	if (ph_config_from_file(ph_path, pv->config)) {
		WARN_ONCE("Error starting pantahub logger service."
				"Unable to parse pantahub config.\n");
	}
}

/*
 * For each newline found in buf, construct a filename to read from.
 */
static int __ph_logger_push_one_log(char *buf, int len, int revision, int offset)
{
	char platform[64];
	char *source = NULL;
	char *filename = buf;
	char *slash_at = strchr(buf + offset, '/');


	if (!slash_at)
		sprintf(platform, "pantavisor-UNKNOWN"); 
	else {
		/*
		 * platform is before the first /.
		 */
		snprintf(platform, sizeof(platform), "%.*s",
				(int)(slash_at  - (buf + offset)), buf + offset);
	}
	/*
	 * Rest of the line is the source
	 */
	if (!slash_at)
		source = filename;
	else
		source = slash_at;

	if (ph_logger_get_connection(&ph_logger, pv_global->config)) {
		if (!pv_global->config->creds.prn || 
				strcmp(pv_global->config->creds.prn, "") == 0) {
			ph_logger_load_config(pv_global);
		}
		return ph_logger_push_from_file(filename, platform, source, revision);
	}
	return -1;
}

static bool ph_logger_helper_function(int revision)
{
	char find_cmd[1024];
	FILE *find_fp = NULL;
	int offset_bytes = 0;
	bool sent_one = false;

	/*
	 * Figure out how much to move
	 * ahead in the returned result set for
	 * each file path returned. We need to move forward
	 * PH_LOGGER_DIR/<revision>/ characters to get to the
	 * actual file path.
	 */

	snprintf(find_cmd, sizeof(find_cmd), "%s/%d/", PH_LOGGER_LOGDIR, revision);
	offset_bytes = strlen(find_cmd);

	/*
	 * reuse find_cmd to load all skip_prefixes if any.
	 */
	snprintf(find_cmd, sizeof(find_cmd), "%s/%d/%s", PH_LOGGER_LOGDIR, revision, PH_LOGGER_SKIP_FILE);
	ph_logger_add_skip_prefixes(&ph_logger, find_cmd);

	snprintf(find_cmd, sizeof(find_cmd), "find %s/%d -type f ! -name '*.gz*' 2>/dev/null", PH_LOGGER_LOGDIR, revision);
	find_fp = popen(find_cmd, "r");

	if (find_fp) {
		char *buf = NULL;
		size_t size = 0;
		
		while (!feof(find_fp)) {
			ssize_t nr_read = 0;
			
			nr_read = getline(&buf, &size, find_fp);
			if ( nr_read> 0) {
				int ret = -1;
				
				/*Get rid of '\n'*/
				buf[nr_read - 1] = '\0';
				if (ph_logger_contains_skip_prefix(&ph_logger, buf + offset_bytes))
					continue;
				ret = __ph_logger_push_one_log(buf, nr_read, 
						revision, offset_bytes);
				if (!sent_one) {
					/*ret == 0 for one sent item*/
					sent_one = (ret == 0); 
				}
			}
			else {
				break;
			}
		}
		if (buf)
			free(buf);
		pclose(find_fp);
	}
	ph_logger_clear_skip_prefix(&ph_logger);
	return sent_one;
}

static pid_t ph_logger_create_push_helper(int revision)
{
	pid_t helper_pid = -1;
	const int max_sleep = 10;
	int sleep_secs = 1;

	helper_pid = fork();
	if (helper_pid == 0) {
		close(ph_logger.epoll_fd);
		close(ph_logger.sock_fd);
		while (1) {
			bool sent_one = ph_logger_helper_function(revision);
			/*
			 * Don't keep poking if there was nothing to send out
			 * but don't stay idle for more than 10 seconds at most.
			 */
			if (!sent_one) {
				pv_log(WARN, "Sleeping for revision %d", revision);
				sleep(sleep_secs);
				sleep_secs ++;
				sleep_secs = (sleep_secs == max_sleep ? max_sleep : sleep_secs);
			} else {
				sleep_secs -= 1;
				sleep_secs = (sleep_secs == 0 ? 1 : sleep_secs);
			}
		}
	}
	return helper_pid;
}

int ph_logger_service_start_for_range(struct pantavisor *pv, int max_revisions)
{
	pid_t range_service = -1;
	/*
	 * Don't start anything for invalid
	 * revisions.
	 */
	if (max_revisions < 0)
		goto out;
	range_service = fork();
	if (range_service == 0) {
		unsigned int iterations = 0;
		
		__ph_logger_init_basic(&ph_logger);
		while (max_revisions >= 0) {
			bool sent_one = false;

			iterations++;
			ph_logger.revision = max_revisions;
			sent_one = ph_logger_helper_function(max_revisions);
			if (!sent_one) {
				max_revisions--;
				iterations = 0;
			}
		}
		pv_log(INFO, "PH pusher service stopped for revision %d", max_revisions + 1);
		_exit(EXIT_SUCCESS);
	}
#ifdef DEBUG
	if (range_service > 0) {
		printf("Started range service for PH logs upto revision %d\n", max_revisions);
	}
#endif
out:
	return range_service;
}

int ph_logger_service_start(struct pantavisor *pv, const char *sock_path, int revision)
{
	pid_t service_pid = -1;
	int pipefd[2] = {-1, -1};
	int service_status = -1;

	pv_global = pv;

	/*
	 * We must tell parent process to wait
	 * for initialization.
	 */
	if (pipe(pipefd)) {
		printf("Not waiting for PH logger service"
			" some logs may not be available\n");
	}
	service_pid = fork();
	if (service_pid == 0) {
		struct sigaction sa;
		pid_t push_pid = -1;
		close(pipefd[0]);
		/*
		 * We set the online status of this dummy to be
		 * false so that we never flush while adding to
		 * the ring buffer.
		 */
		pv_global->online = false;
		memset(&sa, 0, sizeof(sa));
		
		sa.sa_handler = sigterm_handler;
		sa.sa_flags = SA_RESTART;
		sigaction(SIGTERM, &sa, NULL);

		sa.sa_handler = sigchld_handler;
		sigaction(SIGCHLD, &sa, NULL);
retry:
		service_status = ph_logger_init(sock_path, NULL);
		if (service_status) {
			printf("Error initializing pantahub logger service %s\n", sock_path);
			printf("Retrying initialization in 10 seconds\n");
			if (pipefd[1] >= 0)
				write_nointr(pipefd[1], (char*)&service_status, sizeof(service_status));
			pipefd[1] = -1;
			sleep(10);
			goto retry;
		}
		/*
		 * The control socket has now been initialized.
		 * We can ask the parent process to continue.
		 */
		if (pipefd[1] >= 0) {
			write_nointr(pipefd[1], (char*)&service_status, sizeof(service_status));
			/*Allow the parent process to be able to read correct status code.*/
			sleep(10); 
			close(pipefd[1]);
		}
		ph_logger.revision = revision;
		push_pid = ph_logger_create_push_helper(revision);
		if (push_pid > 0)
			printf("Initialized PH push helper, pid = %d by service process (%d)\n",
					push_pid, getpid());
		while (!(ph_logger.flags & PH_LOGGER_FLAG_STOP)) {
			ph_logger_read_write(&ph_logger);
		}
		printf("Exiting ph logger service.\n");
		_exit(EXIT_SUCCESS);
	}

	close(pipefd[1]);
	read_nointr(pipefd[0], (char*)&service_status, sizeof(service_status));
	printf("Pantahub logger service initialized with return code %d\n",
			service_status);
	close(pipefd[0]);
	return service_pid;
}

int ph_logger_read_bytes(struct ph_logger_msg *ph_logger_msg, char *buf, ...)
{
	va_list args;
	va_start(args, buf);
	int ret = 0;
	ph_logger_handler_t reader = get_read_handler(ph_logger_msg->version);

	if (reader)
		ret = reader(ph_logger_msg, buf, args);
	va_end(args);
	return ret;
}

int ph_logger_write_bytes(struct ph_logger_msg *ph_logger_msg, const char *buf, ...)
{
	va_list args;
	va_start(args, buf);
	int written = 0;

	ph_logger_handler_t writer = get_write_handler(ph_logger_msg->version);

	if (writer)
		written = writer(ph_logger_msg, (char*)buf, args);
	va_end(args);
	return written;
}
/*
 * Copyright (c) 2020-2022 Pantacor Ltd.
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
#include <sys/xattr.h>
#include <sys/un.h>
#include <stdlib.h>
#include <stdbool.h>
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
#include <errno.h>

#include "../state.h"
#include "../trestclient.h"
#include "../pantavisor.h"
#include "../pantahub.h"
#include "../version.h"
#include "../pvctl_utils.h"
#include "list.h"
#include "utils/system.h"
#include "utils/math.h"
#include "utils/str.h"
#include "utils/tsh.h"
#include "utils/pvsignals.h"
#include "json.h"
#include "fs.h"
#include "buffer.h"
#include "ph_logger.h"
#include "paths.h"
#include "logserver/logserver.h"

#define MODULE_NAME "ph_logger"
#include "../log.h"

#define PH_LOGGER_POS_FILE PV_PATH "/.ph_logger"
#define PH_LOGGER_BACKLOG (20)
#define PH_LOGGER_LOGFILE "/ph_logger.log"

#define PH_LOGGER_FLAG_STOP (1 << 0)
#define USER_AGENT_LEN (128)

#define MODULE_NAME "ph_logger"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

/*
 * Include after defining MODULE_NAME.
 */
#define PH_LOGGER_MAX_EPOLL_FD (50)

static struct pantavisor *pv_global;

struct ph_logger_fragment {
	struct dl_list list;
	char *json_frag;
};

static DEFINE_DL_LIST(frag_list);

struct ph_logger_file {
	char *path;
	off_t pos;
	struct dl_list list; // ph_logger_file
};

struct ph_logger {
	int flags;
	int epoll_fd;
	trest_ptr *client;
	struct pv_connection *pv_conn;
	char user_agent[USER_AGENT_LEN];
	pid_t log_service;
	pid_t range_service;
	pid_t push_service;
	struct dl_list files; // ph_logger_file
};

static struct ph_logger ph_logger = { .epoll_fd = -1,
				      .pv_conn = NULL,
				      .client = NULL,
				      .log_service = -1,
				      .range_service = -1,
				      .push_service = -1 };

static char *current_process = MODULE_NAME;

static struct ph_logger_fragment *__ph_logger_alloc_frag(char *json_frag,
							 bool do_frag_dup)
{
	struct ph_logger_fragment *frag = NULL;

	if (!json_frag)
		return NULL;
	frag = (struct ph_logger_fragment *)calloc(1, sizeof(*frag));
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
static struct ph_logger_fragment *ph_logger_alloc_frag(char *json_frag)
{
	return __ph_logger_alloc_frag(json_frag, false);
}

static int ph_logger_get_connection(struct ph_logger *ph_logger)
{
	if (ph_logger->pv_conn)
		goto out;

	ph_logger->pv_conn = pv_get_instance_connection();
	if (ph_logger->client) {
		trest_free(ph_logger->client);
		ph_logger->client = NULL;
	}
out:
	return !!ph_logger->pv_conn;
	;
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
	while (waitpid(-1, NULL, WNOHANG) > 0)
		;
}

static int ph_logger_push_logs_endpoint(struct ph_logger *ph_logger, char *logs)
{
	int ret = -1;
	trest_auth_status_enum status = TREST_AUTH_STATUS_NOTAUTH;
	trest_request_ptr req = NULL;
	trest_response_ptr res = NULL;

	if (ph_logger->client)
		goto auth;

	ph_logger->client = pv_get_trest_client(pv_global, ph_logger->pv_conn);

	if (!ph_logger->client) {
		goto out;
	}
auth:
	status = trest_update_auth(ph_logger->client);
	if (status != TREST_AUTH_STATUS_OK) {
		goto out;
	}
	req = trest_make_request(THTTP_METHOD_POST, "/logs/", logs);
	if (!req) {
		goto out;
	}
	res = trest_do_json_request(ph_logger->client, req);
	if (!res) {
		pv_log(WARN,
		       "HTTP request POST /logs/ could not be initialized");
	} else if (!res->code && res->status != TREST_AUTH_STATUS_OK) {
		pv_log(WARN,
		       "HTTP request POST /logs/ could not auth (status=%d)",
		       res->status);
	} else if (res->code != THTTP_STATUS_OK) {
		pv_log(WARN,
		       "HTTP request POST /logs/ returned HTTP error (code=%d; body='%s')",
		       res->code, res->body);
	} else {
		ret = 0;
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
	for (idx = 0; idx < len && src[idx]; idx++) {
		if (src[idx] == ch)
			return src + idx;
	}
	return NULL;
}

struct ph_logger_file *_search_log_file(const char *path)
{
	struct ph_logger_file *f, *tmp;
	dl_list_for_each_safe(f, tmp, &ph_logger.files, struct ph_logger_file,
			      list)
	{
		if (pv_str_matches_len(path, strlen(path), f->path,
				       strlen(f->path)))
			return f;
	}

	return NULL;
}

static void _save_log_file_pos(off_t pos, const char *path)
{
	// try to get file info from memory
	struct ph_logger_file *f;
	f = _search_log_file(path);
	// if not, we create a new entry
	if (!f) {
		pv_log(DEBUG,
		       "log file '%s' not yet stored in memory. Saving new file...",
		       path);
		f = calloc(1, sizeof(struct ph_logger_file));
		if (f) {
			f->path = strdup(path);
			dl_list_add(&ph_logger.files, &f->list);
		}
	}
	if (!f) {
		pv_log(ERROR, "could not initialize log file: %s",
		       strerror(errno));
		return;
	}

	// update pos value in memory
	f->pos = pos;

	// save pos in xattr if possible by config
	if (!pv_config_get_str(PV_STORAGE_LOGTEMPSIZE)) {
		char value[MAX_DEC_STRING_SIZE_OF_TYPE(pos)];
		SNPRINTF_WTRUNC(value, sizeof(value), "%jd", (intmax_t)pos);
		if (setxattr(path, PH_LOGGER_POS_XATTR, value, strlen(value),
			     0))
			pv_log(WARN, "xattr could not be saved in '%s': %s",
			       path, strerror(errno));
	}
}

#define MAX_XATTR_SIZE 32

static off_t _load_log_file_pos(const char *path)
{
	// first, try to get pos from memory
	struct ph_logger_file *f;
	f = _search_log_file(path);
	if (f)
		return f->pos;

	pv_log(DEBUG, "unknown file found in '%s'", path);

	// if not in memory, try to get it from xattr if possible
	char dst[MAX_XATTR_SIZE] = { 0 };
	off_t pos = 0;
	if (!pv_config_get_str(PV_STORAGE_LOGTEMPSIZE)) {
		pv_log(DEBUG, "log file is persistent. Trying to get xattr...",
		       path);
		if (getxattr(path, PH_LOGGER_POS_XATTR, dst, MAX_XATTR_SIZE) >
		    0)
			sscanf(dst, "%jd", &pos);
		else {
			if (errno == ENODATA)
				// if xattr does not yet exist for that path, we save it with pos 0
				_save_log_file_pos(pos, path);
			else
				pv_log(WARN, "xattr could not be loaded: %s",
				       strerror(errno));
		}
	}

	return 0;
}

/*
 * The log files contains each line ending in a '\n'
 * Read 4K block of filename, seek to the last saved position in
 * xattr of the filename and push the log line to PH.
 * If a new line isn't found, it's probably not written yet so wait
 * for it to appear and try again later.
 */
static int ph_logger_push_from_file(const char *filename, char *platform,
				    char *source, char *rev)
{
	int ret = 0;
	off_t pos = 0;
	int offset = 0;
	off_t read_pos = 0;
	struct stat st;
	int fd = -1;
	char *buf = NULL;
	int bytes_read = 0;
	int nr_frags = 0;
	int len_frags = 0;
	struct buffer *log_buff = NULL;
	struct buffer *large_buff = NULL;

	large_buff = pv_buffer_get(true);
	if (!large_buff) {
		ret = -1;
		goto out;
	}

	log_buff = pv_buffer_get(false);
	if (!log_buff) {
		ret = -1;
		goto out;
	}
	buf = log_buff->buf;

	pos = _load_log_file_pos(filename);
#ifdef DEBUG
	if (!dl_list_empty(&frag_list)) {
		pv_log(WARN, "frag list must be empty");
	}
#endif
	dl_list_init(&frag_list);
	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		pv_log(ERROR, "open failed for %s: %s", filename,
		       strerror(errno));
		ret = -1;
		goto out;
	}

	if (lseek(fd, pos, SEEK_SET) == (off_t)-1) {
		pv_log(ERROR, "Unable to seek to position %jd for %s",
		       (intmax_t)pos, filename);
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

	bytes_read = pv_fs_file_read_nointr(fd, buf, log_buff->size);
	/*
	 * we've to get rid of all NULL bytes in buf
	 * otherwise the pv_json_format won't really work as it'll
	 * see the length of the string short.
	 */
	pv_str_replace_char(buf, bytes_read, '\0', ' ');
	while (bytes_read > 0) {
		char *newline_at = NULL;
		char *src = buf + offset;
		char *formatted_json = NULL;
		char *json_holder = NULL;

		json_holder = large_buff->buf;
		newline_at = strnchr(src, '\n', bytes_read);
		if (newline_at) {
			int len = newline_at - src + 1;
			/*
			 * Use json_holder temporarily to
			 * get the source name and platform
			 * name.
			 */
			SNPRINTF_WTRUNC(json_holder, len, "%.*s", len - 1, src);
			offset += len;
			bytes_read -= offset;
			json_holder[len - 1] = '\0';
		} else {
			/* No new line found, there can be 2 cases here,
			 * either we've read a full log_buf->size and found no newline
			 * in which case there's nothing else we can do but dump
			 * it. But if bytes_read are != log_buf->size then we can
			 * safely assume we might get a new line later and in this
			 * case we simply bail out.
			 */
			if (bytes_read == log_buff->size) {
				SNPRINTF_WTRUNC(json_holder, bytes_read + 1,
						"%.*s", bytes_read, src);
				offset += bytes_read;
				json_holder[bytes_read] = '\0';
				bytes_read = 0;
			} else {
				/*
				 * A small file will not be pushed out
				 * if it doesn't contain a '\n'. Similarly a large file's
				 * last chunk log_buf->size may not be pushed out as it's
				 * similar to the case of small file.
				 * The reason being we can't differentiate between a slow
				 * growing file and a file that doesn't grow at all.
				 */
				break;
			}
		}
#ifdef DEBUG
		pv_log(DEBUG, "buf strlen = %zd for file %s\n",
		       strlen(json_holder), filename);
#endif
		formatted_json =
			pv_json_format(json_holder, strlen(json_holder));
		if (formatted_json) {
			struct ph_logger_fragment *frag = NULL;
			char *__json_frag = NULL;
			int frag_len = 0;

			frag_len = sizeof(PH_LOGGER_JSON_FORMAT) +
				   strlen(pv_log_level_name(INFO)) +
				   strlen(source) + strlen(platform) +
				   strlen(rev) + strlen(formatted_json) +
				   /*largest 64 bit is 19 digits*/
				   19 +
				   /*largest 32 bit is 10 digits.
				 * sizeof accomodates for null
				 */
				   10;
			__json_frag = calloc(frag_len, sizeof(char));
			if (__json_frag) {
				char *shrinked = NULL;

				SNPRINTF_WTRUNC(__json_frag, frag_len,
						PH_LOGGER_JSON_FORMAT,
						(uint64_t)0, (uint32_t)0,
						pv_log_level_name(INFO), source,
						platform, rev, formatted_json);
				shrinked = realloc(__json_frag,
						   strlen(__json_frag) + 1);
				if (shrinked)
					__json_frag = shrinked;
				frag = ph_logger_alloc_frag(__json_frag);
				dl_list_add_tail(&frag_list, &frag->list);
				nr_frags++;
				len_frags += strlen(frag->json_frag);
				pos = read_pos + offset;
			} else {
				/*Bail out on the first error*/
				pv_log(ERROR, "alloc error for filename %s",
				       filename);
				bytes_read = 0;
			}
			free(formatted_json);
		} else if (strlen(json_holder)) { /*we actually failed to create json*/
			/*
			 * Dont' try for next block if this block
			 * couldn't be json escaped.
			 */
			pv_log(ERROR, "json format error for filename %s",
			       filename);
			bytes_read = 0;
		} else {
			pos = read_pos + offset;
			_save_log_file_pos(pos, filename);
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
		avail = nr_frags + len_frags + 2;
		json_frag_array = calloc(avail, sizeof(char));
		if (json_frag_array) {
			off = snprintf(json_frag_array, 2, "[");
			avail -= off;
		}

		dl_list_for_each_safe(item, tmp, &frag_list,
				      struct ph_logger_fragment, list)
		{
			if (json_frag_array) {
				written = snprintf(json_frag_array + off, avail,
						   "%s", item->json_frag);
				avail -= written;
				off += written;
			}
			dl_list_del(&item->list);
			/*
			 * Is there another item if so add , in
			 * json.
			 */
			if (!dl_list_empty(&frag_list) && json_frag_array) {
				written = snprintf(json_frag_array + off, avail,
						   ",");
				avail -= written;
				off += written;
			}
			free(item->json_frag);
			free(item);
		}
		if (json_frag_array) {
			SNPRINTF_WTRUNC(json_frag_array + off, avail, "]");
			// set ret to 1, something pending to be sent
			ret = 1;
			if (!ph_logger_push_logs_endpoint(&ph_logger,
							  json_frag_array))
				_save_log_file_pos(pos, filename);
			// in case of error while sending, we return -1
			else
				ret = -1;
			free(json_frag_array);
		}
	}
out:
	pv_buffer_drop(log_buff);
	pv_buffer_drop(large_buff);
	return ret;
}

/*
 * For each newline found in buf, construct a filename to read from.
 */
static int ph_logger_push_from_file_parse_info(char *buf, int len,
					       char *revision, int offset)
{
	char platform[64];
	char *source = NULL;
	char *filename = buf;
	char *slash_at = strchr(buf + offset, '/');

	if (!slash_at)
		SNPRINTF_WTRUNC(platform, sizeof(platform),
				"pantavisor-UNKNOWN");
	else {
		/*
		 * platform is before the first /.
		 */
		SNPRINTF_WTRUNC(platform, sizeof(platform), "%.*s",
				(int)(slash_at - (buf + offset)), buf + offset);
	}
	/*
	 * Rest of the line is the source
	 */
	if (!slash_at)
		source = filename;
	else
		source = slash_at;

	if (ph_logger_get_connection(&ph_logger))
		return ph_logger_push_from_file(filename, platform, source,
						revision);
	pv_log(DEBUG, "exits this way");
	return -1;
}

static int ph_logger_push_revision(char *revision)
{
	char find_cmd[1024], path[PATH_MAX];
	FILE *find_fp = NULL;
	int offset_bytes = 0;
	int result = 0;

	/*
	 * Figure out how much to move
	 * ahead in the returned result set for
	 * each file path returned. We need to move forward
	 * PH_LOGGER_DIR/<revision>/ characters to get to the
	 * actual file path.
	 */

	pv_paths_pv_log(path, PATH_MAX, "");
	SNPRINTF_WTRUNC(find_cmd, sizeof(find_cmd), "%s/%s/", path, revision);
	offset_bytes = strlen(find_cmd);

	SNPRINTF_WTRUNC(find_cmd, sizeof(find_cmd),
			"find %s/%s -type f ! -name '*.gz*' 2>/dev/null", path,
			revision);
	find_fp = popen(find_cmd, "r");

	if (find_fp) {
		char *buf = NULL;
		size_t size = 0;

		while (!feof(find_fp)) {
			ssize_t nr_read = 0;

			nr_read = getline(&buf, &size, find_fp);
			if (nr_read > 0) {
				int ret = -1;

				/*Get rid of '\n'*/
				buf[nr_read - 1] = '\0';
				ret = ph_logger_push_from_file_parse_info(
					buf, nr_read, revision, offset_bytes);
				// if there was something to send for al least one file, return 1
				if (ret > 0)
					result = 1;
				// if we got an error while pushing any of the files, return -1
				else if (ret < 0) {
					result = ret;
					break;
				}
			} else {
				break;
			}
		}
		if (buf)
			free(buf);
		pclose(find_fp);
	}
	return result;
}

static void log_libthttp(int level, const char *fmt, va_list args)
{
	if (level > pv_config_get_int(PV_LIBTHTTP_LOG_LEVEL))
		return;

	pv_logserver_send_vlog(false, PV_PLATFORM_STR, current_process, DEBUG,
			       fmt, args);
}

static pid_t ph_logger_start_push_service(char *revision)
{
	pid_t helper_pid = -1;
	int sleep_secs = 0;
	sigset_t oldmask;

	if (pvsignals_block_chld(&oldmask)) {
		pv_log(ERROR, "failed to block SIGCHLD for ph_logger helper: ",
		       strerror(errno));
		return -1;
	}

	helper_pid = fork();
	if (helper_pid == 0) {
		pv_system_set_process_name("pv-phlogger-push");
		close(ph_logger.epoll_fd);
		signal(SIGCHLD, SIG_DFL);
		if (pvsignals_setmask(&oldmask)) {
			pv_log(ERROR,
			       "Unable to reset sigmask in ph_logger helper child: %s",
			       strerror(errno));
			_exit(-1);
		}

		pv_log(INFO,
		       "Initialized push service with pid %d by process with pid %d",
		       getpid(), getppid());
		pv_log(DEBUG, "Push service pushing logs for rev %s", revision);

		current_process = "push_service_libthttp";
		thttp_set_log_func(log_libthttp);
		while (1) {
			// if nothing to push or error while pushing, sleep
			if (ph_logger_push_revision(revision) <= 0) {
				// increment sleep time until 10
				sleep_secs++;
				sleep_secs =
					(sleep_secs > 10 ? 10 : sleep_secs);
				sleep(sleep_secs);
				// if we have more things to push, just decrement sleep time
			} else {
				sleep_secs--;
				sleep_secs = (sleep_secs < 0 ? 0 : sleep_secs);
			}
		}
		_exit(0);
	}

	if (pvsignals_setmask(&oldmask)) {
		pv_log(ERROR,
		       "Unable to reset sigmask in ph_logger helper parent %s",
		       strerror(errno));
		return -1;
	}

	return helper_pid;
}

static int ph_logger_get_max_revision(struct pantavisor *pv)
{
	const char *cmd_fmt = "find %s -type d -mindepth 1 -maxdepth 1";
	char cmd[PATH_MAX], path[PATH_MAX];
	FILE *fp = NULL;
	char *buf = NULL;
	size_t buf_size = 0;
	int max_revision = 0;

	pv_paths_pv_log(path, PATH_MAX, "");
	SNPRINTF_WTRUNC(cmd, PATH_MAX, cmd_fmt, path);

	fp = popen(cmd, "r");
	if (!fp)
		goto out;
	while (!feof(fp)) {
		ssize_t ret = 0;

		ret = getline(&buf, &buf_size, fp);
		if (ret > 0) {
			char *rev_dir = NULL;
			int this_rev = -1;

			//Throw away null byte.
			buf[ret - 1] = '\0';
			rev_dir = basename(buf);
			sscanf(rev_dir, "%d", &this_rev);
			if (this_rev > max_revision)
				max_revision = this_rev;
		} else {
			break;
		}
	}
	if (buf)
		free(buf);
	pclose(fp);
out:
	return max_revision;
}

static pid_t ph_logger_start_range_service(struct pantavisor *pv,
					   char *avoid_rev)
{
	pid_t range_service = -1;
	int current_rev = -1;
	int sleep_secs = 0;
	int result, len;
	char *rev;
	sigset_t oldmask;

	if (pvsignals_block_chld(&oldmask)) {
		pv_log(ERROR,
		       "failed to block SIGCHLD for ph_logger range service: ",
		       strerror(errno));
		return -1;
	}

	range_service = fork();
	if (range_service == 0) {
		pv_system_set_process_name("pv-phlogger-range");
		signal(SIGCHLD, SIG_DFL);
		if (pvsignals_setmask(&oldmask)) {
			pv_log(ERROR,
			       "Unable to reset sigmask in ph_logger range service child: %s",
			       strerror(errno));
			_exit(-1);
		}

		current_rev = ph_logger_get_max_revision(pv);

		pv_log(INFO,
		       "Initialized range service with pid %d by process with pid %d",
		       getpid(), getppid());

		current_process = "range_service_libthttp";
		thttp_set_log_func(log_libthttp);
		while (current_rev >= 0) {
			// skip current revision.
			if (atoi(avoid_rev) == current_rev) {
				current_rev--;
				continue;
			}
			pv_log(DEBUG,
			       "Range service about to push remaining logs for rev %d",
			       current_rev);
			len = snprintf(NULL, 0, "%d", current_rev) + 1;
			rev = calloc(len, sizeof(char));
			SNPRINTF_WTRUNC(rev, len, "%d", current_rev);
			result = ph_logger_push_revision(rev);
			free(rev);
			// if nothing else to send, go to previous revision
			if (result == 0) {
				current_rev--;
				sleep_secs--;
				sleep_secs = (sleep_secs < 0 ? 0 : sleep_secs);
			}
			// if error while sending, sleep
			else if (result < 0) {
				sleep_secs++;
				// increment sleep time until 10
				sleep_secs =
					(sleep_secs > 10 ? 10 : sleep_secs);
				sleep(sleep_secs);
				// if more things to send, just decrement sleep time
			} else {
				sleep_secs--;
				sleep_secs = (sleep_secs < 0 ? 0 : sleep_secs);
			}
		}
		pv_log(INFO, "Range service stopped normally");
		_exit(EXIT_SUCCESS);
	}

	if (pvsignals_setmask(&oldmask)) {
		pv_log(ERROR,
		       "Unable to reset sigmask in ph_logger range service parent %s",
		       strerror(errno));
		return -1;
	}

	return range_service;
}

static void ph_logger_start_cloud(struct pantavisor *pv, char *revision)
{
	if (!pv || !pv->online)
		return;

	if (ph_logger.push_service == -1) {
		ph_logger.push_service = ph_logger_start_push_service(revision);
		if (ph_logger.push_service > 0) {
			pv_log(DEBUG, "started push service with pid %d",
			       ph_logger.push_service);
		} else {
			pv_log(ERROR, "unable to start push service");
		}
	}

	if (ph_logger.range_service == -1) {
		ph_logger.range_service =
			ph_logger_start_range_service(pv, revision);
		if (ph_logger.range_service > 0) {
			pv_log(DEBUG, "started range service with pid %d",
			       ph_logger.range_service);
		} else {
			pv_log(ERROR, "unable to start range service");
		}
	}
}

void ph_logger_toggle(char *rev)
{
	struct pantavisor *pv = pv_get_instance();
	if (!pv)
		return;

	if (pv_config_get_bool(PV_LOG_PUSH) &&
	    (pv_config_get_log_server_outputs() &
	     LOG_SERVER_OUTPUT_FILE_TREE) &&
	    pv->remote_mode) {
		ph_logger_start_cloud(pv, rev);
	} else {
		ph_logger_stop_lenient();
		ph_logger_stop_force();
	}
}

void ph_logger_stop_lenient()
{
	if (ph_logger.push_service > 0) {
		pv_log(DEBUG, "stopping ph logger push service...");
		pv_system_kill_lenient(ph_logger.push_service);
	}
	if (ph_logger.range_service > 0) {
		pv_log(DEBUG, "stopping ph logger range service...");
		pv_system_kill_lenient(ph_logger.range_service);
	}
}

void ph_logger_stop_force()
{
	if (ph_logger.push_service > 0) {
		pv_system_kill_force(ph_logger.push_service);
		pv_log(DEBUG, "stopped push service with pid %d",
		       ph_logger.push_service);
	}
	if (ph_logger.range_service > 0) {
		pv_system_kill_force(ph_logger.range_service);
		pv_log(DEBUG, "stopped range service with pid %d",
		       ph_logger.range_service);
	}

	ph_logger.push_service = -1;
	ph_logger.range_service = -1;
}

void ph_logger_init()
{
	dl_list_init(&ph_logger.files);
}

static void _ph_logger_free_file(struct ph_logger_file *f)
{
	if (f->path)
		free(f->path);
}

void ph_logger_close()
{
	struct ph_logger_file *f, *tmp;
	dl_list_for_each_safe(f, tmp, &ph_logger.files, struct ph_logger_file,
			      list)
	{
		pv_log(DEBUG, "removing file '%s'", f->path);
		dl_list_del(&f->list);
		_ph_logger_free_file(f);
	}
}

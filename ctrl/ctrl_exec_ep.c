/*
 * Copyright (c) 2026 Pantacor Ltd.
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

#include "ctrl_endpoints.h"
#include "ctrl.h"
#include "ctrl_caller.h"
#include "ctrl_util.h"
#include "pantavisor.h"
#include "platforms.h"
#include "state.h"
#include "utils/json.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/http.h>

#include <mbedtls/base64.h>

#define MODULE_NAME "exec-ep"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define EXEC_MAX_ACTIVE 4
#define EXEC_MAX_BODY (384 * 1024)
#define EXEC_MAX_ARGC 256
#define EXEC_MAX_ARG 4096
#define EXEC_MAX_ARGV_TOTAL (32 * 1024)
#define EXEC_MAX_ENV 32
#define EXEC_MAX_STDIN (256 * 1024)
#define EXEC_MAX_TIMEOUT 600
#define EXEC_DEFAULT_TIMEOUT 30
#define EXEC_MAX_OUTPUT (1024 * 1024)
#define EXEC_DEFAULT_OUTPUT 16384
#define EXEC_MAX_TARGET_FILE (256 * 1024)
#define EXEC_KILL_DELAY_S 2
#define EXEC_DRAIN_DELAY_MS 300

enum exec_msg_type { EXEC_MSG_PID = 1, EXEC_MSG_EXIT, EXEC_MSG_ERROR };

// fixed size, so one write to the status pipe is atomic
struct exec_msg {
	int32_t type;
	int32_t a;
	int32_t b;
	char text[116];
};

struct exec_request {
	char **argv;
	int argc;
	char **env_keys;
	char **env_vals;
	int env_count;
	char *cwd;
	char *stdin_data;
	size_t stdin_len;
	long timeout_s;
	long max_output;
};

// what is read from the container init before the helper is forked
struct exec_target {
	pid_t pid;
	char **env;
	uint64_t cap_bnd;
	char **cgroup_files;
	// the root of a hierarchy does not confine the container
	bool *cgroup_root;
	int cgroup_count;
	char *apparmor_label;
};

struct exec_job;

struct exec_stream {
	struct exec_job *job;
	int fd;
	struct event *ev;
	char *buf;
	size_t len;
	size_t max;
	bool truncated;
	bool eof;
};

struct exec_job {
	struct evhttp_request *req;
	struct evhttp_connection *con;
	struct event_base *base;
	char *name;
	char *argv0;
	char *caller;
	struct timespec start;
	long timeout_s;

	pid_t helper;
	pid_t child;

	int status_fd;
	struct event *status_ev;
	struct exec_msg msg;
	size_t msg_len;

	int stdin_fd;
	struct event *stdin_ev;
	char *stdin_data;
	size_t stdin_len;
	size_t stdin_off;

	struct exec_stream out;
	struct exec_stream err;

	struct event *timeout_ev;
	struct event *kill_ev;
	struct event *hard_ev;
	struct event *drain_ev;

	bool timed_out;
	bool got_exit;
	bool got_error;
	int exit_code;
	int exit_signal;
	char error[160];
};

static int exec_active;

static void exec_free_strv(char **v, int n)
{
	if (!v)
		return;
	for (int i = 0; i < n; i++)
		free(v[i]);
	free(v);
}

static void exec_request_free(struct exec_request *r)
{
	exec_free_strv(r->argv, r->argc);
	exec_free_strv(r->env_keys, r->env_count);
	exec_free_strv(r->env_vals, r->env_count);
	free(r->cwd);
	free(r->stdin_data);
	memset(r, 0, sizeof(*r));
}

static void exec_target_free(struct exec_target *t)
{
	if (t->env) {
		for (char **e = t->env; *e; e++)
			free(*e);
		free(t->env);
	}
	exec_free_strv(t->cgroup_files, t->cgroup_count);
	free(t->cgroup_root);
	free(t->apparmor_label);
	memset(t, 0, sizeof(*t));
}

/* request parsing */

static int exec_hex(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static int exec_hex4(const char *s)
{
	int v = 0;

	for (int i = 0; i < 4; i++) {
		int h = exec_hex(s[i]);
		if (h < 0)
			return -1;
		v = (v << 4) | h;
	}
	return v;
}

static int exec_utf8(unsigned cp, char *out)
{
	if (cp < 0x80) {
		out[0] = cp;
		return 1;
	}
	if (cp < 0x800) {
		out[0] = 0xC0 | (cp >> 6);
		out[1] = 0x80 | (cp & 0x3F);
		return 2;
	}
	if (cp < 0x10000) {
		out[0] = 0xE0 | (cp >> 12);
		out[1] = 0x80 | ((cp >> 6) & 0x3F);
		out[2] = 0x80 | (cp & 0x3F);
		return 3;
	}
	out[0] = 0xF0 | (cp >> 18);
	out[1] = 0x80 | ((cp >> 12) & 0x3F);
	out[2] = 0x80 | ((cp >> 6) & 0x3F);
	out[3] = 0x80 | (cp & 0x3F);
	return 4;
}

// unescaped copy of a JSON string token; NULL on a bad escape or a NUL byte
static char *exec_json_string(const char *buf, const jsmntok_t *t)
{
	if (t->type != JSMN_STRING)
		return NULL;

	const char *s = buf + t->start;
	const char *end = buf + t->end;
	char *out = calloc((end - s) + 1, 1);
	size_t o = 0;

	if (!out)
		return NULL;

	while (s < end) {
		if (*s != '\\') {
			out[o++] = *s++;
			continue;
		}
		s++;
		if (s >= end)
			goto bad;
		switch (*s++) {
		case '"':
			out[o++] = '"';
			break;
		case '\\':
			out[o++] = '\\';
			break;
		case '/':
			out[o++] = '/';
			break;
		case 'b':
			out[o++] = '\b';
			break;
		case 'f':
			out[o++] = '\f';
			break;
		case 'n':
			out[o++] = '\n';
			break;
		case 'r':
			out[o++] = '\r';
			break;
		case 't':
			out[o++] = '\t';
			break;
		case 'u': {
			if (end - s < 4)
				goto bad;
			int cp = exec_hex4(s);
			if (cp < 0)
				goto bad;
			s += 4;
			if (cp >= 0xD800 && cp < 0xDC00) {
				if (end - s < 6 || s[0] != '\\' || s[1] != 'u')
					goto bad;
				int lo = exec_hex4(s + 2);
				if (lo < 0xDC00 || lo > 0xDFFF)
					goto bad;
				s += 6;
				cp = 0x10000 + ((cp - 0xD800) << 10) +
				     (lo - 0xDC00);
			} else if (cp >= 0xDC00 && cp <= 0xDFFF) {
				goto bad;
			}
			if (cp == 0)
				goto bad;
			o += exec_utf8(cp, out + o);
			break;
		}
		default:
			goto bad;
		}
	}
	out[o] = '\0';
	if (strlen(out) != o)
		goto bad;
	return out;
bad:
	free(out);
	return NULL;
}

// index of the first token after the subtree that starts at i
static int exec_tok_next(const jsmntok_t *t, int tokc, int i)
{
	int j = i + 1;

	while (j < tokc && t[j].start < t[i].end)
		j++;
	return j;
}

static bool exec_is_null(const char *buf, const jsmntok_t *t)
{
	return t->type == JSMN_PRIMITIVE && t->end - t->start == 4 &&
	       !strncmp(buf + t->start, "null", 4);
}

static bool exec_json_long(const char *buf, const jsmntok_t *t, long *out)
{
	char num[24];
	char *end = NULL;
	int len = t->end - t->start;

	if (t->type != JSMN_PRIMITIVE || len <= 0 || len >= (int)sizeof(num))
		return false;
	memcpy(num, buf + t->start, len);
	num[len] = '\0';
	errno = 0;
	*out = strtol(num, &end, 10);
	return !errno && end && !*end;
}

// returns NULL when the request is valid, else a message for the 400 reply
static const char *exec_parse_request(const char *buf, size_t len,
				      struct exec_request *r)
{
	jsmn_parser parser;
	jsmntok_t *tokv = NULL;
	const char *err = "Invalid JSON";
	int tokc;

	memset(r, 0, sizeof(*r));
	r->timeout_s = EXEC_DEFAULT_TIMEOUT;
	r->max_output = EXEC_DEFAULT_OUTPUT;

	jsmn_init(&parser);
	tokc = jsmn_parse(&parser, buf, len, NULL, 0);
	if (tokc < 1)
		return err;
	tokv = calloc(tokc, sizeof(jsmntok_t));
	if (!tokv)
		return "Out of memory";
	jsmn_init(&parser);
	if (jsmn_parse(&parser, buf, len, tokv, tokc) < 0 ||
	    tokv[0].type != JSMN_OBJECT)
		goto out;

	int i = 1;
	for (int k = 0; k < tokv[0].size; k++) {
		if (i + 1 >= tokc)
			goto out;

		jsmntok_t *key = &tokv[i];
		jsmntok_t *val = &tokv[i + 1];
		int next = exec_tok_next(tokv, tokc, i + 1);
		int klen = key->end - key->start;
		const char *kname = buf + key->start;

		if (klen == 4 && !strncmp(kname, "argv", 4)) {
			if (val->type != JSMN_ARRAY) {
				err = "'argv' must be an array of strings";
				goto out;
			}
			if (val->size < 1 || val->size > EXEC_MAX_ARGC) {
				err = "'argv' must have between 1 and 256 entries";
				goto out;
			}
			r->argv = calloc(val->size + 1, sizeof(char *));
			if (!r->argv) {
				err = "Out of memory";
				goto out;
			}
			size_t total = 0;
			int e = i + 2;
			for (int a = 0; a < val->size; a++) {
				char *s = exec_json_string(buf, &tokv[e]);
				if (!s) {
					err = "'argv' must be an array of strings without NUL";
					goto out;
				}
				r->argv[r->argc++] = s;
				total += strlen(s) + 1;
				if (strlen(s) > EXEC_MAX_ARG ||
				    total > EXEC_MAX_ARGV_TOTAL) {
					err = "'argv' is too large";
					goto out;
				}
				e = exec_tok_next(tokv, tokc, e);
			}
			if (!r->argv[0][0]) {
				err = "'argv[0]' is empty";
				goto out;
			}
		} else if (klen == 9 && !strncmp(kname, "stdin_b64", 9)) {
			if (exec_is_null(buf, val))
				goto next_key;
			char *b64 = exec_json_string(buf, val);
			if (!b64) {
				err = "'stdin_b64' must be a string";
				goto out;
			}
			size_t olen = 0;
			size_t blen = strlen(b64);
			if (blen) {
				// every 4 characters give at most 3 bytes
				if (blen / 4 * 3 > EXEC_MAX_STDIN + 3) {
					free(b64);
					err = "'stdin_b64' is too large";
					goto out;
				}
				r->stdin_data = malloc(blen);
				if (!r->stdin_data ||
				    mbedtls_base64_decode(
					    (unsigned char *)r->stdin_data,
					    blen, &olen,
					    (const unsigned char *)b64,
					    blen) != 0 ||
				    olen > EXEC_MAX_STDIN) {
					free(b64);
					err = "'stdin_b64' is not valid base64 or too large";
					goto out;
				}
				r->stdin_len = olen;
			}
			free(b64);
		} else if (klen == 9 && !strncmp(kname, "timeout_s", 9)) {
			if (exec_is_null(buf, val))
				goto next_key;
			if (!exec_json_long(buf, val, &r->timeout_s) ||
			    r->timeout_s < 1 ||
			    r->timeout_s > EXEC_MAX_TIMEOUT) {
				err = "'timeout_s' must be a number between 1 and 600";
				goto out;
			}
		} else if (klen == 10 && !strncmp(kname, "max_output", 10)) {
			if (exec_is_null(buf, val))
				goto next_key;
			if (!exec_json_long(buf, val, &r->max_output) ||
			    r->max_output < 1 ||
			    r->max_output > EXEC_MAX_OUTPUT) {
				err = "'max_output' must be a number between 1 and 1048576";
				goto out;
			}
		} else if (klen == 3 && !strncmp(kname, "cwd", 3)) {
			if (exec_is_null(buf, val))
				goto next_key;
			free(r->cwd);
			r->cwd = exec_json_string(buf, val);
			if (!r->cwd || !r->cwd[0] ||
			    strlen(r->cwd) >= PATH_MAX) {
				err = "'cwd' must be a non-empty string";
				goto out;
			}
		} else if (klen == 3 && !strncmp(kname, "env", 3)) {
			if (exec_is_null(buf, val))
				goto next_key;
			if (val->type != JSMN_OBJECT) {
				err = "'env' must be an object of strings";
				goto out;
			}
			if (val->size > EXEC_MAX_ENV) {
				err = "'env' has too many entries";
				goto out;
			}
			r->env_keys = calloc(val->size + 1, sizeof(char *));
			r->env_vals = calloc(val->size + 1, sizeof(char *));
			if (!r->env_keys || !r->env_vals) {
				err = "Out of memory";
				goto out;
			}
			int e = i + 2;
			for (int a = 0; a < val->size; a++) {
				char *ek = exec_json_string(buf, &tokv[e]);
				char *ev = ek ? exec_json_string(buf,
								 &tokv[e + 1]) :
						NULL;
				if (!ek || !ev || !ek[0] || strchr(ek, '=') ||
				    strlen(ek) + strlen(ev) > EXEC_MAX_ARG) {
					free(ek);
					free(ev);
					err = "'env' must map names without '=' to strings";
					goto out;
				}
				r->env_keys[r->env_count] = ek;
				r->env_vals[r->env_count++] = ev;
				e = exec_tok_next(tokv, tokc, e + 1);
			}
		}
	next_key:
		i = next;
	}

	if (!r->argv) {
		err = "Missing 'argv'";
		goto out;
	}
	free(tokv);
	return NULL;
out:
	free(tokv);
	exec_request_free(r);
	return err;
}

/* the container to enter, read before the helper is forked */

static char *exec_read_file(const char *path, size_t *len)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	char *buf = NULL;
	size_t n = 0;

	if (fd < 0)
		return NULL;
	buf = malloc(EXEC_MAX_TARGET_FILE + 1);
	if (buf) {
		for (;;) {
			ssize_t r = read(fd, buf + n, EXEC_MAX_TARGET_FILE - n);
			if (r < 0 && errno == EINTR)
				continue;
			if (r <= 0)
				break;
			n += r;
			if (n >= EXEC_MAX_TARGET_FILE)
				break;
		}
		buf[n] = '\0';
	}
	close(fd);
	if (len)
		*len = n;
	return buf;
}

static bool exec_env_set(char ***env, int *n, const char *key, const char *val)
{
	size_t klen = strlen(key);
	char *entry = NULL;

	if (asprintf(&entry, "%s=%s", key, val) < 0)
		return false;
	for (int i = 0; i < *n; i++) {
		if (!strncmp((*env)[i], key, klen) && (*env)[i][klen] == '=') {
			free((*env)[i]);
			(*env)[i] = entry;
			return true;
		}
	}
	char **grown = realloc(*env, (*n + 2) * sizeof(char *));
	if (!grown) {
		free(entry);
		return false;
	}
	*env = grown;
	(*env)[(*n)++] = entry;
	(*env)[*n] = NULL;
	return true;
}

// the init environment of the container, then the request values
static char **exec_build_env(pid_t pid, const struct exec_request *r)
{
	char path[64];
	size_t len = 0;
	char *raw;
	char **env = calloc(1, sizeof(char *));
	int n = 0;

	if (!env)
		return NULL;

	snprintf(path, sizeof(path), "/proc/%d/environ", pid);
	raw = exec_read_file(path, &len);
	if (raw) {
		for (size_t off = 0; off < len;) {
			char *eq, *entry = raw + off;
			size_t elen = strlen(entry);

			off += elen + 1;
			eq = strchr(entry, '=');
			if (!eq || eq == entry)
				continue;
			*eq = '\0';
			if (!exec_env_set(&env, &n, entry, eq + 1)) {
				free(raw);
				goto fail;
			}
		}
		free(raw);
	}

	for (int i = 0; i < r->env_count; i++) {
		if (!exec_env_set(&env, &n, r->env_keys[i], r->env_vals[i]))
			goto fail;
	}
	return env;
fail:
	for (char **e = env; *e; e++)
		free(*e);
	free(env);
	return NULL;
}

// "CapBnd:" of the container init, all capabilities when it cannot be read
static uint64_t exec_read_cap_bnd(pid_t pid)
{
	char path[64], line[256];
	uint64_t bnd = ~0ULL;
	FILE *f;

	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	f = fopen(path, "re");
	if (!f)
		return bnd;
	while (fgets(line, sizeof(line), f)) {
		if (!strncmp(line, "CapBnd:", 7)) {
			bnd = strtoull(line + 7, NULL, 16);
			break;
		}
	}
	fclose(f);
	return bnd;
}

static bool exec_cgroup_add(struct exec_target *t, const char *base,
			    const char *cpath)
{
	char file[PATH_MAX];
	char **files;
	bool *roots;

	if (*cpath)
		snprintf(file, sizeof(file), "%s/%s/cgroup.procs", base, cpath);
	else
		snprintf(file, sizeof(file), "%s/cgroup.procs", base);

	files = realloc(t->cgroup_files,
			(t->cgroup_count + 1) * sizeof(char *));
	if (!files)
		return false;
	t->cgroup_files = files;
	roots = realloc(t->cgroup_root, (t->cgroup_count + 1) * sizeof(bool));
	if (!roots)
		return false;
	t->cgroup_root = roots;
	t->cgroup_files[t->cgroup_count] = strdup(file);
	if (!t->cgroup_files[t->cgroup_count])
		return false;
	t->cgroup_root[t->cgroup_count] = !*cpath;
	t->cgroup_count++;
	return true;
}

// cgroup.procs files of the container, for every line of /proc/<pid>/cgroup
static bool exec_read_cgroups(struct exec_target *t)
{
	char path[64], *raw, *line, *save = NULL;
	bool hybrid = !access("/sys/fs/cgroup/unified/cgroup.procs", F_OK);

	snprintf(path, sizeof(path), "/proc/%d/cgroup", t->pid);
	raw = exec_read_file(path, NULL);
	if (!raw)
		return false;

	for (line = strtok_r(raw, "\n", &save); line;
	     line = strtok_r(NULL, "\n", &save)) {
		char *ctrls = strchr(line, ':');
		char *cpath = ctrls ? strchr(ctrls + 1, ':') : NULL;
		char *csave = NULL;

		if (!cpath)
			continue;
		*ctrls++ = '\0';
		*cpath++ = '\0';
		while (*cpath == '/')
			cpath++;

		if (!*ctrls) {
			if (!exec_cgroup_add(t,
					     hybrid ? "/sys/fs/cgroup/unified" :
						      "/sys/fs/cgroup",
					     cpath))
				goto fail;
			continue;
		}

		for (char *c = strtok_r(ctrls, ",", &csave); c;
		     c = strtok_r(NULL, ",", &csave)) {
			char base[PATH_MAX];
			const char *eq = strchr(c, '=');

			snprintf(base, sizeof(base), "/sys/fs/cgroup/%s",
				 eq ? eq + 1 : c);
			if (!exec_cgroup_add(t, base, cpath))
				goto fail;
		}
	}
	free(raw);
	return true;
fail:
	free(raw);
	return false;
}

// the AppArmor profile of the container init when it differs from ours
static char *exec_read_apparmor(pid_t pid)
{
	char path[64], *theirs, *ours, *sp, *res = NULL;

	snprintf(path, sizeof(path), "/proc/%d/attr/current", pid);
	theirs = exec_read_file(path, NULL);
	ours = exec_read_file("/proc/self/attr/current", NULL);
	if (theirs && ours) {
		theirs[strcspn(theirs, "\n")] = '\0';
		ours[strcspn(ours, "\n")] = '\0';
		if (strcmp(theirs, ours) && strcmp(theirs, "unconfined")) {
			// "profile (mode)": the mode is not part of the name
			sp = strstr(theirs, " (");
			if (sp)
				*sp = '\0';
			if (theirs[0])
				res = strdup(theirs);
		}
	}
	free(theirs);
	free(ours);
	return res;
}

static bool exec_target_read(struct exec_target *t, pid_t pid,
			     const struct exec_request *r)
{
	memset(t, 0, sizeof(*t));
	t->pid = pid;
	t->env = exec_build_env(pid, r);
	t->cap_bnd = exec_read_cap_bnd(pid);
	t->apparmor_label = exec_read_apparmor(pid);
	if (!t->env || !exec_read_cgroups(t)) {
		exec_target_free(t);
		return false;
	}
	return true;
}

/* the helper: runs in a forked process and never returns */

static void exec_msg_send(int fd, int type, int a, int b, const char *text)
{
	struct exec_msg m;
	ssize_t r;

	memset(&m, 0, sizeof(m));
	m.type = type;
	m.a = a;
	m.b = b;
	if (text)
		snprintf(m.text, sizeof(m.text), "%s", text);
	do {
		r = write(fd, &m, sizeof(m));
	} while (r < 0 && errno == EINTR);
}

#define EXEC_STATUS_FD 3

static void exec_fail(const char *what)
{
	char text[sizeof(((struct exec_msg *)0)->text)];

	snprintf(text, sizeof(text), "%s: %s", what, strerror(errno));
	exec_msg_send(EXEC_STATUS_FD, EXEC_MSG_ERROR, errno, 0, text);
	_exit(125);
}

static void exec_close_from(int low)
{
#ifdef __NR_close_range
	if (!syscall(__NR_close_range, low, ~0U, 0))
		return;
#endif
	long max = sysconf(_SC_OPEN_MAX);

	if (max < 0 || max > 65536)
		max = 65536;
	for (int fd = low; fd < max; fd++)
		close(fd);
}

static bool exec_same_ns(int fd, const char *name)
{
	struct stat a, b;
	char path[64];

	snprintf(path, sizeof(path), "/proc/self/ns/%s", name);
	return !fstat(fd, &a) && !stat(path, &b) && a.st_ino == b.st_ino &&
	       a.st_dev == b.st_dev;
}

static void exec_join_cgroups(const struct exec_target *t)
{
	char pidstr[16];
	int len = snprintf(pidstr, sizeof(pidstr), "%d", getpid());

	for (int i = 0; i < t->cgroup_count; i++) {
		int fd = open(t->cgroup_files[i], O_WRONLY | O_CLOEXEC);

		if (fd >= 0 && write(fd, pidstr, len) == len) {
			close(fd);
			continue;
		}
		if (fd >= 0)
			close(fd);
		// a hierarchy that is not mounted here has nothing to join
		if (t->cgroup_root[i] || errno == ENOENT)
			continue;
		exec_fail(t->cgroup_files[i]);
	}
}

// bounding set of the container: the command never has more than its init
static void exec_drop_caps(uint64_t keep)
{
	int last = 63;
	char *raw = exec_read_file("/proc/sys/kernel/cap_last_cap", NULL);

	if (raw) {
		last = atoi(raw);
		free(raw);
	}
	for (int cap = 0; cap <= last && cap < 64; cap++) {
		if (keep & (1ULL << cap))
			continue;
		if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) && errno != EINVAL)
			exec_fail("drop capability");
	}
#ifdef PR_CAP_AMBIENT
	prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
#endif
}

static void exec_set_apparmor(const char *label)
{
	static const char *files[] = { "/proc/self/attr/apparmor/exec",
				       "/proc/self/attr/exec" };
	char cmd[256];
	int len = snprintf(cmd, sizeof(cmd), "exec %s", label);

	for (int i = 0; i < 2; i++) {
		int fd = open(files[i], O_WRONLY | O_CLOEXEC);

		if (fd < 0)
			continue;
		if (write(fd, cmd, len) == len) {
			close(fd);
			return;
		}
		close(fd);
	}
	errno = EPERM;
	exec_fail("apparmor profile of the container");
}

static void exec_enter_namespaces(const struct exec_target *t)
{
	static const char *names[] = { "user", "cgroup", "ipc",
				       "uts",  "net",	 "pid" };
	int fds[7], n = 0;
	char path[64];

	// open everything first: after the mount namespace /proc is the container's
	for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		snprintf(path, sizeof(path), "/proc/%d/ns/%s", t->pid,
			 names[i]);
		fds[i] = open(path, O_RDONLY | O_CLOEXEC);
		if (fds[i] < 0 && errno != ENOENT)
			exec_fail(path);
		n++;
	}
	snprintf(path, sizeof(path), "/proc/%d/ns/mnt", t->pid);
	fds[n] = open(path, O_RDONLY | O_CLOEXEC);
	if (fds[n] < 0)
		exec_fail(path);

	exec_join_cgroups(t);
	if (t->apparmor_label)
		exec_set_apparmor(t->apparmor_label);

	for (int i = 0; i < n; i++) {
		if (fds[i] < 0 || exec_same_ns(fds[i], names[i]))
			continue;
		if (setns(fds[i], 0))
			exec_fail(names[i]);
	}
	if (!exec_same_ns(fds[n], "mnt") && setns(fds[n], CLONE_NEWNS))
		exec_fail("mnt");
	for (int i = 0; i <= n; i++) {
		if (fds[i] >= 0)
			close(fds[i]);
	}
}

static void exec_command(const struct exec_request *r,
			 const struct exec_target *t)
{
	extern char **environ;

	if (setsid() < 0)
		exec_fail("setsid");
	if (chdir(r->cwd ? r->cwd : "/")) {
		char text[sizeof(((struct exec_msg *)0)->text)];

		snprintf(text, sizeof(text), "chdir %s: %s",
			 r->cwd ? r->cwd : "/", strerror(errno));
		dprintf(STDERR_FILENO, "%s\n", text);
		_exit(126);
	}

	// the PATH of the container finds argv[0]
	environ = t->env;
	execvp(r->argv[0], r->argv);
	dprintf(STDERR_FILENO, "exec %s: %s\n", r->argv[0], strerror(errno));
	_exit(errno == ENOENT ? 127 : 126);
}

static void exec_helper_main(const struct exec_request *r,
			     const struct exec_target *t, int in_fd, int out_fd,
			     int err_fd, int status_fd)
{
	sigset_t none;
	pid_t child;
	int st = 0;

	dup2(in_fd, STDIN_FILENO);
	dup2(out_fd, STDOUT_FILENO);
	dup2(err_fd, STDERR_FILENO);
	dup2(status_fd, EXEC_STATUS_FD);
	fcntl(EXEC_STATUS_FD, F_SETFD, FD_CLOEXEC);
	exec_close_from(EXEC_STATUS_FD + 1);

	for (int s = 1; s < 65; s++) {
		if (s != SIGKILL && s != SIGSTOP)
			signal(s, SIG_DFL);
	}
	sigemptyset(&none);
	sigprocmask(SIG_SETMASK, &none, NULL);
	umask(022);

	exec_enter_namespaces(t);
	exec_drop_caps(t->cap_bnd);

	// a new pid namespace only applies to the children of this process
	child = fork();
	if (child < 0)
		exec_fail("fork");
	if (child == 0)
		exec_command(r, t);

	exec_msg_send(EXEC_STATUS_FD, EXEC_MSG_PID, child, 0, NULL);
	while (waitpid(child, &st, 0) < 0 && errno == EINTR)
		;
	if (WIFEXITED(st))
		exec_msg_send(EXEC_STATUS_FD, EXEC_MSG_EXIT, WEXITSTATUS(st), 0,
			      NULL);
	else
		exec_msg_send(EXEC_STATUS_FD, EXEC_MSG_EXIT, -1,
			      WIFSIGNALED(st) ? WTERMSIG(st) : 0, NULL);
	_exit(0);
}

/* the job in the main loop */

static void exec_event_del(struct event **ev)
{
	if (*ev) {
		event_free(*ev);
		*ev = NULL;
	}
}

static void exec_close_fd(int *fd)
{
	if (*fd >= 0) {
		close(*fd);
		*fd = -1;
	}
}

static void exec_job_free(struct exec_job *j)
{
	exec_event_del(&j->status_ev);
	exec_event_del(&j->stdin_ev);
	exec_event_del(&j->out.ev);
	exec_event_del(&j->err.ev);
	exec_event_del(&j->timeout_ev);
	exec_event_del(&j->kill_ev);
	exec_event_del(&j->hard_ev);
	exec_event_del(&j->drain_ev);
	exec_close_fd(&j->status_fd);
	exec_close_fd(&j->stdin_fd);
	exec_close_fd(&j->out.fd);
	exec_close_fd(&j->err.fd);
	free(j->out.buf);
	free(j->err.buf);
	free(j->stdin_data);
	free(j->name);
	free(j->argv0);
	free(j->caller);
	free(j);
}

static void exec_signal(struct exec_job *j, int sig)
{
	if (j->child > 0 && !j->got_exit) {
		kill(-j->child, sig);
		kill(j->child, sig);
	}
}

static void exec_closecb(struct evhttp_connection *con, void *arg)
{
	struct exec_job *j = arg;

	(void)con;
	j->req = NULL;
	j->con = NULL;
}

static char *exec_b64(const char *buf, size_t len)
{
	size_t cap = (len + 2) / 3 * 4 + 1, olen = 0;
	char *out = malloc(cap);

	if (!out)
		return NULL;
	if (mbedtls_base64_encode((unsigned char *)out, cap, &olen,
				  (const unsigned char *)buf, len)) {
		free(out);
		return NULL;
	}
	out[olen] = '\0';
	return out;
}

static void exec_finish(struct exec_job *j)
{
	struct timespec now;
	long ms;

	exec_signal(j, SIGKILL);
	if (!j->got_exit && j->helper > 0)
		kill(j->helper, SIGKILL);

	clock_gettime(CLOCK_MONOTONIC, &now);
	ms = (now.tv_sec - j->start.tv_sec) * 1000 +
	     (now.tv_nsec - j->start.tv_nsec) / 1000000;

	pv_log(INFO,
	       "exec in %s by %s: %s exit_code=%d signal=%d timed_out=%d duration_ms=%ld",
	       j->name, j->caller, j->argv0, j->got_exit ? j->exit_code : -1,
	       j->got_exit ? j->exit_signal : 0, j->timed_out, ms);

	if (j->req) {
		if (j->con)
			evhttp_connection_set_closecb(j->con, NULL, NULL);

		// the default callback wrote "done" while the command was running
		struct evbuffer *rsp = evhttp_request_get_output_buffer(j->req);

		if (rsp)
			evbuffer_drain(rsp, evbuffer_get_length(rsp));

		if (j->got_error) {
			pv_ctrl_utils_send_error(j->req, HTTP_INTERNAL,
						 j->error);
		} else {
			struct pv_json_ser js;
			char *o = exec_b64(j->out.buf, j->out.len);
			char *e = exec_b64(j->err.buf, j->err.len);

			pv_json_ser_init(&js, 1024 + (o ? strlen(o) : 0) +
						      (e ? strlen(e) : 0));
			pv_json_ser_object(&js);
			pv_json_ser_key(&js, "exit_code");
			if (j->got_exit && j->exit_code >= 0)
				pv_json_ser_number(&js, j->exit_code);
			else
				pv_json_ser_string(&js, NULL);
			pv_json_ser_key(&js, "signal");
			if (j->got_exit && j->exit_signal > 0)
				pv_json_ser_number(&js, j->exit_signal);
			else if (!j->got_exit)
				pv_json_ser_number(&js, SIGKILL);
			else
				pv_json_ser_string(&js, NULL);
			pv_json_ser_key(&js, "timed_out");
			pv_json_ser_bool(&js, j->timed_out);
			pv_json_ser_key(&js, "stdout_b64");
			pv_json_ser_string(&js, o ? o : "");
			pv_json_ser_key(&js, "stderr_b64");
			pv_json_ser_string(&js, e ? e : "");
			pv_json_ser_key(&js, "truncated");
			pv_json_ser_object(&js);
			pv_json_ser_key(&js, "stdout");
			pv_json_ser_bool(&js, j->out.truncated);
			pv_json_ser_key(&js, "stderr");
			pv_json_ser_bool(&js, j->err.truncated);
			pv_json_ser_object_pop(&js);
			pv_json_ser_key(&js, "duration_ms");
			pv_json_ser_number(&js, ms);
			pv_json_ser_object_pop(&js);
			free(o);
			free(e);
			pv_ctrl_utils_send_json(j->req, HTTP_OK, NULL,
						pv_json_ser_str(&js));
		}
	}

	exec_active--;
	if (j->helper > 0) {
		// the init reaper normally collects it first
		waitpid(j->helper, NULL, WNOHANG);
	}
	exec_job_free(j);
}

static void exec_drain_cb(evutil_socket_t fd, short what, void *arg);

static void exec_maybe_finish(struct exec_job *j)
{
	if (j->got_error) {
		exec_finish(j);
		return;
	}
	if (!j->got_exit)
		return;
	if (j->out.eof && j->err.eof) {
		exec_finish(j);
		return;
	}
	// a leftover process of the command can keep a pipe open
	if (!j->drain_ev) {
		struct timeval tv = { 0, EXEC_DRAIN_DELAY_MS * 1000 };

		j->drain_ev = evtimer_new(j->base, exec_drain_cb, j);
		if (!j->drain_ev) {
			exec_finish(j);
			return;
		}
		evtimer_add(j->drain_ev, &tv);
	}
}

static void exec_drain_cb(evutil_socket_t fd, short what, void *arg)
{
	(void)fd;
	(void)what;
	exec_finish(arg);
}

static void exec_stream_cb(evutil_socket_t fd, short what, void *arg)
{
	struct exec_stream *s = arg;
	struct exec_job *j = s->job;
	char tmp[8192];

	(void)what;
	for (int rounds = 0; rounds < 16; rounds++) {
		ssize_t n = read(fd, tmp, sizeof(tmp));

		if (n > 0) {
			size_t room = s->max - s->len;
			size_t take = (size_t)n < room ? (size_t)n : room;

			if (take) {
				char *grown = realloc(s->buf, s->len + take);

				if (grown) {
					s->buf = grown;
					memcpy(s->buf + s->len, tmp, take);
					s->len += take;
				} else {
					take = 0;
				}
			}
			// keep reading so the command never blocks on a full pipe
			if (take < (size_t)n)
				s->truncated = true;
			continue;
		}
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			return;
		break;
	}
	exec_event_del(&s->ev);
	exec_close_fd(&s->fd);
	s->eof = true;
	exec_maybe_finish(j);
}

static void exec_stdin_cb(evutil_socket_t fd, short what, void *arg)
{
	struct exec_job *j = arg;

	(void)what;
	while (j->stdin_off < j->stdin_len) {
		ssize_t n = write(fd, j->stdin_data + j->stdin_off,
				  j->stdin_len - j->stdin_off);

		if (n > 0) {
			j->stdin_off += n;
			continue;
		}
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			return;
		break;
	}
	exec_event_del(&j->stdin_ev);
	exec_close_fd(&j->stdin_fd);
}

static void exec_status_cb(evutil_socket_t fd, short what, void *arg)
{
	struct exec_job *j = arg;
	bool eof = false;

	(void)what;
	for (;;) {
		ssize_t n = read(fd, (char *)&j->msg + j->msg_len,
				 sizeof(j->msg) - j->msg_len);

		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			break;
		if (n <= 0) {
			eof = true;
			break;
		}
		j->msg_len += n;
		if (j->msg_len < sizeof(j->msg))
			continue;
		j->msg_len = 0;
		j->msg.text[sizeof(j->msg.text) - 1] = '\0';
		switch (j->msg.type) {
		case EXEC_MSG_PID:
			j->child = j->msg.a;
			if (j->timed_out)
				exec_signal(j, SIGKILL);
			break;
		case EXEC_MSG_EXIT:
			j->got_exit = true;
			j->exit_code = j->msg.a;
			j->exit_signal = j->msg.b;
			break;
		case EXEC_MSG_ERROR:
			j->got_error = true;
			snprintf(j->error, sizeof(j->error), "exec failed: %s",
				 j->msg.text);
			break;
		}
	}

	if (eof) {
		exec_event_del(&j->status_ev);
		exec_close_fd(&j->status_fd);
		if (!j->got_exit && !j->got_error) {
			j->got_error = true;
			snprintf(j->error, sizeof(j->error),
				 "exec failed: helper ended without a result");
		}
	}
	exec_maybe_finish(j);
}

static void exec_timeout_cb(evutil_socket_t fd, short what, void *arg)
{
	struct exec_job *j = arg;
	struct timeval tv = { EXEC_KILL_DELAY_S, 0 };

	(void)fd;
	(void)what;
	j->timed_out = true;
	exec_signal(j, SIGTERM);
	evtimer_add(j->kill_ev, &tv);
}

static void exec_kill_cb(evutil_socket_t fd, short what, void *arg)
{
	struct exec_job *j = arg;

	(void)fd;
	(void)what;
	exec_signal(j, SIGKILL);
}

// the command did not end after SIGKILL: answer with what was read
static void exec_hard_cb(evutil_socket_t fd, short what, void *arg)
{
	struct exec_job *j = arg;

	(void)fd;
	(void)what;
	j->timed_out = true;
	exec_finish(j);
}

/* endpoint */

static bool exec_pipe(int fds[2])
{
	int p[2];

	if (pipe2(p, O_CLOEXEC))
		return false;
	// keep them clear of 0..3, which the helper uses for its own
	for (int i = 0; i < 2; i++) {
		fds[i] = fcntl(p[i], F_DUPFD_CLOEXEC, 10);
		close(p[i]);
		if (fds[i] < 0) {
			if (i)
				close(fds[0]);
			return false;
		}
	}
	return true;
}

static void exec_close_pair(int fds[2])
{
	for (int i = 0; i < 2; i++) {
		if (fds[i] >= 0)
			close(fds[i]);
	}
}

// true when the job started; false leaves the reply to the caller
static const char *exec_start(struct evhttp_request *req, struct pv_platform *p,
			      struct exec_request *r, const char *caller)
{
	struct exec_target target;
	struct exec_job *j = NULL;
	int in_p[2] = { -1, -1 }, out_p[2] = { -1, -1 }, err_p[2] = { -1, -1 },
	    st_p[2] = { -1, -1 };
	sigset_t block, old;
	pid_t helper;
	const char *err = "Cannot start the command";

	if (!exec_target_read(&target, p->init_pid, r))
		return "Cannot read the container";

	j = calloc(1, sizeof(*j));
	if (!j) {
		exec_target_free(&target);
		return "Out of memory";
	}
	j->status_fd = j->stdin_fd = j->out.fd = j->err.fd = -1;
	j->out.job = j->err.job = j;
	j->out.max = j->err.max = r->max_output;
	j->con = evhttp_request_get_connection(req);
	j->base = evhttp_connection_get_base(j->con);
	j->req = req;
	j->name = strdup(p->name);
	j->argv0 = strdup(r->argv[0]);
	j->caller = strdup(caller);
	j->timeout_s = r->timeout_s;
	j->stdin_data = r->stdin_data;
	j->stdin_len = r->stdin_len;
	r->stdin_data = NULL;
	clock_gettime(CLOCK_MONOTONIC, &j->start);

	if (!j->name || !j->argv0 || !j->caller || !exec_pipe(in_p) ||
	    !exec_pipe(out_p) || !exec_pipe(err_p) || !exec_pipe(st_p))
		goto fail;

	sigemptyset(&block);
	sigaddset(&block, SIGCHLD);
	pthread_sigmask(SIG_BLOCK, &block, &old);
	helper = fork();
	if (helper == 0) {
		pthread_sigmask(SIG_SETMASK, &old, NULL);
		close(in_p[1]);
		close(out_p[0]);
		close(err_p[0]);
		close(st_p[0]);
		exec_helper_main(r, &target, in_p[0], out_p[1], err_p[1],
				 st_p[1]);
		_exit(125);
	}
	pthread_sigmask(SIG_SETMASK, &old, NULL);
	if (helper < 0)
		goto fail;
	j->helper = helper;

	close(in_p[0]);
	close(out_p[1]);
	close(err_p[1]);
	close(st_p[1]);
	j->stdin_fd = in_p[1];
	j->out.fd = out_p[0];
	j->err.fd = err_p[0];
	j->status_fd = st_p[0];
	in_p[0] = in_p[1] = out_p[0] = out_p[1] = -1;
	err_p[0] = err_p[1] = st_p[0] = st_p[1] = -1;
	for (int i = 0; i < 4; i++) {
		int *fd = i == 0 ? &j->stdin_fd :
			  i == 1 ? &j->out.fd :
			  i == 2 ? &j->err.fd :
				   &j->status_fd;
		fcntl(*fd, F_SETFL, fcntl(*fd, F_GETFL) | O_NONBLOCK);
	}

	j->out.ev = event_new(j->base, j->out.fd, EV_READ | EV_PERSIST,
			      exec_stream_cb, &j->out);
	j->err.ev = event_new(j->base, j->err.fd, EV_READ | EV_PERSIST,
			      exec_stream_cb, &j->err);
	j->status_ev = event_new(j->base, j->status_fd, EV_READ | EV_PERSIST,
				 exec_status_cb, j);
	j->timeout_ev = evtimer_new(j->base, exec_timeout_cb, j);
	j->kill_ev = evtimer_new(j->base, exec_kill_cb, j);
	j->hard_ev = evtimer_new(j->base, exec_hard_cb, j);
	if (!j->out.ev || !j->err.ev || !j->status_ev || !j->timeout_ev ||
	    !j->kill_ev || !j->hard_ev) {
		err = "Out of memory";
		goto fail_started;
	}
	if (j->stdin_len) {
		j->stdin_ev =
			event_new(j->base, j->stdin_fd, EV_WRITE | EV_PERSIST,
				  exec_stdin_cb, j);
		if (!j->stdin_ev) {
			err = "Out of memory";
			goto fail_started;
		}
		event_add(j->stdin_ev, NULL);
	} else {
		exec_close_fd(&j->stdin_fd);
	}
	event_add(j->out.ev, NULL);
	event_add(j->err.ev, NULL);
	event_add(j->status_ev, NULL);
	{
		struct timeval tv = { j->timeout_s, 0 };
		struct timeval hard = { j->timeout_s + EXEC_KILL_DELAY_S + 3,
					0 };

		evtimer_add(j->timeout_ev, &tv);
		evtimer_add(j->hard_ev, &hard);
	}
	evhttp_connection_set_closecb(j->con, exec_closecb, j);

	exec_target_free(&target);
	exec_active++;
	return NULL;

fail_started:
	kill(j->helper, SIGKILL);
	waitpid(j->helper, NULL, 0);
fail:
	exec_close_pair(in_p);
	exec_close_pair(out_p);
	exec_close_pair(err_p);
	exec_close_pair(st_p);
	exec_target_free(&target);
	exec_job_free(j);
	return err;
}

static void exec_process_request(struct evbuffer *buf,
				 const struct evbuffer_cb_info *info, void *ctx)
{
	struct evhttp_request *req = ctx;
	struct pantavisor *pv = pv_get_instance();
	struct pv_ctrl_caller caller = { 0 };
	struct exec_request r;
	struct pv_platform *p;
	char split[PV_CTRL_MAX_SPLIT][NAME_MAX] = { 0 };
	const char *err;
	char *data;
	ssize_t len = 0;

	if (!info->n_added)
		return;
	if (!pv_ctrl_utils_has_all_data(req))
		return;

	evbuffer_remove_cb(buf, exec_process_request, ctx);

	if (pv_ctrl_utils_split_path(evhttp_request_get_uri(req), split) < 3) {
		pv_ctrl_utils_send_error(req, HTTP_BADREQUEST,
					 "Missing container name");
		return;
	}
	if (pv_ctrl_caller_init(&caller, req)) {
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL, "Internal Error");
		return;
	}

	// the target may have changed while the body arrived
	p = pv->state ? pv_state_fetch_platform(pv->state, split[1]) : NULL;
	if (!p || !strcmp(p->name, "_pv_")) {
		pv_ctrl_utils_send_error(req, HTTP_NOTFOUND,
					 "Container not found");
		return;
	}
	if (p->init_pid <= 0 ||
	    !(pv_platform_is_started(p) || pv_platform_is_ready(p)) ||
	    kill(p->init_pid, 0)) {
		pv_ctrl_utils_send_error(req, PV_HTTP_CONFLICT,
					 "Container is not running");
		return;
	}

	data = pv_ctrl_utils_get_data(req, EXEC_MAX_BODY, &len);
	if (!data)
		return;
	err = exec_parse_request(data, len, &r);
	free(data);
	if (err) {
		pv_ctrl_utils_send_error(req, HTTP_BADREQUEST, err);
		return;
	}

	if (exec_active >= EXEC_MAX_ACTIVE) {
		evhttp_add_header(evhttp_request_get_output_headers(req),
				  "Retry-After", "1");
		pv_ctrl_utils_send_error(req, HTTP_SERVUNAVAIL,
					 "Too many commands are running");
		exec_request_free(&r);
		return;
	}

	err = exec_start(req, p, &r, caller.plat ? caller.plat->name : "_pv_");
	exec_request_free(&r);
	if (err)
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL, err);
}

static void ctrl_exec_post(struct evhttp_request *req, void *ctx)
{
	char split[PV_CTRL_MAX_SPLIT][NAME_MAX] = { 0 };
	struct pantavisor *pv = pv_get_instance();
	ssize_t cl;
	int code;
	char err[PV_CTRL_MAX_ERR] = { 0 };

	code = pv_ctrl_utils_is_req_ok(req, ctx, err);
	if (code != 0) {
		pv_ctrl_utils_drain_on_arrive_with_err(req, code, err);
		return;
	}

	// the same refusal as the other devmode endpoints
	const char *msg = NULL;

	code = pv_ctrl_devmode_check(&msg);
	if (code) {
		pv_ctrl_utils_drain_on_arrive_with_err(req, code, msg);
		return;
	}

	pv_ctrl_utils_split_path(evhttp_request_get_uri(req), split);
	if (!strcmp(split[1], "_pv_") || !pv->state ||
	    !pv_state_fetch_platform(pv->state, split[1])) {
		pv_ctrl_utils_drain_on_arrive_with_err(req, HTTP_NOTFOUND,
						       "Container not found");
		return;
	}

	cl = pv_ctrl_utils_get_content_length(req);
	if (cl <= 0 || cl > EXEC_MAX_BODY) {
		pv_ctrl_utils_drain_on_arrive_with_err(
			req, HTTP_BADREQUEST,
			"A body of 1 to 393216 bytes with Content-Length is needed");
		return;
	}

	evbuffer_add_cb(evhttp_request_get_input_buffer(req),
			exec_process_request, req);
}

int pv_ctrl_endpoints_exec_init()
{
	pv_ctrl_add_endpoint("/containers/{}/exec", EVHTTP_REQ_POST, true,
			     ctrl_exec_post);

	return 0;
}

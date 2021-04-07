/*
 * Copyright (c) 2017 Pantacor Ltd.
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
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>
#include <stdbool.h>
#include <stdbool.h>
#include <signal.h>

#include <linux/limits.h>

#include <sys/xattr.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "utils.h"
/*
 * private struct.
 */
struct pv_json_format {
       char ch;
       int *off_dst;
       int *off_src;
       const char *src;
       char *dst;
       int (*format)(struct pv_json_format *);
};
#include "tsh.h"

static int seeded = 0;

int mkdir_p(char *dir, mode_t mode)
{
	const char *tmp = dir;
	const char *orig = dir;
	char *makeme;

	do {
		dir = (char*)tmp + strspn(tmp, "/");
		tmp = dir + strcspn(dir, "/");
		makeme = strndup(orig, dir - orig);
		if (*makeme) {
			if (mkdir(makeme, mode) && errno != EEXIST) {
				free(makeme);
				return -1;
			}
		}
		free(makeme);
	} while(tmp != dir);

	return 0;
}

void syncdir(char *file)
{
	int fd;
	char *dir;

	if (!file)
		return;

	dir = strdup(file);
	dirname(dir);

	fd = open(dir, O_RDONLY);
	if (fd)
		fsync(fd);

	if (dir)
		free(dir);

	close(fd);
}

char *rand_string(int size)
{
	char set[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJK";
	char *str;
	time_t t;

	if (!seeded)
		srand(time(&t));

	str = malloc(sizeof(char) * (size + 1));

	for (int i = 0; i < size; i++) {
		int key = rand() % (sizeof(set) - 1);
		str[i] = set[key];
	}

	// null terminate string
	str[size] = '\0';

	return str;
}

int traverse_token (char *buf, jsmntok_t* tok, int t)
{
	int i;
	int c;
	c=t;
	for (i=0; i < tok[t].size; i++) {
		c = traverse_token (buf, tok, c+1);
	}
	return c;
}

int get_digit_count(int number)
{
	int c = 0;

	while (number) {
		number /= 10;
		c++;
	}
	c++;

	return c;
}

int get_json_key_value_int(char *buf, char *key, jsmntok_t* tok, int tokc)
{
	int i;
	int val = 0;
	int t=-1;

	for(i=0; i<tokc; i++) {
		int n = tok[i].end - tok[i].start;
		int m = strlen (key);
		if (tok[i].type == JSMN_PRIMITIVE
		    && n == m
		    && !strncmp(buf + tok[i].start, key, n)) {
			t=1;
		} else if (t==1) {
			char *idval = malloc(n+1);
			idval[n] = 0;
			strncpy(idval, buf + tok[i].start, n);
			val = atoi(idval);
			free(idval);
			return val;
		} else if (t==1) {
			return val;
		}
	}
	return val;
}

char* get_json_key_value(char *buf, char *key, jsmntok_t* tok, int tokc)
{
	int i;
	int t=-1;

	for(i=0; i<tokc; i++) {
		int n = tok[i].end - tok[i].start;
		int m = strlen (key);
		if (n == m
		    && tok[i].type == JSMN_STRING
		    && !strncmp(buf + tok[i].start, key, n)) {
			t=1;
		} else if (t==1) {
			char *idval = malloc(n+1);
			idval[n] = 0;
			strncpy(idval, buf + tok[i].start, n);
			return idval;
		} else if (t==1) {
			return NULL;
		}
	}
	return NULL;
}

char* json_get_one_str(char *buf, jsmntok_t **tok)
{
	int c;
	char *value = NULL;
	c = (*tok)->end - (*tok)->start;
	value = calloc(1, (c+1) * sizeof(char));
	if (value)
		strncpy(value, buf+(*tok)->start, c);
	return value;
}

char* json_array_get_one_str(char *buf, int *n, jsmntok_t **tok)
{
	char *value = NULL;

	if (*n == 0)
		return NULL;
	value = json_get_one_str(buf, tok);
	if (value) {
		(*tok)++;
		(*n)--;
	}
	return value;
}

int json_get_key_count(char *buf, char *key, jsmntok_t *tok, int tokc)
{
	int count = 0;

	for (int i=0; i<tokc; i++) {
		int n = tok[i].end - tok[i].start;
		int m = strlen(key);

		if (n == m &&
		    tok[i].type == JSMN_STRING
		    && !strncmp(buf + tok[i].start, key, n)) {
			count += 1;
		}
	}

	return count;
}

char *unescape_str_to_ascii(char *buf, char *code, char c)
{
	char *p = 0;
	char *new = 0;
	char *old;
	int pos = 0, replaced = 0;
	char *tmp;

	tmp = malloc(strlen(buf) + strlen(code) + 1);
	strcpy(tmp, buf);
	strcat(tmp, code);
	old = tmp;

	p = strstr(tmp, code);
	while (p) {
		*p = '\0';
		new = realloc(new, pos + strlen(tmp) + 2);
		strcpy(new+pos, tmp);
		pos = pos + strlen(tmp);
		new[pos] = c;
		pos += 1;
		new[pos] = '\0';
		replaced += 1;
		tmp = p+strlen(code);
		p = strstr(tmp, code);
	}

	if (new[strlen(new)-1] == c)
		new[strlen(new)-1] = '\0';

	if (old)
		free(old);
	if (buf)
		free(buf);

	return new;
}

char* skip_prefix(char *str, const char *key)
{
	if (!str || !key)
		return str;
	while (*key) {
		if (*key != *str)
			break;
		key++;
		str++;
	}
	return str;
}

static bool char_is_json_special(char ch)
{
	/* From RFC 7159, section 7 Strings
	 * All Unicode characters may be placed within the
	 * quotation marks, except for the characters that must be escaped:
	 * quotation mark, reverse solidus, and the control characters (U+0000
	 * through U+001F).
	 */

	switch(ch) {
		case 0x00 ... 0x1f:
		case '\\':
		case '\"':
			return true;
		default:
			return false;
	}
}

static char nibble_to_hexchar(char nibble_val) {

	if (nibble_val <= 9)
		return '0' + nibble_val;
	nibble_val -= 10;
	return 'A' + nibble_val;
}

static int modify_to_json(struct pv_json_format *json_fmt)
{
	char nibble_val;

	json_fmt->dst[(*json_fmt->off_dst)++] = '\\';
	json_fmt->dst[(*json_fmt->off_dst)++] = 'u';
	json_fmt->dst[(*json_fmt->off_dst)++] = '0';
	json_fmt->dst[(*json_fmt->off_dst)++] = '0';
	/*
	 * get the higher order byte nibble.
	 */
	nibble_val = (json_fmt->ch & 0xff) >> 4;
	json_fmt->dst[(*json_fmt->off_dst)++] = nibble_to_hexchar(nibble_val);
	/*
	 * get the lower order byte nibble.
	 */
	nibble_val = (json_fmt->ch & 0x0f);
	json_fmt->dst[(*json_fmt->off_dst)++] = nibble_to_hexchar(nibble_val);

	return 0;
}

char* format_json(char *buf, int len)
{
	char *json_string = NULL;
	int idx = 0;
	int json_str_idx = 0;

	if (len > 0) //We make enough room for worst case.
		json_string = (char*) calloc(1, (len * 6) + 1); //Add 1 for '\0'.

	if (!json_string)
		goto out;
	while (len > idx) {
		if (char_is_json_special(buf[idx])) {
			struct pv_json_format json_fmt = {
				.src = buf,
				.dst = json_string,
				.off_dst = &json_str_idx,
				.off_src = &idx,
				.ch = buf[idx],
				.format = modify_to_json
			};
			json_fmt.format(&json_fmt);
		} else
			json_string[json_str_idx++] = buf[idx];
		idx++;
	}
out:
	if (json_string) {
		char *shrinked = realloc(json_string, strlen(json_string) + 1);
		if (shrinked)
			json_string = shrinked;
	}
	return json_string;
}

char *str_replace(char *str, int len, char which, char what)
{
	int char_at = 0;

	if (!str)
		return NULL;

	for (char_at = 0; char_at < len; char_at++){
		if (str[char_at] == which)
			str[char_at] = what;
	}
	return str;
}

int get_endian(void)
{
	unsigned long t = 0x00102040;
	return ((((char*)(&t))[0]) == 0x40);
}

int get_dt_model(char *buf, int buflen)
{
	int fd = -1;
	int ret = -1;

	fd = check_and_open_file("/proc/device-tree/model", O_RDONLY, 0);
	if (fd >= 0) {
		ret = read_nointr(fd, buf, buflen);
		close(fd);
	}
	return ret >= 0 ? 0 : ret;
}

int check_and_open_file(const char *fname, int flags,
			mode_t mode)
{
	struct stat st;
	int fd = -1;

	if (!fname)
		goto out;
	if (stat(fname, &st))
		goto out;
	fd = open(fname, flags, mode);
out:
	return fd;
}

int get_cpu_model(char *buf, int buflen)
{
	int fd = -1;
	int ret = -1;
	char *cur = NULL, *value = NULL;
	int bytes_read = 0;

	if (!buf || buflen <= 0)
		goto out;

	fd = check_and_open_file("/proc/cpuinfo", O_RDONLY, 0);
	if (fd >= 0) {
		bytes_read = read_nointr(fd, buf, buflen);
		close(fd);
	}
	if (bytes_read > 0)
		buf[bytes_read - 1] = '\0';
	else
		goto out;

	cur = strstr(buf, PREFIX_MODEL);
	if (cur) {
		int len = 0;
		/*
		 * sizeof gets us past the space after
		 * colon as well if present. For example
		 * model name	: XXX Processor rev YY (ZZZ)
		 */
		value = cur + sizeof(PREFIX_MODEL);
		cur = strchr(value, '\n');
		if (cur) {
			char *__value = NULL;
			/*
			 * don't copy the newline
			 */
			len = cur - value;
			__value = (char*)calloc(1, len + 1);
			if (__value) {
				memcpy(__value, value, len);
				snprintf(buf, buflen, "%s", __value);
				free(__value);
				ret = 0;
			}
		}
	}
out:
	return ret;
}

pid_t fork_child_process(const char* name)
{
	pid_t pid = fork();
	if (pid < 0)
		return -1;
	else if (!pid)
		prctl(PR_SET_NAME, name);

	return pid;
}

void kill_child_process(pid_t pid)
{
	bool exited = false;

	if (pid <= 0)
		return;

	// first, try to kill gracefully
	kill(pid, SIGTERM);

	// check process has end
	for (int i = 0; i < 5; i++) {
		if (kill(pid, 0))
			exited = true;
		if (exited)
			break;
		sleep(1);
	}

	// force kill if process could not finish
	if (!exited)
		kill(pid, SIGKILL);
}

int set_xattr_on_file(const char *filename, char *attr, char *value)
{
	int val_len = getxattr(filename, attr, NULL, 0);
	int set_flag = XATTR_REPLACE;
	int ret = 0;

	if (val_len < 0 && errno == ENODATA)
		set_flag = XATTR_CREATE;
	ret = setxattr(filename, attr, value, strlen(value), set_flag);
	return ret < 0 ? -errno : ret;
}


int get_xattr_on_file(const char *filename, char *attr, char **dst, int(*alloc)(char**, int))
{
	int val_len = -1;

	val_len = getxattr(filename, attr, NULL, 0);
	if (val_len > 0) {
		int ret = 0;

		if (alloc)
			ret = alloc(dst, val_len + 1);
		if (!ret)
			val_len = getxattr(filename, attr, *dst, val_len);
	}
	return val_len < 0 ? -errno : val_len;
}

ssize_t write_nointr(int fd, char *buf, ssize_t len)
{
	ssize_t written = 0;
	
	while (written != len) {
		int __written = write(fd, buf + written, len - written);
		
		if (__written < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		written += __written;
	}
	return written;
}

ssize_t read_nointr(int fd, char *buf, ssize_t len)
{
	ssize_t nr_read = 0;
	
	while (nr_read != len) {
		int __read = read(fd, buf + nr_read, len - nr_read);
		
		if (__read < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (__read == 0)
			break;
		nr_read += __read;
	}
	return nr_read;
}

int lock_file(int fd)
{
	struct flock flock;
	int ret = 0;

	flock.l_whence = SEEK_SET;
	/*Lock the whole file*/
	flock.l_len = 0; 
	flock.l_start = 0;
	flock.l_type = F_WRLCK;

	while ( (ret = fcntl(fd, F_SETLK, &flock)) < 0 && errno == EINTR)
		;
	return ret;
}

/*
 * Returns the open file descriptor, if successful.
 * */
int open_and_lock_file(const char *fname, int flags, mode_t mode)
{
	int fd = -1;
	int ret = -1;

	fd = open(fname, flags, mode);
	if (fd > 0)
		ret = lock_file(fd);		
	if (ret) {
		close(fd);
		fd = -1;
	}
	return fd;
}

int unlock_file(int fd)
{
	struct flock flock;
	int ret = 0;

	flock.l_whence = SEEK_SET;
	/*Lock the whole file*/
	flock.l_len = 0; 
	flock.l_start = 0;
	flock.l_type = F_UNLCK;

	while ( (ret = fcntl(fd, F_SETLK, &flock)) < 0 && errno == EINTR)
		;
	return ret;
}

int gzip_file(const char *filename, const char *target_name)
{
	int __outfile[] = {-1, -1};
	char cmd[PATH_MAX + 32];

	snprintf(cmd, sizeof(cmd), "gzip %s", filename);
	__outfile[1] = open(target_name, O_RDWR | O_APPEND | O_CREAT);
	if (__outfile[1] >= 0) {
		tsh_run_io(cmd, 1, NULL, NULL, __outfile, NULL);
		close(__outfile[1]);
		return 0;
	}
	return -1;
}

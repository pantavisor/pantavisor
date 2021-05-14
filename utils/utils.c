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
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <sys/xattr.h>
#include <signal.h>

#include "utils.h"
#include "tsh.h"

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

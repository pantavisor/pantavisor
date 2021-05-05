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
#include <stdlib.h>
#include <libgen.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <stdio.h>
#include <errno.h>
#include "ph_logger.h"
#include "ph_logger_v1.h"
#include "utils.h"

/*
 * v1 has the following message format in buffer
 * level (int),
 * platform (NULL terminated string),
 * source (NULL terminated string),
 *
 * args should contain the valid addresses for the above in the order they appear above.
 */
int ph_logger_read_handler_v1(struct ph_logger_msg *ph_logger_msg, char *buf, va_list args)
{
	int level = 0;
	char *platform = NULL;
	char *source = NULL;
	char *data = NULL;
	int *dst_level = NULL;
	char **dst_platform = NULL, **dst_source = NULL;
	int bytes_read = 0;

	sscanf(ph_logger_msg->buffer, "%d", &level);
	bytes_read += strlen(ph_logger_msg->buffer) + 1;
	//+ 1 to Skip over the NULL byte post level
	platform = ph_logger_msg->buffer + strlen(ph_logger_msg->buffer) + 1;
	bytes_read += strlen(platform) + 1;
	source =  platform + strlen(platform) + 1;
	bytes_read += strlen(source) + 1;

	data =  source + strlen(source) + 1;
	//Copy level.
	dst_level = va_arg(args, int*);
	*dst_level = level;

	//Copy platform.
	dst_platform = va_arg(args, char**);
	*dst_platform = platform;

	//Copy source.
	dst_source = va_arg(args, char **);
	*dst_source = source;

	ph_logger_msg->len -= bytes_read;
	//Copy data
	if (buf)
		memcpy(buf, data, ph_logger_msg->len);
	return 0;
}

/*
 * v1 has the following message format in buffer
 * level (int),
 * platform (NULL terminated string),
 * source (NULL terminated string),
 * len (length of the data in buf)
 * args should contain the valid addresses for the above in the order they appear above.
 */
int ph_logger_write_handler_v1(struct ph_logger_msg *ph_logger_msg, char *buf, va_list args)
{
	int level = 0;
	char *platform = NULL;
	char *source = NULL;
	char *data = NULL;
	int avail_len = ph_logger_msg->len;
	int data_len = 0;
	ssize_t written = 0;
	int to_copy = 0;

	//Copy level.
	level = va_arg(args, int);
	written += snprintf(ph_logger_msg->buffer + written, avail_len, "%d%c", level,'\0');
	avail_len -= written;

	//Copy platform.
	platform = va_arg(args, char*);
	written += snprintf(ph_logger_msg->buffer + written, avail_len, "%s%c", platform,'\0');
	avail_len -= written;

	//Copy source.
	source = va_arg(args, char*);
	written += snprintf(ph_logger_msg->buffer + written, avail_len, "%s%c", source,'\0');
	avail_len -= written;

	data_len = va_arg(args, int); 
	to_copy = (data_len <= avail_len) ? data_len : avail_len;
	if (buf)
		memcpy(ph_logger_msg->buffer + written, buf, to_copy);
	data = ph_logger_msg->buffer + written;
	ph_logger_msg->len = to_copy;
	ph_logger_msg->len = written + to_copy;
	return to_copy;
}

int ph_logger_write_to_file_handler_v1(struct ph_logger_msg *ph_logger_msg, const char *log_dir, char *rev)
{
	char pathname[PATH_MAX];
	int written = 0;
	int log_fd = -1;
	int level;
	char *platform = NULL;
	char *source = NULL;
	char *data = NULL;
	int ret = -1;
	char *dup_pathname = NULL;
	char *fname = NULL;
	struct stat st;
	const int MAX_SIZE = 2 * 1024 * 1024;

	ph_logger_read_bytes(ph_logger_msg, NULL, &level, &platform, &source);
	/*Data is after source*/
	data = source + strlen(source) + 1;
	written = snprintf(pathname, sizeof(pathname), "%s/%s/%s/%s", log_dir, rev, platform, source);
	dup_pathname = strdup(pathname);
	fname = dirname(dup_pathname);
	/*
	 * Create directory for logged item according to platform and source.
	 */
	if (mkdir_p(fname, 0755))
		goto error;
	log_fd = open(pathname, O_CREAT | O_SYNC | O_RDWR | O_APPEND, 0644);
	if (log_fd >= 0) {
		if (!fstat(log_fd, &st)) {
			/* Do we need to make a zip out of it?*/
			if (st.st_size >= MAX_SIZE) 
				ftruncate(log_fd, 0);
		}
		dprintf(log_fd, "%.*s\n", ph_logger_msg->len, data);
		close(log_fd);
		ret = 0;
	} else {
		WARN_ONCE("Error opening file %s/%s, "
				"errno = %d\n", platform, source, errno);
	}
error:
	free(dup_pathname);
	return ret;
}

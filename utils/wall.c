#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <utmpx.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>

static char *concat_path_file(const char *path, const char *file)
{
	size_t len_path = strlen(path);
	size_t len_file = strnlen(file, __UT_LINESIZE);
	int need_slash = (len_path > 0 && path[len_path - 1] != '/');
	size_t len_total =
		len_path + len_file + (need_slash ? 2 : 1); // +1 for \0

	char *result = malloc(len_total);
	if (!result)
		return NULL;

	snprintf(result, len_total, "%s%s%s", path, (need_slash ? "/" : ""),
		 file);
	return result;
}

static void write_to_tty(const char *tty_path, const char *message)
{
	int fd = open(tty_path, O_WRONLY | O_NOCTTY);
	if (fd >= 0) {
		write(fd, message, strlen(message));
		close(fd);
	}
}

void wall(const char *message)
{
	struct utmpx *ut;

	if (!message)
		return;

	setutxent();
	while ((ut = getutxent()) != NULL) {
		if (ut->ut_type != USER_PROCESS)
			continue;
		char linebuf[__UT_LINESIZE + 1] = { 0 };
		memcpy(linebuf, ut->ut_line, __UT_LINESIZE);
		char *line = concat_path_file("/dev", ut->ut_line);
		if (line) {
			write_to_tty(line, message);
			free(line);
		}
	}
	endutxent();
}

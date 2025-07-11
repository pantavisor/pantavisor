#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>

#include "../log.h"

#define MODULE_NAME "wall"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)

void wall(const char *message, ...)
{
	int con_fd;

	con_fd = open("/dev/console", O_RDWR);
	if (con_fd < 0) {
		pv_log(WARN, "Unable to open /dev/console");
		return;
	}
	va_list args;
	va_start(args, message);
	vdprintf(con_fd, message, args);
	dprintf(con_fd, "\r\n");
	va_end(args);
}
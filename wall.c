#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <limits.h>
#include <utmp.h>

#include "log.h"
#include "version.h"

#define MODULE_NAME "wall"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)

void pv_wall(const char *message, ...)
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
	dprintf(con_fd, "\n");
	va_end(args);
}

void pv_wall_ssh_users(const char *message)
{
	struct utmp *entry;
	setutent();
	while ((entry = getutent()) != NULL) {

		if (entry->ut_type != USER_PROCESS)
			continue;

		char tty_path[PATH_MAX];
		snprintf(tty_path, sizeof(tty_path), "/dev/%s", entry->ut_line);

		int fd = open(tty_path, O_WRONLY | O_NOCTTY);
		if (fd >= 0) {
			dprintf(fd, "%s\r\n", message);
			close(fd);
		}
		endutent();
	}
}

void pv_wall_welcome()
{
	pv_wall("______           _              _                ");
	pv_wall("| ___ \\         | |            (_)               ");
	pv_wall("| |_/ /_ _ _ __ | |_ __ ___   ___ ___  ___  _ __ ");
	pv_wall("|  __/ _` | '_ \\| __/ _` \\ \\ / / / __|/ _ \\| '__|");
	pv_wall("| | | (_| | | | | || (_| |\\ V /| \\__ \\ (_) | |   ");
	pv_wall("\\_|  \\__,_|_| |_|\\__\\__,_| \\_/ |_|___/\\___/|_|   ");
	pv_wall("                                                 ");
	pv_wall("Pantavisor (TM) (%s) - pantavisor.io", pv_build_version);
	pv_wall("                                                 ");
}
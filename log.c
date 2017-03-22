#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>

#include "log.h"

#define LEVEL_NAME(LEVEL)	{ LEVEL, #LEVEL }
static struct level_name level_names[] = {
	LEVEL_NAME(FATAL),
	LEVEL_NAME(ERROR),
	LEVEL_NAME(WARN),
	LEVEL_NAME(INFO),
	LEVEL_NAME(DEBUG)
};

static int prio = ERROR;

// default STDOUT
int log_fd = 1;

void exit_error(int err, char *msg)
{
	printf("ERROR: %s (err=%d)\n", msg, err);
	printf("ERROR: rebooting system in 30 seconds\n");

	// FIXME: Should drop to ash console
	sync();
	sleep(30);
	exit(0);
}

static void log_print_date(void)
{
	char date[sizeof(DATE_FORMAT)];
	struct timeval tv;
	const struct tm *t;

	gettimeofday(&tv, NULL);
	t = localtime(&tv.tv_sec);

	strftime(date, sizeof(date), "%Y-%m-%d %H:%M:%S", t);

	dprintf(log_fd, "[%s] ", date);
}

static const char *strip_newline(const char *str)
{
	char *c = strdup(str);
	char *t = c;

	t = strchr(t, '\n');
	while (t) {
		*t = 32; // whitespace
		t = strchr(t, '\n');
	}

	return (const char *) c;
}

void __vlog(char *module, int level, const char *fmt, ...)
{
	const char *format = 0;
	va_list args;
	va_start(args, fmt);

	if (level <= prio) {
		dprintf(log_fd, "[systemc] %s\t", level_names[level].name);
		log_print_date();
		dprintf(log_fd, "[%s]: -- ", module);
		format = strip_newline(fmt);
		vdprintf(log_fd, format, args);
		if (fmt[strlen(fmt)] != '\n')
			dprintf(log_fd, "\n");
	}
	free((char *) format);

	va_end(args);
}

void sc_log_flush(struct systemc *sc)
{
	// FIXME: Push to cloud somehow, device meta?

	return;
}

int sc_log_set_level(unsigned int level)
{
	if (level <= ALL)
		prio = level;

	//log_fd = open("/tmp/systemc.log", O_CREAT | O_SYNC | O_WRONLY | O_APPEND, 0644);

	// FIXME: Setup other stuff like remote log, etc

	return prio;
}

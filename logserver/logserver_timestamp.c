#include "logserver_timestamp.h"

#include <string.h>

struct time_format {
	char *name;
	char *fmt;
};

struct time_format formats[] = {
	{ "golang:Layout", "%m/%d %H:%M:%S%p '%y %z" },
	{ "golang:RubyDate", "%a %b %d %T %z %Y" },
	{ "golang:ANSIC", "%a %b _%d %T %Y" },
	{ "golang:RFC822Z", "%d %b %y %H:%M %z" },
	{ "golang:RFC1123Z", "%a, %d %b %Y %T %z" },
};

#define LOGSERVER_TS_FMT_LIST_SIZE sizeof(formats) / sizeof(struct time_format)
#define LOGSERVER_TS_STR_MAX_SIZE 128
#define LOGSERVER_TS_STRFTIME_PREFIX "strftime"

static const char *get_fmt(const char *name)
{
	if (!name)
		return NULL;

	if (!strncmp(name, LOGSERVER_TS_STRFTIME_PREFIX,
		     strlen(LOGSERVER_TS_STRFTIME_PREFIX))) {
		return name + strlen(LOGSERVER_TS_STRFTIME_PREFIX) + 1;
	}

	for (size_t i = 0; i < LOGSERVER_TS_FMT_LIST_SIZE; ++i) {
		if (!strcmp(name, formats[i].name))
			return formats[i].fmt;
	}
	return NULL;
}

int logserver_timestamp_get_formated(char *buf, int buf_size,
				     const time_t *time, const char *name)
{
	const char *fmt = get_fmt(name);
	if (!fmt)
		goto err;

	if (strftime(buf, buf_size, fmt, localtime(time)) == 0)
		goto err;

	return 0;

err:
	buf[0] = '\0';
	return -1;
}

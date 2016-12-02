#ifndef SC_LOG_H
#define SC_LOG_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>

#include "systemc.h"

void exit_error(int err, char *msg);

#ifdef DEBUG
#undef DEBUG
#endif

enum log_level {
	FATAL,	// 0
	ERROR,	// 1
	WARN,	// 2
	INFO,	// 3
	DEBUG,	// 4
	ALL	// 5
};

struct level_name {
	int log_level;
	char *name;
};

// Example log:		"[systemc] WARN [2016-12-01 13:22:26] -- [updater]: Cannot poke cloud"
#define DATE_FORMAT		"2016-12-01 13:22:26"

#define vlog(module, level, ...)	__vlog(module, level, ## __VA_ARGS__);

void __vlog(char *module, int level, const char *fmt, ...);
void sc_log_flush(struct systemc *sc);
int sc_log_set_level(unsigned int level);

#endif

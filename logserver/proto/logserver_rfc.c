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

#include "logserver_rfc.h"
#include "logserver/logserver_timestamp.h"
#include "log.h"
#include "cgroup.h"

#include <syslog.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LOGSERVER_RFC_SOCKET "/dev/log"
#define LOGSERVER_RFC_PV "_pv_"
#define LOGSERVER_RFC_MAIN_PLAT "pantavisor"
#define LOGSERVER_RFC_UNK_PLAT "unknown-platform"

static void logserver_rfc_set_platform_name(pid_t pid, char *name)
{
	char *plat = pv_cgroup_get_process_name(pid);

	if (!plat) {
		memccpy(name, LOGSERVER_RFC_UNK_PLAT, 0,
			strlen(LOGSERVER_RFC_UNK_PLAT) + 1);
		return;
	}

	if (!strncmp(plat, LOGSERVER_RFC_PV, strlen(LOGSERVER_RFC_PV))) {
		memccpy(name, LOGSERVER_RFC_MAIN_PLAT, 0,
			strlen(LOGSERVER_RFC_MAIN_PLAT) + 1);
		goto out;
	}
	memccpy(name, plat, 0, LOGSERVER_PLAT_MAX_LEN);
	name[LOGSERVER_PLAT_MAX_LEN - 1] = '\0';

out:
	if (plat)
		free(plat);
}

int logserver_rfc_level_to_pv(int prival)
{
	int level = prival & 0x07;

	enum log_level pv_level = ALL;
	switch (level) {
	case LOG_EMERG:
	case LOG_ALERT:
		pv_level = FATAL;
		break;
	case LOG_CRIT:
	case LOG_ERR:
		pv_level = ERROR;
		break;
	case LOG_WARNING:
		pv_level = WARN;
		break;
	case LOG_NOTICE:
	case LOG_INFO:
		pv_level = INFO;
		break;
	case LOG_DEBUG:
		pv_level = DEBUG;
		break;
	default:
		pv_level = ALL;
		break;
	}

	return pv_level;
}

char *logserver_rfc_get_facility(int prival)
{
	int facility = prival >> 3;

	switch (facility) {
	case LOG_AUTH:
		return "auth";
	case LOG_AUTHPRIV:
		return "auth_priv";
	case LOG_CRON:
		return "cron";
	case LOG_DAEMON:
		return "daemon";
	case LOG_FTP:
		return "ftp";
	case LOG_KERN:
		return "kernel";
	case LOG_LOCAL0:
		return "container";
	case LOG_LPR:
		return "printer sys";
	case LOG_MAIL:
		return "mail sys";
	case LOG_NEWS:
		return "news sys";
	case LOG_SYSLOG:
		return "syslog";
	case LOG_USER:
		return "user";
	case LOG_UUCP:
		return "UUCP";
	}

	return "unknown";
}

int logserver_rfc_get_prival(const char *buf)
{
	if (buf[0] != '<')
		return -1;

	// follows RFC 3164 and 5424 max 3 digits
	char pri_buf[4] = { 0 };
	int i = 1;
	while (i < 4 && isdigit(buf[i])) {
		pri_buf[i - 1] = buf[i];
		i++;
	}

	errno = 0;
	int prival = (int)strtol(pri_buf, NULL, 10);
	if (errno != 0 || buf[i] != '>')
		return -1;

	return prival;
}

int logserver_rfc_create_socket(const char *cur_sock)
{
	return symlink(cur_sock, LOGSERVER_RFC_SOCKET);
}

log_protocol_code_t logserver_rfc_get_type(const char *buf)
{
	if (buf[0] != '<')
		return LOG_PROTOCOL_UNKNOWN;

	int i = 1;
	while (i < 5 && isdigit(buf[i]))
		i++;

	if (i > 1 && buf[i] == '>') {
		if (buf[i + 1] == '1')
			return LOG_PROTOCOL_RFC5424;
		return LOG_PROTOCOL_RFC3164;
	}
	return LOG_PROTOCOL_UNKNOWN;
}

int logserver_rfc_to_log(struct logserver_rfc *rfc, pid_t pid, const char *rev,
			 const char *upd_rev, struct logserver_log *log)
{
	if (!rfc || !log)
		return -1;

	logserver_rfc_set_platform_name(pid, log->plat);

	log->code = rfc->code;
	log->lvl = logserver_rfc_level_to_pv(rfc->prival);
	log->tnano = 0;
	log->time = rfc->time;
	log->tsec = logserver_timestamp_get_tsec(log->time);
	log->src = rfc->app;
	log->running_rev = rev ? (char *)rev : "";
	log->updated_rev = upd_rev ? (char *)upd_rev : "";
	log->data.buf = rfc->msg;
	log->data.len = strlen(rfc->msg);

	return 0;
}

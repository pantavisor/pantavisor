/*
 * Copyright (c) 2017-2025 Pantacor Ltd.
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
#ifndef PV_TSH_H
#define PV_TSH_H

#include <sys/types.h>

#define TSH_DEFAULT_TIMEOUT (60)
#define TSH_NO_TIMEOUT (-1)

pid_t tsh_run(const char *cmd, int wait, int *status);
pid_t tsh_run_io(const char *cmd, int wait, int *status, int stdin_p[],
		 int stdout_p[], int stderr_p[]);

pid_t tsh_run_timeout(const char *cmd, int wait, int *status, int timeout_s);
pid_t tsh_run_io_timeout(const char *cmd, int wait, int *status, int timeout_s,
			 int stdin_p[], int stdout_p[], int stderr_p[]);

int tsh_run_output(const char *cmd, int timeout_s, char *out_buf, int out_size,
		   char *err_buf, int err_size);

#ifndef DISABLE_LOGSERVER
int tsh_run_logserver(const char *cmd, int *wstatus, const char *log_source_out,
		      const char *log_source_err);

int tsh_run_logserver_timeout(const char *cmd, int *wstatus, int timeout_s,
			      const char *log_source_out,
			      const char *log_source_err);

pid_t tsh_run_daemon_logserver(const char *cmd, const char *log_source_out,
			       const char *log_source_err);
#endif

#endif

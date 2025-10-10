/*
 * Copyright (c) 2021-2023 Pantacor Ltd.
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
#ifndef PV_DEBUG_H
#define PV_DEBUG_H

#include <stdbool.h>
#include <unistd.h>

bool pv_debug_is_shell_open();
void pv_debug_run_shell_early();
void pv_debug_start();
void pv_debug_defer_reboot_shell(const char *payload);

void pv_debug_start_ssh(void);
void pv_debug_stop_ssh(void);
void pv_debug_check_ssh_running(void);
bool pv_debug_is_ssh_pid(pid_t pid);
pid_t pv_debug_get_ssh_pid(void);

#endif // PV_DEBUG_H

/*
 * Copyright (c) 2021-2025 Pantacor Ltd.
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

#ifndef UTILS_SYSTEM_H
#define UTILS_SYSTEM_H

#include <stdint.h>

#include <sys/types.h>

#ifdef __arm__
#define PV_ARCH "arm"
#elif __aarch64__
#define PV_ARCH "aarch64"
#elif __x86_64__
#define PV_ARCH "x86_64"
#elif __mips__
#define PV_ARCH "mips"
#else
#define PV_ARCH "unknown"
#endif

#if UINTPTR_MAX == 0xffffffff
#define PV_BITS "32"
#else
#define PV_BITS "64"
#endif

typedef enum {
	PV_SYSTEM_TRANSITION_NONE = 0,
	PV_SYSTEM_TRANSITION_NONREBOOT = 1,
	PV_SYSTEM_TRANSITION_REBOOT = 2,
	PV_SYSTEM_TRANSITION_POWEROFF = 3
} pv_system_transition_t;

int get_endian(void);
int get_dt_model(char *buf, int buflen);
int get_cpu_model(char *buf, int buflen);

void pv_system_kill_lenient(pid_t pid);
void pv_system_kill_force(pid_t pid);
int pv_system_kill_and_wait(pid_t pid);

void pv_system_set_process_name(const char *fmt, ...);

char *pv_system_transition_str(pv_system_transition_t t);
int pv_system_linux_reboot_cmd(pv_system_transition_t t);

#endif // UTILS_SYSTEM_H

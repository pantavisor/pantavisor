/*
 * Copyright (c) 2017 Pantacor Ltd.
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
#ifndef PV_UTILS_H
#define PV_UTILS_H

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>

#include <jsmn/jsmnutil.h>

bool dir_exist(const char *dir);
int mkdir_p(char *dir, mode_t mode);
void syncdir(char *dir);
int get_digit_count(int number);
int get_endian(void);
int get_dt_model(char *buf, int buflen);
int get_cpu_model(char *buf, int buflen);
void kill_child_process(pid_t pid);

#ifndef ARRAY_LEN
#define ARRAY_LEN(X) 	(ssize_t)(sizeof(X)/sizeof(X[0]))
#endif /* ARRAY_LEN*/

#ifndef free_member
#define free_member(ptr, member)\
({\
 if (ptr->member)\
	free((void*)(ptr->member));\
 ptr->member = NULL;\
})
#endif /* free_member */

#ifdef __arm__
#define PV_ARCH		"arm"
#elif __aarch64__
#define PV_ARCH		"aarch64"
#elif __x86_64__
#define PV_ARCH		"x86_64"
#elif __mips__
#define	PV_ARCH		"mips"
#else
#define PV_ARCH		"unknown"
#endif

#if UINTPTR_MAX == 0xffffffff
#define	PV_BITS		"32"
#else
#define	PV_BITS		"64"
#endif

#define PREFIX_MODEL	"model name\t:"

#endif // PV_UTILS_H

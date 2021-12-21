/*
 * Copyright (c) 2021 Pantacor Ltd.
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

#define _GNU_SOURCE

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>
#include <linux/sysctl.h>

#include "pantavisor.h"
#include "init.h"

int _sysctl(struct __sysctl_args *args );

static int pv_vm_init(struct pv_init *this)
{
	int system_swappiness = pv_config_get_system_swappiness();

	if (system_swappiness >= 0) {
		struct __sysctl_args args;
		char val[25];
		int rv;
		snprintf(val, 25, "%d", system_swappiness);
		args.name = (int[]) {CTL_VM, VM_SWAPPINESS, 0};
		args.newval = val;
		if((rv = _sysctl(&args))){
			return rv;
		}
	}

	return 0;
}

struct pv_init pv_init_vm =  {
	.init_fn = pv_vm_init,
	.flags = 0,
};

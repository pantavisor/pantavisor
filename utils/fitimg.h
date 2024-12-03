/*
 * Copyright (c) 2025 Pantacor Ltd.
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

#ifndef PV_FITIMAGE_H
#define PV_FITIMAGE_H

#include "list.h"

#include <stdint.h>
#include <stddef.h>

enum mfit_header {
	PV_FIT_MAGIC,
	PV_FIT_TOTALSIZE,
	PV_FIT_OFF_DT_STRUCT,
	PV_FIT_OFF_DT_STRINGS,
	PV_FIT_OFF_MEM_RSVMAP,
	PV_FIT_VERSION,
	PV_FIT_LAST_COMP_VERSION,
	PV_FIT_BOOT_CPUID_PHYS,
	PV_FIT_SIZE_DT_STRINGS,
	PV_FIT_SIZE_DT_STRUCT,
	PV_FIT_MAX_HEADER
};

struct pv_fit_prop {
	uint32_t len;
	uint32_t *data;
	struct dl_list list;
};

struct pv_fit {
	void *mem;
	size_t len;

	struct struct_block {
		uint32_t *data;
		uint32_t *pos;
		uint32_t size;
	} st_blk;

	struct string_block {
		char *data;
		uint32_t size;
	} str_blk;
};

struct pv_fit *pv_fit_new(int fd);
int pv_fit_get_signatures(struct pv_fit *fit, struct dl_list *list);
void pv_fit_free(struct pv_fit *fit);
void pv_fit_prop_free(struct pv_fit_prop *prop);

#endif

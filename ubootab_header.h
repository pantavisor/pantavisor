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

#ifndef PV_UBOOTAB_HEADER_H
#define PV_UBOOTAB_HEADER_H

#include <stddef.h>

/*
 * The first UBOOTAB_HEADER_SIZE bytes of a fit partition tell U-Boot which
 * revision it holds: "fit_rev=<rev>\nfit_size=<bytes>\n", NUL padded. The FIT
 * itself starts right after, at UBOOTAB_HEADER_SIZE.
 */
#define UBOOTAB_HEADER_SIZE 4096
#define UBOOTAB_REV_MAX 128

struct ubootab_header {
	char rev[UBOOTAB_REV_MAX];
	long long fit_size; // -1 in headers written before fit_size existed
};

/* Fill buf (UBOOTAB_HEADER_SIZE bytes) for rev; 0, or -1 for an unusable rev */
int ubootab_header_format(char *buf, const char *rev, long long fit_size);

/* Read a header; -1 when buf holds no fit_rev (erased, garbage). */
int ubootab_header_parse(const char *buf, size_t len,
			 struct ubootab_header *hdr);

/* 1 when hdr (NULL for none) names exactly rev. */
int ubootab_header_has_rev(const struct ubootab_header *hdr, const char *rev);

/*
 * Index (0 = A, 1 = B) of the partition a new revision goes into: the one
 * that does not hold pv_rev, so a failed try always leaves pv_rev bootable.
 * When none or both hold it, B (U-Boot boots A when it finds no match).
 */
int ubootab_pick_inactive(const struct ubootab_header *a,
			  const struct ubootab_header *b, const char *pv_rev);

#endif

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

#ifndef PV_PVTX_STATE_H
#define PV_PVTX_STATE_H

#include "pvtx_error.h"

#include <stddef.h>

#define PVTX_STATE_EMPTY "{\"#spec\":\"pantavisor-service-system@1\"}"

struct pv_pvtx_state {
	char *json;
	size_t len;
	struct pv_pvtx_state_priv *priv;
};

struct pv_pvtx_state *pv_pvtx_state_from_str(const char *str, size_t len,
					     struct pv_pvtx_error *err);
struct pv_pvtx_state *pv_pvtx_state_from_file(const char *path, struct pv_pvtx_error *err);

void pv_pvtx_state_free(struct pv_pvtx_state *st);

int pv_pvtx_state_add(struct pv_pvtx_state *dst, struct pv_pvtx_state *src);
int pv_pvtx_state_remove(struct pv_pvtx_state *st, const char *part);

#endif

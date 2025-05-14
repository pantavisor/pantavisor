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

#ifndef PV_PVTX_CTRL_H
#define PV_PVTX_CTRL_H

#include "pvtx_error.h"

#include <stddef.h>
#include <stdbool.h>

struct pv_pvtx_ctrl {
	int sock;
	struct pv_pvtx_error error;
};

struct pv_pvtx_ctrl *pv_pvtx_ctrl_new(const char *path);
void pv_pvtx_ctrl_free(struct pv_pvtx_ctrl *ctrl);
char *pv_pvtx_ctrl_steps_get(struct pv_pvtx_ctrl *ctrl, const char *rev,
			     size_t *size);
int pv_pvtx_ctrl_steps_put(struct pv_pvtx_ctrl *ctrl, const char *data,
			   size_t size, const char *rev);

int pv_pvtx_ctrl_obj_put(struct pv_pvtx_ctrl *ctrl, const unsigned char *data,
			 size_t size, const char *sha256);

#endif

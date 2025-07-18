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

#ifndef PV_PVTX_ERROR_H
#define PV_PVTX_ERROR_H
#define PV_PVTX_ERROR_MAX_LEN (512)

struct pv_pvtx_error {
	int code;
	char str[PV_PVTX_ERROR_MAX_LEN];
};

#define PVTX_ERROR_SET(err, code, tmpl, ...)                                   \
	pv_pvtx_error_set(err, code, __func__, __LINE__, tmpl, ##__VA_ARGS__)

void pv_pvtx_error_set(struct pv_pvtx_error *err, int code, const char *func,
		       int line, const char *tmpl, ...);
void pv_pvtx_error_clear(struct pv_pvtx_error *err);

#endif

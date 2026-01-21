/*
 * Copyright (c) 2022 Pantacor Ltd.
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
#ifndef PV_LOGSERVER_SINK_H
#define PV_LOGSERVER_SINK_H

#include "utils/list.h"

struct pv_logserver_log {
	int ver;
	int level;
	uint64_t tsec;
	uint32_t tnano;
	char *plat;
	char *src;
	char *rev;
	struct {
		char *data;
		int len;
	} msg;
};

struct pv_logserver_sink {
	char *name;
	int (*add)(const struct pv_logserver_sink *sink,
		   const struct pv_logserver_log *);
	void (*free)(struct pv_logserver_sink *);
	void *priv;
	struct dl_list list;
};

struct pv_logserver_sink *
pv_logserver_sink_new(const char *name,
		      int (*add)(const struct pv_logserver_sink *sink,
				 const struct pv_logserver_log *log),
		      void (*free)(struct pv_logserver_sink *sink), void *priv);

#endif

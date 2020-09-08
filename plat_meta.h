/*
 * Copyright (c) 2020 Pantacor Ltd.
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

#ifndef __PV_PLAT_META_H__
#define __PV_PLAT_META_H__

#include <sys/inotify.h>
#include "utils/list.h"
#include "init.h"

#define PV_PLAT_META_DIR 	"/pv-plat-meta"

#define PV_META_FLAG_NOCREATE 	(1<<0)
#define PV_META_FLAG_NOMODIFY 	(1<<1)
#define PV_META_FLAG_NODELETE 	(1<<2)
#define PV_META_FLAG_NODEFACT 	(1<<3)

struct pv_plat_meta_watch {
	int flags;
	void *opaque;
	int (*action)(struct pv_plat_meta_watch *, struct inotify_event *ev);
};

static inline void pv_plat_meta_watch_init(struct pv_plat_meta_watch *watch,
						void *opaque)
{
	watch->flags = 0;
	watch->action = NULL;
	watch->opaque = opaque;
}

int pv_plat_meta_watch_action(struct pv_plat_meta_watch *watch,
					struct inotify_event *ev);
int pv_plat_meta_add_watch(struct pv_plat_meta_watch *watch, int flags);
int pv_plat_meta_upload(void);
#endif /*__PV_PLAT_META_H__*/

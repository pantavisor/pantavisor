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
#ifndef PV_VOLUMES_H
#define PV_VOLUMES_H

typedef enum {
	VOL_LOOPIMG,
	VOL_PERMANENT,
	VOL_REVISION,
	VOL_BOOT,
	VOL_UNKNOWN
} pv_volume_t;

struct pv_volume {
	char *name;
	char *mode;
	char *src;
	char *dest;
	pv_volume_t type;
	int loop_fd;
	int file_fd;
	struct pv_platform *plat;
	struct pv_volume *next;
};

struct pv_volume* pv_volume_add(struct pv_state *s, char *name);

int pv_volumes_mount(struct pantavisor *pv, int runlevel);
int pv_volumes_unmount(struct pantavisor *pv, int runlevel);
void pv_volumes_remove(struct pv_state *s);

#endif // PV_VOLUMES_H

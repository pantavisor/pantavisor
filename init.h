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
#ifndef PV_INIT_H
#define PV_INIT_H

#ifndef CLONE_FS
#define CLONE_FS 0x00000200
#endif
#ifndef CLONE_NEWNS
#define CLONE_NEWNS 0x00020000
#endif
#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif
#ifndef CLONE_NEWUTS
#define CLONE_NEWUTS 0x04000000
#endif
#ifndef CLONE_NEWIPC
#define CLONE_NEWIPC 0x08000000
#endif
#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif
#ifndef CLONE_NEWPID
#define CLONE_NEWPID 0x20000000
#endif
#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0x40000000
#endif

#include <sys/types.h>

#define PV_INIT_FLAG_CANFAIL (1 << 0)

struct pv_init {
	int flags;
	/*
	 * Initializer function to call.
	 */
	int (*init_fn)(struct pv_init *);
	/*
	 * Data for use by init_fn.
	 */
	void *data;
	/*
	 * private data for internal use, not
	 * available to init_fn.
	 */
	void *priv;
};

extern struct pv_init *pv_init_tbl[];
extern struct pv_init pv_init_bl;
extern struct pv_init pv_init_creds;
extern struct pv_init pv_init_config_trail;
extern struct pv_init pv_init_storage;
extern struct pv_init pv_init_ctrl;
extern struct pv_init pv_init_metadata;
extern struct pv_init pv_init_log;
extern struct pv_init pv_init_mount;
extern struct pv_init ph_init_mount;
extern struct pv_init pv_init_network;
extern struct pv_init pv_init_pantavisor;
extern struct pv_init pv_init_volume;
extern struct pv_init pv_init_platform;
extern struct pv_init pv_init_update;
extern struct pv_init pv_init_apparmor;

int pv_do_execute_init(void);
void pv_init_umount(void);

#endif

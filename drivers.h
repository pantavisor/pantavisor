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
#ifndef PV_DRIVERS_H
#define PV_DRIVERS_H

#include <stdlib.h>
#include <limits.h>

#include "platforms.h"
#include "pantavisor.h"

typedef enum {
	MOD_LOAD = 0,
	MOD_UNLOAD
} mod_action_t;

typedef enum {
	MOD_UNKNOWN = -1,
	MOD_UNLOADED,
	MOD_LOADED
} mod_state_t;

struct pv_driver {
	char *alias;
	char **modules;
	bool loaded;
	struct dl_list list;
};

const char *pv_drivers_state_str(char *match);
const char *pv_drivers_type_str(plat_driver_t type);
int pv_drivers_state(char *match);
char *pv_drivers_state_all(struct pv_platform *p);
int pv_drivers_load(char *match);
int pv_drivers_unload(char *match);

struct pv_driver* pv_drivers_add(struct pv_state *s, char *alias, int len, char **modules);
void pv_drivers_empty(struct pv_state *s);

static inline void pv_driver_free(struct pv_driver *driver)
{
	char **modules = driver->modules;

	if (driver->alias)
		free(driver->alias);
	if (!driver->modules)
		return;
	while (*modules != 0) {
		free(*modules);
		modules++;
	}

	free(driver);
}

#define pv_drivers_iter_begin(state, item) 	\
{\
	struct pv_driver *item##__tmp;\
	struct dl_list *item##__head = &(state)->bsp.drivers;\
	dl_list_for_each_safe(item, item##__tmp, item##__head,\
			struct pv_driver, list)

#define pv_drivers_iter_end	}
#endif // PV_DRIVERS_H

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
#ifndef __PH_LOGGER_H__
#define __PH_LOGGER_H__
#include <stdarg.h>
#include <stdbool.h>
#include <inttypes.h>
#include "../pantavisor.h"
#define PH_LOGGER_JSON_FORMAT     "{ \"tsec\": %"PRId64", \"tnano\": %"PRId32",\
\"lvl\": \"%s\", \"src\": \"%s\",\"plat\":\"%s\",\
\"rev\": \"%s\" , \"msg\": \"%s\" }"

#define PH_LOGGER_POS_XATTR 	"trusted.ph.logger.pos"


#ifdef DEBUG
#define WARN_ONCE(msg, args...) 	\
do {\
	static bool __warned = false; 	\
	if (! __warned) { 		\
		printf(msg, ##args); 	\
		__warned = true; 	\
	}\
}while(0)
#else
#define WARN_ONCE(msg, args...) 	
#endif


void ph_logger_toggle(struct pantavisor *pv, char *rev);
void ph_logger_stop(struct pantavisor *pv);
#endif /* __PH_LOGGER_H__ */

#ifndef __PV_BLKID_H__
#define __PV_BLKID_H__
/*
 * Copyright (c) 2019 Pantacor Ltd.
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

#include "utils.h"
#include <string.h>

struct blkid_info {
	char *fstype;
	char *uuid;
	char *label;
	char *sec_type;
	char *device;
};

static inline void free_blkid_info(struct blkid_info *info)
{
	free_member(info, fstype);
	free_member(info, uuid);
	free_member(info, label);
	free_member(info, sec_type);
	free_member(info, device);
}
static inline void blkid_init(struct blkid_info *info)
{
	memset(info, 0, sizeof(*info));
}
int get_blkid(struct blkid_info *info, const char *key);
#endif /*__PV_BUILD_H__*/

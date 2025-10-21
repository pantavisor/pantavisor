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

#include "fitimg.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <endian.h>
#include <sys/stat.h>
#include <sys/mman.h>

#define MODULE_NAME "pv_fit"
#define pv_log(level, msg, ...)                                                \
	vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__,       \
	     ##__VA_ARGS__)
#include "../log.h"

// The implementation of this library is based on the devicetree specification
// https://github.com/devicetree-org/devicetree-specification
// In particular to the chapter five: FLATTENED DEVICETREE (DTB) FORMAT

#define PV_FIT_BEGIN_NODE 0x1
#define PV_FIT_PROP_NODE 0x3

struct pv_fit *pv_fit_new(int fd)
{
	if (fd < 0) {
		pv_log(DEBUG, "invalid file descriptor fd = %d", fd);
		return NULL;
	}

	struct pv_fit *fit = calloc(1, sizeof(struct pv_fit));
	if (!fit)
		goto err;

	struct stat st = { 0 };
	if (fstat(fd, &st) != 0)
		goto err;

	fit->mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (!fit->mem)
		goto err;

	union {
		uint32_t *data32;
		char *data;
	} ptr;

	ptr.data = fit->mem;
	fit->st_blk.size = be32toh(ptr.data32[PV_FIT_SIZE_DT_STRUCT]);
	fit->st_blk.data =
		ptr.data32 +
		(be32toh(ptr.data32[PV_FIT_OFF_DT_STRUCT]) / sizeof(uint32_t));

	fit->st_blk.pos = fit->st_blk.data;
	fit->str_blk.data =
		ptr.data + be32toh(ptr.data32[PV_FIT_OFF_DT_STRINGS]);

	fit->str_blk.size = be32toh(ptr.data32[PV_FIT_SIZE_DT_STRINGS]);
	fit->len = st.st_size;

	return fit;
err:
	if (fit)
		pv_fit_free(fit);
	return NULL;
}

static int pv_fit_go_to_token(struct pv_fit *fit, uint32_t token,
			      uint32_t end_token)
{
	uint32_t be_token = htobe32(token);
	uint32_t be_end = htobe32(end_token);
	uint32_t *end = fit->st_blk.data + (fit->st_blk.size / 4);

	for (; fit->st_blk.pos < end; fit->st_blk.pos++) {
		if (*fit->st_blk.pos == be_token) {
			fit->st_blk.pos++;
			return 0;
		} else if (end_token > 0 && *fit->st_blk.pos == be_end) {
			break;
		}
	}

	return -1;
}

static int pv_fit_go_to_init(struct pv_fit *fit, const char *name)
{
	union {
		uint32_t *data32;
		char *data;
	} ptr;

	ptr.data32 = NULL;

	while (pv_fit_go_to_token(fit, PV_FIT_BEGIN_NODE, 0) != -1) {
		ptr.data32 = fit->st_blk.pos;
		if (!strncmp(ptr.data, name, strlen(name)))
			return 0;
	}
	return -1;
}

static struct pv_fit_prop *pv_fit_get_property(struct pv_fit *fit,
					       const char *name)
{
	while (pv_fit_go_to_token(fit, PV_FIT_PROP_NODE, PV_FIT_BEGIN_NODE) !=
	       -1) {
		uint32_t nameoff = be32toh(*(fit->st_blk.pos + 1));
		char *p = fit->str_blk.data + nameoff;
		if (strncmp(p, name, strlen(name)))
			continue;

		struct pv_fit_prop *prop =
			calloc(1, sizeof(struct pv_fit_prop));
		if (!prop) {
			pv_log(DEBUG, "couldn't allocate property");
			break;
		}

		prop->len = be32toh(*fit->st_blk.pos);
		prop->data = calloc(prop->len, sizeof(char));

		if (!prop->data) {
			pv_log(DEBUG, "couldn't allocate property data");
			pv_fit_prop_free(prop);
		}

		// pv_fit_go_to_token() moves the pointer just after of the
		// token, so in this case:
		// 0x3 len nameoff property_val
		//      ^
		//      |
		//  we are here
		//
		// all those values are 32bit integers, that's the reason for
		// the +2 in the memcpy() call
		memcpy(prop->data, fit->st_blk.pos + 2, prop->len);

		return prop;
	}

	return NULL;
}

int pv_fit_get_signatures(struct pv_fit *fit, struct dl_list *list)
{
	int i = 0;
	// "signature-1" is the name of the begin node for all the signature
	// properties. There are as many signature-1 blocks as there are
	// signatures in the file
	while (pv_fit_go_to_init(fit, "signature-1") != -1) {
		// "value" is the property where the signature value is stored
		struct pv_fit_prop *prop = pv_fit_get_property(fit, "value");

		if (!prop)
			continue;

		dl_list_add(list, &prop->list);
		++i;
	}
	return i;
}

void pv_fit_free(struct pv_fit *fit)
{
	if (!fit)
		return;

	munmap(fit->mem, fit->len);
	free(fit);
}

void pv_fit_prop_free(struct pv_fit_prop *prop)
{
	if (!prop)
		return;

	if (prop->data)
		free(prop->data);

	free(prop);
}

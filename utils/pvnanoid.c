/*
 * Copyright (c) 2024 Pantacor Ltd.
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

#include "pvnanoid.h"
#include "fs.h"

#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>

#define PV_NANOID_CHARS_LEN 63

static char *chars =
	"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz";

static int get_random(struct pv_nanoid *nid)
{
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		return -1;

	ssize_t nbytes =
		pv_fs_file_read_nointr(fd, nid->buf, PV_NANOID_RNG_BUF_SIZE);

	if (nbytes < 0) {
		nid->ok = false;
		return -1;
	}

	close(fd);

	nid->cur = 0;
	nid->ok = true;

	return 0;
}

static int get_index(struct pv_nanoid *nid)
{
	if (!nid->ok) {
		int err = get_random(nid);
		if (err != 0)
			return -1;
	}

	int32_t n = nid->buf[nid->cur];

	// abs
	uint32_t tmp = n >> 31;
	n ^= tmp;
	n += tmp & 1;

	nid->cur++;
	if (nid->cur == PV_NANOID_RNG_BUF_SIZE)
		nid->ok = false;

	return n % PV_NANOID_CHARS_LEN;
}

char *pv_nanoid_id(struct pv_nanoid *nid)
{
	char *nanoid = calloc(PV_NANOID_LEN, sizeof(char));
	if (!nanoid)
		return NULL;

	for (int i = 0; i < PV_NANOID_LEN; ++i) {
		int idx = get_index(nid);
		if (idx < 0) {
			free(nanoid);
			return NULL;
		}
		nanoid[i] = chars[idx];
	}

	return nanoid;
}
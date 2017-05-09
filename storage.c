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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/statfs.h>

#define MODULE_NAME             "storage"
#define sc_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "systemc.h"
#include "storage.h"

void sc_storage_gc_run(struct systemc *sc)
{
	//FIXME: unimplemented
	sync();

	return;
}

int sc_storage_get_free(struct systemc *sc)
{
	int fs_free, fs_min;
	struct statfs buf;
	
	if (statfs("/storage/trails/0.json", &buf) < 0)
		return -1;

	fs_free = (int) buf.f_bsize * (int) buf.f_bfree;
	fs_min = (int) buf.f_bsize * (int) buf.f_blocks;

	// Always leave 5%
	fs_min -= (fs_min * 95) / 100;

	sc_log(DEBUG, "fs_free: %d, fs_min: %d", fs_free, fs_min); 

	if (fs_free < fs_min)
		return 0;

	return fs_free;
}

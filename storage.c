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

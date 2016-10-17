#ifndef SC_LOOP_H
#define SC_LOOP_H

#include <sys/stat.h>
#include <sys/mount.h>

int mkdir_p(const char *dir, mode_t mode);
int get_free_loop(char *devname);
int bind_loop_dev(char *devname, char *file);
int mount_loop(char *src, char *dest, char *fstype);

#endif

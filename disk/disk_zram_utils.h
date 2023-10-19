#ifndef PV_DISK_ZRAM_UTILS_H
#define PV_DISK_ZRAM_UTILS_H

#include <stddef.h>

int pv_disk_zram_utils_find_or_create_device(void);
int pv_disk_zram_utils_reset(int devno);
int pv_disk_zram_utils_set_compression(int devno, const char *comp);
int pv_disk_zram_utils_set_size(int devno, const char *size);
int pv_disk_zram_utils_set_streams(int devno, const char *n);
int pv_disk_zram_utils_set_multple_ops(int devno, char *options);
int pv_disk_zram_utils_get_compression(int devno, char *buf, size_t size);
int pv_disk_zram_utils_get_size(int devno, char *buf, size_t size);
int pv_disk_zram_utils_get_stream(int devno, char *buf, size_t size);
char *pv_disk_zram_utils_get_path(int devno);
int pv_disk_zram_utils_get_devno(const char *path);

#endif

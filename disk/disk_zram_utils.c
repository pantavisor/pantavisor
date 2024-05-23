#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "disk_zram_utils.h"
#include "utils/fs.h"

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/limits.h>

#define PV_DISK_ZRAM_DEV_NAME "/dev/zram%d"
#define PV_DISK_ZRAM_SYSFS_CONF "/sys/block/zram%d"
#define PV_DISK_ZRAM_SYSFS_CONF_ATTR "/sys/block/zram%d/%s"
#define PV_DISK_ZRAM_SYSFS_HOT_ADD "/sys/class/zram-control/hot_add"
#define PV_DISK_ZRAM_SYSFS_HOT_RM "/sys/class/zram-control/hot_remove"

typedef enum {
	PV_ZRAM_DEV_UNKNOWN,
	PV_ZRAM_DEV_NOT_INITIALIZED,
	PV_ZRAM_DEV_INITIALIZED,
	PV_ZRAM_DEV_NOT_EXIST
} zram_state_t;

static ssize_t write_op(int devno, const char *key, const char *value)
{
	char buf[PATH_MAX] = { 0 };
	char *path = NULL;

	if (!strcmp(key, "remove")) {
		path = PV_DISK_ZRAM_SYSFS_HOT_RM;
	} else {
		snprintf(buf, PATH_MAX, PV_DISK_ZRAM_SYSFS_CONF_ATTR, devno,
			 key);
		path = buf;
	}

	int fd = open(path, O_WRONLY);
	if (fd < 0)
		return -1;

	ssize_t bytes_write = write(fd, value, strlen(value));
	close(fd);

	if (bytes_write < 0)
		return -2;

	return bytes_write;
}

static ssize_t read_op(int devno, const char *key, char *buf, size_t size)
{
	char path_buf[PATH_MAX] = { 0 };
	char *path = NULL;

	if (!strcmp(key, "add")) {
		path = PV_DISK_ZRAM_SYSFS_HOT_ADD;
	} else {
		snprintf(path_buf, PATH_MAX, PV_DISK_ZRAM_SYSFS_CONF_ATTR,
			 devno, key);
		path = path_buf;
	}

	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	ssize_t bytes_read = read(fd, buf, size);
	close(fd);

	if (bytes_read < 0)
		return -2;

	return bytes_read;
}

static zram_state_t is_available(int devno)
{
	char path[PATH_MAX] = { 0 };
	snprintf(path, PATH_MAX, PV_DISK_ZRAM_SYSFS_CONF, devno);

	int acc = access(path, F_OK);

	if (acc != 0)
		return PV_ZRAM_DEV_NOT_EXIST;

	char buf[3] = { 0 };
	if (read_op(devno, "initstate", buf, 2) < 0)
		return PV_ZRAM_DEV_UNKNOWN;

	if (buf[0] == '0')
		return PV_ZRAM_DEV_NOT_INITIALIZED;

	return PV_ZRAM_DEV_INITIALIZED;
}

int pv_disk_zram_utils_find_or_create_device()
{
	zram_state_t status = PV_ZRAM_DEV_UNKNOWN;
	int devno = 0;
	for (; devno < 100; ++devno) {
		status = is_available(devno);
		if (status == PV_ZRAM_DEV_INITIALIZED ||
		    status == PV_ZRAM_DEV_UNKNOWN) {
			continue;
		} else if (status == PV_ZRAM_DEV_NOT_INITIALIZED ||
			   status == PV_ZRAM_DEV_NOT_EXIST) {
			break;
		}
	}

	char buf[3] = { 0 };

	if (status == PV_ZRAM_DEV_NOT_EXIST) {
		if (read_op(devno, "add", buf, 3) < 0)
			return -1;

		errno = 0;
		int new_dev = strtol(buf, NULL, 10);

		if (new_dev < 0 || errno != 0)
			return -1;

		return new_dev;

	} else if (status == PV_ZRAM_DEV_NOT_INITIALIZED) {
		return devno;
	}
	return -1;
}

int pv_disk_zram_utils_reset(int devno)
{
	return write_op(devno, "reset", "1");
}

int pv_disk_zram_utils_set_compression(int devno, const char *comp)
{
	return write_op(devno, "comp_algorithm", comp);
}

int pv_disk_zram_utils_set_size(int devno, const char *size)
{
	return write_op(devno, "disksize", size);
}

int pv_disk_zram_utils_set_streams(int devno, const char *n)
{
	return write_op(devno, "max_comp_streams", n);
}

int pv_disk_zram_utils_set_multple_ops(int devno, char *options)
{
	char *ops = strdup(options);
	if (!ops)
		return -1;

	int not_set = 0;
	int n_op = 0;
	char *tmp = NULL;
	char *tok = strtok_r(ops, " ", &tmp);
	while (tok) {
		char *key = tok;
		char *value = strstr(tok, "=");
		*value = '\0';
		++value;

		if (write_op(devno, key, value) < 0)
			++not_set;
		++n_op;
		tok = strtok_r(NULL, " ", &tmp);
	}

	free(ops);
	return not_set;
}

int pv_disk_zram_utils_get_compression(int devno, char *buf, size_t size)
{
	return read_op(devno, "comp_algorithm", buf, size);
}

int pv_disk_zram_utils_get_size(int devno, char *buf, size_t size)
{
	return read_op(devno, "disksize", buf, size);
}

int pv_disk_zram_utils_get_stream(int devno, char *buf, size_t size)
{
	return read_op(devno, "max_comp_streams", buf, size);
}

char *pv_disk_zram_utils_get_path(int devno)
{
	if (devno < 0)
		return NULL;
	char *path = NULL;
	if (asprintf(&path, PV_DISK_ZRAM_DEV_NAME, devno) < 1)
		return NULL;

	return path;
}

int pv_disk_zram_utils_get_devno(const char *path)
{
	const char *dev_name = pv_fs_path_basename(path);

	errno = 0;
	int devno = strtol(dev_name + strlen("zram"), NULL, 10);
	if (devno < 0 || errno != 0)
		return -1;
	return devno;
}
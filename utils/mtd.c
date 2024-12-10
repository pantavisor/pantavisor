#include "mtd.h"

#include "fs.h"

#include <stdbool.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <mtd/mtd-user.h>

#define MODULE_NAME "pv_mtd"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define PV_MTD_DEV_PATH "/dev/mtd%d"
#define PV_MTD_SYS_PATH "/sys/block/mtdblock%d/device/%s"
#define PV_MTD_MAX_DEVS (100)
#define PV_MTD_MAX_SIZE_STR 64

static int get_attribute(int mtd_idx, const char *attr, char *buf, int size)
{
	int ret = -1;
	char path[PATH_MAX] = { 0 };
	snprintf(path, PATH_MAX, PV_MTD_SYS_PATH, mtd_idx, attr);
	errno = 0;
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		pv_log(DEBUG, "couldn't open device: %s(%d)", strerror(errno),
		       errno);
		goto out;
	}

	if (pv_fs_file_read_nointr(fd, buf, size) < 0) {
		pv_log(DEBUG, "couldn't read device attribute");
		goto out;
	}

out:
	if (fd >= 0)
		close(fd);
	return ret;
}

static int get_attribute_num(int mtd_idx, const char *attr, off_t *result)
{
	char buf[PV_MTD_MAX_SIZE_STR] = { 0 };
	if (get_attribute(mtd_idx, attr, buf, PV_MTD_MAX_SIZE_STR) != 0)
		return -1;

	errno = 0;
	long n = strtol(buf, NULL, 10);

	if (errno != 0) {
		pv_log(DEBUG, "couldn't convert str '%s': %s(%d)", attr,
		       strerror(errno), errno);
		return -1;
	}

	*result = n;

	return 0;
}

static int search_device_by_name(const char *name)
{
	int i = 0;
	while (i < PV_MTD_MAX_DEVS) {
		char buf[NAME_MAX] = { 0 };
		if (get_attribute(i, "name", buf, NAME_MAX) != 0)
			return -1;
		if (!strncmp(name, buf, strlen(buf)))
			return i;
	}
	return -1;
}

static int get_mtd_fd(const char *dev)
{
	int fd = open(dev, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		pv_log(DEBUG, "couldn't open device %s: %s (%d)", dev,
		       strerror(errno), errno);
	}
	return fd;
}

struct pv_mtd *pv_mtd_from_name(const char *name)
{
	int idx = search_device_by_name(name);
	if (idx < 0)
		return NULL;

	struct pv_mtd *mtd = calloc(1, sizeof(struct pv_mtd));
	if (!mtd)
		return NULL;

	if (get_attribute_num(idx, "erasesize", &mtd->erasesize) != 0)
		goto err;
	if (get_attribute_num(idx, "writesize", &mtd->writesize) != 0)
		goto err;
	if (get_attribute_num(idx, "size", &mtd->size) != 0)
		goto err;

	snprintf(mtd->dev, PATH_MAX, PV_MTD_DEV_PATH, idx);
	memcpy(mtd->name, name, strlen(name));

	return mtd;

err:
	if (mtd)
		free(mtd);
	return NULL;
}

int pv_mtd_erase(struct pv_mtd *mtd)
{
	int fd = get_mtd_fd(mtd->dev);
	if (fd < 0)
		return -1;

	erase_info_t ei = { 0 };
	errno = 0;
	ei.length = mtd->erasesize;
	for (ei.start = 0; ei.start < mtd->size; ei.start += ei.length) {
		if (ioctl(fd, MEMUNLOCK, &ei) == -1) {
			// errno 524 is ENOTSUPP in the linux driver
			// implementation, sadly seems no to be visible from
			// here using that name.
			if (errno != 524) {
				pv_log(DEBUG, "couldn't unlock %s (%d)",
				       strerror(errno), errno);
				return -1;
			}
		}

		if (ioctl(fd, MEMERASE, &ei) == -1) {
			pv_log(DEBUG, "couldn't erase %s (%d)", strerror(errno),
			       errno);
			return -1;
		}
	}

	return 0;
}

ssize_t pv_mtd_read(struct pv_mtd *mtd, char *buf, size_t size, off_t offset)
{
	int fd = get_mtd_fd(mtd->dev);
	if (fd < 0)
		return -1;

	ssize_t read_bytes = 0;
	while (read_bytes < size) {
		char *ptr = buf + read_bytes;
		ssize_t cur_rd = read(fd, ptr, mtd->writesize);
		if (cur_rd < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		read_bytes += cur_rd;
	}

	close(fd);
	return read_bytes;
}

ssize_t pv_mtd_write(struct pv_mtd *mtd, const char *buf, size_t buf_sz,
		     off_t offset)
{
	int fd = get_mtd_fd(mtd->dev);
	if (fd < 0)
		return -1;

	lseek(fd, offset, SEEK_SET);

	size_t wbytes = 0;
	while (wbytes < buf_sz) {
		ssize_t cur_wr = 0;
		do {
			const char *ptr = buf + wbytes + cur_wr;
			cur_wr += write(fd, ptr, mtd->writesize);
			if (cur_wr < 0) {
				if (errno == EINTR)
					continue;

				break;
			}
		} while (cur_wr < (mtd->writesize - buf_sz - wbytes));
		wbytes += cur_wr;
	}
	fsync(fd);
	close(fd);
	return wbytes;
}

ssize_t pv_mtd_copy_fd(struct pv_mtd *mtd, int fd, off_t offset)
{
	if (fd < 0) {
		pv_log(DEBUG, "source fd isn't open (fd < 0)");
		return -1;
	}

	int mtd_fd = get_mtd_fd(mtd->dev);
	if (mtd_fd < 0)
		return -1;

	struct stat st = { 0 };
	if (fstat(fd, &st) != 0) {
		pv_log(DEBUG, "couldn't get fd's file size");
		close(mtd_fd);
		return -1;
	}

	char *buf = calloc(mtd->writesize, sizeof(char));
	if (!buf) {
		pv_log(WARN,
		       "couldn't allocate buffer, kernel image will not be written");
		close(mtd_fd);
		return -1;
	}

	ssize_t read_bytes = 0;
	ssize_t write_bytes = 0;

	while (write_bytes < st.st_size) {
		ssize_t cur_rd = read(fd, buf, mtd->writesize);
		if (cur_rd < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		ssize_t cur_wr = 0;
		do {
			cur_wr += write(mtd_fd, buf + cur_wr, mtd->writesize);
			if (cur_wr < 0) {
				if (errno == EINTR)
					continue;

				break;
			}
		} while (cur_wr < cur_rd);

		write_bytes += cur_wr;
	}

	fsync(mtd_fd);
	close(mtd_fd);
	free(buf);

	pv_log(DEBUG, "file size: %zd, written bytes: %zd", (size_t)st.st_size,
	       write_bytes);

	return write_bytes;
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <mtd/mtd-user.h>

#define MODULE_NAME			"bootloader"
#define sc_log(level, msg, ...)		vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "utils.h"

#include "bootloader.h"

static int uboot_set_try_rev(struct systemc *sc, int rev)
{
	int fd;
	char s[256];
	erase_info_t ei;

	fd = open("/dev/mtd2", O_RDWR | O_SYNC);
	if (!fd)
		return 0;

	ei.start = 0;
	ioctl(fd, MEMUNLOCK, &ei);
	ioctl(fd, MEMERASE, &ei);

	lseek(fd, 0, SEEK_SET);
	sprintf(s, "sc_try=%d\0", rev);
	write(fd, &s, strlen(s) + 1);

	close(fd);

	return 1;
}

int sc_bl_set_try(struct systemc *sc, int rev)
{
	int fd;
	char s[256];

	if (strcmp(sc->config->storage.fstype, "ubifs") == 0)
		return uboot_set_try_rev(sc, rev);

	sprintf(s, "%s/boot/uboot.txt", sc->config->storage.mntpoint);
	fd = open(s, O_WRONLY | O_APPEND | O_SYNC);
	if (!fd)
		return 0;

	memset(s, 0, sizeof(s));
	sprintf(s, "sc_try=%d\0", rev);
	write(fd, s, strlen(s) + 1);
	sync();
	close(fd);

	return 1;
}

static int uboot_get_key_int(struct systemc *sc, char *key)
{
	int fd, n;
	int value = 0;
	char s[256];
	char *buf;
	struct stat st;

	if (strcmp(sc->config->storage.fstype, "ubifs") == 0)
		sprintf(s, "/dev/mtd2");
	else
		sprintf(s, "%s/boot/uboot.txt", sc->config->storage.mntpoint);
	stat(s, &st);

	fd = open(s, O_RDONLY);
	if (!fd)
		return -1;

	lseek(fd, 0, SEEK_SET);
	buf = calloc(1, st.st_size * sizeof(char));
	read(fd, buf, st.st_size);

	n = strlen(key);

	int k = 0;
	for (int i = 0; i < st.st_size; i++) {
		printf("%c", buf[i]);
		if (buf[i] != '\0')
			continue;

		if (strncmp(buf+k, key, n) == 0) {
			value = atoi(buf+k+n+1);
			break;
		}
		k = i+1;
	}
	free(buf);

	return value;
}

int sc_bl_get_current(struct systemc *sc)
{
	return uboot_get_key_int(sc, "sc_rev");
}

int sc_bl_get_try(struct systemc *sc)
{
	return uboot_get_key_int(sc, "sc_try");
}

void sc_bl_set_current(struct systemc *sc, int rev)
{
	int fd;
	char s[256];

	sprintf(s, "%s/boot/uboot.txt", sc->config->storage.mntpoint);
	fd = open(s, O_RDWR | O_TRUNC | O_SYNC);
	memset(s, 0, sizeof(s));
	sprintf(s, "sc_rev=%d\0", rev);
	write(fd, s, strlen(s) + 1);
	sync();
	close(fd);
}

int sc_bl_clear_update(struct systemc *sc)
{
	int fd;
	char buf[64] = { 0 };

	fd = open("/dev/mtd2", O_RDWR | O_SYNC);
	if (fd < 0) {
		sc_log(ERROR, "unable to clear bootloader update buffer");
		return -1;
	}

	lseek(fd, 0, SEEK_SET);
	write(fd, &buf, sizeof(buf));
	sc_log(INFO, "cleared bootloader update buffer");
	close(fd);

	return 0;
}

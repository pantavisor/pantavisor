/*
 * Copyright (c) 2023 Pantacor Ltd.
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

#include "disks.h"
#include "paths.h"
#include "utils/tsh.h"
#include "logserver/logserver.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <linux/limits.h>

#define MODULE_NAME "disks"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

int pv_disks_mount_handler(struct pv_disk *d, char *action);

static void pv_disk_free(struct pv_disk *d)
{
	if (d->name)
		free(d->name);
	if (d->path)
		free(d->path);
	if (d->uuid)
		free(d->uuid);
	if (d->options)
		free(d->options);

	free(d);
}

void pv_disks_empty(struct pv_state *s)
{
	if (!s)
		return;

	int num_disk = 0;
	struct pv_disk *d, *tmp;
	struct dl_list *disks = &s->disks;

	if (!disks)
		return;

	// Iterate over all disks from state
	dl_list_for_each_safe(d, tmp, disks, struct pv_disk, list)
	{
		pv_log(DEBUG, "removing disk %s", d->name);
		dl_list_del(&d->list);
		pv_disk_free(d);
		num_disk++;
	}

	pv_log(INFO, "removed %d disks", num_disk);
}

int pv_disks_mount_handler(struct pv_disk *d, char *action)
{
	char path[PATH_MAX], script[PATH_MAX];
	char *command = NULL;
	char *crypt_type;
	int ret;

	pv_paths_storage_mounted_disk_path(path, PATH_MAX, "dmcrypt", d->name);
	if (!strcmp("mount", action) && !access(path, F_OK)) {
		pv_log(DEBUG, "disk %s already mounted", path);
		return 0;
	}

	switch (d->type) {
	case DISK_DM_CRYPT_CAAM:
		crypt_type = "caam";
		break;
	case DISK_DM_CRYPT_DCP:
		crypt_type = "dcp";
		break;
	case DISK_DM_CRYPT_VERSATILE:
		crypt_type = "versatile";
		break;
	case DISK_DIR:
	case DISK_UNKNOWN:
	default:
		pv_log(ERROR, "unknown disk type %d", d->type);
		return -4;
	}

	pv_paths_lib_crypt(script, PATH_MAX, "crypt");
	command = malloc(sizeof(char) *
			 (strlen("%s %s %s %s %s") + strlen(script) +
			  strlen(action) + strlen(crypt_type) +
			  strlen(d->path) + strlen(path) + 1));
	if (!command) {
		pv_log(ERROR, "cannot alloc disk action command");
		return -5;
	}

	sprintf(command, "%s %s %s %s %s", script, action, crypt_type, d->path,
		path);
	pv_log(INFO, "command: %s", command);

	int wstatus;
	int outpipe[2];
	if ((ret = pipe(outpipe))) {
		pv_log(ERROR, "cannot create pipe %s", strerror(errno));
		return ret;
	}

	int errpipe[2];
	if ((ret = pipe(errpipe))) {
		pv_log(ERROR, "cannot create errpipe %s", strerror(errno));
		return ret;
	}

	pv_logserver_subscribe_fd(outpipe[0], "pantavisor", "crypt-mount-info",
				  INFO);
	pv_logserver_subscribe_fd(errpipe[0], "pantavisor", "crypt-mount-err",
				  WARN);

	ret = tsh_run_io(command, 1, &wstatus, NULL, outpipe, errpipe);
	close(outpipe[1]);
	close(errpipe[1]);
	if (ret < 0) {
		pv_log(ERROR, "command: %s error: %s", command);
	} else if (WIFEXITED(wstatus) && WEXITSTATUS(wstatus)) {
		pv_log(ERROR, "command failed with status: %s=%d", command,
		       WEXITSTATUS(wstatus));
		ret = -1;
	} else if (WIFEXITED(wstatus)) {
		pv_log(DEBUG, "command succeeded: %s", command);
		ret = 0;
	} else if (WIFSIGNALED(wstatus)) {
		pv_log(ERROR, "command signalled: %s %d", command,
		       WTERMSIG(wstatus));
		ret = -2;
	} else {
		pv_log(ERROR, "command failed with wstatus: %d", wstatus);
		ret = -3;
	}

	if (command)
		free(command);

	return ret;
}

int pv_disks_umount_all(struct pv_state *s)
{
	int ret = 0;

	if (!s)
		return ret;

	struct pv_disk *d, *tmp;
	struct dl_list *disks = &s->disks;

	if (!disks)
		return ret;

	pv_log(INFO, "unmounting all disks...");
	dl_list_for_each_safe(d, tmp, disks, struct pv_disk, list)
	{
		int r;
		if ((r = pv_disks_mount_handler(d, "umount"))) {
			pv_log(ERROR, "error unmounting disk (%d), %s", r,
			       d->name);
			ret |= r;
		} else {
			pv_log(DEBUG, "successfully unmounted disk %s",
			       d->name);
		}
	}
	return ret;
}

struct pv_disk *pv_disk_add(struct pv_state *s)
{
	struct pv_disk *d = calloc(1, sizeof(struct pv_disk));

	if (d) {
		dl_list_init(&d->list);
		dl_list_add_tail(&s->disks, &d->list);
	}

	return d;
}

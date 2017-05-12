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
#include <errno.h>
#include <string.h>
#include <libgen.h>
#include <unistd.h>

#include <sys/utsname.h>
#include <sys/stat.h>

#include <lxc/lxccontainer.h>

#include "utils.h"

#include "pv_lxc.h"

extern int lxc_log_init(const char *name, const char *file,
			const char *priority, const char *prefix, int quiet,
			const char *lxcpath);

void *pv_start_container(char *name, char *conf_file, void *data)
{
	int fd, err;
	struct lxc_container *c;
	char *dname;
	struct utsname uts;
	struct stat st;

	// Go to LXC config dir for platform
	dname = strdup(conf_file);
	dname = dirname(dname);
	chdir(dname);
	free(dname);

	// Make sure lxc state dir is there
	mkdir_p("/usr/var/lib/lxc", 0644);

	c = lxc_container_new(name, NULL);
	if (!c) {
		return NULL;
	}
	c->clear_config(c);
	if (!c->load_config(c, conf_file)) {
		lxc_container_put(c);
		return NULL;
	}

	lxc_log_init(name, "/storage/log", "DEBUG", "init", 0, name);

	unsigned short share_ns = (1 << LXC_NS_NET) | (1 << LXC_NS_UTS) | (1 << LXC_NS_IPC);
	c->set_inherit_namespaces(c, 1, share_ns);

	c->want_daemonize(c, true);
	c->want_close_all_fds(c, true);

	// Strip consoles from kernel cmdline
	char tmp_cmd[] = "/tmp/cmdline-XXXXXX";
	mktemp(tmp_cmd);
	fd = open("/proc/cmdline", O_RDONLY);
	if (fd) {
		char *buf = calloc(1024, 1);
		char *new = calloc(1024, 1);
		read(fd, buf, 1024);
		char *tok = strtok(buf, " ");
		while (tok) {
			if (strncmp("console=", tok, 8) == 0) {
				tok = strtok(NULL, " ");
				continue;
			}
			strcat(new, tok);
			strcat(new, " ");
			tok = strtok(NULL, " ");
		}
		close(fd);
		fd = open(tmp_cmd, O_CREAT | O_RDWR | O_SYNC);
		write(fd, new, strlen(new));
		close(fd);
		free(new);
		free(buf);
	}
	char entry[1024];
	//sprintf(entry, "%s proc/cmdline none bind,ro 0 0", tmp_cmd);
	//c->set_config_item(c, "lxc.mount.entry", entry);

	char *cpath = "/tmp/pantavisor/ run/pantavisor none bind,ro,create=dir 0 0";
	c->set_config_item(c, "lxc.mount.entry", cpath);

	c->set_config_item(c, "lxc.mount.entry", "/dev dev none bind,rw,create=dir 0 0");

	int ret = uname(&uts);
	// FIXME: Implement modules volume and use that instead
	if (!ret) {
		if (stat("/volumes/modules.squashfs", &st) == 0) {
			sprintf(entry, "/volumes/modules.squashfs lib/modules/%s none bind,ro,create=dir 0 0", uts.release);
			c->set_config_item(c, "lxc.mount.entry", entry);
		}
	}
	if (stat("/volumes/firmware.squashfs", &st) == 0)
		c->set_config_item(c, "lxc.mount.entry", "/volumes/firmware.squashfs lib/firmware none bind,ro,create=dir 0 0");

	err = c->start(c, 0, NULL) ? 0 : 1;

	if (err && (c->error_num != 1)) {
		lxc_container_put(c);
		c = NULL;
	}

	return (void *) c;
}

// cannot fail if data is valid
void *pv_stop_container(char *name, char *conf_file, void *data)
{
	bool s;
	struct lxc_container *c = (struct lxc_container *) data;

	if (!data)
		return NULL;

	s = c->shutdown(c, 5); // 5 second timeout
	if (!s)
		c->stop(c);

	// unref
	lxc_container_put(c);

	return NULL;
}


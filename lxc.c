#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <libgen.h>
#include <unistd.h>

#include <sys/utsname.h>

#include <lxc/lxccontainer.h>

#include "utils.h"
#include "loop.h"

#define MODULE_NAME             "lxc"
#define sc_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "lxc.h"

void *start_lxc_container(char *name, char *conf_file, void *data)
{
	int fd;
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
		exit_error(errno, "Failed to create contaier");
	}
	c->clear_config(c);
	if (!c->load_config(c, conf_file)) {
		sc_log(ERROR, "failed to load rcfile");
		lxc_container_put(c);
		return NULL;
	}

	lxc_log_init(name, "/tmp/log", "DEBUG", "init", 0, name);
	
	unsigned short share_ns = (1 << LXC_NS_NET) | (1 << LXC_NS_UTS) | (1 << LXC_NS_IPC);
	c->set_inherit_namespaces(c, 1, share_ns);

	c->want_daemonize(c, true);
	c->want_close_all_fds(c, true);

	// Strip consoles from kernel cmdline
	char tmp_cmd[] = "/tmp/cmdline-XXXXXX";
	mktemp(tmp_cmd);
	fd = open("/proc/cmdline", O_RDONLY);
	if (fd < 0) {
		sc_log(ERROR, "cannot open cmdline\n");
	} else {
		sc_log(DEBUG, "opened cmdline\n\n");
		char *buf = calloc(1024, 1);
		char *new = calloc(1024, 1);
		int bytes = read(fd, buf, 1024);
		sc_log(DEBUG, "read=%d bytes, old cmdline='%s'\n\n", bytes, buf);
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
		sc_log(DEBUG, "new cmdline='%s'", new);
		close(fd);
		fd = open(tmp_cmd, O_CREAT | O_RDWR | O_SYNC);
		write(fd, new, strlen(new));
		close(fd);
	}
	char entry[1024];
	sprintf(entry, "%s proc/cmdline none bind,ro 0 0", tmp_cmd);
	c->set_config_item(c, "lxc.mount.entry", entry);
	int ret = uname(&uts);
	
	// FIXME: Implement modules volume and use that instead
	sc_log(DEBUG, "uname ret=%d, errno=%d, rev='%s'", ret, errno, uts.release);
	if (!ret) {
		sprintf(entry, "/lib/modules/%s", uts.release);
		if (stat(entry, &st) == 0) {
			sprintf(entry, "/lib/modules/%s lib/modules/%s none bind,ro,create=dir 0 0", uts.release, uts.release);
			c->set_config_item(c, "lxc.mount.entry", entry);
		}
	}
	errno = c->start(c, 0, NULL);

	return (void *) c;
}

// cannot fail if data is valid
void *stop_lxc_container(char *name, char *conf_file, void *data)
{
	bool s;
	struct lxc_container *c = (struct lxc_container *) data;
	
	if (!data)
		return NULL;

	s = c->shutdown(c, 5); // 5 second timeout
	if (!s)
		c->stop(c);

	sc_log(INFO, "stopped platform '%s'", c->name);

	// unref
	lxc_container_put(c);

	return NULL;
}


#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <libgen.h>
#include <unistd.h>

#include <lxc/lxccontainer.h>

#include "utils.h"
#include "loop.h"

#define MODULE_NAME             "lxc"
#define sc_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "lxc.h"

void *start_lxc_container(char *name, char *conf_file, void *data)
{
	struct lxc_container *c;
	char *dname;

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


#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <libgen.h>
#include <unistd.h>

#include <lxc/lxccontainer.h>

#include "loop.h"
#include "log.h"
#include "lxc.h"

void *start_lxc_container(char *name, char *conf_file, void *data)
{
	int err;
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
		printf("Failed to load rcfile");
		lxc_container_put(c);
		exit_error(errno, "Failed to start container");
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

	printf("SYSTEMC: Stopped platform '%s'\n", c->name);

	// unref
	lxc_container_put(c);

	return NULL;
}


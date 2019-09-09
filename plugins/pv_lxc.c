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
#include <fcntl.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <lxc/lxccontainer.h>
#include <lxc/pv_export.h>
#include <limits.h>
#include <unistd.h>
#include "utils.h"
#include "pv_lxc.h"
#include "utils/list.h"
#include <stdbool.h>
#include <limits.h>
#define LXC_LOG_DEFAULT_PREFIX	"/storage/logs/"

#ifndef free_member
#define free_member(ptr, member)\
({\
	if (ptr->member)\
		free((void*)ptr->member);\
})
#endif

static struct lxc_log pv_lxc_log = {
	.level = "DEBUG",
	.prefix = "init",
	.quiet = false
};
 
struct pv_log_info* (*__pv_new_log)(bool,const void*, const char*) = NULL;

void pv_set_new_log_fn( void *fn_pv_new_log)
{
	__pv_new_log = fn_pv_new_log;
}

static void pv_free_lxc_log(struct pv_log_info *pv_log_i)
{
	free_member(pv_log_i, name);
	free_member(pv_log_i, logfile);
}

static int pv_setup_lxc_log(	struct pv_log_info *pv_log_i,
				const char *plat_name,
				struct lxc_container *c,
				const char *key)
{
	char logfile[PATH_MAX] = {0};

	c->get_config_item(c, key, logfile, PATH_MAX);
	if (!strlen(logfile)) {
		if (!strcmp(key, "lxc.log.file")) {
			snprintf(logfile, sizeof(logfile), 
					LXC_LOG_DEFAULT_PREFIX"%s/%s_%s.log",
					plat_name,plat_name,key);
		} else {
			/*
			 * We've a console log but no console file
			 * specified.
			 * */
			pv_free_lxc_log(pv_log_i);
			return -1;
		}
	}
	pv_log_i->logfile = strdup(logfile);
	/*
	 * This is the default truncate size.
	 * Caller can change this before logging starts.
	 * */
	pv_log_i->truncate_size = (2 * 1024 * 1024);
	pv_log_i->on_logger_closed = pv_free_lxc_log;
	return 0;
}

static void pv_setup_lxc_container(struct lxc_container *c,
					unsigned int share_ns)
{
	int fd, ret;
	struct utsname uts;
	struct stat st;
	char tmp_cmd[] = "/tmp/cmdline-XXXXXX";
	char entry[1024];
	c->set_inherit_namespaces(c, 1, share_ns);
	c->want_daemonize(c, true);
	c->want_close_all_fds(c, true);
	c->set_config_item(c, "lxc.mount.entry", "/pv pantavisor"
						" none bind,ro,create=dir 0 0");
	c->set_config_item(c, "lxc.mount.entry", "/pv/logs pantavisor/logs"
						" none bind,ro,create=dir 0 0");
	if (stat("/lib/firmware", &st) == 0)
		c->set_config_item(c, "lxc.mount.entry", "/lib/firmware"
					" lib/firmware none bind,ro,create=dir"
					" 0 0");
	ret = uname(&uts);
	// FIXME: Implement modules volume and use that instead
	if (!ret) {
		if (stat("/volumes/modules.squashfs", &st) == 0) {
			sprintf(entry, "/volumes/modules.squashfs "
					"lib/modules/%s "
					"none bind,ro,create=dir 0 0",
					uts.release
				);
			c->set_config_item(c, "lxc.mount.entry", entry);
		}
	}
	// Strip consoles from kernel cmdline
	mktemp(tmp_cmd);
	fd = open("/proc/cmdline", O_RDONLY);
	if (fd > 0) {
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
		fd = open(tmp_cmd, O_CREAT | O_RDWR | O_SYNC, 0644);
		if (fd > 0)
			write(fd, new, strlen(new));
		close(fd);
		free(new);
		free(buf);
	}
	// override container=lxc environment of pid 1
	c->set_container_type(c, "pv-platform");
}

/*
 * Use only after loading config.
 * Use threshold as 0 to always truncate.
 * */
static void pv_truncate_lxc_log(struct lxc_container *c,
				const char *platform_name, off_t threshold,
				const char *key) {
	char *logfile_name = NULL;

	logfile_name = (char*)calloc(1, PATH_MAX);
	if (!logfile_name)
		return;

	c->get_config_item(c, key, logfile_name, PATH_MAX); 
	if (!strlen(logfile_name)) {
		/*
		 * /storage/logs is hardcoded in pv_lxc_log->lxcpath
		 * and used when lxc.log.file isn't set in lxc.conf of
		 * the container.
		 * */
		snprintf(logfile_name, PATH_MAX,
				LXC_LOG_DEFAULT_PREFIX"/%s/%s.log",
				platform_name, platform_name);
	}

	if (!threshold)
		truncate(logfile_name, 0);
	else {
		struct stat st;
		if (!stat(logfile_name, &st)) {
			if (st.st_size >= threshold)
				truncate(logfile_name, 0);
		}
	}
	free(logfile_name);
}

static struct pv_log_info*  pv_create_lxc_log(struct pv_platform *p,
				struct lxc_container *c,
				struct pv_logger_config *item_config)
{
	struct pv_log_info *pv_log_i = NULL;
	const char *log_key = NULL;
	char logger_name[128] = {0};
	const char *lxc_log_key [][2] = {
		{"lxc", "lxc.log.file"},
		{"console","lxc.console.logfile"},
	        {NULL, NULL}
	};
	int i = 0, j = 0;
	while (lxc_log_key[j][0]) {
		bool found = false;
		const char *key = lxc_log_key[j][0];
		i = 0;
		while (item_config->pair[i][0]) {
			if (!strncmp(item_config->pair[i][0], key,
						strlen(key))) {
				log_key = lxc_log_key[j][1];
				found = true;
				break;
			}
			i++;
		}
		if (found)
			break;
		j++;
	}

	if (!log_key) {
		printf("Configuration not for lxc/console log"
			" Skipping for %s.\n", __func__);
		goto out;
	}
	snprintf(logger_name, sizeof(logger_name), "%s-%s", p->name,
			(strstr("lxc.console", log_key) ? "console" : "lxc"));

	pv_log_i = __pv_new_log(true, item_config, logger_name);

	if (pv_log_i) {
		int ret = 
			pv_setup_lxc_log(pv_log_i, p->name, c, log_key);
		if (!ret) {
			pv_free_lxc_log(pv_log_i);
			free(pv_log_i);
			pv_log_i = NULL;
		}
	}
out:
	return pv_log_i;
}

void *pv_start_container(struct pv_platform *p, char *conf_file, void *data)
{
	int err;
	struct lxc_container *c;
	char *dname;
	int pipefd[2];
	struct pv_log_info *pv_log_i = NULL;
	unsigned short share_ns = (1 << LXC_NS_NET) | (1 << LXC_NS_UTS) 
					| (1 << LXC_NS_IPC);
	pid_t child_pid = -1;
	// Go to LXC config dir for platform
	dname = strdup(conf_file);
	dname = dirname(dname);
	chdir(dname);
	free(dname);
	// Make sure lxc state dir is there
	mkdir_p("/usr/var/lib/lxc", 0644);

	c = lxc_container_new(p->name, NULL);
	if (!c) {
		goto out_no_container;
	}
	c->clear_config(c);
	/*
	 * For returning back the
	 * container_pid to pv parent
	 * process.
	 * */
	if (pipe(pipefd)) {
		lxc_container_put(c);
		c = NULL;
		goto out_no_container;
	}

	child_pid = fork();

	if (child_pid < 0) {
		lxc_container_put(c);
		close(pipefd[0]);
		close(pipefd[1]);
		c = NULL;
		goto out_no_container;
	}
	else if (child_pid){ /*Parent*/
		pid_t container_pid = -1;
		close(pipefd[1]); /*Parent would read*/
		while (read(pipefd[0], &container_pid, 
				sizeof(container_pid)) < 0 && errno == EINTR)
			;

		if (container_pid <= 0) {
			lxc_container_put(c);
			c = NULL;
			goto out_no_container;
		}
		*((pid_t *) data) = container_pid;
		close(pipefd[0]);
	}
	else { /* Child process */
		close(pipefd[0]);
		*( (pid_t*) data) = -1;
		pv_lxc_log.name = p->name;
		pv_lxc_log.lxcpath = LXC_LOG_DEFAULT_PREFIX;
		lxc_log_init(&pv_lxc_log);
		c = lxc_container_new(p->name, NULL);

		if (!c) {
			goto out_container_init;
		}
		c->clear_config(c);
		/*
		 * Load config later which allows us to
		 * override the log file configured by default.
		 * */
		if (!c->load_config(c, conf_file)) {
			lxc_container_put(c);
			*((pid_t *) data) = -1;
			goto out_container_init;
		}

		pv_setup_lxc_container(c, share_ns);
		if (p->exec)
			c->set_config_item(c, "lxc.init.cmd", p->exec);
		err = c->start(c, 0, NULL) ? 0 : 1;

		if (err && (c->error_num != 1)) {
			lxc_container_put(c);
			c = NULL;
		}

		if (c)
			*((pid_t *) data) = c->init_pid(c);
out_container_init:
		while (write(pipefd[1], data, sizeof(pid_t)) < 0
				&& errno == EINTR)
			;
		_exit(0);
	}
	/*
	 * Parent loads the config after container is setup.
	 * This is just required to stop container and get
	 * any config items required in the parent.
	 * */
	if (!c->load_config(c, conf_file)) {
		pid_t *container_pid = (pid_t*)data;
		lxc_container_put(c);
		if (*container_pid > 0) {
			kill(*container_pid, SIGKILL);
		}
		c = NULL;
		goto out_no_container;
	}
	pv_setup_lxc_container(c, share_ns); /*Do we need this?*/

	if (__pv_new_log) {
		struct pv_logger_config *item_config, *tmp_config;
		struct dl_list *head = &p->logger_list;
		struct dl_list *config_head = &p->logger_configs;

		dl_list_for_each_safe(item_config, tmp_config,
				config_head, struct pv_logger_config,
				item_list) {
			/*
			 * Change pv_log_i->truncate_size here
			 * if required.
			 * */
			pv_log_i = pv_create_lxc_log(p, c,item_config);
			if (pv_log_i) {
				const char *truncate_item = 
					pv_log_i->pv_get_log_config_item(item_config,
							"maxsize");
				if (truncate_item) {
					sscanf(truncate_item, "%lld",
							&pv_log_i->truncate_size);	
				}
				/*
				 * Truncate the logs for now.
				 * platform will have information on when
				 * to truncate the logs.
				 * */

				if (pv_log_i->
						pv_get_log_config_item(item_config, "lxc"))
					pv_truncate_lxc_log(c, p->name,
							pv_log_i->truncate_size,
							"lxc.log.file");
				else if (pv_log_i->
						pv_get_log_config_item(item_config, "console"))
					pv_truncate_lxc_log(c, p->name,
							pv_log_i->truncate_size,
							"lxc.console.logfile");
				dl_list_add(head, &pv_log_i->next);
			}
			/*
			 * Free config items.
			 * */
			dl_list_del(&item_config->item_list);
			pv_free_logger_config(item_config);
		}
	}
out_no_container:
	return (void *) c;
}

// cannot fail if data is valid
void *pv_stop_container(struct pv_platform *p, char *conf_file, void *data)
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

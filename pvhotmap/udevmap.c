/*
 * Copyright (c) 2021 Pantacor Ltd.
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

#include <errno.h>
#include <fnmatch.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

#include <asm/types.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include "pvhotmap_parser.h"

#define ENV_BLOCKSIZE 64

enum uevent_op {
	ADD,
	BIND,
	CHANGE,
	REMOVE,
	UNBIND,
	UNDEFINED
};

struct uevent_kobject {
	enum uevent_op op;
	char *optarget;
	char **envv;
	int envc;
	int envs;
	int err;
};

struct udevmap_rule {
	/* what to execute and where */
	char *command;
	int command_ns;

	/* what uevent node to execute against */
	char **matches;
	int matches_cnt;

	/* what ancestor conditions to filter for */
	char **in_matches;
	int in_matches_cnt;
};

static pthread_mutex_t _mutex_in = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t _mutex_out = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t _cond_in = PTHREAD_COND_INITIALIZER;
static pthread_cond_t _cond_out = PTHREAD_COND_INITIALIZER;
static struct uevent_kobject *event_in = NULL;
static struct uevent_kobject *event_out = NULL;
static struct uevent_kobject *event_err = NULL;

static int len_rule_add, len_rule_rm;
static char** matches_add;

struct udevmap_rule rule_add = {
		.command = "mknod b %MAJOR% %MINOR% /dev/pv/%DEVNAME%",
		.matches_cnt = 1
};

char** matches_rm;
struct udevmap_rule rule_rm = {
		.command = "rm -f /dev/pv/%DEVNAME%",
		.matches_cnt = 1
};

struct udevmap_rule *global_rules[] = {
		&rule_add,
		&rule_rm,
		NULL
};

int process_rule(struct udevmap_rule *rule,
		struct uevent_kobject *event,
		struct uevent_kobject *ancestors[128]) {

	int rv;
	int is_fnm_match, f;
	char** matches = calloc(sizeof(char*), rule->matches_cnt);
	char** matches_p = matches;

	memcpy(matches_p, rule->matches, sizeof(char*) * rule->matches_cnt);

	f = 0;

	for(int x=0; x < rule->matches_cnt; x++) {
		is_fnm_match = 0;
		for (int j=0; j < event->envc; j++) {
//			printf("Matching: %s fn %s\n", matches_p[x], event->envv[j]);
			if (!fnmatch(matches_p[x], event->envv[j], FNM_PATHNAME)) {
				printf("Matching: %s fn %s x: %d j: %d\n", matches_p[x], event->envv[j], x, j);
				is_fnm_match = 1;
				break;
			}
		}
	}
	if (!is_fnm_match)
		f=1;
	//Increment matches_p?

	rv = -1;
//	printf("f: %d is_fnm_match: %d\n", f, is_fnm_match);
	if (!f) {
		printf("SUCCESS: %d\n", event->op);
		printf("SUCCESS: %s\n",event->optarget);
//		printf("%s\n", rule->command);
		rv = 0;
	}

	free(matches);
	return rv;
}

int process_event(struct udevmap_rule **rules, int rules_c, struct uevent_kobject *event)
{
	struct udevmap_rule **rules_p = rules;
	struct uevent_kobject *ancestors[128];
	memset(&ancestors, 0, sizeof(struct uevent_kobject *) * 128);

	if(!rules_p)
		return 0;

	while(*rules_p) {
		if (process_rule(*rules_p, event, ancestors) == 1)
			break;
		rules_p++;
	}
	return 0;
}

void* do_work(void *arg)
{
	int c;
	struct udevmap_rule **rules = arg;
	struct udevmap_rule **r = rules;

	// process counts and remember
	c=0;
	while (*r) {
		char **m = (*r)->matches;
		int mc=0;
		while (*m++) {
			mc++;
		}
		(*r)->matches_cnt = mc;

		char **im = (*r)->in_matches;
		int imc = 0;
		while (im && *im++) {
			imc++;
		}
		(*r)->in_matches_cnt = imc;
		c++; r++;
	}

	while (1) {
		int rv = 0;
		struct uevent_kobject *e = NULL;

		pthread_mutex_lock(&_mutex_in);
		while (!event_in)
			pthread_cond_wait(&_cond_in, &_mutex_in);

		e = event_in;
		pthread_mutex_unlock(&_mutex_in);

		rv = process_event(rules, c, e);

		pthread_mutex_lock(&_mutex_out);
		if (rv) {
			event_err = e;
			event_out = NULL;
		} else {
			event_err = NULL;
			event_out = e;
		}
		event_in = NULL;
		pthread_cond_signal(&_cond_out);
		pthread_mutex_unlock(&_mutex_out);
	}
	return NULL;
}

struct uevent_kobject* apply_event(struct uevent_kobject *event)
{
	struct uevent_kobject *out;
	pthread_mutex_lock(&_mutex_in);

	// wait for others already going through
	while (event_in) {
		pthread_cond_wait(&_cond_in, &_mutex_in);
	}

	event_in = event;

	pthread_cond_broadcast(&_cond_in);
	pthread_mutex_unlock(&_mutex_in);

	pthread_mutex_lock(&_mutex_out);
	// wait for others
	while (!event_out) {
		pthread_cond_wait(&_cond_out, &_mutex_out);
	}

	out = event_out;
	event_out = NULL;

	pthread_mutex_unlock(&_mutex_out);

	return out;
}

static int uevent_add_env(struct uevent_kobject* event, char *bufp)
{
	if(event->envc >= event->envs) {
		event->envs += ENV_BLOCKSIZE;
		event->envv = (char**) realloc(event->envv, event->envs * sizeof(char*));
		if (!event->envv) {
			printf("out of memory - failed to grow envv array.\n");
			event->envs -= ENV_BLOCKSIZE;
			event->err = 1;
			return -1;
		}
	}
	*(event->envv + event->envc) = strdup(bufp);
	event->envc++;
	return 0;
}

static int uevent_parse(struct uevent_kobject* event, char *bufp, int len)
{
	char *at_p = strchr(bufp, '@');
	char b;
	char *key, *value;
	int pc=0;

	b = *at_p;
	*at_p = 0;
	key = strdup(bufp);
	*at_p = b;
	value = strdup(at_p+1);
	pc = strlen(bufp);
	bufp += (pc+1);
	len -= (pc+1);
	if (!strcmp(key, "add"))
		event->op = ADD;
	else if (!strcmp(key, "bind"))
		event->op = BIND;
	else if (!strcmp(key, "change"))
		event->op = CHANGE;
	else if (!strcmp(key, "remove"))
		event->op = REMOVE;
	else if (!strcmp(key, "unbind"))
		event->op = UNBIND;
	else {
		printf ("unknown action: %s\n", key);
		if (key) free(key);
		if (value) free(value);
		return -1;
	}
	if (key) free(key);

	event->optarget = value;
	// lets add the envs
	while (len > 0) {
		pc = strlen(bufp);
		if ((at_p = strchr(bufp,'=')) == 0) {
			printf("nlmsg_buf is not a NAME=VALUE entry %s\n", bufp);
			break;
		}

		uevent_add_env(event, bufp);
		bufp += (pc+1);
		len -= (pc+1);
	}
	return 0;
}

static int generate_match_rule(void) {

	struct dl_list *head = NULL;
	struct _match *temp_p;
	/*
	 * add_counter: counter for keeping track for no. of "ACTION=add" action in linked list
	 * rm_counter: counter for keeping track for no. of "ACTION=remove" action in linked list
	 * s_action_itr: struct _match *action[2] array index iterator should only be only 0 or 1
	 * */
	int add_counter=0, rm_counter = 0;
	bool s_action_itr = 0;

	head = parse_rules_file();

	if(!head)
		return 0;

	len_rule_add = len_rule_rm = s_action_itr = 0;

	dl_list_for_each(temp_p, head, struct _match, next_match) {
		// iterate through linked list and compute the size of linked list to be used
		//later for allocating memory for match rules array matches_add[] and matches_rm[] individually
		if (!strcmp(temp_p->action[s_action_itr], "ACTION=add")) {
			//compute length of all add rules needed for allocating memory for *match_add[]
			len_rule_add += temp_p->devname_size + sizeof(char) + add_counter;
			add_counter++;
		}

		if (!strcmp(temp_p->action[s_action_itr], "ACTION=remove")) {
			//compute length of all remove rules needed for allocating memory for *match_rm[]
			len_rule_rm += temp_p->devname_size + sizeof(char) + rm_counter;
			rm_counter++;
		}
		s_action_itr ^= 1;
	}
	printf("LenRuleAdd: %d LenRuleRm: %d\n", len_rule_add, len_rule_rm);
	matches_add = calloc(len_rule_add, sizeof(char *));
	matches_rm = calloc(len_rule_rm, sizeof(char *));
	len_rule_add = len_rule_rm = s_action_itr = add_counter = rm_counter = 0;

	dl_list_for_each(temp_p, head, struct _match, next_match) {

		if (!strcmp(temp_p->action[s_action_itr], "ACTION=add")) {

			for(int i=0; i<temp_p->devname_size; i++) {
				matches_add[i+len_rule_add+add_counter] = calloc(1, strlen(temp_p->devname[i])+sizeof(char));
				memcpy(matches_add[i+len_rule_add+add_counter], temp_p->devname[i], strlen(temp_p->devname[i])+sizeof(char));
			}
			len_rule_add += temp_p->devname_size;

			if (!add_counter) {
				matches_add[s_action_itr+len_rule_add+add_counter] = calloc(1, strlen(temp_p->action[s_action_itr])+sizeof(char));
				strcpy(matches_add[s_action_itr+len_rule_add+add_counter], temp_p->action[s_action_itr]);
				add_counter++;
			}

			matches_add[s_action_itr+len_rule_add+add_counter] = calloc(1, strlen(temp_p->subsystem)+sizeof(char));
			strcpy(matches_add[s_action_itr+len_rule_add+add_counter], temp_p->subsystem);
			len_rule_add += s_action_itr+add_counter;

		}
		if (!strcmp(temp_p->action[s_action_itr], "ACTION=remove")) {
			for(int i=0; i<temp_p->devname_size; i++) {
				matches_rm[len_rule_rm+rm_counter+i] = calloc(1, strlen(temp_p->devname[i])+sizeof(char));
				strcpy(matches_rm[len_rule_rm+rm_counter+i], temp_p->devname[i]);
			}
			len_rule_rm += temp_p->devname_size;

			if(!rm_counter) {
				matches_rm[len_rule_rm+rm_counter] = calloc(1, strlen(temp_p->action[s_action_itr])+sizeof(char));
				strcpy(matches_rm[len_rule_rm+rm_counter], temp_p->action[s_action_itr]);
				rm_counter++;
			}

			matches_rm[len_rule_rm+rm_counter] = calloc(1, strlen(temp_p->subsystem)+sizeof(char));
			strcpy(matches_rm[len_rule_rm+rm_counter], temp_p->subsystem);

			len_rule_rm += rm_counter;
		}
		s_action_itr ^= 1;
	}
	matches_add[len_rule_add+1] = NULL;
	matches_rm[len_rule_rm+1] = NULL;
	rule_add.matches = matches_add;
	rule_rm.matches = matches_rm;

	return 0;
}
int main()
{
	struct sockaddr_nl sa;
	int fd;
	pthread_t thread_id;
	pthread_attr_t thread_attr;
	int rv;

	generate_match_rule();

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_pid = getpid();
	sa.nl_groups = -1;

	rv = pthread_attr_init(&thread_attr);
	if(rv) {
		printf("ERROR pthread_attr_init: %s\n", strerror(errno));
		return 1;
	}
	rv = pthread_create(&thread_id, &thread_attr, do_work, global_rules);
	if(rv) {
		printf("ERROR phtread_create: %s\n", strerror(errno));
		return 2;
	}

	fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
	bind(fd, (struct sockaddr *) &sa, sizeof(sa));

	int len;
	char buf[8192];

	while (1) {
		len = recv(fd, buf, sizeof(buf), 0);
		char *bufp = (char*) buf;
		struct uevent_kobject event;
		if (!strncmp(bufp, "libudev", strlen("libudev")))
			continue;

		if (len <= 0) {
			printf("empty netlink message received ...\n");
			continue;
		}
		memset(&event, 0, sizeof(event));
		uevent_parse(&event, bufp, len);
		apply_event(&event);
	}
	return 0;
}

#include <errno.h>
#include <fnmatch.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <asm/types.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include "json-parser.h"

#define ENV_BLOCKSIZE 64

#define GENERATE_ENUM(ENUM) ENUM,
#define GENERATE_STRING(STRING) #STRING,

#define FOREACH_UEVENT_OP(UEVENT_OP)	\
        UEVENT_OP(ADD)	\
        UEVENT_OP(BIND)	\
        UEVENT_OP(CHANGE)	\
        UEVENT_OP(REMOVE)	\
		UEVENT_OP(UNBIND)	\
		UEVENT_OP(UNDEFINED)	\

static const char *UEVENT_STRING[] = {
    FOREACH_UEVENT_OP(GENERATE_STRING)
};


enum uevent_op {
	FOREACH_UEVENT_OP(GENERATE_ENUM)
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
	char** matches;
	int matches_c;

	/* what ancestor conditions to filter for */
	char **in_matches;
	int in_matches_c;
};

static pthread_mutex_t _mutex_in = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t _mutex_out = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t _cond_in = PTHREAD_COND_INITIALIZER;
static pthread_cond_t _cond_out = PTHREAD_COND_INITIALIZER;
static struct uevent_kobject *event_in = NULL;
static struct uevent_kobject *event_out = NULL;
static struct uevent_kobject *event_err = NULL;
int len_rule_a, len_rule_r;

int process_rule(struct udevmap_rule *rule,
		 struct uevent_kobject *event,
		 struct uevent_kobject *ancestors[128]) {

	int c, b, f, rv;
	char** matches = malloc(sizeof(char*) * rule->matches_c);
	char** matches_p = matches;

	memcpy(matches_p, rule->matches, sizeof(char*) * rule->matches_c);

//	for(int z=0; z<=len_rule_a; z++) {
//		printf("%d %s\n",z, matches_p[z]);
//	}

	c = 0;
	f = 0;
	
	while (matches_p[c]) {
		for(int x=0; x <= len_rule_a; x++) {
			b = 0;
			for (int j=0; j < event->envc; j++) {
//				printf("Matching: %s fn %s\n", matches_p[x], event->envv[j]);
				if (!fnmatch(matches_p[x], event->envv[j], FNM_PATHNAME)) {
//					*matches = NULL;
//					memmove (matches_p, matches_p+1, sizeof(char*) * (rule->matches_c - c - 1));
					b = 1;
					break;
				}
			}
		}
		if (!b) {
			f=1;
			break;
		}
		c++;
//		matches_p++;
	}

	rv = -1;
	if (!f) {
		printf("SUCCESS: %s\n", UEVENT_STRING[event->op]);
		printf("SUCCESS: %s\n",event->optarget);
//		for (int ii=0; ii < event->envc; ii++) {
//			printf("SUCCESS: %s\n",event->envv[ii]);
//		}
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
		if (process_rule(*rules_p, event, ancestors) == 1) {
			break;
		}
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
		(*r)->matches_c = mc;

		char **im = (*r)->in_matches;
		int imc = 0;
		while (im && *im++) {
			imc++;
		}
		(*r)->in_matches_c = imc;
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

	if (!strcmp(key, "add")) {
		event->op = ADD;
	} else if (!strcmp(key, "bind")) {
		event->op = BIND;
	} else if (!strcmp(key, "change")) {
		event->op = CHANGE;
	} else if (!strcmp(key, "remove")) {
		event->op = REMOVE;
	} else if (!strcmp(key, "unbind")) {
		event->op = UNBIND;
	} else {
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


char* matches1a[50] =  {};
struct udevmap_rule rule_1a = {
		.command = "mknod b %MAJOR% %MINOR% /dev/pv/%DEVNAME%",
		.matches = matches1a,
		.matches_c = 1
};

char* matches1r[50] =  {};
struct udevmap_rule rule_1r = {
		.command = "rm -f /dev/pv/%DEVNAME%",
		.matches = matches1r,
		.matches_c = 1
};

const char* matches2a[] =  { "ACTION=add", "DEVNAME=ttyU*", NULL };
struct udevmap_rule rule_2a = {
		.command = "mknod c %MAJOR% %MINOR% /dev/pv/%DEVNAME%",
		.matches = matches2a,
		.matches_c = 1
};

const char* matches2r[] =  { "ACTION=remove", "DEVNAME=ttyU*", NULL };
struct udevmap_rule rule_2r = {
		.command = "mknod c %MAJOR% %MINOR% /dev/pv/%DEVNAME%",
		.matches = matches2r,
		.matches_c = 1
};

struct udevmap_rule *global_rules[] = {
	&rule_1a,
	&rule_1r,
	NULL
};

int main()
{
	struct sockaddr_nl sa;
	int fd;
	pthread_t thread_id;
	pthread_attr_t thread_attr;
	int rv, itr=0, idx=0;
	struct dl_list *match_p = NULL;
	match *t;

	match_p = parse_json();
	if(match_p != NULL) {
		len_rule_a = len_rule_r = idx = itr = 0;
		dl_list_for_each(t, match_p, struct _match, next_match) {
			int j = sizeof(t->action)/sizeof(*t->action);
			for(int itr=0; itr<j; itr++) {
				if (!strcmp(t->action[itr], "add")) {
					matches1a[idx+len_rule_a] = malloc(strlen("ACTION=")+strlen(t->action[itr])+sizeof(char));
					strcpy(matches1a[idx+len_rule_a], "ACTION=");
					strcat(matches1a[idx+len_rule_a], t->action[itr]);
					printf("%p matches1a[%d]: %s\n", &matches1a[(idx+len_rule_a)], (idx+len_rule_a), matches1a[idx+len_rule_a]);
					for(int i=0; i<t->devname_size; i++) {
						matches1a[1+i+idx+len_rule_a] = malloc(strlen("DEVNAME=")+strlen(t->devname[i])+sizeof(char));
						strcpy(matches1a[1+i+idx+len_rule_a], "DEVNAME=");
						strcat(matches1a[1+i+idx+len_rule_a], t->devname[i]);
						printf("%p matches1a[%d]: %s\n", &matches1a[(1+i+idx+len_rule_a)], (1+i+idx+len_rule_a), matches1a[1+i+idx+len_rule_a]);
					}
					matches1a[1+t->devname_size+idx+len_rule_a] = malloc(strlen("SUBSYSTEM=")+strlen(t->subsystem)+sizeof(char));
					strcpy(matches1a[1+t->devname_size+idx+len_rule_a], "SUBSYSTEM=");
					strcat(matches1a[1+t->devname_size+idx+len_rule_a], t->subsystem);
					printf("%p matches1a[%d]: %s\n",&matches1a[(1+t->devname_size+idx+len_rule_a)], (1+t->devname_size+idx+len_rule_a), matches1a[1+t->devname_size+idx+len_rule_a]);
					printf("Len: matches1a[%d]\n", (1+t->devname_size+idx+len_rule_a));
					len_rule_a = (1+t->devname_size+idx+len_rule_a);
				}
				if (!strcmp(t->action[itr], "remove")) {
					matches1r[idx+len_rule_r] = malloc(strlen("ACTION=")+strlen(t->action[itr])+sizeof(char));
					strcpy(matches1r[idx+len_rule_r], "ACTION=");
					strcat(matches1r[idx+len_rule_r], t->action[itr]);
					printf("%p matches1r[%d]: %s\n", &matches1r[(idx+len_rule_r)], idx+len_rule_r, matches1r[idx+len_rule_r]);
					for(int i=0; i<t->devname_size; i++) {
						matches1r[1+i+idx+len_rule_r] = malloc(strlen("DEVNAME=")+strlen(t->devname[i])+sizeof(char));
						strcpy(matches1r[1+i+idx+len_rule_r], "DEVNAME=");
						strcat(matches1r[1+i+idx+len_rule_r], t->devname[i]);
						printf("%p matches1r[%d]: %s\n", &matches1r[(1+i+idx+len_rule_r)], (1+i+idx+len_rule_r), matches1r[1+i+idx+len_rule_r]);
					}
					matches1r[1+t->devname_size+idx+len_rule_r] = malloc(strlen("SUBSYSTEM=")+strlen(t->subsystem)+sizeof(char));
					strcpy(matches1r[1+t->devname_size+idx+len_rule_r], "SUBSYSTEM=");
					strcat(matches1r[1+t->devname_size+idx+len_rule_r], t->subsystem);
					printf("%p matches1r[%d]: %s\n", &matches1r[(1+t->devname_size+idx+len_rule_r)], (1+t->devname_size+idx+len_rule_r), matches1r[1+t->devname_size+idx+len_rule_r]);
					printf("Len: matches1r[%d]\n", 1+t->devname_size+idx+len_rule_r);
					len_rule_r = (1+t->devname_size+idx+len_rule_r);
				}
			}
			idx++;
		}
		matches1a[len_rule_a+1] = NULL;
		matches1r[len_rule_r+1] = NULL;
	}
//	printf("length: %d %d\n", len_rule_a, len_rule_r);
//	for(int i=0; i<=len_rule_a; i++) {
//		printf("%p matches1a[%d]: %s\n",&matches1a[i], i, matches1a[i]);
//	}
//	printf("\n");
//	for(int i=0; i<=len_rule_r; i++) {
//		printf("matches1r[%d]: %s\n",i, matches1r[i]);
//	}

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

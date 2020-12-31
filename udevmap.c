
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <asm/types.h>
#include <linux/netlink.h>
#include <sys/socket.h>

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

	char **matches;
	int matches_c;
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
static int doexit = 0;

int process_event(struct uevent_kobject *event)
{
	printf("processing event!\n");
	return 0;
}

void* do_work(void *arg)
{
	while (1) {
		int rv = 0;
		struct uevent_kobject *e = NULL;

		pthread_mutex_lock(&_mutex_in);
		while (!event_in)
			pthread_cond_wait(&_cond_in, &_mutex_in);
	
		e = event_in;
		pthread_mutex_unlock(&_mutex_in);

		rv = process_event(event_in);

		pthread_mutex_lock(&_mutex_out);
		if (rv) {
			event_err = event_in;
			event_out = NULL;
		} else {
			event_err = NULL;
			event_out = event_in;
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

int main()
{
	struct sockaddr_nl sa;
	int fd;
	pthread_t thread_id;
	pthread_attr_t thread_attr;
	int rv;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_pid = getpid();
	sa.nl_groups = -1;

	rv = pthread_attr_init(&thread_attr);
	if(rv) {
		printf("ERROR pthread_attr_init: %s\n", strerror(errno));
		return 1;
	}
	rv = pthread_create(&thread_id, &thread_attr, do_work, NULL);
	if(rv) {
		printf("ERROR phtread_create: %s\n", strerror(errno));
		return 2;
	}

	fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
	bind(fd, (struct sockaddr *) &sa, sizeof(sa));

	int len;
	char buf[8192];
	struct nlmsghdr *nh;

	while (1) {
		int pc=0;
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

		char *at_p = strchr(bufp, '@');
		char b;
		char *key, *value;
		b = *at_p;
		*at_p = 0;
		key = strdup(bufp);
		*at_p = b;
		value = strdup(at_p+1);
		pc = strlen(bufp);
		bufp += (pc+1);
		len -= (pc+1);

		if (!strcmp(key, "add")) {
			event.op = ADD;
		} else if (!strcmp(key, "bind")) {
			event.op = BIND;
		} else if (!strcmp(key, "change")) {
			event.op = CHANGE;
		} else if (!strcmp(key, "remove")) {
			event.op = REMOVE;
		} else if (!strcmp(key, "unbind")) {
			event.op = UNBIND;
		} else {
			printf ("unknown action: %s\n", key);
			if (key) free(key);
			if (value) free(value);
			continue;
		}
		if (key) free(key);

		event.optarget = value;

		// lets add the envs
		while (len > 0) {
			pc = strlen(bufp);
			if ((at_p = strchr(bufp,'=')) == 0) {
				printf("nlmsg_buf is not a NAME=VALUE entry %s\n", bufp);
				break;
			}
			pc = strlen(bufp);
			bufp += (pc+1);
			len -= (pc+1);

			if(event.envc >= event.envs) {
				event.envs += ENV_BLOCKSIZE;
				event.envv = (char**) realloc(event.envv, event.envs * sizeof(char*));
				if (!event.envv) {
					printf("out of memory - failed to grow envv array.\n");
					event.envs -= ENV_BLOCKSIZE;
					event.err = 1;
					break;
				}
			}
			*(event.envv + event.envc) = strdup(bufp);
			event.envc++;
		}
		apply_event(&event);
	}
	return 0;
}

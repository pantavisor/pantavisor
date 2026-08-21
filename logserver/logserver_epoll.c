#include "logserver_epoll.h"

#include <errno.h>

static int logserver_epoll_command(int epfd, int fd, int cmd)
{
	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLRDHUP,
		.data.fd = fd,
	};

	errno = 0;
	return epoll_ctl(epfd, cmd, fd, &ev);
}

int logserver_epoll_add(int epfd, int fd)
{
	return logserver_epoll_command(epfd, fd, EPOLL_CTL_ADD);
}

int logserver_epoll_del(int epfd, int fd)
{
	return logserver_epoll_command(epfd, fd, EPOLL_CTL_DEL);
}

int logserver_epoll_wait(int epfd, struct epoll_event *ev, int max)
{
	int ready = 0;
	errno = 0;
	do {
		ready = epoll_wait(epfd, ev, max, -1);
		if (errno != 0 && errno != EINTR)
			return 0;
	} while (ready < 0);

	return ready;
}

int logserver_epoll_create(void)
{
	return epoll_create1(0);
}

/*
 * Copyright (c) 2019 Pantacor Ltd.
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

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/if.h>
#include <linux/sockios.h>

#define MODULE_NAME		"network"
#define pv_log(level, msg, ...)		vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "utils.h"
#include "pantahub.h"
#include "network.h"
#include "init.h"

#define ifreq_offsetof(x)  offsetof(struct ifreq, x)

#define IFACES_FMT "{\"interfaces\":{"
#define IFACE_FMT "\"%s\":[%s]"

static int _set_netmask(int skfd, char *intf, char *newmask)
{
	struct ifreq ifr;
	unsigned int dst;
	struct sockaddr_in *sin = (struct sockaddr_in *) &ifr.ifr_addr;
	memset(&ifr, 0, sizeof(ifr));
	sin->sin_family = AF_INET;
	if (!inet_pton(AF_INET, newmask, &sin->sin_addr)) {
		return -1;
	}
	strncpy(ifr.ifr_name, intf, IFNAMSIZ-1);
	if (ioctl(skfd,SIOCSIFNETMASK,&ifr) == -1) {
		return -1;
	}
	return 0;
}

static int pv_network_init(struct pantavisor *pv)
{
	int fd, ret;
	struct pantavisor_config *c;
	struct ifreq ifr;
	struct sockaddr_in sai;
	int sockfd;                     /* socket fd we use to manipulate stuff with */
	char *p;

	if (!pv)
		return -1;

	memset(&ifr, 0, sizeof(ifr));

	c = pv->config;
	if (!c->net.brdev)
		return -1;

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		pv_log(WARN, "unable to setup network ops socket");
		return -1;
	}

	ret = ioctl(fd, SIOCBRADDBR, c->net.brdev);
	if (ret < 0) {
		pv_log(WARN, "unable to create bridge dev %s: %s",
		       c->net.brdev, strerror(errno));
	}


	/* Create a channel to the NET kernel. */
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	/* get interface name */
	strncpy(ifr.ifr_name, c->net.brdev, IFNAMSIZ);

	ret = ioctl(sockfd, SIOCGIFFLAGS, &ifr);
	if (ret < 0) {
		pv_log(WARN, "unable to get flags for bridge dev %s: %s",
		       c->net.brdev, strerror(errno));
		goto out;
	}

	ifr.ifr_flags |= IFF_UP;
	ifr.ifr_flags |= IFF_RUNNING;
        ret = ioctl(sockfd, SIOCSIFFLAGS, &ifr);
	if (ret < 0) {
		pv_log(WARN, "unable to update flags for bridge dev %s: %s",
		       c->net.brdev, strerror(errno));
		goto out;
	}

        memset(&sai, 0, sizeof(struct sockaddr));
        sai.sin_family = AF_INET;
        sai.sin_port = 0;

        sai.sin_addr.s_addr = inet_addr(c->net.braddress4);

        p = (char *) &sai;
        memcpy( (((char *)&ifr + ifreq_offsetof(ifr_addr) )),
		p, sizeof(struct sockaddr));

        ret = ioctl(sockfd, SIOCSIFADDR, &ifr);
	if (ret < 0) {
		pv_log(WARN, "unable to set IPv4 of bridge dev %s to %s: %s",
		       c->net.brdev, c->net.braddress4, strerror(errno));
		goto out;
	}

	ret = _set_netmask(sockfd, c->net.brdev, c->net.brmask4);
	if (ret < 0) {
		pv_log(WARN, "unable to set netmask %s: %s",
		       c->net.brdev, strerror(errno));
		goto out;
	}

 out:
        close(sockfd);

	return ret;
}

int pv_network_update_meta(struct pantavisor *pv)
{
	struct ifaddrs *ifaddr, *ifa;
	int family, s, n, len, ilen = 0;
	char host[NI_MAXHOST], ifn[IFNAMSIZ+5], iff[IFNAMSIZ+5];
	char *t, *buf, *ifaces = 0, *ifaddrs = 0;

	if (getifaddrs(&ifaddr) < 0) {
		pv_log(DEBUG, "error calling getifaddrs()");
		return -1;
	}

	len = sizeof(IFACES_FMT);
	ifaces = strdup(IFACES_FMT);

	for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
		if (ifa->ifa_addr == NULL)
			continue;

		family = ifa->ifa_addr->sa_family;
		if (family == AF_PACKET)
			continue;

		s = getnameinfo(ifa->ifa_addr,
			(family == AF_INET) ? sizeof(struct sockaddr_in) :
					      sizeof(struct sockaddr_in6),
			host, NI_MAXHOST,
			NULL, 0, NI_NUMERICHOST);

		sprintf(iff, "%s.%s", ifa->ifa_name, family == AF_INET ? "ipv4" : "ipv6");
		if (!strcmp(ifn, iff)) {
			ilen += strlen(host) + 4;
			ifaddrs = realloc(ifaddrs, ilen);
			t = strdup(ifaddrs);
			sprintf(ifaddrs, "%s,\"%s\"", t, host);
			free(t);
		} else {
			sprintf(ifn, "%s.%s", ifa->ifa_name, family == AF_INET ? "ipv4" : "ipv6");
			ilen = 0;
			ilen += strlen(host) + 4;
			ifaddrs = realloc(ifaddrs, ilen);
			sprintf(ifaddrs, "\"%s\"", host);
		}
		if (ifa->ifa_next != NULL) {
			sprintf(iff, "%s.%s", ifa->ifa_next->ifa_name,
				ifa->ifa_next->ifa_addr->sa_family == AF_INET ? "ipv4" : "ipv6");
			if (!strcmp(ifn, iff))
				continue;
		}

		sprintf(ifn, "%s.%s", ifa->ifa_name, family == AF_INET ? "ipv4" : "ipv6");
		buf = calloc(1, sizeof(IFACE_FMT) + strlen(ifn) + strlen(ifaddrs));
		len += sprintf(buf, IFACE_FMT, ifn, ifaddrs);
		len++;
		ifaces = realloc(ifaces, len);
		strcat(ifaces, buf);
		free(buf);
		if (ifa->ifa_next != NULL)
			strcat(ifaces, ",");
	}
	free(ifaddrs);

	ifaces = realloc(ifaces, len + 2);
	strcat(ifaces, "}}");

	// upload to cloud
	pv_ph_upload_metadata(pv, ifaces);

	freeifaddrs(ifaddr);
	free(ifaces);

	return 0;
}

static int pv_network_early_init(struct pv_init *this)
{
	struct pantavisor *pv = NULL;

	pv = get_pv_instance();
	if (!pv || !pv->config)
		return 0;
	pv_network_init(pv);
	return 0;
}

struct pv_init pv_init_network = {
	.init_fn = pv_network_early_init,
	.flags = PV_INIT_FLAG_CANFAIL,
};

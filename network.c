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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>

#include <netinet/in.h>

#include <sys/ioctl.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#include <linux/if.h>
#include <linux/sockios.h>

#include "pantahub.h"
#include "network.h"
#include "init.h"
#include "metadata.h"
#include "utils/str.h"

#define MODULE_NAME		"network"
#define pv_log(level, msg, ...)		vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#define ifreq_offsetof(x)  offsetof(struct ifreq, x)

#define IFACES_FMT "{"
#define IFACE_FMT "\"%s\":[%s]"

static int _set_netmask(int skfd, char *intf, char *newmask)
{
	struct ifreq ifr;
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

void pv_network_update_meta(struct pantavisor *pv)
{
	struct ifaddrs *ifaddr, *ifa;
	int family, s, n, len, ilen = 0;
	int size;
	char host[NI_MAXHOST], ifn[IFNAMSIZ+5], iff[IFNAMSIZ+5];
	char *t, *buf, *ifaces = 0, *ifaddrs = 0;

	if (getifaddrs(&ifaddr) < 0) {
		pv_log(DEBUG, "error calling getifaddrs()");
		return;
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

		SNPRINTF_WTRUNC(iff, sizeof (iff), "%s.%s", ifa->ifa_name, family == AF_INET ? "ipv4" : "ipv6");
		if (!strcmp(ifn, iff)) {
			ilen += strlen(host) + 4;
			ifaddrs = realloc(ifaddrs, ilen);
			t = strdup(ifaddrs);
			SNPRINTF_WTRUNC(ifaddrs, ilen, "%s,\"%s\"", t, host);
			free(t);
		} else {
			SNPRINTF_WTRUNC(ifn, sizeof (ifn), "%s.%s", ifa->ifa_name, family == AF_INET ? "ipv4" : "ipv6");
			ilen = 0;
			ilen += strlen(host) + 4;
			ifaddrs = realloc(ifaddrs, ilen);
			SNPRINTF_WTRUNC(ifaddrs, ilen, "\"%s\"", host);
		}
		if (ifa->ifa_next != NULL) {
			SNPRINTF_WTRUNC(iff, sizeof (iff),
					"%s.%s", ifa->ifa_next->ifa_name,
					ifa->ifa_next->ifa_addr->sa_family == AF_INET ? "ip4" : "ipv6");

			if (!strncmp(ifn, iff, sizeof (ifn)))
				continue;
		}

		SNPRINTF_WTRUNC(ifn, sizeof (ifn), "%s.%s", ifa->ifa_name, family == AF_INET ? "ipv4" : "ipv6");
		size = sizeof(IFACE_FMT) + strlen(ifn) + strlen(ifaddrs);
		buf = calloc(sizeof (char), size);
		len += snprintf(buf, size, IFACE_FMT, ifn, ifaddrs);
		len++;
		ifaces = realloc(ifaces, len);
		strcat(ifaces, buf);
		free(buf);
		if (ifa->ifa_next != NULL)
			strcat(ifaces, ",");
	}
	free(ifaddrs);

	ifaces = realloc(ifaces, len + 1);
	strcat(ifaces, "}");

	pv_metadata_add_devmeta(DEVMETA_KEY_INTERFACES, ifaces);

	freeifaddrs(ifaddr);
	free(ifaces);
}

static int pv_network_early_init(struct pv_init *this)
{
	int fd, ret;
	struct ifreq ifr;
	struct sockaddr_in sai;
	int sockfd;                     /* socket fd we use to manipulate stuff with */
	char *p;

	memset(&ifr, 0, sizeof(ifr));

	if (!pv_config_get_network_brdev())
		return -1;

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		pv_log(WARN, "unable to setup network ops socket");
		return -1;
	}

	ret = ioctl(fd, SIOCBRADDBR, pv_config_get_network_brdev());
	if (ret < 0) {
		pv_log(WARN, "unable to create bridge dev %s: %s",
		       pv_config_get_network_brdev(), strerror(errno));
	}


	/* Create a channel to the NET kernel. */
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	/* get interface name */
	memcpy(ifr.ifr_name, pv_config_get_network_brdev(), IFNAMSIZ);

	ret = ioctl(sockfd, SIOCGIFFLAGS, &ifr);
	if (ret < 0) {
		pv_log(WARN, "unable to get flags for bridge dev %s: %s",
		       pv_config_get_network_brdev(), strerror(errno));
		goto out;
	}

	ifr.ifr_flags |= IFF_UP;
	ifr.ifr_flags |= IFF_RUNNING;
        ret = ioctl(sockfd, SIOCSIFFLAGS, &ifr);
	if (ret < 0) {
		pv_log(WARN, "unable to update flags for bridge dev %s: %s",
		       pv_config_get_network_brdev(), strerror(errno));
		goto out;
	}

        memset(&sai, 0, sizeof(struct sockaddr));
        sai.sin_family = AF_INET;
        sai.sin_port = 0;

        sai.sin_addr.s_addr = inet_addr(pv_config_get_network_braddress4());

        p = (char *) &sai;
        memcpy( (((char *)&ifr + ifreq_offsetof(ifr_addr) )),
		p, sizeof(struct sockaddr));

        ret = ioctl(sockfd, SIOCSIFADDR, &ifr);
	if (ret < 0) {
		pv_log(WARN, "unable to set IPv4 of bridge dev %s to %s: %s",
		       pv_config_get_network_brdev(), pv_config_get_network_braddress4(), strerror(errno));
		goto out;
	}

	ret = _set_netmask(sockfd, pv_config_get_network_brdev(), pv_config_get_network_brmask4());
	if (ret < 0) {
		pv_log(WARN, "unable to set netmask %s: %s",
		       pv_config_get_network_brdev(), strerror(errno));
		goto out;
	}

 out:
        close(sockfd);

	return ret;
}

struct pv_init pv_init_network = {
	.init_fn = pv_network_early_init,
	.flags = PV_INIT_FLAG_CANFAIL,
};

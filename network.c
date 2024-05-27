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

#include <jsmn/jsmnutil.h>

#include "pantahub.h"
#include "network.h"
#include "init.h"
#include "metadata.h"
#include "utils/str.h"
#include "utils/json.h"
#include "utils/list.h"

#define MODULE_NAME "network"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define ifreq_offsetof(x) offsetof(struct ifreq, x)

// max len of iface + .ipvN + '\0'
#define IFACE_KEY_SIZE IFNAMSIZ + 5 + 1

static int _set_netmask(int skfd, const char *intf, char *newmask)
{
	struct ifreq ifr;
	struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
	memset(&ifr, 0, sizeof(ifr));
	sin->sin_family = AF_INET;
	if (!inet_pton(AF_INET, newmask, &sin->sin_addr)) {
		return -1;
	}
	strncpy(ifr.ifr_name, intf, IFNAMSIZ - 1);
	if (ioctl(skfd, SIOCSIFNETMASK, &ifr) == -1) {
		return -1;
	}
	return 0;
}

static struct ifaddrs *_get_sort_ifaces(void)
{
	struct ifaddrs *iface = NULL;

	if (getifaddrs(&iface) < 0) {
		pv_log(DEBUG, "error calling getifaddrs()");
		return NULL;
	}

	struct ifaddrs *com = iface;
	struct ifaddrs *cur = iface;

	while (com) {
		if (!cur->ifa_next ||
		    strcmp(com->ifa_name, cur->ifa_next->ifa_name)) {
			cur = cur->ifa_next;
			if (!cur) {
				com = com->ifa_next;
				cur = com;
			}
		} else if (!strcmp(com->ifa_name, cur->ifa_next->ifa_name)) {
			if (com == cur) {
				com = com->ifa_next;
				cur = cur->ifa_next;
			} else {
				struct ifaddrs *tmp = com->ifa_next;
				com->ifa_next = cur->ifa_next;
				cur->ifa_next = cur->ifa_next->ifa_next;
				com = com->ifa_next;
				com->ifa_next = tmp;
				cur = com;
			}
		}
	}

	return iface;
}

void pv_network_update_meta(struct pantavisor *pv)
{
	struct ifaddrs *ifaddr = _get_sort_ifaces();

	struct pv_json_ser js;
	pv_json_ser_init(&js, 512);
	pv_json_ser_object(&js);

	char last[IFACE_KEY_SIZE] = { 0 };
	char cur[IFACE_KEY_SIZE] = { 0 };
	char host[NI_MAXHOST] = { 0 };

	for (struct ifaddrs *ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr)
			continue;

		char *family = NULL;
		size_t size = 0;
		if (ifa->ifa_addr->sa_family == AF_PACKET) {
			continue;
		} else if (ifa->ifa_addr->sa_family == AF_INET) {
			family = "ipv4";
			size = sizeof(struct sockaddr_in);
		} else {
			family = "ipv6";
			size = sizeof(struct sockaddr_in6);
		}

		getnameinfo(ifa->ifa_addr, size, host, NI_MAXHOST, NULL, 0,
			    NI_NUMERICHOST);

		snprintf(cur, IFACE_KEY_SIZE, "%s.%s", ifa->ifa_name, family);
		if (strncmp(cur, last, IFACE_KEY_SIZE)) {
			if (strlen(last) > 0)
				pv_json_ser_array_pop(&js);

			strncpy(last, cur, IFACE_KEY_SIZE);
			pv_json_ser_key(&js, last);
			pv_json_ser_array(&js);
		}
		pv_json_ser_string(&js, host);
	}
	pv_json_ser_array_pop(&js);
	pv_json_ser_object_pop(&js);

	char *str = pv_json_ser_str(&js);
	pv_metadata_add_devmeta(DEVMETA_KEY_INTERFACES, str);

	freeifaddrs(ifaddr);
	free(str);
}

static int pv_network_early_init(struct pv_init *this)
{
	int fd, ret;
	struct ifreq ifr;
	struct sockaddr_in sai;
	int sockfd; /* socket fd we use to manipulate stuff with */
	char *p;

	memset(&ifr, 0, sizeof(ifr));

	const char *brdev = pv_config_get_str(PV_NET_BRDEV);
	if (!brdev)
		return -1;

	const char *braddress4 = pv_config_get_str(PV_NET_BRADDRESS4);

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		pv_log(WARN, "unable to setup network ops socket");
		return -1;
	}

	ret = ioctl(fd, SIOCBRADDBR, brdev);
	if (ret < 0) {
		pv_log(WARN, "unable to create bridge dev %s: %s", brdev,
		       strerror(errno));
	}

	/* Create a channel to the NET kernel. */
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	/* get interface name */
	memcpy(ifr.ifr_name, brdev, IFNAMSIZ);

	ret = ioctl(sockfd, SIOCGIFFLAGS, &ifr);
	if (ret < 0) {
		pv_log(WARN, "unable to get flags for bridge dev %s: %s", brdev,
		       strerror(errno));
		goto out;
	}

	ifr.ifr_flags |= IFF_UP;
	ifr.ifr_flags |= IFF_RUNNING;
	ret = ioctl(sockfd, SIOCSIFFLAGS, &ifr);
	if (ret < 0) {
		pv_log(WARN, "unable to update flags for bridge dev %s: %s",
		       brdev, strerror(errno));
		goto out;
	}

	memset(&sai, 0, sizeof(struct sockaddr));
	sai.sin_family = AF_INET;
	sai.sin_port = 0;

	sai.sin_addr.s_addr = inet_addr(braddress4);

	p = (char *)&sai;
	memcpy((((char *)&ifr + ifreq_offsetof(ifr_addr))), p,
	       sizeof(struct sockaddr));

	ret = ioctl(sockfd, SIOCSIFADDR, &ifr);
	if (ret < 0) {
		pv_log(WARN, "unable to set IPv4 of bridge dev %s to %s: %s",
		       brdev, braddress4, strerror(errno));
		goto out;
	}

	ret = _set_netmask(sockfd, brdev, pv_config_get_str(PV_NET_BRMASK4));
	if (ret < 0) {
		pv_log(WARN, "unable to set netmask %s: %s", brdev,
		       strerror(errno));
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

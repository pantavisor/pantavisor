/*
 * Copyright (c) 2026 Pantacor Ltd.
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
//
// pvx_services nft table
// ----------------------
//
// Owns the `ip pvx_services` nftables table. We keep this STRICTLY
// separate from IPAM's `pvipam` table so we never trip over each other's
// rules during reload, flush, or teardown. Same rationale as the IPAM
// setup_nat() function (ipam.c) and same nft/iptables fallback shape.
//
// Layout:
//   table ip pvx_services {
//     chain prerouting { type nat hook prerouting priority dstnat; }
//   }
// Per established Tier-1 link, we install one rule:
//   ip daddr <ClusterIP> <proto> dport <svc-port> dnat to <backend-ip>:<port>
//
// Tier-2 (userspace proxy) does NOT use this table — those services bind
// the ClusterIP directly on the pv-services bridge.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "include/xconnect.h"
#include "services_nft.h"

static int g_have_nft = -1;
static int g_have_iptables = -1;

static void detect_backends(void)
{
	if (g_have_nft < 0)
		g_have_nft = (system("command -v nft >/dev/null 2>&1") == 0);
	if (g_have_iptables < 0)
		g_have_iptables =
			(system("command -v iptables >/dev/null 2>&1") == 0);
}

static int run(const char *cmd)
{
	int rc = system(cmd);
	if (rc != 0)
		fprintf(stderr, "pvx-nft: rc=%d cmd=%s\n", rc, cmd);
	return rc;
}

int pvx_services_nft_init(void)
{
	detect_backends();
	if (!g_have_nft && !g_have_iptables) {
		fprintf(stderr,
			"pvx-nft: neither nft nor iptables available; Tier-1 DNAT disabled\n");
		return -1;
	}

	if (g_have_nft) {
		// Idempotent table+chain creation. Errors on already-exists
		// are silenced; any real failure surfaces on the rule installs.
		// Two chains: prerouting catches packets arriving from a pool
		// bridge (consumer in container netns); output catches locally
		// generated packets (consumer in host netns).
		run("nft add table ip pvx_services 2>/dev/null");
		run("nft 'add chain ip pvx_services prerouting "
		    "{ type nat hook prerouting priority dstnat ; }' 2>/dev/null");
		run("nft 'add chain ip pvx_services output "
		    "{ type nat hook output priority -100 ; }' 2>/dev/null");
		fprintf(stderr,
			"pvx-nft: initialized ip pvx_services (nftables)\n");
		return 0;
	}

	// iptables fallback: nothing to set up upfront — we add MASQUERADE-
	// style PREROUTING rules per-link directly into the nat table.
	fprintf(stderr, "pvx-nft: using iptables fallback (legacy)\n");
	return 0;
}

void pvx_services_nft_teardown(void)
{
	detect_backends();
	if (g_have_nft)
		run("nft delete table ip pvx_services 2>/dev/null");
	// iptables fallback rules carry the comment "pvx-services" so we can
	// flush them by comment match if the table API isn't available.
	if (g_have_iptables) {
		run("iptables -t nat -S PREROUTING 2>/dev/null | "
		    "grep -- '--comment pvx-services' | "
		    "sed 's/^-A /-D /' | "
		    "while read line; do iptables -t nat $line; done");
		run("iptables -t nat -S OUTPUT 2>/dev/null | "
		    "grep -- '--comment pvx-services' | "
		    "sed 's/^-A /-D /' | "
		    "while read line; do iptables -t nat $line; done");
	}
}

static void ip_to_str(uint32_t ip_n, char *out, size_t outlen)
{
	struct in_addr a = { .s_addr = ip_n };
	const char *p = inet_ntoa(a);
	strncpy(out, p ? p : "0.0.0.0", outlen - 1);
	out[outlen - 1] = '\0';
}

// Stable, unique-per-link comment we can grep on for removal. nft 1.x
// treats `:` as a token separator inside unquoted comments and the shell
// strips our outer quotes before nft sees them, so we use `_` rather than
// `:` and `/` to keep the comment a single bareword on the nft side.
static void link_comment(const struct pvx_link *link, char *out, size_t outlen)
{
	snprintf(out, outlen, "pvx_services_%s_%s",
		 link->consumer ? link->consumer : "u",
		 link->name ? link->name : "u");
	for (char *p = out; *p; p++) {
		if (*p == ':' || *p == '/' || *p == ' ' || *p == '-')
			*p = '_';
	}
}

int pvx_services_nft_add_dnat(const struct pvx_link *link)
{
	if (!link || !link->cluster_ip || !link->cluster_port ||
	    !link->provider_ip || !link->provider_port)
		return -1;
	detect_backends();

	char cluster_ip[INET_ADDRSTRLEN];
	char backend_ip[INET_ADDRSTRLEN];
	ip_to_str(link->cluster_ip, cluster_ip, sizeof(cluster_ip));
	ip_to_str(link->provider_ip, backend_ip, sizeof(backend_ip));

	char comment[128];
	link_comment(link, comment, sizeof(comment));

	char cmd[512];
	// Install in both prerouting (pool consumer ingress through bridge)
	// and output (host-netns consumer's locally-generated traffic). One
	// rule each, identical match+rewrite, distinguished only by chain.
	static const char *const chains[] = { "prerouting", "output" };
	if (g_have_nft) {
		for (size_t i = 0; i < sizeof(chains) / sizeof(chains[0]); i++) {
			// Re-add is idempotent only if we first remove a stale
			// rule for the same link; best-effort delete-by-handle
			// dance via the comment.
			snprintf(cmd, sizeof(cmd),
				 "nft -a list chain ip pvx_services %s 2>/dev/null | "
				 "awk -v c='%s' '$0 ~ c {for (i=1;i<=NF;i++) if ($i==\"handle\") print $(i+1)}' | "
				 "while read h; do nft delete rule ip pvx_services %s handle $h; done",
				 chains[i], comment, chains[i]);
			run(cmd);

			snprintf(cmd, sizeof(cmd),
				 "nft add rule ip pvx_services %s "
				 "ip daddr %s tcp dport %u "
				 "dnat to %s:%u "
				 "comment \"%s\"",
				 chains[i], cluster_ip, link->cluster_port,
				 backend_ip, link->provider_port, comment);
			if (run(cmd) != 0)
				return -1;
		}
		return 0;
	}

	if (g_have_iptables) {
		// iptables: chain names are upper-case and OUTPUT is the
		// equivalent of nft's output hook.
		static const char *const ipt_chains[] = { "PREROUTING",
							  "OUTPUT" };
		for (size_t i = 0; i < sizeof(ipt_chains) / sizeof(ipt_chains[0]);
		     i++) {
			// Best-effort de-dupe: -C is silent if missing, otherwise -D.
			snprintf(cmd, sizeof(cmd),
				 "iptables -t nat -C %s -p tcp -d %s --dport %u "
				 "-m comment --comment '%s' "
				 "-j DNAT --to-destination %s:%u 2>/dev/null && "
				 "iptables -t nat -D %s -p tcp -d %s --dport %u "
				 "-m comment --comment '%s' "
				 "-j DNAT --to-destination %s:%u 2>/dev/null; true",
				 ipt_chains[i], cluster_ip, link->cluster_port,
				 comment, backend_ip, link->provider_port,
				 ipt_chains[i], cluster_ip, link->cluster_port,
				 comment, backend_ip, link->provider_port);
			run(cmd);

			snprintf(cmd, sizeof(cmd),
				 "iptables -t nat -A %s -p tcp -d %s --dport %u "
				 "-m comment --comment '%s' "
				 "-j DNAT --to-destination %s:%u",
				 ipt_chains[i], cluster_ip, link->cluster_port,
				 comment, backend_ip, link->provider_port);
			if (run(cmd) != 0)
				return -1;
		}
		return 0;
	}

	return -1;
}

int pvx_services_nft_del_dnat(const struct pvx_link *link)
{
	if (!link)
		return -1;
	detect_backends();

	char comment[128];
	link_comment(link, comment, sizeof(comment));
	char cmd[512];

	static const char *const chains[] = { "prerouting", "output" };
	if (g_have_nft) {
		int rc = 0;
		for (size_t i = 0; i < sizeof(chains) / sizeof(chains[0]); i++) {
			snprintf(cmd, sizeof(cmd),
				 "nft -a list chain ip pvx_services %s 2>/dev/null | "
				 "awk -v c='%s' '$0 ~ c {for (i=1;i<=NF;i++) if ($i==\"handle\") print $(i+1)}' | "
				 "while read h; do nft delete rule ip pvx_services %s handle $h; done",
				 chains[i], comment, chains[i]);
			if (run(cmd) != 0)
				rc = -1;
		}
		return rc;
	}

	if (g_have_iptables) {
		static const char *const ipt_chains[] = { "PREROUTING",
							  "OUTPUT" };
		int rc = 0;
		for (size_t i = 0; i < sizeof(ipt_chains) / sizeof(ipt_chains[0]);
		     i++) {
			snprintf(cmd, sizeof(cmd),
				 "iptables -t nat -S %s 2>/dev/null | "
				 "grep -- '--comment %s' | "
				 "sed 's/^-A /-D /' | "
				 "while read line; do iptables -t nat $line; done",
				 ipt_chains[i], comment);
			if (run(cmd) != 0)
				rc = -1;
		}
		return rc;
	}
	return -1;
}

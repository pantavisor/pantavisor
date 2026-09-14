/*
 * Copyright (c) 2025 Pantacor Ltd.
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

#ifdef PANTAVISOR_XCONNECT_DBUS_SYSTEMBUS

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>

#include "dbus_daemon.h"
#include "daemons.h"
#include "state.h"
#include "platforms.h"
#include "paths.h"
#include "config.h"
#include "utils/fs.h"
#include "utils/json.h"

#define MODULE_NAME "dbus-daemon"
#define pv_log(level, msg, ...)                                                \
	vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__,       \
	     ##__VA_ARGS__)
#include "log.h"

#define PV_DBUS_ROLE_UID_BASE 90000
#define PV_DBUS_ROLE_UID_MAP "dbus-role-uids.json"

// Upper bound on distinct roles tracked per generation pass for passwd dedup.
// Roles beyond this still get policy rules; they just risk a duplicate (and
// harmless) passwd line.
#define PV_DBUS_GEN_MAX_ROLES 128

// Default-deny base policy for the hosted system bus. Per-name allow rules are
// generated into PV_DBUS_SYSTEMBUS_POLICYDIR from the owns/allow declarations in
// container service manifests (see pv_dbus_daemon_generate). Rules match in
// order, last match wins: method calls and name ownership are denied by default
// and only re-granted by the generated per-role fragments; calls to the bus
// driver, replies and signals stay allowed so peers can connect and reply.
static const char dbus_systembus_base_conf[] =
	"<!DOCTYPE busconfig PUBLIC "
	"\"-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN\" "
	"\"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd\">\n"
	"<busconfig>\n"
	"  <type>system</type>\n"
	"  <listen>unix:path=" PV_DBUS_SYSTEMBUS_SOCKET "</listen>\n"
	"  <auth>EXTERNAL</auth>\n"
	"\n"
	"  <policy context=\"default\">\n"
	"    <allow user=\"*\"/>\n"
	"    <deny own=\"*\"/>\n"
	"    <deny send_type=\"method_call\"/>\n"
	"    <allow send_destination=\"org.freedesktop.DBus\"/>\n"
	"    <allow receive_sender=\"org.freedesktop.DBus\"/>\n"
	// Receiving is not the security gate (sending is, via the deny above plus
	// the per-role send_destination grants), so allow delivery of method calls
	// to their destination — exactly as the stock dbus system.conf does.
	"    <allow receive_type=\"method_call\"/>\n"
	"    <allow send_requested_reply=\"true\" send_type=\"method_return\"/>\n"
	"    <allow send_requested_reply=\"true\" send_type=\"error\"/>\n"
	"    <allow receive_requested_reply=\"true\" receive_type=\"method_return\"/>\n"
	"    <allow receive_requested_reply=\"true\" receive_type=\"error\"/>\n"
	"    <allow send_type=\"signal\"/>\n"
	"    <allow receive_type=\"signal\"/>\n"
	"  </policy>\n"
	"\n"
	"  <includedir>" PV_DBUS_SYSTEMBUS_POLICYDIR "</includedir>\n"
	"</busconfig>\n";

// Upper bound on role uid pins tracked per generation pass.
#define PV_DBUS_ROLE_PIN_MAX 128

// Role uid pins from the state's "roles" declarations, populated by
// pv_dbus_daemon_validate() (role_uid_pins_populate()) before generation and
// consulted first by pv_dbus_daemon_role_uid(), so a pinned role never
// touches the persistent pool.
static struct {
	char *role;
	int uid;
} role_uid_pins[PV_DBUS_ROLE_PIN_MAX];
static int role_uid_pins_n;

static void role_uid_pins_reset(void)
{
	for (int i = 0; i < role_uid_pins_n; i++)
		free(role_uid_pins[i].role);
	role_uid_pins_n = 0;
}

static void role_uid_pins_add(const char *role, int uid)
{
	if (!role)
		return;
	for (int i = 0; i < role_uid_pins_n; i++) {
		if (!strcmp(role_uid_pins[i].role, role)) {
			role_uid_pins[i].uid = uid;
			return;
		}
	}
	if (role_uid_pins_n >= PV_DBUS_ROLE_PIN_MAX)
		return;
	role_uid_pins[role_uid_pins_n].role = strdup(role);
	role_uid_pins[role_uid_pins_n].uid = uid;
	role_uid_pins_n++;
}

static int role_uid_pins_lookup(const char *role)
{
	for (int i = 0; i < role_uid_pins_n; i++) {
		if (!strcmp(role_uid_pins[i].role, role))
			return role_uid_pins[i].uid;
	}
	return -1;
}

// Populate the pin table from every platform's parsed "roles" declarations.
// Called from pv_dbus_daemon_validate() so pins are current before both the
// pool-collision checks below and the generation pass that follows.
static void role_uid_pins_populate(struct pv_state *s)
{
	role_uid_pins_reset();

	struct pv_platform *p, *tmp_p;
	dl_list_for_each_safe(p, tmp_p, &s->platforms, struct pv_platform, list)
	{
		struct pv_platform_role_pin *rp, *tmp_rp;
		dl_list_for_each_safe(rp, tmp_rp, &p->role_pins,
				      struct pv_platform_role_pin, list)
		{
			role_uid_pins_add(rp->role, rp->uid);
		}
	}
}

// Return the role name the persistent pool has recorded for `uid`, or NULL.
// Mirrors the pool read in pv_dbus_daemon_role_uid(); used only to detect a
// pin colliding with an existing pool assignment at validation time.
static char *pool_role_for_uid(int uid)
{
	char path[PATH_MAX];
	pv_paths_storage_config_file(path, PATH_MAX, PV_DBUS_ROLE_UID_MAP);

	size_t size = 0;
	char *buf = pv_fs_file_read(path, &size);
	jsmntok_t *tokv = NULL;
	int tokc;
	char *found = NULL;
	if (buf && size > 0 && jsmnutil_parse_json(buf, &tokv, &tokc) > 0 &&
	    tokc > 0 && tokv[0].type == JSMN_OBJECT) {
		int n = tokv[0].size;
		jsmntok_t *t = tokv + 1;
		for (int i = 0; i < n; i++) {
			int klen = t->end - t->start;
			int v = atoi(buf + (t + 1)->start);
			if (v == uid) {
				found = calloc(klen + 1, 1);
				if (found)
					memcpy(found, buf + t->start, klen);
				break;
			}
			t += 2;
		}
	}
	if (tokv)
		free(tokv);
	if (buf)
		free(buf);
	return found;
}

int pv_dbus_daemon_role_uid(const char *role)
{
	if (!role)
		return -1;

	int pinned = role_uid_pins_lookup(role);
	if (pinned >= 0)
		return pinned;

	char path[PATH_MAX];
	pv_paths_storage_config_file(path, PATH_MAX, PV_DBUS_ROLE_UID_MAP);

	int next = PV_DBUS_ROLE_UID_BASE;
	int found = -1;

	struct pv_json_ser js;
	pv_json_ser_init(&js, 256);
	pv_json_ser_object(&js);

	size_t size = 0;
	char *buf = pv_fs_file_read(path, &size);
	jsmntok_t *tokv = NULL;
	int tokc;
	if (buf && size > 0 && jsmnutil_parse_json(buf, &tokv, &tokc) > 0 &&
	    tokc > 0 && tokv[0].type == JSMN_OBJECT) {
		int n = tokv[0].size;
		jsmntok_t *t = tokv + 1;
		for (int i = 0; i < n; i++) {
			int klen = t->end - t->start;
			char kbuf[256];
			if (klen >= (int)sizeof(kbuf))
				klen = sizeof(kbuf) - 1;
			memcpy(kbuf, buf + t->start, klen);
			kbuf[klen] = '\0';
			int v = atoi(buf + (t + 1)->start);

			// Carry every existing mapping forward unchanged.
			pv_json_ser_key(&js, kbuf);
			pv_json_ser_number(&js, v);
			if (v >= next)
				next = v + 1;
			if (!strcmp(kbuf, role))
				found = v;

			t += 2;
		}
	}
	if (tokv)
		free(tokv);
	if (buf)
		free(buf);

	if (found >= 0) {
		char *tmp = (pv_json_ser_object_pop(&js), pv_json_ser_str(&js));
		if (tmp)
			free(tmp);
		return found;
	}

	// New role: append and persist the rewritten map.
	pv_json_ser_key(&js, role);
	pv_json_ser_number(&js, next);
	pv_json_ser_object_pop(&js);

	char *out = pv_json_ser_str(&js);
	if (out) {
		pv_fs_file_save(path, out, 0600);
		free(out);
	}

	return next;
}

int pv_dbus_daemon_validate(struct pv_state *s)
{
	if (!pv_config_get_bool(PV_XCONNECT_DBUS_SYSTEMBUS_ENABLED))
		return 0;

	struct pv_platform *p, *tmp_p;
	dl_list_for_each_safe(p, tmp_p, &s->platforms, struct pv_platform, list)
	{
		struct pv_platform_service_export *exp, *tmp_exp;
		dl_list_for_each_safe(exp, tmp_exp, &p->service_exports,
				      struct pv_platform_service_export, list)
		{
			// (a) platform export name collides with builtin export
			if (exp->name &&
			    !strcmp(exp->name, PV_DBUS_SYSTEMBUS_NAME)) {
				pv_log(ERROR,
				       "platform '%s' exports reserved service name '%s' while the hosted system bus is enabled",
				       p->name, PV_DBUS_SYSTEMBUS_NAME);
				return -1;
			}

			// (a2) an 'allow' object with no 'role' names nothing
			struct pv_platform_service_allow *al, *tmp_al;
			dl_list_for_each_safe(al, tmp_al, &exp->allow,
					      struct pv_platform_service_allow,
					      list)
			{
				if (!al->role) {
					pv_log(ERROR,
					       "platform '%s' name '%s' has an 'allow' object with no 'role'",
					       p->name,
					       exp->owns ? exp->owns :
							   "(none)");
					return -1;
				}
			}

			if (!exp->owns)
				continue;

			// (b) two apps owning the same name on the same bus
			const char *bus =
				exp->bus ? exp->bus : PV_DBUS_SYSTEMBUS_NAME;

			// (c) on-demand activation is limited to the hosted
			// system bus in v1 (see xconnect/XCONNECT.md scope).
			if (exp->activatable &&
			    strcmp(bus, PV_DBUS_SYSTEMBUS_NAME)) {
				pv_log(ERROR,
				       "name '%s' declares on-demand activation on bus '%s'; activation is only supported on the hosted '%s'",
				       exp->owns, bus, PV_DBUS_SYSTEMBUS_NAME);
				return -1;
			}

			struct pv_platform *p2, *tmp_p2;
			dl_list_for_each_safe(p2, tmp_p2, &s->platforms,
					      struct pv_platform, list)
			{
				struct pv_platform_service_export *e2, *te2;
				dl_list_for_each_safe(
					e2, te2, &p2->service_exports,
					struct pv_platform_service_export, list)
				{
					const char *b2 =
						e2->bus ?
							e2->bus :
							PV_DBUS_SYSTEMBUS_NAME;
					if (e2 == exp || !e2->owns)
						continue;
					if (!strcmp(e2->owns, exp->owns) &&
					    !strcmp(b2, bus)) {
						pv_log(ERROR,
						       "well-known name '%s' on bus '%s' is owned by more than one app",
						       exp->owns, bus);
						return -1;
					}
				}
			}
		}
	}

	// (d) role uid pins: only a platform with an 'owns' export may pin
	// (a consumer cannot promote its own identity); pins are device-wide
	// by role name and must not collide with each other or with the
	// persistent pool (xconnect/XCONNECT.md "Role UID Pinning").
	dl_list_for_each_safe(p, tmp_p, &s->platforms, struct pv_platform, list)
	{
		if (dl_list_empty(&p->role_pins))
			continue;

		bool has_owns = false;
		struct pv_platform_service_export *exp, *tmp_exp;
		dl_list_for_each_safe(exp, tmp_exp, &p->service_exports,
				      struct pv_platform_service_export, list)
		{
			if (exp->owns) {
				has_owns = true;
				break;
			}
		}
		if (!has_owns) {
			pv_log(ERROR,
			       "platform '%s' declares role pins in 'roles' but owns no D-Bus name; only a provider may pin a role uid",
			       p->name);
			return -1;
		}

		struct pv_platform_role_pin *rp, *tmp_rp;
		dl_list_for_each_safe(rp, tmp_rp, &p->role_pins,
				      struct pv_platform_role_pin, list)
		{
			struct pv_platform *p2, *tmp_p2;
			dl_list_for_each_safe(p2, tmp_p2, &s->platforms,
					      struct pv_platform, list)
			{
				struct pv_platform_role_pin *rp2, *tmp_rp2;
				dl_list_for_each_safe(
					rp2, tmp_rp2, &p2->role_pins,
					struct pv_platform_role_pin, list)
				{
					if (rp2 == rp || !rp2->role ||
					    strcmp(rp2->role, rp->role))
						continue;
					if (rp2->uid != rp->uid) {
						pv_log(ERROR,
						       "role '%s' is pinned to uid %d by platform '%s' and to uid %d by platform '%s'",
						       rp->role, rp->uid,
						       p->name, rp2->uid,
						       p2->name);
						return -1;
					}
				}
			}

			char *pool_role = pool_role_for_uid(rp->uid);
			if (pool_role && strcmp(pool_role, rp->role)) {
				pv_log(ERROR,
				       "platform '%s' pins role '%s' to uid %d, already assigned to role '%s' in the role uid pool",
				       p->name, rp->role, rp->uid, pool_role);
				free(pool_role);
				return -1;
			}
			free(pool_role);

			if (rp->uid == 0) {
				pv_log(WARN,
				       "role '%s' is pinned to uid 0; pv-xconnect's ownership-monitor connection also authenticates as uid 0 and will match any policy for this role",
				       rp->role);
			}
		}
	}

	role_uid_pins_populate(s);

	return 0;
}

struct pv_platform *pv_dbus_daemon_activatable_owner(struct pv_state *s,
						     const char *name)
{
	if (!name)
		return NULL;

	// The owner index: the platform that owns well-known `name` on the
	// hosted system bus AND declares on-demand activation. Used by the
	// activate endpoint to resolve which container to start on first use.
	// One-owner-per-name is enforced by pv_dbus_daemon_validate(), so the
	// first match is authoritative.
	struct pv_platform *p, *tmp_p;
	dl_list_for_each_safe(p, tmp_p, &s->platforms, struct pv_platform, list)
	{
		struct pv_platform_service_export *exp, *tmp_exp;
		dl_list_for_each_safe(exp, tmp_exp, &p->service_exports,
				      struct pv_platform_service_export, list)
		{
			if (!exp->owns || !exp->activatable)
				continue;
			const char *bus =
				exp->bus ? exp->bus : PV_DBUS_SYSTEMBUS_NAME;
			if (strcmp(bus, PV_DBUS_SYSTEMBUS_NAME))
				continue;
			if (!strcmp(exp->owns, name))
				return p;
		}
	}
	return NULL;
}

// Reuse the normal lifecycle: flip the goal to STARTED and re-inject the
// platform into the run loop (set_installed). The next pv_state_run tick
// drives mount -> drivers -> start; a chained dependency (a cold call made by
// the platform being started here) re-enters activation through the proxy.
static void pv_dbus_daemon_promote(struct pv_platform *p)
{
	pv_platform_set_status_goal(p, PLAT_STARTED);
	pv_platform_set_installed(p);
}

int pv_dbus_daemon_activate(struct pv_state *s, const char *name)
{
	struct pv_platform *owner = pv_dbus_daemon_activatable_owner(s, name);
	if (!owner)
		return -1; // no activatable owner for this name

	// Already running (or on its way): nothing to do.
	if (pv_platform_is_starting(owner) || pv_platform_is_started(owner) ||
	    pv_platform_is_ready(owner))
		return 0;

	pv_log(INFO,
	       "on-demand activation: starting '%s' (owner of D-Bus name '%s')",
	       owner->name, name);
	pv_dbus_daemon_promote(owner);
	return 0;
}

int pv_dbus_daemon_activate_container(struct pv_state *s, const char *container)
{
	struct pv_platform *p = pv_state_fetch_platform(s, container);
	if (!p)
		return -1; // unknown container

	if (!pv_platform_is_mounted(p))
		return 0; // already started (or never passive) — success no-op

	pv_log(INFO, "on-owner activation: starting consumer container '%s'",
	       container);
	pv_dbus_daemon_promote(p);
	return 0;
}

// Map a role to its passwd username ("<prefix><role>").
static void role_to_user(const char *role, char *buf, size_t n)
{
	snprintf(buf, n, "%s%s", PV_DBUS_ROLE_NAME_PREFIX, role);
}

// Append one passwd line for `role` (resolving its masquerade uid to a name the
// jailed daemon can look up), at most once per generation pass. `seen` holds
// the roles already written; entries point into state-owned strings.
static void passwd_add_role(FILE *pw, const char **seen, int *seen_n,
			    const char *role, int uid)
{
	for (int i = 0; i < *seen_n; i++)
		if (!strcmp(seen[i], role))
			return;

	char user[256];
	role_to_user(role, user, sizeof(user));
	fprintf(pw, "%s:x:%d:%d::/nonexistent:/sbin/nologin\n", user, uid, uid);

	if (*seen_n < PV_DBUS_GEN_MAX_ROLES)
		seen[(*seen_n)++] = role;
}

// Seed the daemon's private passwd with the rootfs passwd, so role lookups for
// the daemon's own identity (root, nobody, ...) keep working; role entries are
// appended on top.
static void passwd_write_base(FILE *pw)
{
	size_t n = 0;
	char *base = pv_fs_file_read("/etc/passwd", &n);
	if (base && n > 0)
		fwrite(base, 1, n, pw);
	if (base)
		free(base);
}

void pv_dbus_daemon_prepare(void)
{
	struct pv_init_daemon *daemons = pv_init_get_daemons();

	if (!pv_config_get_bool(PV_XCONNECT_DBUS_SYSTEMBUS_ENABLED)) {
		pv_log(INFO,
		       "hosted dbus system bus disabled via config, not starting %s",
		       PV_DBUS_SYSTEMBUS_DAEMON);
		for (int i = 0; daemons && daemons[i].name; i++) {
			if (!strcmp(daemons[i].name,
				    PV_DBUS_SYSTEMBUS_DAEMON)) {
				daemons[i].respawn = 0;
				daemons[i].pid = -1;
			}
		}
		return;
	}

	if (pv_fs_mkdir_p(PV_DBUS_SYSTEMBUS_POLICYDIR, 0755)) {
		pv_log(ERROR, "could not create %s: %s",
		       PV_DBUS_SYSTEMBUS_POLICYDIR, strerror(errno));
		return;
	}

	// Seed the jail passwd before the daemon spawns so it can start even
	// before any state defines roles; pv_dbus_daemon_generate() rewrites it
	// in place (same inode, so the bind-mount keeps tracking it) on each
	// state application.
	FILE *pw = fopen(PV_DBUS_SYSTEMBUS_PASSWD, "w");
	if (pw) {
		passwd_write_base(pw);
		fclose(pw);
	} else {
		pv_log(ERROR, "could not write %s: %s",
		       PV_DBUS_SYSTEMBUS_PASSWD, strerror(errno));
	}

	FILE *f = fopen(PV_DBUS_SYSTEMBUS_CONF, "w");
	if (!f) {
		pv_log(ERROR, "could not write %s: %s", PV_DBUS_SYSTEMBUS_CONF,
		       strerror(errno));
		return;
	}
	fputs(dbus_systembus_base_conf, f);
	fclose(f);

	pv_log(INFO, "hosted dbus system bus enabled, base config at %s",
	       PV_DBUS_SYSTEMBUS_CONF);
}

// True if the file at `path` does not already hold exactly `len` bytes of
// `buf` (missing file counts as different).
static bool file_differs(const char *path, const char *buf, size_t len)
{
	size_t n = 0;
	char *cur = pv_fs_file_read(path, &n);
	bool diff = !cur || n != len || memcmp(cur, buf, len) != 0;
	if (cur)
		free(cur);
	return diff;
}

// Rewrite `path` in place (fopen "w" truncates the existing inode) with the
// generated content, so a passwd bind-mount keeps tracking the same inode.
static int write_inplace(const char *path, const char *buf, size_t len)
{
	FILE *fp = fopen(path, "w");
	if (!fp) {
		pv_log(ERROR, "could not write %s: %s", path, strerror(errno));
		return -1;
	}
	if (len)
		fwrite(buf, 1, len, fp);
	fclose(fp);
	return 0;
}

void pv_dbus_daemon_generate(struct pv_state *s)
{
	if (!pv_config_get_bool(PV_XCONNECT_DBUS_SYSTEMBUS_ENABLED))
		return;

	if (pv_fs_mkdir_p(PV_DBUS_SYSTEMBUS_POLICYDIR, 0755))
		return;

	// passwd and policy are two projections of the same role->uid map and
	// must stay in lockstep. pv_state_run() calls us on every controller
	// tick, but this projection only changes when the state's owns/allow
	// declarations change; rewriting the files and SIGHUP'ing the daemon
	// unconditionally would reload the bus every couple of seconds for the
	// life of the revision. So build both into memory, and only touch disk
	// (and reload the daemon) when the generated content actually differs.
	char *pw_buf = NULL, *pol_buf = NULL;
	size_t pw_len = 0, pol_len = 0;

	FILE *pw = open_memstream(&pw_buf, &pw_len);
	FILE *f = open_memstream(&pol_buf, &pol_len);
	if (!pw || !f) {
		pv_log(ERROR, "could not allocate dbus policy buffers");
		if (pw)
			fclose(pw);
		if (f)
			fclose(f);
		free(pw_buf);
		free(pol_buf);
		return;
	}

	passwd_write_base(pw);

	char polpath[PATH_MAX];
	snprintf(polpath, sizeof(polpath), "%s/pv-generated.conf",
		 PV_DBUS_SYSTEMBUS_POLICYDIR);

	fputs("<!DOCTYPE busconfig PUBLIC "
	      "\"-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN\" "
	      "\"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd\">\n"
	      "<busconfig>\n",
	      f);

	const char *seen[PV_DBUS_GEN_MAX_ROLES];
	int seen_n = 0;

	struct pv_platform *p, *tmp_p;
	dl_list_for_each_safe(p, tmp_p, &s->platforms, struct pv_platform, list)
	{
		struct pv_platform_service_export *exp, *tmp_exp;
		dl_list_for_each_safe(exp, tmp_exp, &p->service_exports,
				      struct pv_platform_service_export, list)
		{
			if (!exp->owns || exp->svc_type != SVC_TYPE_DBUS)
				continue;

			const char *orole = exp->role ? exp->role : exp->owns;
			int owner_uid = pv_dbus_daemon_role_uid(orole);
			if (owner_uid < 0)
				continue;

			char ouser[256];
			role_to_user(orole, ouser, sizeof(ouser));
			passwd_add_role(pw, seen, &seen_n, orole, owner_uid);

			fprintf(f,
				"  <!-- %s owns %s (owner role '%s' uid %d) -->\n"
				"  <policy user=\"%s\">\n"
				"    <allow own=\"%s\"/>\n"
				"    <allow send_destination=\"%s\"/>\n"
				"    <allow receive_sender=\"%s\"/>\n"
				"  </policy>\n",
				p->name, exp->owns, orole, owner_uid, ouser,
				exp->owns, exp->owns, exp->owns);

			struct pv_platform_service_allow *al, *tmp_al;
			dl_list_for_each_safe(al, tmp_al, &exp->allow,
					      struct pv_platform_service_allow,
					      list)
			{
				int uid = pv_dbus_daemon_role_uid(al->role);
				if (uid < 0)
					continue;

				char cuser[256];
				role_to_user(al->role, cuser, sizeof(cuser));
				passwd_add_role(pw, seen, &seen_n, al->role,
						uid);

				fprintf(f,
					"  <!-- caller role '%s' uid %d -> %s -->\n"
					"  <policy user=\"%s\">\n",
					al->role, uid, exp->owns, cuser);

				// Narrowing: one <allow> per combination of the
				// non-empty dimensions, since the daemon
				// matches a rule's attributes conjunctively.
				// A plain role (no dimensions) keeps today's
				// single unnarrowed line.
				int ni = al->interfaces_count > 0 ?
						 al->interfaces_count :
						 1;
				int nm = al->members_count > 0 ?
						 al->members_count :
						 1;
				int np = al->paths_count > 0 ? al->paths_count :
							       1;
				for (int ii = 0; ii < ni; ii++) {
					for (int mi = 0; mi < nm; mi++) {
						for (int pi = 0; pi < np;
						     pi++) {
							fprintf(f,
								"    <allow send_destination=\"%s\"",
								exp->owns);
							if (al->interfaces_count >
							    0)
								fprintf(f,
									" send_interface=\"%s\"",
									al->interfaces
										[ii]);
							if (al->members_count >
							    0)
								fprintf(f,
									" send_member=\"%s\"",
									al->members
										[mi]);
							if (al->paths_count > 0)
								fprintf(f,
									" send_path=\"%s\"",
									al->paths[pi]);
							fputs("/>\n", f);
						}
					}
				}

				// receive_sender is never narrowed: replies
				// and signals must always reach an allowed
				// caller.
				fprintf(f,
					"    <allow receive_sender=\"%s\"/>\n"
					"  </policy>\n",
					exp->owns);
			}
		}
	}

	fputs("</busconfig>\n", f);
	fclose(f);
	fclose(pw);

	bool changed = file_differs(PV_DBUS_SYSTEMBUS_PASSWD, pw_buf, pw_len) ||
		       file_differs(polpath, pol_buf, pol_len);

	if (changed) {
		write_inplace(PV_DBUS_SYSTEMBUS_PASSWD, pw_buf, pw_len);
		write_inplace(polpath, pol_buf, pol_len);

		struct pv_init_daemon *d = pv_init_get_daemons();
		for (int i = 0; d && d[i].name; i++) {
			if (!strcmp(d[i].name, PV_DBUS_SYSTEMBUS_DAEMON) &&
			    d[i].pid > 0) {
				pv_log(INFO,
				       "reloading %s (pid %d) dbus policy",
				       PV_DBUS_SYSTEMBUS_DAEMON, d[i].pid);
				kill(d[i].pid, SIGHUP);
			}
		}
	}

	free(pw_buf);
	free(pol_buf);
}

#endif /* PANTAVISOR_XCONNECT_DBUS_SYSTEMBUS */

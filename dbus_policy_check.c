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

#ifdef PANTAVISOR_XCONNECT_DBUS_SYSTEMBUS

#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <stddef.h>

#include "dbus_policy_check.h"

#define MODULE_NAME "dbus-policy-check"
#define pv_log(level, msg, ...)                                                \
	vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__,       \
	     ##__VA_ARGS__)
#include "log.h"

// Exact token/literal comparison, avoiding hand-counted length constants.
static bool token_eq(const char *s, size_t len, const char *lit)
{
	return strlen(lit) == len && !strncmp(s, lit, len);
}

static bool str_in_list(const char *s, size_t len, const char **list, int n)
{
	for (int i = 0; i < n; i++) {
		if (list[i] && token_eq(s, len, list[i]))
			return true;
	}
	return false;
}

// busconfig child elements permitted in a fragment (xconnect/XCONNECT.md
// "Validation" level 2); anything else — include, includedir, listen, type,
// auth, servicedir, limit, selinux, apparmor, ... — is rejected.
static bool element_allowed(const char *name, size_t len)
{
	return token_eq(name, len, "busconfig") ||
	       token_eq(name, len, "policy") || token_eq(name, len, "allow") ||
	       token_eq(name, len, "deny");
}

static const char *skip_ws(const char *p)
{
	while (*p && isspace((unsigned char)*p))
		p++;
	return p;
}

// Skip one XML comment "<!-- ... -->" at `p` (which must point at '<'), or
// return NULL if `p` is not a comment start.
static const char *skip_comment(const char *p)
{
	if (strncmp(p, "<!--", 4))
		return NULL;
	const char *end = strstr(p + 4, "-->");
	if (!end) // unterminated: leave it for the daemon's grammar check
		return p + strlen(p);
	return end + 3;
}

static const char *skip_noise(const char *p)
{
	for (;;) {
		const char *ws = skip_ws(p);
		const char *c = skip_comment(ws);
		if (c) {
			p = c;
			continue;
		}
		if (ws != p) {
			p = ws;
			continue;
		}
		return p;
	}
}

static bool is_name_char(char c)
{
	return isalnum((unsigned char)c) || c == '_' || c == '-' || c == '.' ||
	       c == ':';
}

// Parse a quoted attribute value at `p` (pointing at the opening quote).
// Returns the position right after the closing quote, or NULL if
// unterminated.
static const char *parse_attr_value(const char *p, const char **val,
				    size_t *val_len)
{
	char q = *p;
	p++;
	*val = p;
	while (*p && *p != q)
		p++;
	if (!*p)
		return NULL;
	*val_len = (size_t)(p - *val);
	return p + 1;
}

int pv_dbus_policy_check(const char *platform, const char *fragment,
			 const char *xml, const char **owns, int owns_count,
			 const char **known_roles, int known_roles_count,
			 const char **allow_roles, int allow_roles_count)
{
	if (!xml)
		return -1;

	const char *p = xml;
	for (;;) {
		p = skip_noise(p);
		if (!*p)
			break;
		if (*p != '<') {
			// Bare text between tags is a grammar concern, left to
			// the daemon's own parse (validation level 1).
			const char *next = strchr(p, '<');
			if (!next)
				break;
			p = next;
			continue;
		}

		bool closing = (p[1] == '/');
		const char *namep = p + (closing ? 2 : 1);
		const char *name_end = namep;
		while (is_name_char(*name_end))
			name_end++;
		size_t name_len = (size_t)(name_end - namep);
		if (name_len == 0) {
			pv_log(ERROR,
			       "platform '%s' policy fragment '%s': malformed tag near '%.20s'",
			       platform, fragment, p);
			return -1;
		}
		if (!element_allowed(namep, name_len)) {
			pv_log(ERROR,
			       "platform '%s' policy fragment '%s': disallowed element '<%s%.*s>' (only busconfig, policy, allow, deny are permitted)",
			       platform, fragment, closing ? "/" : "",
			       (int)name_len, namep);
			return -1;
		}

		char tag[16] = { 0 };
		size_t tl =
			name_len < sizeof(tag) - 1 ? name_len : sizeof(tag) - 1;
		memcpy(tag, namep, tl);

		if (closing) {
			const char *gt = strchr(name_end, '>');
			if (!gt) {
				pv_log(ERROR,
				       "platform '%s' policy fragment '%s': unterminated closing tag '</%s'",
				       platform, fragment, tag);
				return -1;
			}
			p = gt + 1;
			continue;
		}

		bool is_policy = !strcmp(tag, "policy");
		bool is_allow_deny =
			!strcmp(tag, "allow") || !strcmp(tag, "deny");
		bool saw_user = false;

		const char *q = name_end;
		for (;;) {
			q = skip_ws(q);
			if (q[0] == '/' && q[1] == '>') {
				q += 2;
				break;
			}
			if (q[0] == '>') {
				q += 1;
				break;
			}
			if (!*q) {
				pv_log(ERROR,
				       "platform '%s' policy fragment '%s': unterminated tag '<%s'",
				       platform, fragment, tag);
				return -1;
			}

			const char *anamep = q;
			while (is_name_char(*q))
				q++;
			size_t anlen = (size_t)(q - anamep);
			if (anlen == 0) {
				pv_log(ERROR,
				       "platform '%s' policy fragment '%s': malformed attribute in '<%s>'",
				       platform, fragment, tag);
				return -1;
			}
			q = skip_ws(q);
			if (*q != '=') {
				pv_log(ERROR,
				       "platform '%s' policy fragment '%s': attribute '%.*s' in '<%s>' has no value",
				       platform, fragment, (int)anlen, anamep,
				       tag);
				return -1;
			}
			q = skip_ws(q + 1);
			if (*q != '"' && *q != '\'') {
				pv_log(ERROR,
				       "platform '%s' policy fragment '%s': attribute '%.*s' in '<%s>' is not quoted",
				       platform, fragment, (int)anlen, anamep,
				       tag);
				return -1;
			}
			const char *aval;
			size_t avlen;
			q = parse_attr_value(q, &aval, &avlen);
			if (!q) {
				pv_log(ERROR,
				       "platform '%s' policy fragment '%s': unterminated attribute value in '<%s>'",
				       platform, fragment, tag);
				return -1;
			}

			if (is_policy) {
				if (!token_eq(anamep, anlen, "user")) {
					pv_log(ERROR,
					       "platform '%s' policy fragment '%s': <policy> attribute '%.*s' is not permitted (only 'user' is allowed)",
					       platform, fragment, (int)anlen,
					       anamep);
					return -1;
				}
				saw_user = true;

				bool wrapped = avlen >= 8 &&
					       !strncmp(aval, "@role:", 6) &&
					       aval[avlen - 1] == '@';
				if (!wrapped) {
					pv_log(ERROR,
					       "platform '%s' policy fragment '%s': <policy user=\"%.*s\"> must use the form '@role:<name>@'",
					       platform, fragment, (int)avlen,
					       aval);
					return -1;
				}
				const char *role = aval + 6;
				size_t role_len = avlen - 6 - 1;
				if (role_len == 0) {
					pv_log(ERROR,
					       "platform '%s' policy fragment '%s': <policy user=\"%.*s\"> must use the form '@role:<name>@'",
					       platform, fragment, (int)avlen,
					       aval);
					return -1;
				}
				if (!str_in_list(role, role_len, known_roles,
						 known_roles_count)) {
					pv_log(ERROR,
					       "platform '%s' policy fragment '%s': <policy> references unknown role '%.*s'",
					       platform, fragment,
					       (int)role_len, role);
					return -1;
				}
				if (!str_in_list(role, role_len, allow_roles,
						 allow_roles_count)) {
					pv_log(ERROR,
					       "platform '%s' policy fragment '%s': role '%.*s' is not granted in this export's 'allow' list",
					       platform, fragment,
					       (int)role_len, role);
					return -1;
				}
			} else if (is_allow_deny) {
				if (token_eq(anamep, anlen, "eavesdrop")) {
					pv_log(ERROR,
					       "platform '%s' policy fragment '%s': <%s eavesdrop=...> is not permitted",
					       platform, fragment, tag);
					return -1;
				}
				bool is_send = anlen > 5 &&
					       !strncmp(anamep, "send_", 5);
				bool is_recv = anlen > 8 &&
					       !strncmp(anamep, "receive_", 8);
				bool is_own =
					token_eq(anamep, anlen, "own") ||
					token_eq(anamep, anlen, "own_prefix");
				if (!is_send && !is_recv && !is_own) {
					pv_log(ERROR,
					       "platform '%s' policy fragment '%s': <%s> attribute '%.*s' is not permitted (only send_*, receive_*, own, own_prefix)",
					       platform, fragment, tag,
					       (int)anlen, anamep);
					return -1;
				}

				bool needs_owns_name =
					is_own ||
					token_eq(anamep, anlen,
						 "send_destination") ||
					token_eq(anamep, anlen,
						 "receive_sender");
				if (needs_owns_name &&
				    !str_in_list(aval, avlen, owns,
						 owns_count)) {
					pv_log(ERROR,
					       "platform '%s' policy fragment '%s': <%s %.*s=\"%.*s\"> does not name one of this platform's own 'owns' names",
					       platform, fragment, tag,
					       (int)anlen, anamep, (int)avlen,
					       aval);
					return -1;
				}
			}
			// <busconfig> attributes are not part of the
			// declarative vocabulary; nothing to check.
		}

		if (is_policy && !saw_user) {
			pv_log(ERROR,
			       "platform '%s' policy fragment '%s': <policy> must carry a 'user' attribute",
			       platform, fragment);
			return -1;
		}

		p = q;
	}

	return 0;
}

#endif /* PANTAVISOR_XCONNECT_DBUS_SYSTEMBUS */

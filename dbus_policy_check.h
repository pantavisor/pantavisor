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

#ifndef PV_DBUS_POLICY_CHECK_H
#define PV_DBUS_POLICY_CHECK_H

#ifdef PANTAVISOR_XCONNECT_DBUS_SYSTEMBUS

// Attribute-level validation of a raw D-Bus policy fragment, i.e. validation
// levels 2 and 3 of xconnect/XCONNECT.md "Policy Fragments" > "Validation"
// (level 1, the daemon's own grammar check, is a separate throwaway
// dbus-daemon run in dbus_daemon.c). This scanner assumes the grammar is
// otherwise valid and only walks element names and the attributes of
// <policy>, <allow> and <deny>:
//
//   - only <busconfig>, <policy>, <allow>, <deny> elements are permitted;
//   - <policy> may carry only user="@role:<name>@", where <name> is present
//     in `known_roles` (declared somewhere in the state) AND in
//     `allow_roles` (this export's own 'allow' list — the JSON says who,
//     the fragment may only narrow or detail how);
//   - <allow>/<deny> may carry only send_*, receive_*, own, own_prefix
//     attributes ('eavesdrop' explicitly rejected);
//   - own, own_prefix, send_destination and receive_sender must name one of
//     `owns` (this platform's own owned names).
//
// `platform` and `fragment` name the offending platform and fragment path in
// every logged ERROR. Returns 0 if the fragment is accepted, -1 otherwise.
int pv_dbus_policy_check(const char *platform, const char *fragment,
			 const char *xml, const char **owns, int owns_count,
			 const char **known_roles, int known_roles_count,
			 const char **allow_roles, int allow_roles_count);

#endif /* PANTAVISOR_XCONNECT_DBUS_SYSTEMBUS */
#endif /* PV_DBUS_POLICY_CHECK_H */

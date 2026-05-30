/*
 * Copyright (c) 2026 Pantacor Ltd.
 * SPDX-License-Identifier: MIT
 */
#ifndef PV_UTILS_SYSCTL_H
#define PV_UTILS_SYSCTL_H

// Write `value` (caller chooses trailing newline if desired) to a /proc/sys
// path. Direct open()/write()/close() — no fork, no shell.
//
// Returns 0 on success, -1 on failure (errno preserved). Use this instead of
// `system("echo ... > /proc/sys/...")` everywhere.
int pv_sysctl_write(const char *path, const char *value);

#endif

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

#ifndef PV_HOOK_HOOKS_H
#define PV_HOOK_HOOKS_H

#include <stdbool.h>

int pv_hooks_set_env(const char *env[][2], int size);
int pv_hooks_set_var(const char *key, const char *value);
void pv_hooks_unset_var(const char *key);
void pv_hooks_unset_env(const char **env, int size);
void pv_hooks_unset_default_env(const char **extra_env, int size);
void pv_hooks_set_default_env(const char *pv_op, const char *pv_rev,
			      const char *pv_try, const char *extra_env[][2],
			      int size);
int pv_hooks_run(const char *dir, bool log);

#endif

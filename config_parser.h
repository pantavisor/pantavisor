/*
 * Copyright (c) 2021-2025 Pantacor Ltd.
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

#ifndef PV_CONFIG_PARSER_H
#define PV_CONFIG_PARSER_H

#include "utils/list.h"

int config_parse_cmdline(struct dl_list *list, char *hint);
int config_parse_env(struct dl_list *list);
int load_key_value_file(const char *path, struct dl_list *list);
char *config_get_value(struct dl_list *list, char *key);
void config_iterate_items(struct dl_list *list,
			  int (*action)(const char *key, const char *value,
					void *opaque),
			  void *opaque);
void config_iterate_items_prefix(struct dl_list *list,
				 int (*action)(const char *key,
					       const char *value, void *opaque),
				 char *prefix, void *opaque);
void config_clear_items(struct dl_list *list);

char *pv_config_parser_sysctl_key(const char *key);

#endif

/*
 * Copyright (c) 2017 Pantacor Ltd.
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
#ifndef PV_PARSER_H
#define PV_PARSER_H

#include <stdbool.h>

#include "pantavisor.h"

//  pantavisor-multi-platform@1
struct pv_state* multi1_parse(struct pantavisor *pv, struct pv_state *this, char *buf);
char* multi1_parse_initrd_config_name(char *buf);

//  pantavisor-service-system@1
struct pv_state* system1_parse(struct pantavisor *pv, struct pv_state *this, char *buf);
char* system1_parse_initrd_config_name(char *buf);

struct pv_state* pv_parser_get_state(struct pantavisor *pv, char *buf, const char *rev);
char* pv_parser_get_initrd_config_name(char *buf);

#endif

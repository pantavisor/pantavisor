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
#ifndef PV_PANTAHUB_MSG_H
#define PV_PANTAHUB_MSG_H

#include <sys/types.h>

struct pv_step {
	char *msg;
	char *progress;
	char *rev;
	char *state;
};

struct pv_object_metadata {
	off_t size;
	char *sha256sum;
	char *geturl;
};

char *pv_pantahub_msg_ser_login_json(const char *user, const char *pass);

char *pv_pantahub_msg_parse_session_token(const char *json);
char *pv_pantahub_msg_parse_next_step(const char *json);

int pv_pantahub_msg_parse_trails(const char *json);

void pv_pantahub_msg_parse_step(const char *json, struct pv_step *step);
void pv_pantahub_msg_print_step(struct pv_step *step);
void pv_pantahub_msg_clean_step(struct pv_step *step);

void pv_pantahub_msg_parse_object_metadata(
	const char *json, struct pv_object_metadata *object_metadata);
void pv_pantahub_msg_print_object_metadata(
	struct pv_object_metadata *object_metadata);
void pv_pantahub_msg_clean_object_metadata(
	struct pv_object_metadata *object_metadata);

#endif

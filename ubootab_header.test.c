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

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "ubootab_header.h"

static void parse_ok(const char *text, const char *rev, long long size)
{
	struct ubootab_header h;

	assert(!ubootab_header_parse(text, strlen(text), &h));
	assert(!strcmp(h.rev, rev));
	assert(h.fit_size == size);
}

static void test_format_layout(void)
{
	char buf[UBOOTAB_HEADER_SIZE];
	const char want[] = "fit_rev=12\nfit_size=20699136\n";

	memset(buf, 0x55, sizeof(buf));
	assert(!ubootab_header_format(buf, "12", 20699136));
	assert(!memcmp(buf, want, sizeof(want) - 1));
	// everything after the text is NUL up to the 4096 byte header
	for (size_t i = sizeof(want) - 1; i < sizeof(buf); i++)
		assert(buf[i] == 0);
}

static void test_format_rejects_bad_rev(void)
{
	char buf[UBOOTAB_HEADER_SIZE];
	char longrev[UBOOTAB_REV_MAX + 8];

	memset(longrev, '1', sizeof(longrev) - 1);
	longrev[sizeof(longrev) - 1] = '\0';

	assert(ubootab_header_format(buf, "", 1));
	assert(ubootab_header_format(buf, NULL, 1));
	assert(ubootab_header_format(buf, "1\n2", 1));
	assert(ubootab_header_format(buf, "a=b", 1));
	assert(ubootab_header_format(buf, longrev, 1));
	assert(ubootab_header_format(buf, "1", -1));
}

static void test_roundtrip(void)
{
	char buf[UBOOTAB_HEADER_SIZE];
	struct ubootab_header h;

	assert(!ubootab_header_format(buf, "locals/dev-3", 4096));
	assert(!ubootab_header_parse(buf, sizeof(buf), &h));
	assert(!strcmp(h.rev, "locals/dev-3"));
	assert(h.fit_size == 4096);
}

static void test_old_header_without_size(void)
{
	char buf[UBOOTAB_HEADER_SIZE] = "fit_rev=7";
	struct ubootab_header h;

	assert(!ubootab_header_parse(buf, sizeof(buf), &h));
	assert(!strcmp(h.rev, "7"));
	assert(h.fit_size == -1);
	parse_ok("fit_rev=7\n", "7", -1);
}

static void test_no_header(void)
{
	unsigned char erased[UBOOTAB_HEADER_SIZE];
	char zeros[UBOOTAB_HEADER_SIZE] = { 0 };
	struct ubootab_header h;

	memset(erased, 0xff, sizeof(erased));
	assert(ubootab_header_parse((char *)erased, sizeof(erased), &h));
	assert(ubootab_header_parse(zeros, sizeof(zeros), &h));
	assert(ubootab_header_parse("fit_rev=\n", 9, &h));
	assert(ubootab_header_parse("fit_size=5\n", 11, &h));
	assert(ubootab_header_parse("", 0, &h));
	assert(!ubootab_header_has_rev(&h, "0"));
}

static void test_exact_rev_match(void)
{
	struct ubootab_header h;

	parse_ok("fit_rev=10\nfit_size=5\n", "10", 5);
	assert(!ubootab_header_parse("fit_rev=10\n", 11, &h));
	assert(ubootab_header_has_rev(&h, "10"));
	assert(!ubootab_header_has_rev(&h, "1"));
	assert(!ubootab_header_has_rev(&h, "100"));
	assert(!ubootab_header_has_rev(NULL, "10"));
	assert(!ubootab_header_has_rev(&h, NULL));
}

static struct ubootab_header hdr(const char *rev)
{
	struct ubootab_header h = { .fit_size = 1 };

	snprintf(h.rev, sizeof(h.rev), "%s", rev);
	return h;
}

static void test_pick_inactive(void)
{
	struct ubootab_header a = hdr("3"), b = hdr("4"), none = hdr("");

	// the partition that holds pv_rev is kept, the other one is written
	assert(ubootab_pick_inactive(&a, &b, "3") == 1);
	assert(ubootab_pick_inactive(&a, &b, "4") == 0);
	// 1 must not match 10 in the other partition
	b = hdr("10");
	assert(ubootab_pick_inactive(&a, &b, "1") == 1);
	assert(ubootab_pick_inactive(&b, &a, "10") == 1);
	assert(ubootab_pick_inactive(&b, &a, "3") == 0);
	// fresh flash: only fitA holds rev 0
	a = hdr("0");
	assert(ubootab_pick_inactive(&a, &none, "0") == 1);
	// nothing matches (erased env, wrong flash): B, which U-Boot never
	// picked over a matching A
	assert(ubootab_pick_inactive(&none, &none, "0") == 1);
	// both hold the same rev: B
	b = hdr("0");
	assert(ubootab_pick_inactive(&a, &b, "0") == 1);
}

int main(void)
{
	test_format_layout();
	test_format_rejects_bad_rev();
	test_roundtrip();
	test_old_header_without_size();
	test_no_header();
	test_exact_rev_match();
	test_pick_inactive();
	puts("ubootab_header: ok");
	return 0;
}

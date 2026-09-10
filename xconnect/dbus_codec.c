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
#include <string.h>
#include "dbus_codec.h"

// D-Bus header field codes (the ones we read).
#define FIELD_INTERFACE 2
#define FIELD_MEMBER 3
#define FIELD_REPLY_SERIAL 5
#define FIELD_DESTINATION 6

#define DBUS_IFACE "org.freedesktop.DBus"
#define DBUS_PATH "/org/freedesktop/DBus"

static inline size_t align8(size_t n)
{
	return (n + 7u) & ~((size_t)7u);
}
static inline size_t align4(size_t n)
{
	return (n + 3u) & ~((size_t)3u);
}

static uint32_t rd32(const uint8_t *p, bool little)
{
	if (little)
		return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
		       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
	return (uint32_t)p[3] | ((uint32_t)p[2] << 8) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[0] << 24);
}

static void wr32(uint8_t *p, uint32_t v, bool little)
{
	if (little) {
		p[0] = v & 0xff;
		p[1] = (v >> 8) & 0xff;
		p[2] = (v >> 16) & 0xff;
		p[3] = (v >> 24) & 0xff;
	} else {
		p[3] = v & 0xff;
		p[2] = (v >> 8) & 0xff;
		p[1] = (v >> 16) & 0xff;
		p[0] = (v >> 24) & 0xff;
	}
}

// Read a marshaled STRING/OBJECT_PATH ('s'/'o') at *pp (already 4-aligned by the
// caller as needed): UINT32 len, `len` bytes, NUL. Copies into dst (cap bytes,
// truncating safely) and advances *pp. Returns false on bounds error.
static bool read_string(const uint8_t *buf, size_t end, size_t *pp, bool little,
			char *dst, size_t cap)
{
	size_t p = align4(*pp);
	if (p + 4 > end)
		return false;
	uint32_t len = rd32(buf + p, little);
	p += 4;
	if (p + (size_t)len + 1 > end)
		return false;
	if (dst) {
		size_t n = len < cap - 1 ? len : cap - 1;
		memcpy(dst, buf + p, n);
		dst[n] = '\0';
	}
	p += (size_t)len + 1; // skip string + trailing NUL
	*pp = p;
	return true;
}

bool pv_dbus_read_string(const uint8_t *buf, size_t end, size_t *pp,
			 bool little, char *dst, size_t cap)
{
	return read_string(buf, end, pp, little, dst, cap);
}

int pv_dbus_msg_parse(const uint8_t *buf, size_t avail, struct pv_dbus_msg *out)
{
	memset(out, 0, sizeof(*out));
	if (avail < 16)
		return 0; // need fixed header (12) + fields array length (4)

	bool little;
	if (buf[0] == 'l')
		little = true;
	else if (buf[0] == 'B')
		little = false;
	else
		return -1;

	out->little = little;
	out->type = buf[1];
	out->flags = buf[2];
	uint32_t body_len = rd32(buf + 4, little);
	out->serial = rd32(buf + 8, little);
	uint32_t fields_len = rd32(buf + 12, little);

	size_t header_end = 16 + (size_t)fields_len;
	size_t body_off = align8(header_end);
	size_t total = body_off + (size_t)body_len;

	// Guard against overflow / absurd sizes before publishing total_len.
	if (header_end < 16 || total < body_off)
		return -1;
	out->body_off = body_off;
	out->total_len = total;

	if (avail < total)
		return 0; // framed but not all bytes here yet

	// Walk the header fields array [16, header_end) to lift the fields we
	// gate on. Each element is a STRUCT (8-aligned): BYTE code, VARIANT.
	size_t p = 16;
	while (p < header_end) {
		p = align8(p);
		if (p >= header_end)
			break;
		uint8_t code = buf[p++];
		if (p >= header_end)
			return -1;
		// VARIANT: SIGNATURE (BYTE len, bytes, NUL) then the value.
		uint8_t siglen = buf[p++];
		if (p + (size_t)siglen + 1 > header_end)
			return -1;
		char sig = siglen ? (char)buf[p] : 0;
		p += (size_t)siglen + 1; // signature bytes + NUL

		if (sig == 's' || sig == 'o') {
			char *dst = NULL;
			if (code == FIELD_DESTINATION)
				dst = out->destination;
			else if (code == FIELD_MEMBER)
				dst = out->member;
			else if (code == FIELD_INTERFACE)
				dst = out->interface;
			if (!read_string(buf, header_end, &p, little, dst,
					 PV_DBUS_STR_MAX))
				return -1;
		} else if (sig == 'g') {
			uint8_t gl = buf[p++];
			if (p + (size_t)gl + 1 > header_end)
				return -1;
			p += (size_t)gl + 1;
		} else if (sig == 'u' || sig == 'i') {
			p = align4(p);
			if (p + 4 > header_end)
				return -1;
			if (code == FIELD_REPLY_SERIAL)
				out->reply_serial = rd32(buf + p, little);
			p += 4;
		} else {
			// A field type we don't model — we can't compute its
			// length, so we cannot safely continue the walk.
			return -1;
		}
	}
	return 1;
}

bool pv_dbus_parse_name_owner_changed(const uint8_t *buf, size_t avail,
				      char *name, char *new_owner)
{
	struct pv_dbus_msg m;
	if (pv_dbus_msg_parse(buf, avail, &m) != 1)
		return false;
	if (m.type != PV_DBUS_TYPE_SIGNAL)
		return false;

	// Body signature is "sss": name, old_owner, new_owner.
	size_t p = m.body_off;
	char skip[PV_DBUS_STR_MAX];
	if (!read_string(buf, m.total_len, &p, m.little, name, PV_DBUS_STR_MAX))
		return false;
	if (!read_string(buf, m.total_len, &p, m.little, skip, PV_DBUS_STR_MAX))
		return false;
	if (!read_string(buf, m.total_len, &p, m.little, new_owner,
			 PV_DBUS_STR_MAX))
		return false;
	return true;
}

// --- builders --------------------------------------------------------------

// Append a string header field (code + variant("s"/"o", value)) at 8-aligned
// struct boundary. Returns false on overflow.
static bool put_field_str(uint8_t *buf, size_t cap, size_t *pp, uint8_t code,
			  char sig, const char *val, bool little)
{
	size_t p = align8(*pp);
	size_t vlen = strlen(val);
	// worst case: 4 (code+sig header) + 4 align + 4 len + vlen + 1
	if (p + 8 + 4 + vlen + 1 > cap)
		return false;
	buf[p++] = code;
	buf[p++] = 1; // signature length
	buf[p++] = (uint8_t)sig;
	buf[p++] = 0; // signature NUL
	p = align4(p);
	wr32(buf + p, (uint32_t)vlen, little);
	p += 4;
	memcpy(buf + p, val, vlen);
	p += vlen;
	buf[p++] = 0;
	*pp = p;
	return true;
}

// Append a SIGNATURE ('g') header field: value marshals as a single length
// BYTE + bytes + NUL (not a UINT32-prefixed string). Used for the body
// signature field (code 8).
static bool put_field_sig(uint8_t *buf, size_t cap, size_t *pp, uint8_t code,
			  const char *val)
{
	size_t p = align8(*pp);
	size_t vlen = strlen(val);
	if (p + 4 + 1 + vlen + 1 > cap)
		return false;
	buf[p++] = code;
	buf[p++] = 1; // variant signature length
	buf[p++] = 'g'; // variant signature is "g"
	buf[p++] = 0;
	buf[p++] = (uint8_t)vlen; // signature value: length byte
	memcpy(buf + p, val, vlen);
	p += vlen;
	buf[p++] = 0;
	*pp = p;
	return true;
}

// Marshal a plain string body ("s"): UINT32 len + bytes + NUL at *pp.
static bool put_body_str(uint8_t *buf, size_t cap, size_t *pp, const char *val,
			 bool little)
{
	size_t p = *pp; // body starts 8-aligned already
	size_t vlen = strlen(val);
	if (p + 4 + vlen + 1 > cap)
		return false;
	wr32(buf + p, (uint32_t)vlen, little);
	p += 4;
	memcpy(buf + p, val, vlen);
	p += vlen;
	buf[p++] = 0;
	*pp = p;
	return true;
}

static size_t finalize(uint8_t *buf, size_t fields_start, size_t fields_end,
		       size_t body_start, size_t body_end, bool little)
{
	wr32(buf + 4, (uint32_t)(body_end - body_start), little); // body_len
	wr32(buf + 12, (uint32_t)(fields_end - fields_start), little); // fields
	return body_end;
}

size_t pv_dbus_build_call(uint8_t *buf, size_t cap, uint32_t serial,
			  const char *member, const char *str_arg)
{
	if (cap < 16)
		return 0;
	bool little = true;
	memset(buf, 0, cap);
	buf[0] = 'l';
	buf[1] = PV_DBUS_TYPE_METHOD_CALL;
	buf[2] = 0;
	buf[3] = 1;
	wr32(buf + 8, serial, little);

	size_t p = 16; // header fields start
	if (!put_field_str(buf, cap, &p, 1, 'o', DBUS_PATH, little) ||
	    !put_field_str(buf, cap, &p, FIELD_DESTINATION, 's', DBUS_IFACE,
			   little) ||
	    !put_field_str(buf, cap, &p, FIELD_INTERFACE, 's', DBUS_IFACE,
			   little) ||
	    !put_field_str(buf, cap, &p, FIELD_MEMBER, 's', member, little))
		return 0;
	if (str_arg && !put_field_sig(buf, cap, &p, 8, "s"))
		return 0;

	size_t fields_end = p;
	size_t body_start = align8(p);
	if (body_start > cap)
		return 0;
	// zero any pad bytes between fields and body
	for (size_t z = fields_end; z < body_start; z++)
		buf[z] = 0;
	size_t body_end = body_start;
	if (str_arg && !put_body_str(buf, cap, &body_end, str_arg, little))
		return 0;

	return finalize(buf, 16, fields_end, body_start, body_end, little);
}

size_t pv_dbus_build_error(uint8_t *buf, size_t cap, uint32_t serial,
			   uint32_t reply_serial, const char *error_name,
			   const char *message)
{
	if (cap < 16)
		return 0;
	bool little = true;
	memset(buf, 0, cap);
	buf[0] = 'l';
	buf[1] = PV_DBUS_TYPE_ERROR;
	buf[2] = PV_DBUS_FLAG_NO_REPLY_EXPECTED;
	buf[3] = 1;
	wr32(buf + 8, serial, little);

	size_t p = 16;
	// ERROR_NAME(s)=4, REPLY_SERIAL(u)=5, SIGNATURE(g)="s"=8
	if (!put_field_str(buf, cap, &p, 4, 's', error_name, little))
		return 0;
	// REPLY_SERIAL is a UINT32 variant.
	p = align8(p);
	if (p + 8 + 4 > cap)
		return 0;
	buf[p++] = 5;
	buf[p++] = 1;
	buf[p++] = 'u';
	buf[p++] = 0;
	p = align4(p);
	wr32(buf + p, reply_serial, little);
	p += 4;
	if (!put_field_sig(buf, cap, &p, 8, "s"))
		return 0;

	size_t fields_end = p;
	size_t body_start = align8(p);
	for (size_t z = fields_end; z < body_start; z++)
		buf[z] = 0;
	size_t body_end = body_start;
	if (!put_body_str(buf, cap, &body_end, message ? message : "", little))
		return 0;

	return finalize(buf, 16, fields_end, body_start, body_end, little);
}

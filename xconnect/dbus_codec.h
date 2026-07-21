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
#ifndef PV_XCONNECT_DBUS_CODEC_H
#define PV_XCONNECT_DBUS_CODEC_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// A deliberately minimal D-Bus wire codec: just enough to frame messages on the
// hosted-bus proxy path, read the header fields we gate activation on
// (DESTINATION, MEMBER, INTERFACE, the NO_AUTO_START flag), parse the
// NameOwnerChanged signal body, and build the few method calls the activation
// monitor connection needs (Hello, AddMatch). It is NOT a general marshaller.

// D-Bus message types (header byte 1).
#define PV_DBUS_TYPE_METHOD_CALL 1
#define PV_DBUS_TYPE_METHOD_RETURN 2
#define PV_DBUS_TYPE_ERROR 3
#define PV_DBUS_TYPE_SIGNAL 4

// D-Bus header flags (header byte 2).
#define PV_DBUS_FLAG_NO_REPLY_EXPECTED 0x1
#define PV_DBUS_FLAG_NO_AUTO_START 0x2

#define PV_DBUS_STR_MAX 256

struct pv_dbus_msg {
	uint8_t type;
	uint8_t flags;
	bool little; // wire byte order
	uint32_t serial;
	uint32_t reply_serial; // REPLY_SERIAL header field (0 if absent)
	size_t body_off; // offset of the body within the message
	size_t total_len; // full on-wire size of this message (header+pad+body)
	// Selected header fields (empty string if absent).
	char destination[PV_DBUS_STR_MAX];
	char member[PV_DBUS_STR_MAX];
	char interface[PV_DBUS_STR_MAX];
};

// Parse the message at the start of `buf` (`avail` bytes readable).
//   returns  1  a full message is present; *out filled, out->total_len set.
//   returns  0  incomplete — need more bytes (out->total_len set to the needed
//               size once the 16-byte prefix is available, else 0).
//   returns -1  malformed (caller should drop the connection).
int pv_dbus_msg_parse(const uint8_t *buf, size_t avail,
		      struct pv_dbus_msg *out);

// True if the signal in `buf`/`avail` (assumed a full, already-parsed message of
// type SIGNAL with member NameOwnerChanged) yields its body triple. `name` and
// `new_owner` receive the 1st and 3rd string args (PV_DBUS_STR_MAX buffers).
// Returns false on any parse error.
bool pv_dbus_parse_name_owner_changed(const uint8_t *buf, size_t avail,
				      char *name, char *new_owner);

// Read a marshaled STRING/OBJECT_PATH at *pp (advancing it past the value),
// with 4-byte alignment applied first. `end` bounds the buffer. Copies into dst
// (cap bytes, safely truncated) if non-NULL. Returns false on bounds error.
// Exposed so callers can walk a method_return body (e.g. ListNames "as").
bool pv_dbus_read_string(const uint8_t *buf, size_t end, size_t *pp,
			 bool little, char *dst, size_t cap);

// Build a method_call to org.freedesktop.DBus with the given member and an
// optional single string argument (NULL for none, e.g. Hello). Writes at most
// `cap` bytes; returns the number written, or 0 on overflow.
size_t pv_dbus_build_call(uint8_t *buf, size_t cap, uint32_t serial,
			  const char *member, const char *str_arg);

// Build an org.freedesktop.DBus.Error method-return-shaped error reply to
// `reply_serial`, carrying `error_name` and a human message. Used to fail a held
// activation cleanly instead of hanging the client. Returns bytes written or 0.
size_t pv_dbus_build_error(uint8_t *buf, size_t cap, uint32_t serial,
			   uint32_t reply_serial, const char *error_name,
			   const char *message);

#endif /* PV_XCONNECT_DBUS_CODEC_H */

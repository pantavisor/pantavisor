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
 *
 * SPDX-License-Identifier: MIT
 *
 * dcp-blob-create: Create a valid mainline Linux kernel DCP trusted key blob
 *                  from a plaintext key read on stdin.
 *
 * The output blob can be loaded with:
 *   keyctl add trusted <name> "load <hex_blob>" @u
 *
 * This enables migration from legacy DCP key formats (x--pv-dcp-tool) to
 * mainline trusted keys without the kernel import patch.
 *
 * Algorithm:
 *   1. Read plaintext key from stdin
 *   2. Generate random BEK (blob encryption key)
 *   3. Encrypt BEK with DCP UNIQUE key via ecb(aes) zero-length key
 *   4. Encrypt plaintext key with BEK via gcm(aes)
 *   5. Assemble blob in kernel-expected format and output as hex
 *
 * Build:
 *   cc -o dcp-blob-create dcp-blob-create.c -lkcapi
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <endian.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <kcapi.h>

/*
 * From kernel security/keys/trusted-keys/trusted_dcp.c:
 *
 * struct dcp_blob_fmt {
 *     __u8  fmt_version;
 *     __u8  blob_key[AES_KEYSIZE_128];
 *     __u8  nonce[AES_KEYSIZE_128];
 *     __le32 payload_len;
 *     __u8  payload[];    // encrypted payload + 16-byte GCM auth tag
 * };
 */

#define DCP_BLOB_VERSION 0x01
#define AES_KEYSIZE_128 16
#define GCM_AES_IV_SIZE 16
#define DCP_BLOB_AUTHLEN 16
#define MAX_KEY_SIZE 128

static int read_random(void *buf, size_t len)
{
	int fd;
	ssize_t n;

	fd = open("/dev/hwrng", O_RDONLY);
	if (fd < 0) {
		fd = open("/dev/urandom", O_RDONLY);
		if (fd < 0) {
			perror("open random source");
			return -1;
		}
		fprintf(stderr,
			"WARNING: /dev/hwrng not available, using /dev/urandom\n");
	}

	n = read(fd, buf, len);
	close(fd);

	if (n != (ssize_t)len) {
		fprintf(stderr,
			"short read from random source: got %zd, want %zu\n",
			n, len);
		return -1;
	}

	return 0;
}

/*
 * Encrypt the BEK with DCP hardware key (UNIQUE or OTP depending on fuses).
 *
 * The kernel trusted_dcp.c uses "ecb-paes-dcp" (CRYPTO_ALG_INTERNAL) with
 * a 1-byte paes key reference (DCP_PAES_KEY_UNIQUE=0xfe or OTP=0xff).
 * That cipher is not accessible from userspace.
 *
 * From userspace we use "ecb(aes)" with a zero-length key. The NXP DCP
 * kernel patch maps a zero-length key to the same DCP hardware key
 * (UNIQUE or OTP based on device fuse state). The encryption result is
 * identical — same hardware AES engine, same key material.
 */
static int encrypt_bek(const uint8_t *bek, uint8_t *encrypted_bek)
{
	struct kcapi_handle *handle = NULL;
	int ret;

	ret = kcapi_cipher_init(&handle, "ecb(aes)", 0);
	if (ret) {
		fprintf(stderr, "kcapi_cipher_init(ecb(aes)) failed: %d\n",
			ret);
		return -1;
	}

	/*
	 * Zero-length key: the NXP DCP kernel patch interprets this as
	 * "use the DCP hardware key" (UNIQUE or OTP depending on fuses).
	 * This produces the same result as the kernel-internal ecb-paes-dcp
	 * cipher used by trusted_dcp.c.
	 *
	 * Requires NXP DCP kernel patch that maps /dev/null (zero-length)
	 * keyfile to the hardware key.
	 */
	ret = kcapi_cipher_setkey(handle, (const uint8_t *)"", 0);
	if (ret) {
		fprintf(stderr,
			"kcapi_cipher_setkey (zero-length) failed: %d\n"
			"Is the NXP DCP driver loaded with null-key support?\n",
			ret);
		kcapi_cipher_destroy(handle);
		return -1;
	}

	ret = kcapi_cipher_encrypt(handle, bek, AES_KEYSIZE_128, NULL,
				   encrypted_bek, AES_KEYSIZE_128, 0);
	if (ret != AES_KEYSIZE_128) {
		fprintf(stderr, "kcapi_cipher_encrypt failed: %d\n", ret);
		kcapi_cipher_destroy(handle);
		return -1;
	}

	kcapi_cipher_destroy(handle);
	return 0;
}

/*
 * Encrypt the plaintext key with BEK using AES-128-GCM.
 *
 * The kernel DCP blob uses a 16-byte nonce field. The kernel GCM
 * implementation takes the IV buffer as-is (the kernel gcm code uses
 * the full buffer passed to it). We pass the 16-byte nonce to match
 * the kernel behavior exactly.
 */
static int encrypt_payload(const uint8_t *bek, const uint8_t *nonce,
			   const uint8_t *plaintext, size_t pt_len,
			   uint8_t *ciphertext, size_t *ct_len)
{
	struct kcapi_handle *handle = NULL;
	int ret;

	ret = kcapi_aead_init(&handle, "gcm(aes)", 0);
	if (ret) {
		fprintf(stderr, "kcapi_aead_init(gcm(aes)) failed: %d\n", ret);
		return -1;
	}

	ret = kcapi_aead_setkey(handle, bek, AES_KEYSIZE_128);
	if (ret) {
		fprintf(stderr, "kcapi_aead_setkey failed: %d\n", ret);
		kcapi_aead_destroy(handle);
		return -1;
	}

	kcapi_aead_settaglen(handle, DCP_BLOB_AUTHLEN);
	kcapi_aead_setassoclen(handle, 0);

	/*
	 * GCM encrypt: output is ciphertext (same length as plaintext)
	 * followed by the authentication tag (16 bytes).
	 */
	ret = kcapi_aead_encrypt(handle, plaintext, pt_len, nonce, ciphertext,
				 pt_len + DCP_BLOB_AUTHLEN, 0);
	if (ret < 0) {
		fprintf(stderr, "kcapi_aead_encrypt failed: %d\n", ret);
		kcapi_aead_destroy(handle);
		return -1;
	}

	*ct_len = (size_t)ret;
	kcapi_aead_destroy(handle);
	return 0;
}

static void hexdump(const uint8_t *data, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		printf("%02x", data[i]);
}

int main(void)
{
	uint8_t plaintext[MAX_KEY_SIZE];
	uint8_t bek[AES_KEYSIZE_128];
	uint8_t encrypted_bek[AES_KEYSIZE_128];
	uint8_t nonce[GCM_AES_IV_SIZE];
	uint8_t ciphertext[MAX_KEY_SIZE + DCP_BLOB_AUTHLEN];
	size_t ct_len = 0;
	uint32_t payload_len_le;
	ssize_t pt_len;

	/* Read plaintext key from stdin */
	pt_len = read(STDIN_FILENO, plaintext, sizeof(plaintext));
	if (pt_len <= 0) {
		fprintf(stderr, "failed to read plaintext key from stdin\n");
		return 1;
	}

	fprintf(stderr, "read %zd byte plaintext key\n", pt_len);

	/* Generate random BEK */
	if (read_random(bek, sizeof(bek)) != 0)
		return 1;

	/* Generate random nonce */
	if (read_random(nonce, sizeof(nonce)) != 0)
		return 1;

	/* Encrypt BEK with DCP UNIQUE key */
	if (encrypt_bek(bek, encrypted_bek) != 0)
		return 1;

	/* Encrypt plaintext key with BEK */
	if (encrypt_payload(bek, nonce, plaintext, (size_t)pt_len, ciphertext,
			    &ct_len) != 0)
		return 1;

	/*
	 * Output blob as hex string to stdout.
	 * Format: version(1) | encrypted_bek(16) | nonce(16) |
	 *         payload_len(4) | payload+tag
	 *
	 * This is what keyctl add trusted <name> "load <hex>" expects.
	 */
	payload_len_le = htole32((uint32_t)pt_len);

	hexdump((uint8_t[]){ DCP_BLOB_VERSION }, 1);
	hexdump(encrypted_bek, AES_KEYSIZE_128);
	hexdump(nonce, GCM_AES_IV_SIZE);
	hexdump((uint8_t *)&payload_len_le, 4);
	hexdump(ciphertext, ct_len);
	printf("\n");

	/* Scrub sensitive material */
	memset(plaintext, 0, sizeof(plaintext));
	memset(bek, 0, sizeof(bek));

	return 0;
}

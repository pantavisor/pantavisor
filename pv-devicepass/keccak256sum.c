/*
 * keccak256sum.c - Self-contained Keccak-256 hash (Ethereum variant)
 *
 * Implements the original Keccak-256 submission (NOT NIST SHA-3).
 * Ethereum uses Keccak with 0x01 padding, not SHA-3's 0x06 padding.
 *
 * Usage:
 *   keccak256sum [FILE]           Read file, output 64 hex chars
 *   echo -n "data" | keccak256sum Read stdin
 *   keccak256sum --hex < file     Read hex-encoded input
 *   keccak256sum --raw < file     Output raw 32 bytes (binary)
 *
 * Public domain Keccak-f[1600] sponge construction.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Keccak-f[1600] round constants */
static const uint64_t RC[24] = {
	0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL,
	0x8000000080008000ULL, 0x000000000000808BULL, 0x0000000080000001ULL,
	0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008AULL,
	0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
	0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL,
	0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
	0x000000000000800AULL, 0x800000008000000AULL, 0x8000000080008081ULL,
	0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

/* Rotation offsets */
static const int ROTC[24] = { 1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
			       27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44 };

/* Pi permutation indices */
static const int PILN[24] = { 10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
			       15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1 };

static inline uint64_t
rotl64(uint64_t x, int n)
{
	return (x << n) | (x >> (64 - n));
}

/* Keccak-f[1600] permutation */
static void
keccakf(uint64_t st[25])
{
	uint64_t t, bc[5];
	int i, j, r;

	for (r = 0; r < 24; r++) {
		/* Theta */
		for (i = 0; i < 5; i++)
			bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^
				st[i + 20];
		for (i = 0; i < 5; i++) {
			t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
			for (j = 0; j < 25; j += 5)
				st[j + i] ^= t;
		}

		/* Rho and Pi */
		t = st[1];
		for (i = 0; i < 24; i++) {
			j = PILN[i];
			bc[0] = st[j];
			st[j] = rotl64(t, ROTC[i]);
			t = bc[0];
		}

		/* Chi */
		for (j = 0; j < 25; j += 5) {
			for (i = 0; i < 5; i++)
				bc[i] = st[j + i];
			for (i = 0; i < 5; i++)
				st[j + i] ^= (~bc[(i + 1) % 5]) &
					      bc[(i + 2) % 5];
		}

		/* Iota */
		st[0] ^= RC[r];
	}
}

/* Keccak-256 context */
struct keccak256_ctx {
	uint64_t state[25];
	uint8_t buf[136]; /* rate = 1088 bits = 136 bytes */
	size_t buflen;
};

static void
keccak256_init(struct keccak256_ctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
}

static void
keccak256_update(struct keccak256_ctx *ctx, const uint8_t *data, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		ctx->buf[ctx->buflen++] = data[i];
		if (ctx->buflen == 136) {
			size_t j;
			for (j = 0; j < 136 / 8; j++) {
				uint64_t v;
				memcpy(&v, ctx->buf + j * 8, 8);
				ctx->state[j] ^= v;
			}
			keccakf(ctx->state);
			ctx->buflen = 0;
		}
	}
}

static void
keccak256_final(struct keccak256_ctx *ctx, uint8_t hash[32])
{
	size_t j;

	/* Keccak padding: 0x01 ... 0x80 (NOT SHA-3's 0x06) */
	memset(ctx->buf + ctx->buflen, 0, 136 - ctx->buflen);
	ctx->buf[ctx->buflen] = 0x01;
	ctx->buf[135] |= 0x80;

	for (j = 0; j < 136 / 8; j++) {
		uint64_t v;
		memcpy(&v, ctx->buf + j * 8, 8);
		ctx->state[j] ^= v;
	}
	keccakf(ctx->state);

	/* Squeeze 32 bytes (256 bits) */
	memcpy(hash, ctx->state, 32);
}

/* Convert one hex char to nibble, return -1 on error */
static int
hexchar(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static void
usage(void)
{
	fprintf(stderr,
		"Usage: keccak256sum [OPTIONS] [FILE]\n"
		"  --hex    Read hex-encoded input\n"
		"  --raw    Output raw binary (32 bytes)\n"
		"  -h       Show this help\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	struct keccak256_ctx ctx;
	uint8_t hash[32];
	FILE *f = NULL;
	int hex_input = 0;
	int raw_output = 0;
	const char *filename = NULL;
	int i;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--hex") == 0)
			hex_input = 1;
		else if (strcmp(argv[i], "--raw") == 0)
			raw_output = 1;
		else if (strcmp(argv[i], "-h") == 0 ||
			 strcmp(argv[i], "--help") == 0)
			usage();
		else if (argv[i][0] != '-')
			filename = argv[i];
		else
			usage();
	}

	if (filename) {
		f = fopen(filename, "rb");
		if (!f) {
			perror(filename);
			return 1;
		}
	} else {
		f = stdin;
	}

	keccak256_init(&ctx);

	if (hex_input) {
		/* Read hex-encoded input, convert to binary, hash */
		int c1, c2;
		int n1, n2;
		while ((c1 = fgetc(f)) != EOF) {
			/* Skip whitespace */
			if (c1 == ' ' || c1 == '\n' || c1 == '\r' ||
			    c1 == '\t')
				continue;
			c2 = fgetc(f);
			if (c2 == EOF) {
				fprintf(stderr,
					"keccak256sum: odd number of hex digits\n");
				return 1;
			}
			n1 = hexchar(c1);
			n2 = hexchar(c2);
			if (n1 < 0 || n2 < 0) {
				fprintf(stderr,
					"keccak256sum: invalid hex input\n");
				return 1;
			}
			uint8_t byte = (n1 << 4) | n2;
			keccak256_update(&ctx, &byte, 1);
		}
	} else {
		/* Read raw binary input */
		uint8_t buf[4096];
		size_t n;
		while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
			keccak256_update(&ctx, buf, n);
	}

	keccak256_final(&ctx, hash);

	if (filename && f != stdin)
		fclose(f);

	if (raw_output) {
		fwrite(hash, 1, 32, stdout);
	} else {
		for (i = 0; i < 32; i++)
			printf("%02x", hash[i]);
		printf("\n");
	}

	return 0;
}

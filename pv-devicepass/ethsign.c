/*
 * ethsign.c - Ethereum-compatible secp256k1 ECDSA tool using mbedtls
 *
 * Usage:
 *   ethsign genkey [--dir DIR]     Generate keypair (device.key, device.pub.hex)
 *   ethsign pubkey --key FILE      Extract uncompressed pubkey (hex, no 04 prefix)
 *   ethsign sign --key FILE HASH   Sign 32-byte hex hash, output r+s+v (130 hex)
 *
 * Links: mbedcrypto
 */

#include <mbedtls/bignum.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* --- Hex helpers --- */

static int
hex2bin(const char *hex, unsigned char *bin, size_t bin_len)
{
	size_t i;
	for (i = 0; i < bin_len; i++) {
		int hi, lo;
		char c;

		c = hex[i * 2];
		if (c >= '0' && c <= '9')
			hi = c - '0';
		else if (c >= 'a' && c <= 'f')
			hi = c - 'a' + 10;
		else if (c >= 'A' && c <= 'F')
			hi = c - 'A' + 10;
		else
			return -1;

		c = hex[i * 2 + 1];
		if (c >= '0' && c <= '9')
			lo = c - '0';
		else if (c >= 'a' && c <= 'f')
			lo = c - 'a' + 10;
		else if (c >= 'A' && c <= 'F')
			lo = c - 'A' + 10;
		else
			return -1;

		bin[i] = (hi << 4) | lo;
	}
	return 0;
}

static void
bin2hex(const unsigned char *bin, size_t len, char *hex)
{
	size_t i;
	for (i = 0; i < len; i++)
		sprintf(hex + i * 2, "%02x", bin[i]);
	hex[len * 2] = '\0';
}

/* Write MPI as zero-padded big-endian hex (pad_bytes * 2 hex chars) */
static int
mpi_to_hex(const mbedtls_mpi *m, char *hex, size_t pad_bytes)
{
	unsigned char buf[64];
	int ret;

	if (pad_bytes > sizeof(buf))
		return -1;
	ret = mbedtls_mpi_write_binary(m, buf, pad_bytes);
	if (ret != 0)
		return ret;
	bin2hex(buf, pad_bytes, hex);
	return 0;
}

/* Read hex file into buffer, return length or -1 */
static int
read_hex_file(const char *path, char *buf, size_t maxlen)
{
	FILE *f;
	size_t n;

	f = fopen(path, "r");
	if (!f)
		return -1;
	n = fread(buf, 1, maxlen - 1, f);
	fclose(f);
	/* Strip trailing whitespace */
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' ||
			 buf[n - 1] == ' '))
		n--;
	buf[n] = '\0';
	return (int)n;
}

/* Load private key from hex file into MPI */
static int
load_privkey(const char *path, mbedtls_mpi *d)
{
	char hex[128];
	unsigned char bin[32];
	int n;

	n = read_hex_file(path, hex, sizeof(hex));
	if (n != 64) {
		fprintf(stderr, "ethsign: invalid key file (expected 64 hex chars, got %d)\n",
			n);
		return -1;
	}
	if (hex2bin(hex, bin, 32) != 0) {
		fprintf(stderr, "ethsign: invalid hex in key file\n");
		return -1;
	}
	return mbedtls_mpi_read_binary(d, bin, 32);
}

/* Compute public key Q = d * G on secp256k1 */
static int
compute_pubkey(const mbedtls_mpi *d, mbedtls_ecp_point *Q,
	       mbedtls_ecp_group *grp)
{
	return mbedtls_ecp_mul(grp, Q, d, &grp->G, NULL, NULL);
}

/* Output public key as 128 hex chars (x || y, no 04 prefix) */
static int
output_pubkey(const mbedtls_ecp_point *Q, char *hex)
{
	if (mpi_to_hex(&Q->X, hex, 32) != 0)
		return -1;
	if (mpi_to_hex(&Q->Y, hex + 64, 32) != 0)
		return -1;
	return 0;
}

/*
 * Recover public key from ECDSA signature for v determination.
 * v_bit: 0 or 1 (y-parity of R point)
 * Returns 0 on success, recovered key in Q_rec.
 */
static int
ecrecover(mbedtls_ecp_group *grp, const mbedtls_mpi *r, const mbedtls_mpi *s,
	  int v_bit, const unsigned char *hash, size_t hlen,
	  mbedtls_ecp_point *Q_rec)
{
	mbedtls_ecp_point R;
	mbedtls_mpi r_inv, u1, u2, tmp, y2, exp, z;
	int ret;

	mbedtls_ecp_point_init(&R);
	mbedtls_mpi_init(&r_inv);
	mbedtls_mpi_init(&u1);
	mbedtls_mpi_init(&u2);
	mbedtls_mpi_init(&tmp);
	mbedtls_mpi_init(&y2);
	mbedtls_mpi_init(&exp);
	mbedtls_mpi_init(&z);

	/* R.X = r */
	MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&R.X, r));

	/* Compute R.Y from curve equation: y^2 = x^3 + 7 (mod P) */
	/* tmp = x^2 mod P */
	MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&tmp, &R.X, &R.X));
	MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tmp, &tmp, &grp->P));
	/* tmp = x^3 mod P */
	MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&tmp, &tmp, &R.X));
	MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tmp, &tmp, &grp->P));
	/* y2 = x^3 + 7 mod P */
	MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&y2, &tmp, 7));
	MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&y2, &y2, &grp->P));

	/*
	 * sqrt via Euler criterion: P ≡ 3 (mod 4) for secp256k1
	 * so sqrt(a) = a^((P+1)/4) mod P
	 */
	MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&exp, &grp->P, 1));
	MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(&exp, 2));
	MBEDTLS_MPI_CHK(
		mbedtls_mpi_exp_mod(&R.Y, &y2, &exp, &grp->P, NULL));

	/* Verify: R.Y^2 mod P == y2? */
	MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&tmp, &R.Y, &R.Y));
	MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&tmp, &tmp, &grp->P));
	if (mbedtls_mpi_cmp_mpi(&tmp, &y2) != 0) {
		ret = MBEDTLS_ERR_ECP_INVALID_KEY;
		goto cleanup;
	}

	/* Fix parity: if v_bit doesn't match LSB of Y, negate Y */
	if ((mbedtls_mpi_get_bit(&R.Y, 0) != 0) != (v_bit != 0)) {
		MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&R.Y, &grp->P, &R.Y));
	}

	/* R.Z = 1 (affine) */
	MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&R.Z, 1));

	/* z = hash as big-endian integer */
	MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&z, hash, hlen));

	/* r_inv = r^(-1) mod N */
	MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod(&r_inv, r, &grp->N));

	/* u1 = (-z * r_inv) mod N = (N - z mod N) * r_inv mod N */
	MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&u1, &z, &grp->N));
	MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&u1, &grp->N, &u1));
	MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&u1, &u1, &r_inv));
	MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&u1, &u1, &grp->N));

	/* u2 = s * r_inv mod N */
	MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&u2, s, &r_inv));
	MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&u2, &u2, &grp->N));

	/* Q_rec = u1*G + u2*R */
	MBEDTLS_MPI_CHK(
		mbedtls_ecp_muladd(grp, Q_rec, &u1, &grp->G, &u2, &R));

cleanup:
	mbedtls_ecp_point_free(&R);
	mbedtls_mpi_free(&r_inv);
	mbedtls_mpi_free(&u1);
	mbedtls_mpi_free(&u2);
	mbedtls_mpi_free(&tmp);
	mbedtls_mpi_free(&y2);
	mbedtls_mpi_free(&exp);
	mbedtls_mpi_free(&z);
	return ret;
}

/* --- genkey command --- */

static int
cmd_genkey(const char *dir)
{
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ecp_group grp;
	mbedtls_mpi d;
	mbedtls_ecp_point Q;
	char path[512];
	char hex[130];
	unsigned char bin[32];
	FILE *f;
	int ret = 1;

	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_ecp_group_init(&grp);
	mbedtls_mpi_init(&d);
	mbedtls_ecp_point_init(&Q);

	if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
				   (const unsigned char *)"ethsign", 7) != 0) {
		fprintf(stderr, "ethsign: failed to seed RNG\n");
		goto cleanup;
	}

	if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1) != 0) {
		fprintf(stderr, "ethsign: failed to load secp256k1\n");
		goto cleanup;
	}

	/* Generate keypair */
	if (mbedtls_ecp_gen_keypair(&grp, &d, &Q, mbedtls_ctr_drbg_random,
				    &ctr_drbg) != 0) {
		fprintf(stderr, "ethsign: key generation failed\n");
		goto cleanup;
	}

	/* Write private key as hex */
	if (mbedtls_mpi_write_binary(&d, bin, 32) != 0)
		goto cleanup;
	bin2hex(bin, 32, hex);

	snprintf(path, sizeof(path), "%s/device.key", dir);
	f = fopen(path, "w");
	if (!f) {
		perror(path);
		goto cleanup;
	}
	fprintf(f, "%s\n", hex);
	fclose(f);
	/* Restrict permissions on private key */
	chmod(path, 0600);

	/* Write public key as hex (x || y, no 04 prefix) */
	if (output_pubkey(&Q, hex) != 0)
		goto cleanup;

	snprintf(path, sizeof(path), "%s/device.pub.hex", dir);
	f = fopen(path, "w");
	if (!f) {
		perror(path);
		goto cleanup;
	}
	fprintf(f, "%s\n", hex);
	fclose(f);

	ret = 0;

cleanup:
	mbedtls_ecp_point_free(&Q);
	mbedtls_mpi_free(&d);
	mbedtls_ecp_group_free(&grp);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	return ret;
}

/* --- pubkey command --- */

static int
cmd_pubkey(const char *keyfile)
{
	mbedtls_ecp_group grp;
	mbedtls_mpi d;
	mbedtls_ecp_point Q;
	char hex[130];
	int ret = 1;

	mbedtls_ecp_group_init(&grp);
	mbedtls_mpi_init(&d);
	mbedtls_ecp_point_init(&Q);

	if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1) != 0)
		goto cleanup;
	if (load_privkey(keyfile, &d) != 0)
		goto cleanup;
	if (compute_pubkey(&d, &Q, &grp) != 0) {
		fprintf(stderr, "ethsign: failed to compute public key\n");
		goto cleanup;
	}

	if (output_pubkey(&Q, hex) != 0)
		goto cleanup;

	printf("%s\n", hex);
	ret = 0;

cleanup:
	mbedtls_ecp_point_free(&Q);
	mbedtls_mpi_free(&d);
	mbedtls_ecp_group_free(&grp);
	return ret;
}

/* --- sign command --- */

static int
cmd_sign(const char *keyfile, const char *hash_hex)
{
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ecp_group grp;
	mbedtls_mpi d, r, s, half_n;
	mbedtls_ecp_point Q, Q_rec;
	unsigned char hash[32];
	char sig_hex[132];
	int v = 27;
	int ret = 1;

	if (strlen(hash_hex) != 64) {
		fprintf(stderr,
			"ethsign: hash must be 64 hex chars (32 bytes)\n");
		return 1;
	}
	if (hex2bin(hash_hex, hash, 32) != 0) {
		fprintf(stderr, "ethsign: invalid hex in hash\n");
		return 1;
	}

	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_ecp_group_init(&grp);
	mbedtls_mpi_init(&d);
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);
	mbedtls_mpi_init(&half_n);
	mbedtls_ecp_point_init(&Q);
	mbedtls_ecp_point_init(&Q_rec);

	if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
				   (const unsigned char *)"ethsign-sign",
				   12) != 0) {
		fprintf(stderr, "ethsign: failed to seed RNG\n");
		goto cleanup;
	}

	if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1) != 0)
		goto cleanup;
	if (load_privkey(keyfile, &d) != 0)
		goto cleanup;
	if (compute_pubkey(&d, &Q, &grp) != 0) {
		fprintf(stderr, "ethsign: failed to compute public key\n");
		goto cleanup;
	}

	/* Sign the hash */
	if (mbedtls_ecdsa_sign(&grp, &r, &s, &d, hash, 32,
			       mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
		fprintf(stderr, "ethsign: signing failed\n");
		goto cleanup;
	}

	/*
	 * Ethereum requires low-s: if s > N/2, replace with N - s.
	 * This also affects the recovery id (v).
	 */
	MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&half_n, &grp.N));
	MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(&half_n, 1));

	if (mbedtls_mpi_cmp_mpi(&s, &half_n) > 0) {
		MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&s, &grp.N, &s));
	}

	/*
	 * Determine v (recovery id): try v=0 and v=1, recover pubkey,
	 * compare with known pubkey to find the correct one.
	 * Ethereum uses v=27 or v=28 (27 + recovery_id).
	 */
	v = 27;
	if (ecrecover(&grp, &r, &s, 0, hash, 32, &Q_rec) == 0 &&
	    mbedtls_mpi_cmp_mpi(&Q_rec.X, &Q.X) == 0 &&
	    mbedtls_mpi_cmp_mpi(&Q_rec.Y, &Q.Y) == 0) {
		v = 27; /* recovery id 0 */
	} else if (ecrecover(&grp, &r, &s, 1, hash, 32, &Q_rec) == 0 &&
		   mbedtls_mpi_cmp_mpi(&Q_rec.X, &Q.X) == 0 &&
		   mbedtls_mpi_cmp_mpi(&Q_rec.Y, &Q.Y) == 0) {
		v = 28; /* recovery id 1 */
	} else {
		fprintf(stderr, "ethsign: failed to determine recovery id\n");
		goto cleanup;
	}

	/* Output: r (32 bytes) + s (32 bytes) + v (1 byte) = 65 bytes = 130 hex */
	if (mpi_to_hex(&r, sig_hex, 32) != 0)
		goto cleanup;
	if (mpi_to_hex(&s, sig_hex + 64, 32) != 0)
		goto cleanup;
	sprintf(sig_hex + 128, "%02x", v);

	printf("%s\n", sig_hex);
	ret = 0;

cleanup:
	mbedtls_ecp_point_free(&Q_rec);
	mbedtls_ecp_point_free(&Q);
	mbedtls_mpi_free(&half_n);
	mbedtls_mpi_free(&s);
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&d);
	mbedtls_ecp_group_free(&grp);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	return ret;
}

static void
usage(void)
{
	fprintf(stderr,
		"Usage: ethsign genkey [--dir DIR]\n"
		"       ethsign pubkey --key FILE\n"
		"       ethsign sign --key FILE HASH\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	if (argc < 2)
		usage();

	if (strcmp(argv[1], "genkey") == 0) {
		const char *dir = ".";
		int i;
		for (i = 2; i < argc; i++) {
			if (strcmp(argv[i], "--dir") == 0 && i + 1 < argc)
				dir = argv[++i];
			else
				usage();
		}
		return cmd_genkey(dir);
	}

	if (strcmp(argv[1], "pubkey") == 0) {
		const char *keyfile = NULL;
		int i;
		for (i = 2; i < argc; i++) {
			if (strcmp(argv[i], "--key") == 0 && i + 1 < argc)
				keyfile = argv[++i];
			else
				usage();
		}
		if (!keyfile)
			usage();
		return cmd_pubkey(keyfile);
	}

	if (strcmp(argv[1], "sign") == 0) {
		const char *keyfile = NULL;
		const char *hash = NULL;
		int i;
		for (i = 2; i < argc; i++) {
			if (strcmp(argv[i], "--key") == 0 && i + 1 < argc)
				keyfile = argv[++i];
			else if (argv[i][0] != '-')
				hash = argv[i];
			else
				usage();
		}
		if (!keyfile || !hash)
			usage();
		return cmd_sign(keyfile, hash);
	}

	usage();
	return 1;
}

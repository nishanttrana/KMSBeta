/* Byte buffers, base64, PEM, the DER the module reads and writes, and
 * SHA-2. No dependency beyond libc: the module links only libcurl. */
#ifndef VECTA_UTIL_H
#define VECTA_UTIL_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
	unsigned char *p;
	size_t n, cap;
} buf_t;

/* 0, or -1 when out of memory (the buffer is unchanged). */
int buf_append(buf_t *b, const void *d, size_t n);
int buf_appends(buf_t *b, const char *s);
/* Zeroizes before freeing: buffers carry plaintext and credentials. */
void buf_free(buf_t *b);
void secure_zero(void *p, size_t n);

/* Standard alphabet, padded. Encode returns a malloc'd string or NULL. */
char *b64_encode(const unsigned char *d, size_t n);
/* 0, or -1 for anything but canonical padded base64. *out is malloc'd. */
int b64_decode(const char *s, size_t slen, unsigned char **out, size_t *outn);
/* The first "-----BEGIN PUBLIC KEY-----" block's DER. 0 or -1. */
int pem_public_key_der(const char *pem, unsigned char **der, size_t *dern);

/* A SubjectPublicKeyInfo, as PKCS#11 attributes need it. Pointers point
 * into the parsed DER, which must outlive this. */
enum { SPKI_EC = 1, SPKI_RSA = 2 };
typedef struct {
	int kind;
	int curve_bits;                /* 256, 384, 521 */
	const unsigned char *ec_oid;   /* DER OID (tag included): CKA_EC_PARAMS */
	size_t ec_oid_len;
	const unsigned char *ec_point; /* 04 || X || Y */
	size_t ec_point_len;
	const unsigned char *modulus;  /* big-endian, no leading zeros */
	size_t modulus_len;
	const unsigned char *exponent;
	size_t exponent_len;
} spki_t;
int spki_parse(const unsigned char *der, size_t n, spki_t *out);

/* ECDSA signatures: DER SEQUENCE{r, s} (the KMS) and r||s, each half
 * coord bytes (PKCS#11). 0 or -1. */
int ecdsa_der_to_raw(const unsigned char *der, size_t n, size_t coord, unsigned char *raw);
int ecdsa_raw_to_der(const unsigned char *raw, size_t coord, buf_t *der);

/* SHA-256, SHA-384, SHA-512. */
typedef struct {
	int bits; /* 256, 384, 512 */
	uint64_t total;
	size_t fill;
	union {
		uint32_t h32[8];
		uint64_t h64[8];
	} h;
	unsigned char block[128];
} sha2_ctx;
void sha2_init(sha2_ctx *c, int bits);
void sha2_update(sha2_ctx *c, const unsigned char *d, size_t n);
/* Writes bits/8 bytes. */
void sha2_final(sha2_ctx *c, unsigned char *out);

#endif

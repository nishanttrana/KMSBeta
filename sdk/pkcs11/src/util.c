#include "util.h"

#include <stdlib.h>
#include <string.h>

void secure_zero(void *p, size_t n)
{
	volatile unsigned char *v = p;
	while (n--)
		*v++ = 0;
}

int buf_append(buf_t *b, const void *d, size_t n)
{
	if (n == 0)
		return 0;
	if (n > SIZE_MAX - b->n - 1)
		return -1;
	if (b->n + n + 1 > b->cap) {
		size_t cap = b->cap ? b->cap : 256;
		while (cap < b->n + n + 1) {
			if (cap > SIZE_MAX / 2)
				return -1;
			cap *= 2;
		}
		/* Not realloc: the old block may hold secrets and must be wiped. */
		unsigned char *p = malloc(cap);
		if (!p)
			return -1;
		if (b->p) {
			memcpy(p, b->p, b->n);
			secure_zero(b->p, b->cap);
			free(b->p);
		}
		b->p = p;
		b->cap = cap;
	}
	memcpy(b->p + b->n, d, n);
	b->n += n;
	b->p[b->n] = 0; /* always NUL-terminated, for text */
	return 0;
}

int buf_appends(buf_t *b, const char *s)
{
	return buf_append(b, s, strlen(s));
}

void buf_free(buf_t *b)
{
	if (b->p) {
		secure_zero(b->p, b->cap);
		free(b->p);
	}
	b->p = NULL;
	b->n = b->cap = 0;
}

static const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *b64_encode(const unsigned char *d, size_t n)
{
	if (n > (SIZE_MAX - 1) / 4 * 3 - 3)
		return NULL;
	size_t outn = (n + 2) / 3 * 4;
	char *out = malloc(outn + 1), *o = out;
	if (!out)
		return NULL;
	size_t i = 0;
	for (; i + 2 < n; i += 3) {
		uint32_t v = (uint32_t)d[i] << 16 | (uint32_t)d[i + 1] << 8 | d[i + 2];
		*o++ = b64chars[v >> 18 & 63];
		*o++ = b64chars[v >> 12 & 63];
		*o++ = b64chars[v >> 6 & 63];
		*o++ = b64chars[v & 63];
	}
	if (i < n) {
		uint32_t v = (uint32_t)d[i] << 16 | (i + 1 < n ? (uint32_t)d[i + 1] << 8 : 0);
		*o++ = b64chars[v >> 18 & 63];
		*o++ = b64chars[v >> 12 & 63];
		*o++ = i + 1 < n ? b64chars[v >> 6 & 63] : '=';
		*o++ = '=';
	}
	*o = 0;
	return out;
}

static int b64val(unsigned char c)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A';
	if (c >= 'a' && c <= 'z')
		return c - 'a' + 26;
	if (c >= '0' && c <= '9')
		return c - '0' + 52;
	if (c == '+')
		return 62;
	if (c == '/')
		return 63;
	return -1;
}

int b64_decode(const char *s, size_t slen, unsigned char **out, size_t *outn)
{
	*out = NULL;
	*outn = 0;
	if (slen % 4 != 0)
		return -1;
	unsigned char *o = malloc(slen / 4 * 3 + 1);
	if (!o)
		return -1;
	size_t k = 0;
	for (size_t i = 0; i < slen; i += 4) {
		int v[4], pad = 0;
		for (int j = 0; j < 4; j++) {
			unsigned char c = (unsigned char)s[i + j];
			if (c == '=' && i + 4 == slen && j >= 2) {
				v[j] = 0;
				pad++;
				continue;
			}
			if (pad) /* data after padding */
				goto bad;
			if ((v[j] = b64val(c)) < 0)
				goto bad;
		}
		if (pad == 1 && s[i + 2] == '=')
			goto bad;
		uint32_t w = (uint32_t)v[0] << 18 | (uint32_t)v[1] << 12 | (uint32_t)v[2] << 6 | (uint32_t)v[3];
		/* Canonical: the bits padding drops must be zero. */
		if ((pad == 1 && (w & 0xff)) || (pad == 2 && (w & 0xffff)))
			goto bad;
		o[k++] = w >> 16 & 0xff;
		if (pad < 2)
			o[k++] = w >> 8 & 0xff;
		if (pad < 1)
			o[k++] = w & 0xff;
	}
	*out = o;
	*outn = k;
	return 0;
bad:
	free(o);
	return -1;
}

int pem_public_key_der(const char *pem, unsigned char **der, size_t *dern)
{
	static const char begin[] = "-----BEGIN PUBLIC KEY-----", end[] = "-----END PUBLIC KEY-----";
	const char *b = strstr(pem, begin);
	if (!b)
		return -1;
	b += sizeof(begin) - 1;
	const char *e = strstr(b, end);
	if (!e)
		return -1;
	buf_t body = {0};
	for (const char *p = b; p < e; p++) {
		if (*p == '\n' || *p == '\r' || *p == ' ' || *p == '\t')
			continue;
		if (buf_append(&body, p, 1) != 0) {
			buf_free(&body);
			return -1;
		}
	}
	int rc = body.n ? b64_decode((const char *)body.p, body.n, der, dern) : -1;
	buf_free(&body);
	return rc;
}

/* der_next reads one TLV with the expected tag: definite lengths only, in
 * minimal form, within [*p, end). */
static int der_next(const unsigned char **p, const unsigned char *end, unsigned char tag,
		    const unsigned char **val, size_t *len)
{
	const unsigned char *q = *p;
	if (end - q < 2 || q[0] != tag)
		return -1;
	size_t l = q[1];
	q += 2;
	if (l & 0x80) {
		size_t nb = l & 0x7f;
		if (nb == 0 || nb > 3 || (size_t)(end - q) < nb || q[0] == 0)
			return -1;
		l = 0;
		for (size_t i = 0; i < nb; i++)
			l = l << 8 | *q++;
		if (l < 128)
			return -1;
	}
	if ((size_t)(end - q) < l)
		return -1;
	*val = q;
	*len = l;
	*p = q + l;
	return 0;
}

static const unsigned char oid_ec_public_key[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01};
static const unsigned char oid_rsa_encryption[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01};
static const struct {
	unsigned char der[10];
	size_t len;
	int bits;
} curves[] = {
	{{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}, 10, 256}, /* P-256 */
	{{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22}, 7, 384},                   /* P-384 */
	{{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23}, 7, 521},                   /* P-521 */
};

static int der_uint(const unsigned char **p, const unsigned char *end, const unsigned char **v, size_t *n)
{
	if (der_next(p, end, 0x02, v, n) != 0 || *n == 0 || (*v)[0] & 0x80)
		return -1; /* empty or negative */
	while (*n > 1 && (*v)[0] == 0) {
		(*v)++;
		(*n)--;
	}
	return 0;
}

int spki_parse(const unsigned char *der, size_t n, spki_t *out)
{
	memset(out, 0, sizeof(*out));
	const unsigned char *p = der, *end = der + n, *seq, *alg, *oid, *bits;
	size_t seql, algl, oidl, bitsl;
	if (der_next(&p, end, 0x30, &seq, &seql) != 0 || p != end)
		return -1;
	p = seq;
	end = seq + seql;
	if (der_next(&p, end, 0x30, &alg, &algl) != 0)
		return -1;
	if (der_next(&p, end, 0x03, &bits, &bitsl) != 0 || p != end || bitsl < 2 || bits[0] != 0)
		return -1;
	bits++;
	bitsl--;
	const unsigned char *a = alg, *aend = alg + algl;
	if (der_next(&a, aend, 0x06, &oid, &oidl) != 0)
		return -1;
	if (oidl == sizeof(oid_ec_public_key) && memcmp(oid, oid_ec_public_key, oidl) == 0) {
		const unsigned char *cstart = a, *coid;
		size_t coidl;
		if (der_next(&a, aend, 0x06, &coid, &coidl) != 0 || a != aend)
			return -1;
		size_t whole = (size_t)(a - cstart);
		for (size_t i = 0; i < sizeof(curves) / sizeof(curves[0]); i++) {
			if (whole == curves[i].len && memcmp(cstart, curves[i].der, whole) == 0) {
				size_t coord = ((size_t)curves[i].bits + 7) / 8;
				if (bitsl != 1 + 2 * coord || bits[0] != 0x04)
					return -1; /* uncompressed points only */
				out->kind = SPKI_EC;
				out->curve_bits = curves[i].bits;
				out->ec_oid = cstart;
				out->ec_oid_len = whole;
				out->ec_point = bits;
				out->ec_point_len = bitsl;
				return 0;
			}
		}
		return -1;
	}
	if (oidl == sizeof(oid_rsa_encryption) && memcmp(oid, oid_rsa_encryption, oidl) == 0) {
		const unsigned char *nul;
		size_t nl;
		if (a != aend && (der_next(&a, aend, 0x05, &nul, &nl) != 0 || nl != 0 || a != aend))
			return -1;
		const unsigned char *k = bits, *kend = bits + bitsl, *rs;
		size_t rsl;
		if (der_next(&k, kend, 0x30, &rs, &rsl) != 0 || k != kend)
			return -1;
		k = rs;
		kend = rs + rsl;
		if (der_uint(&k, kend, &out->modulus, &out->modulus_len) != 0 ||
		    der_uint(&k, kend, &out->exponent, &out->exponent_len) != 0 || k != kend)
			return -1;
		if (out->modulus_len < 256 || out->modulus_len > 1024)
			return -1; /* RSA-2048 and up */
		out->kind = SPKI_RSA;
		return 0;
	}
	return -1;
}

int ecdsa_der_to_raw(const unsigned char *der, size_t n, size_t coord, unsigned char *raw)
{
	const unsigned char *p = der, *end = der + n, *seq, *r, *s;
	size_t seql, rl, sl;
	if (der_next(&p, end, 0x30, &seq, &seql) != 0 || p != end)
		return -1;
	p = seq;
	end = seq + seql;
	if (der_uint(&p, end, &r, &rl) != 0 || der_uint(&p, end, &s, &sl) != 0 || p != end)
		return -1;
	if (rl > coord || sl > coord)
		return -1;
	memset(raw, 0, 2 * coord);
	memcpy(raw + coord - rl, r, rl);
	memcpy(raw + 2 * coord - sl, s, sl);
	return 0;
}

static int der_put_len(buf_t *b, size_t l)
{
	unsigned char h[4];
	if (l < 128) {
		h[0] = (unsigned char)l;
		return buf_append(b, h, 1);
	}
	if (l < 256) {
		h[0] = 0x81;
		h[1] = (unsigned char)l;
		return buf_append(b, h, 2);
	}
	h[0] = 0x82;
	h[1] = (unsigned char)(l >> 8);
	h[2] = (unsigned char)l;
	return buf_append(b, h, 3);
}

static int der_put_uint(buf_t *b, const unsigned char *v, size_t n)
{
	while (n > 1 && v[0] == 0) {
		v++;
		n--;
	}
	int pad = v[0] & 0x80 ? 1 : 0;
	unsigned char tag = 0x02, zero = 0;
	if (buf_append(b, &tag, 1) || der_put_len(b, n + (size_t)pad) || (pad && buf_append(b, &zero, 1)) ||
	    buf_append(b, v, n))
		return -1;
	return 0;
}

int ecdsa_raw_to_der(const unsigned char *raw, size_t coord, buf_t *der)
{
	buf_t body = {0};
	unsigned char tag = 0x30;
	int rc = -1;
	if (der_put_uint(&body, raw, coord) == 0 && der_put_uint(&body, raw + coord, coord) == 0 &&
	    buf_append(der, &tag, 1) == 0 && der_put_len(der, body.n) == 0 && buf_append(der, body.p, body.n) == 0)
		rc = 0;
	buf_free(&body);
	return rc;
}

/* SHA-2 (FIPS 180-4). */

static const uint32_t k256[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static const uint64_t k512[80] = {
	0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
	0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
	0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
	0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
	0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
	0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
	0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
	0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
	0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
	0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
	0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
	0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
	0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
	0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
	0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
	0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
	0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
	0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
	0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
	0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

#define ROR32(x, n) ((x) >> (n) | (x) << (32 - (n)))
#define ROR64(x, n) ((x) >> (n) | (x) << (64 - (n)))

static void block256(uint32_t h[8], const unsigned char *p)
{
	uint32_t w[64], a, b, c, d, e, f, g, hh;
	for (int i = 0; i < 16; i++)
		w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 | (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
	for (int i = 16; i < 64; i++) {
		uint32_t s0 = ROR32(w[i - 15], 7) ^ ROR32(w[i - 15], 18) ^ (w[i - 15] >> 3);
		uint32_t s1 = ROR32(w[i - 2], 17) ^ ROR32(w[i - 2], 19) ^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
	for (int i = 0; i < 64; i++) {
		uint32_t t1 = hh + (ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25)) + ((e & f) ^ (~e & g)) + k256[i] + w[i];
		uint32_t t2 = (ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
		hh = g, g = f, f = e, e = d + t1, d = c, c = b, b = a, a = t1 + t2;
	}
	h[0] += a, h[1] += b, h[2] += c, h[3] += d, h[4] += e, h[5] += f, h[6] += g, h[7] += hh;
}

static void block512(uint64_t h[8], const unsigned char *p)
{
	uint64_t w[80], a, b, c, d, e, f, g, hh;
	for (int i = 0; i < 16; i++) {
		w[i] = 0;
		for (int j = 0; j < 8; j++)
			w[i] = w[i] << 8 | p[8 * i + j];
	}
	for (int i = 16; i < 80; i++) {
		uint64_t s0 = ROR64(w[i - 15], 1) ^ ROR64(w[i - 15], 8) ^ (w[i - 15] >> 7);
		uint64_t s1 = ROR64(w[i - 2], 19) ^ ROR64(w[i - 2], 61) ^ (w[i - 2] >> 6);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
	for (int i = 0; i < 80; i++) {
		uint64_t t1 = hh + (ROR64(e, 14) ^ ROR64(e, 18) ^ ROR64(e, 41)) + ((e & f) ^ (~e & g)) + k512[i] + w[i];
		uint64_t t2 = (ROR64(a, 28) ^ ROR64(a, 34) ^ ROR64(a, 39)) + ((a & b) ^ (a & c) ^ (b & c));
		hh = g, g = f, f = e, e = d + t1, d = c, c = b, b = a, a = t1 + t2;
	}
	h[0] += a, h[1] += b, h[2] += c, h[3] += d, h[4] += e, h[5] += f, h[6] += g, h[7] += hh;
}

void sha2_init(sha2_ctx *c, int bits)
{
	static const uint32_t i256[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
					 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
	static const uint64_t i384[8] = {0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL,
					 0x152fecd8f70e5939ULL, 0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL,
					 0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL};
	static const uint64_t i512[8] = {0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
					 0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
					 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};
	memset(c, 0, sizeof(*c));
	c->bits = bits;
	if (bits == 256)
		memcpy(c->h.h32, i256, sizeof(i256));
	else
		memcpy(c->h.h64, bits == 384 ? i384 : i512, sizeof(i512));
}

void sha2_update(sha2_ctx *c, const unsigned char *d, size_t n)
{
	size_t bs = c->bits == 256 ? 64 : 128;
	c->total += n;
	while (n > 0) {
		size_t take = bs - c->fill < n ? bs - c->fill : n;
		memcpy(c->block + c->fill, d, take);
		c->fill += take;
		d += take;
		n -= take;
		if (c->fill == bs) {
			if (bs == 64)
				block256(c->h.h32, c->block);
			else
				block512(c->h.h64, c->block);
			c->fill = 0;
		}
	}
}

void sha2_final(sha2_ctx *c, unsigned char *out)
{
	size_t bs = c->bits == 256 ? 64 : 128, lenbytes = bs == 64 ? 8 : 16;
	uint64_t bitlen = c->total * 8;
	unsigned char pad[128 + 16] = {0x80};
	size_t padn = (c->fill < bs - lenbytes ? bs - lenbytes - c->fill : 2 * bs - lenbytes - c->fill);
	unsigned char len[16] = {0};
	for (int i = 0; i < 8; i++)
		len[lenbytes - 1 - i] = (unsigned char)(bitlen >> (8 * i));
	sha2_update(c, pad, padn);
	sha2_update(c, len, lenbytes);
	if (c->bits == 256) {
		for (int i = 0; i < 8; i++)
			for (int j = 0; j < 4; j++)
				out[4 * i + j] = (unsigned char)(c->h.h32[i] >> (24 - 8 * j));
	} else {
		int words = c->bits / 64;
		for (int i = 0; i < words; i++)
			for (int j = 0; j < 8; j++)
				out[8 * i + j] = (unsigned char)(c->h.h64[i] >> (56 - 8 * j));
	}
	secure_zero(c, sizeof(*c));
}

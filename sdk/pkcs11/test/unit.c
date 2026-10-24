/* Unit tests for the module's parsers and SHA-2, run under AddressSanitizer
 * and UBSan (make check). The KMS's answers are untrusted input to a library
 * loaded into someone else's process: every parser also gets mutated input. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"
#include "util.h"
#include "vectors.h"

static int failures;
#define CHECK(cond)                                                                                                    \
	do {                                                                                                           \
		if (!(cond)) {                                                                                         \
			fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #cond);                                     \
			failures++;                                                                                    \
		}                                                                                                      \
	} while (0)

static void hex(const unsigned char *d, size_t n, char *out)
{
	for (size_t i = 0; i < n; i++)
		snprintf(out + 2 * i, 3, "%02x", d[i]);
}

static void sha_vector(int bits, const char *msg, size_t reps, const char *want)
{
	sha2_ctx c;
	unsigned char out[64];
	char got[129];
	sha2_init(&c, bits);
	for (size_t i = 0; i < reps; i++)
		sha2_update(&c, (const unsigned char *)msg, strlen(msg));
	sha2_final(&c, out);
	hex(out, (size_t)bits / 8, got);
	if (strcmp(got, want)) {
		fprintf(stderr, "SHA-%d(%s x%zu) = %s, want %s\n", bits, msg, reps, got, want);
		failures++;
	}
}

static void test_sha2(void)
{
	/* FIPS 180-4 examples, and the one-million-'a' vectors (block edges). */
	sha_vector(256, "abc", 1, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
	sha_vector(256, "", 1, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
	sha_vector(256, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1,
		   "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
	sha_vector(256, "a", 1000000, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
	sha_vector(384, "abc", 1,
		   "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
	sha_vector(512, "abc", 1,
		   "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd"
		   "454d4423643ce80e2a9ac94fa54ca49f");
	sha_vector(512, "a", 1000000,
		   "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31b"
		   "eb009c5c2c49aa2e4eadb217ad8cc09b");
	/* 55, 56, 64 bytes: the padding boundaries. */
	sha_vector(256, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1,
		   "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318");
	sha_vector(256, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1,
		   "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a");
	sha_vector(256, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1,
		   "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb");
}

static void test_base64(void)
{
	const char *cases[][2] = {{"", ""}, {"f", "Zg=="}, {"fo", "Zm8="}, {"foo", "Zm9v"}, {"foob", "Zm9vYg=="},
				  {"fooba", "Zm9vYmE="}, {"foobar", "Zm9vYmFy"}};
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		char *e = b64_encode((const unsigned char *)cases[i][0], strlen(cases[i][0]));
		CHECK(e && !strcmp(e, cases[i][1]));
		unsigned char *d;
		size_t n;
		CHECK(b64_decode(cases[i][1], strlen(cases[i][1]), &d, &n) == 0 && n == strlen(cases[i][0]) &&
		      !memcmp(d, cases[i][0], n));
		free(e);
		free(d);
	}
	const char *bad[] = {"Zg", "Zg=", "Z===", "Zg==Zg==", "Zh==", "Zm9=", "Zm9v!", "====", "Zg=a"};
	for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		unsigned char *d;
		size_t n;
		CHECK(b64_decode(bad[i], strlen(bad[i]), &d, &n) != 0);
	}
}

static void test_json(void)
{
	jval v;
	const char *ok = "{\"a\":\"x\\u00e9\\ud83d\\ude00\\n\",\"n\":-42,\"big\":12345678901234567890,\"f\":1.5e3,"
			 "\"t\":true,\"z\":null,\"arr\":[1,[2,{}],\"s\"],\"e\":\"\"}";
	CHECK(json_parse(ok, strlen(ok), &v) == 0);
	CHECK(json_str(&v, "a") && !strcmp(json_str(&v, "a"), "x\xc3\xa9\xf0\x9f\x98\x80\n"));
	int64_t i;
	CHECK(json_int(&v, "n", &i) == 0 && i == -42);
	CHECK(json_int(&v, "big", &i) != 0); /* beyond int64: not an integer */
	CHECK(json_int(&v, "f", &i) != 0);
	CHECK(json_true(&v, "t") && !json_true(&v, "z") && !json_true(&v, "missing"));
	CHECK(json_get(&v, "arr")->n == 3);
	CHECK(json_str(&v, "e") && !*json_str(&v, "e"));
	json_free(&v);

	const char *bad[] = {"",       "{",	       "{\"a\"}",	"{\"a\":}",	   "[1,]",	   "{\"a\":1,}",
			     "01",     "1.",	       "-",		"\"\\x\"",	   "\"\\ud800\"",  "\"\\udc00\"",
			     "\"a\tb\"", "tru",       "{\"a\":1} x",    "[\"\\u12\"]",     "\"\\ud800\\u0041\"", "nul"};
	for (size_t k = 0; k < sizeof(bad) / sizeof(bad[0]); k++)
		CHECK(json_parse(bad[k], strlen(bad[k]), &v) != 0);
	char deep[200];
	memset(deep, '[', 100);
	memset(deep + 100, ']', 100);
	CHECK(json_parse(deep, sizeof(deep), &v) != 0); /* nesting beyond 32 */

	buf_t b = {0};
	CHECK(json_put_str(&b, "a\"b\\c\n\x01") == 0 && !strcmp((char *)b.p, "\"a\\\"b\\\\c\\n\\u0001\""));
	buf_free(&b);
}

static void test_spki(void)
{
	spki_t s;
	CHECK(spki_parse(spki_p256, sizeof(spki_p256), &s) == 0 && s.kind == SPKI_EC && s.curve_bits == 256 &&
	      s.ec_point_len == 65 && s.ec_point[0] == 4 && s.ec_oid_len == 10);
	CHECK(spki_parse(spki_p384, sizeof(spki_p384), &s) == 0 && s.curve_bits == 384 && s.ec_point_len == 97);
	CHECK(spki_parse(spki_p521, sizeof(spki_p521), &s) == 0 && s.curve_bits == 521 && s.ec_point_len == 133);
	CHECK(spki_parse(spki_rsa2048, sizeof(spki_rsa2048), &s) == 0 && s.kind == SPKI_RSA &&
	      s.modulus_len == 256 && s.exponent_len == 3 && s.exponent[0] == 1);
	CHECK(spki_parse(spki_p256, sizeof(spki_p256) - 1, &s) != 0);
	unsigned char trailing[sizeof(spki_p256) + 1];
	memcpy(trailing, spki_p256, sizeof(spki_p256));
	trailing[sizeof(spki_p256)] = 0;
	CHECK(spki_parse(trailing, sizeof(trailing), &s) != 0);
}

static void test_ecdsa(void)
{
	unsigned char raw[64];
	buf_t der = {0};
	CHECK(ecdsa_der_to_raw(sig_p256, sizeof(sig_p256), 32, raw) == 0);
	CHECK(ecdsa_raw_to_der(raw, 32, &der) == 0 && der.n == sizeof(sig_p256) && !memcmp(der.p, sig_p256, der.n));
	buf_free(&der);
	unsigned char small[64] = {0};
	small[31] = 1; /* r = 1, s = 0x80...: s needs a zero byte */
	small[32] = 0x80;
	CHECK(ecdsa_raw_to_der(small, 32, &der) == 0);
	unsigned char back[64];
	CHECK(ecdsa_der_to_raw(der.p, der.n, 32, back) == 0 && !memcmp(back, small, 64));
	buf_free(&der);
	CHECK(ecdsa_der_to_raw(sig_p256, sizeof(sig_p256), 16, raw) != 0); /* too long for the curve */
}

/* Mutated inputs: every parser must reject or accept without a memory error
 * (the sanitizers make one fatal). */
static uint32_t rng = 2463534242u;
static uint32_t next(void)
{
	rng ^= rng << 13;
	rng ^= rng >> 17;
	rng ^= rng << 5;
	return rng;
}

static void mutate(const unsigned char *in, size_t n, unsigned char *out, size_t *outn)
{
	memcpy(out, in, n);
	*outn = n;
	for (int k = 0, m = 1 + (int)(next() % 4); k < m; k++) {
		switch (next() % 3) {
		case 0:
			out[next() % *outn] = (unsigned char)next();
			break;
		case 1:
			if (*outn > 1)
				(*outn)--;
			break;
		default:
			out[next() % *outn] ^= (unsigned char)(1u << (next() % 8));
		}
	}
}

static void test_mutations(void)
{
	const char *docs[] = {
		"{\"items\":[{\"id\":\"key_1\",\"name\":\"a\",\"current_version\":2}],\"has_more\":true,"
		"\"next_cursor\":{\"after_created_at\":\"2026-10-24T00:00:00Z\",\"after_id\":\"key_1\"}}",
		"{\"error\":{\"code\":\"access_denied\",\"message\":\"no \\u00e9\",\"request_id\":\"req_1\"}}",
	};
	unsigned char buf[4096];
	size_t n;
	for (int round = 0; round < 50000; round++) {
		const char *d = docs[round % 2];
		mutate((const unsigned char *)d, strlen(d), buf, &n);
		jval v;
		if (json_parse((const char *)buf, n, &v) == 0)
			json_free(&v);
		const unsigned char *keys[] = {spki_p256, spki_rsa2048, sig_p256};
		size_t lens[] = {sizeof(spki_p256), sizeof(spki_rsa2048), sizeof(sig_p256)};
		int which = round % 3;
		mutate(keys[which], lens[which], buf, &n);
		spki_t s;
		unsigned char raw[64];
		if (which < 2)
			(void)spki_parse(buf, n, &s);
		else
			(void)ecdsa_der_to_raw(buf, n, 32, raw);
		unsigned char *out;
		size_t outn;
		char text[64];
		for (int k = 0; k < 16; k++)
			text[k] = "AZaz09+/=!-_ \n"[next() % 14];
		if (b64_decode(text, 16, &out, &outn) == 0)
			free(out);
	}
}

int main(void)
{
	test_sha2();
	test_base64();
	test_json();
	test_spki();
	test_ecdsa();
	test_mutations();
	if (failures) {
		fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	printf("unit ok\n");
	return 0;
}

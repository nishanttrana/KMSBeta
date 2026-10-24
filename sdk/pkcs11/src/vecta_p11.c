/* Vecta KMS PKCS#11 module (PKCS#11 v2.40): the keys a REST client can see,
 * as token objects of one slot. Key material never leaves the KMS: signing,
 * verification, encryption and decryption are KMS calls, and the module
 * hashes locally so only digests are sent. docs/PKCS11.md. */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) __attribute__((visibility("default"))) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif
#include "pkcs11.h"

#include "kms.h"
#include "util.h"

#define SLOT_ID 1
#define LIST_TTL 10              /* seconds a key listing is reused */
#define MAX_BUFFERED (16u << 20) /* multi-part data held for one KMS call */

enum { K_AES = 1, K_EC, K_RSA };
enum { OP_NONE, OP_SIGN, OP_VERIFY, OP_ENCRYPT, OP_DECRYPT };

typedef struct keyinfo {
	char *id, *name, *kcv;
	int kind, bits, usable, alive; /* usable: active (not only deactivated) */
	int64_t version;
	unsigned char *spki;
	size_t spki_len;
	int64_t spki_version;
	spki_t pub;
} keyinfo;

typedef struct {
	CK_OBJECT_HANDLE h;
	CK_OBJECT_CLASS cls;
	keyinfo *k;
} object;

typedef struct session {
	CK_SESSION_HANDLE h;
	CK_FLAGS flags;
	int busy, closing;
	int finding;
	CK_OBJECT_HANDLE *found;
	size_t nfound, pos;
	int op, multipart;
	CK_MECHANISM_TYPE mech;
	keyinfo *key;
	int hash_bits; /* 0: the caller passes the digest */
	sha2_ctx sha;
	buf_t data, aad;
	unsigned char iv[12];
	CK_BYTE_PTR iv_out; /* gcm_iv = generated: where the KMS's IV goes */
} session;

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static int g_init, g_logged_in;
static kms_config g_cfg;
static kms *g_kms;
static keyinfo **g_keys;
static size_t g_nkeys;
static object *g_objs;
static size_t g_nobjs;
static CK_OBJECT_HANDLE g_next_obj = 1;
static time_t g_listed;
static session **g_sess;
static size_t g_nsess;
static CK_SESSION_HANDLE g_next_sess = 1;
static pthread_once_t g_fork_once = PTHREAD_ONCE_INIT;

static time_t mono(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec;
}

/* Fork: the child gets the module's state and opens its own connections. */
static void fork_prepare(void)
{
	pthread_mutex_lock(&g_mu);
}
static void fork_parent(void)
{
	pthread_mutex_unlock(&g_mu);
}
static void fork_child(void)
{
	pthread_mutex_unlock(&g_mu);
	if (g_init && g_kms)
		kms_after_fork(g_kms);
}
static void register_fork(void)
{
	pthread_atfork(fork_prepare, fork_parent, fork_child);
}

static void pad(CK_UTF8CHAR *dst, size_t n, const char *src)
{
	size_t l = strlen(src);
	memset(dst, ' ', n);
	memcpy(dst, src, l < n ? l : n);
}

static CK_VERSION lib_version(void)
{
	CK_VERSION v = {0, 0};
	unsigned a = 0, b = 0;
	if (sscanf(VECTA_VERSION, "%u.%u", &a, &b) == 2) {
		v.major = (CK_BYTE)a;
		v.minor = (CK_BYTE)b;
	}
	return v;
}

/* Sessions and objects. Called with g_mu held. */

static session *get_session(CK_SESSION_HANDLE h)
{
	for (size_t i = 0; i < g_nsess; i++)
		if (g_sess[i]->h == h)
			return g_sess[i];
	return NULL;
}

static void op_end(session *s)
{
	buf_free(&s->data);
	buf_free(&s->aad);
	secure_zero(&s->sha, sizeof(s->sha));
	secure_zero(s->iv, sizeof(s->iv));
	s->op = OP_NONE;
	s->multipart = 0;
	s->key = NULL;
	s->iv_out = NULL;
}

static void find_end(session *s)
{
	free(s->found);
	s->found = NULL;
	s->nfound = s->pos = 0;
	s->finding = 0;
}

static void session_free(session *s)
{
	op_end(s);
	find_end(s);
	free(s);
}

/* release ends a call that let go of g_mu while using s. */
static void release(session *s)
{
	if (--s->busy == 0 && s->closing)
		session_free(s);
}

static void drop_session(size_t i)
{
	session *s = g_sess[i];
	g_sess[i] = g_sess[--g_nsess];
	if (s->busy)
		s->closing = 1; /* freed when its call returns */
	else
		session_free(s);
}

static void forget_keys(void)
{
	for (size_t i = 0; i < g_nkeys; i++)
		g_keys[i]->alive = 0;
}

static void logout_all(void)
{
	if (!g_logged_in)
		return;
	g_logged_in = 0;
	kms_logout(g_kms);
	forget_keys();
	g_listed = 0;
	for (size_t i = 0; i < g_nsess; i++) {
		op_end(g_sess[i]);
		find_end(g_sess[i]);
	}
}

static object *get_object(CK_OBJECT_HANDLE h)
{
	for (size_t i = 0; i < g_nobjs; i++)
		if (g_objs[i].h == h)
			return g_logged_in && g_objs[i].k->alive ? &g_objs[i] : NULL;
	return NULL;
}

static int add_object(keyinfo *k, CK_OBJECT_CLASS cls)
{
	for (size_t i = 0; i < g_nobjs; i++)
		if (g_objs[i].k == k && g_objs[i].cls == cls)
			return 0;
	object *o = realloc(g_objs, (g_nobjs + 1) * sizeof(object));
	if (!o)
		return -1;
	g_objs = o;
	g_objs[g_nobjs++] = (object){g_next_obj++, cls, k};
	return 0;
}

static int contains(const char *s, const char *w)
{
	return strstr(s, w) != NULL;
}

/* classify maps a KMS key to what the module offers, or 0. */
static int classify(const kms_key *x, int *bits)
{
	char a[64];
	size_t i;
	for (i = 0; x->algorithm[i] && i < sizeof(a) - 1; i++)
		a[i] = (char)(x->algorithm[i] >= 'a' && x->algorithm[i] <= 'z' ? x->algorithm[i] - 32 : x->algorithm[i]);
	a[i] = 0;
	if (strcmp(x->status, "active") && strcmp(x->status, "deactivated"))
		return 0;
	if (!strcmp(x->key_type, "public") || contains(a, "+") || contains(a, "ML-") || contains(a, "SLH") ||
	    contains(a, "COMPOSITE"))
		return 0;
	if (contains(a, "AES")) {
		static const char *modes[] = {"CBC", "CTR", "ECB", "CCM", "CFB", "OFB", "XTS", "KW", "SIV"};
		for (size_t m = 0; m < sizeof(modes) / sizeof(modes[0]); m++)
			if (contains(a, modes[m]))
				return 0;
		*bits = contains(a, "128") ? 128 : contains(a, "192") ? 192 : 256;
		return K_AES;
	}
	if (!contains(x->purpose, "sign"))
		return 0;
	if (!strncmp(a, "ECDSA", 5) || !strncmp(a, "EC-", 3)) {
		*bits = contains(a, "256") ? 256 : contains(a, "384") ? 384 : contains(a, "521") ? 521 : 0;
		return *bits ? K_EC : 0;
	}
	if (!strncmp(a, "RSA", 3)) {
		*bits = contains(a, "2048") ? 2048 : contains(a, "3072") ? 3072 : contains(a, "4096") ? 4096 : 0;
		return *bits ? K_RSA : 0;
	}
	return 0;
}

static void keyinfo_set_pub(keyinfo *k, unsigned char *der, size_t n, int64_t version)
{
	free(k->spki);
	k->spki = der;
	k->spki_len = n;
	k->spki_version = version;
	if (!der || spki_parse(der, n, &k->pub) != 0) {
		free(k->spki);
		k->spki = NULL;
		k->spki_len = 0;
		memset(&k->pub, 0, sizeof(k->pub));
	}
}

static CK_RV map_err(const kms_err *e, CK_RV bad_request)
{
	switch (e->http) {
	case 0:
		return CKR_DEVICE_ERROR;
	case 202:
		return CKR_FUNCTION_REJECTED; /* waits for approval */
	case 400:
		return bad_request;
	case 401:
		return CKR_USER_NOT_LOGGED_IN;
	case 403:
	case 409:
		return CKR_KEY_FUNCTION_NOT_PERMITTED;
	case 404:
		return CKR_KEY_HANDLE_INVALID;
	default:
		return e->http >= 500 || e->http == 200 ? CKR_DEVICE_ERROR : CKR_FUNCTION_FAILED;
	}
}

/* refresh lists the keys again when the last listing is older than
 * LIST_TTL (or force). Called with g_mu held; lets go of it meanwhile. */
static CK_RV refresh(session *s, int force)
{
	if (!g_logged_in || (!force && g_listed && mono() - g_listed < LIST_TTL))
		return CKR_OK;
	kms_key *keys;
	size_t n;
	kms_err e;
	s->busy++;
	pthread_mutex_unlock(&g_mu);
	int rc = kms_list_keys(g_kms, &keys, &n, &e);
	pthread_mutex_lock(&g_mu);
	int closing = s->closing;
	release(s); /* s may be gone now: not touched below */
	if (rc)
		return map_err(&e, CKR_DEVICE_ERROR);
	if (closing) {
		kms_keys_free(keys, n);
		return CKR_SESSION_CLOSED;
	}
	if (!g_logged_in) {
		kms_keys_free(keys, n);
		return CKR_USER_NOT_LOGGED_IN;
	}
	forget_keys();
	CK_RV rv = CKR_OK;
	for (size_t i = 0; i < n && rv == CKR_OK; i++) {
		int bits = 0, kind = classify(&keys[i], &bits);
		if (!kind)
			continue;
		keyinfo *k = NULL;
		for (size_t j = 0; j < g_nkeys; j++)
			if (!strcmp(g_keys[j]->id, keys[i].id))
				k = g_keys[j];
		if (!k) {
			keyinfo **g = realloc(g_keys, (g_nkeys + 1) * sizeof(keyinfo *));
			if (!g || !(k = calloc(1, sizeof(keyinfo))) || !(k->id = strdup(keys[i].id))) {
				if (g)
					g_keys = g;
				free(k);
				rv = CKR_HOST_MEMORY;
				break;
			}
			g_keys = g;
			g_keys[g_nkeys++] = k;
		}
		char *name = strdup(keys[i].name), *kcv = strdup(keys[i].kcv);
		if (!name || !kcv) {
			free(name);
			free(kcv);
			rv = CKR_HOST_MEMORY;
			break;
		}
		free(k->name);
		free(k->kcv);
		k->name = name;
		k->kcv = kcv;
		k->kind = kind;
		k->bits = bits;
		k->usable = !strcmp(keys[i].status, "active");
		if (k->version != keys[i].version)
			keyinfo_set_pub(k, NULL, 0, 0); /* rotated: a new public key */
		k->version = keys[i].version;
		k->alive = 1;
		if (kind == K_AES ? add_object(k, CKO_SECRET_KEY)
				  : add_object(k, CKO_PRIVATE_KEY) || add_object(k, CKO_PUBLIC_KEY))
			rv = CKR_HOST_MEMORY;
	}
	kms_keys_free(keys, n);
	if (rv == CKR_OK)
		g_listed = mono();
	return rv;
}

/* ensure_pub reads the key's public key once per version. g_mu held. */
static CK_RV ensure_pub(session *s, keyinfo *k)
{
	if (k->kind == K_AES || (k->spki && k->spki_version == k->version))
		return CKR_OK;
	char *id = strdup(k->id);
	if (!id)
		return CKR_HOST_MEMORY;
	unsigned char *der = NULL;
	size_t n = 0;
	int64_t ver = 0;
	kms_err e;
	s->busy++;
	pthread_mutex_unlock(&g_mu);
	int rc = kms_public_key(g_kms, id, &der, &n, &ver, &e);
	pthread_mutex_lock(&g_mu);
	int closing = s->closing;
	release(s);
	free(id);
	if (rc)
		return map_err(&e, CKR_DEVICE_ERROR);
	if (closing) {
		free(der);
		return CKR_SESSION_CLOSED;
	}
	keyinfo_set_pub(k, der, n, k->version);
	if (!k->spki || (k->kind == K_EC) != (k->pub.kind == SPKI_EC))
		return CKR_DEVICE_ERROR; /* not the key the listing described */
	if (k->kind == K_EC)
		k->bits = k->pub.curve_bits;
	else
		k->bits = (int)k->pub.modulus_len * 8;
	return CKR_OK;
}

static int needs_pub(CK_ATTRIBUTE_TYPE t)
{
	return t == CKA_EC_PARAMS || t == CKA_EC_POINT || t == CKA_MODULUS || t == CKA_PUBLIC_EXPONENT ||
	       t == CKA_MODULUS_BITS || t == CKA_PUBLIC_KEY_INFO;
}

/* Attribute values. */

enum { A_OK, A_SENSITIVE, A_INVALID };

static int put_bool(buf_t *v, int b)
{
	CK_BBOOL x = b ? CK_TRUE : CK_FALSE;
	return buf_append(v, &x, sizeof(x));
}

static int put_ulong(buf_t *v, CK_ULONG x)
{
	return buf_append(v, &x, sizeof(x));
}

static int hexval(char c)
{
	return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
}

static int attr(const object *o, CK_ATTRIBUTE_TYPE t, buf_t *v)
{
	const keyinfo *k = o->k;
	int priv = o->cls == CKO_PRIVATE_KEY, pub = o->cls == CKO_PUBLIC_KEY, sec = o->cls == CKO_SECRET_KEY;
	int rc;
	switch (t) {
	case CKA_CLASS:
		rc = put_ulong(v, o->cls);
		break;
	case CKA_KEY_TYPE:
		rc = put_ulong(v, k->kind == K_AES ? CKK_AES : k->kind == K_EC ? CKK_EC : CKK_RSA);
		break;
	case CKA_TOKEN:
		rc = put_bool(v, 1);
		break;
	case CKA_PRIVATE:
		rc = put_bool(v, !pub);
		break;
	case CKA_MODIFIABLE:
	case CKA_COPYABLE:
	case CKA_DESTROYABLE:
	case CKA_LOCAL:
	case CKA_DERIVE:
	case CKA_TRUSTED:
		rc = put_bool(v, 0);
		break;
	case CKA_LABEL:
		rc = buf_appends(v, k->name);
		break;
	case CKA_ID:
		rc = buf_appends(v, k->id);
		break;
	case CKA_START_DATE:
	case CKA_END_DATE:
		rc = 0; /* empty: not set */
		break;
	case CKA_KEY_GEN_MECHANISM:
		rc = put_ulong(v, CK_UNAVAILABLE_INFORMATION);
		break;
	case CKA_ENCRYPT:
		rc = put_bool(v, sec && k->usable);
		break;
	case CKA_DECRYPT:
		rc = put_bool(v, sec);
		break;
	case CKA_SIGN:
		rc = put_bool(v, priv && k->usable);
		break;
	case CKA_VERIFY:
		rc = put_bool(v, pub);
		break;
	case CKA_WRAP:
	case CKA_UNWRAP:
	case CKA_SIGN_RECOVER:
	case CKA_VERIFY_RECOVER:
		rc = put_bool(v, 0);
		break;
	case CKA_SENSITIVE:
		if (pub)
			return A_INVALID;
		rc = put_bool(v, 1);
		break;
	case CKA_EXTRACTABLE:
	case CKA_ALWAYS_SENSITIVE:
	case CKA_NEVER_EXTRACTABLE: /* unknown here: the KMS may have imported it */
	case CKA_ALWAYS_AUTHENTICATE:
	case CKA_WRAP_WITH_TRUSTED:
		if (pub)
			return A_INVALID;
		rc = put_bool(v, 0);
		break;
	case CKA_VALUE_LEN:
		if (!sec)
			return A_INVALID;
		rc = put_ulong(v, (CK_ULONG)k->bits / 8);
		break;
	case CKA_CHECK_VALUE: {
		if (!sec || strlen(k->kcv) != 6)
			return A_INVALID;
		unsigned char kcv[3];
		for (int i = 0; i < 3; i++) {
			int hi = hexval(k->kcv[2 * i]), lo = hexval(k->kcv[2 * i + 1]);
			if (hi < 0 || lo < 0)
				return A_INVALID;
			kcv[i] = (unsigned char)(hi << 4 | lo);
		}
		rc = buf_append(v, kcv, 3);
		break;
	}
	case CKA_SUBJECT:
		if (sec)
			return A_INVALID;
		rc = 0;
		break;
	case CKA_PUBLIC_KEY_INFO:
		if (sec || !k->spki)
			return A_INVALID;
		rc = buf_append(v, k->spki, k->spki_len);
		break;
	case CKA_EC_PARAMS:
		if (k->kind != K_EC || !k->spki)
			return A_INVALID;
		rc = buf_append(v, k->pub.ec_oid, k->pub.ec_oid_len);
		break;
	case CKA_EC_POINT: {
		if (k->kind != K_EC || !pub || !k->spki)
			return A_INVALID;
		unsigned char h[3] = {0x04};
		size_t hn = 2, l = k->pub.ec_point_len;
		if (l < 128) {
			h[1] = (unsigned char)l;
		} else {
			h[1] = 0x81;
			h[2] = (unsigned char)l;
			hn = 3;
		}
		rc = buf_append(v, h, hn) || buf_append(v, k->pub.ec_point, l);
		break;
	}
	case CKA_MODULUS:
		if (k->kind != K_RSA || !k->spki)
			return A_INVALID;
		rc = buf_append(v, k->pub.modulus, k->pub.modulus_len);
		break;
	case CKA_PUBLIC_EXPONENT:
		if (k->kind != K_RSA || !k->spki)
			return A_INVALID;
		rc = buf_append(v, k->pub.exponent, k->pub.exponent_len);
		break;
	case CKA_MODULUS_BITS:
		if (k->kind != K_RSA || !pub || !k->spki)
			return A_INVALID;
		rc = put_ulong(v, (CK_ULONG)k->pub.modulus_len * 8);
		break;
	case CKA_VALUE:
	case CKA_PRIVATE_EXPONENT:
	case CKA_PRIME_1:
	case CKA_PRIME_2:
	case CKA_EXPONENT_1:
	case CKA_EXPONENT_2:
	case CKA_COEFFICIENT:
		if (pub)
			return A_INVALID;
		return A_SENSITIVE; /* never leaves the KMS */
	default:
		return A_INVALID;
	}
	return rc ? A_INVALID : A_OK;
}

/* Mechanisms. */

static const struct {
	CK_MECHANISM_TYPE m;
	int kind, hash_bits;
	CK_ULONG min, max;
	CK_FLAGS flags;
} mechs[] = {
#define EC_FLAGS (CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS)
	{CKM_ECDSA, K_EC, 0, 256, 521, EC_FLAGS},
	{CKM_ECDSA_SHA256, K_EC, 256, 256, 521, EC_FLAGS},
	{CKM_ECDSA_SHA384, K_EC, 384, 256, 521, EC_FLAGS},
	{CKM_ECDSA_SHA512, K_EC, 512, 256, 521, EC_FLAGS},
	{CKM_RSA_PKCS_PSS, K_RSA, 0, 2048, 4096, CKF_SIGN | CKF_VERIFY},
	{CKM_SHA256_RSA_PKCS_PSS, K_RSA, 256, 2048, 4096, CKF_SIGN | CKF_VERIFY},
	{CKM_SHA384_RSA_PKCS_PSS, K_RSA, 384, 2048, 4096, CKF_SIGN | CKF_VERIFY},
	{CKM_SHA512_RSA_PKCS_PSS, K_RSA, 512, 2048, 4096, CKF_SIGN | CKF_VERIFY},
	{CKM_AES_GCM, K_AES, 0, 16, 32, CKF_ENCRYPT | CKF_DECRYPT},
};
#define NMECHS (sizeof(mechs) / sizeof(mechs[0]))

static int mech_index(CK_MECHANISM_TYPE m)
{
	for (size_t i = 0; i < NMECHS; i++)
		if (mechs[i].m == m)
			return (int)i;
	return -1;
}

static const char *hash_name(int bits)
{
	return bits == 256 ? "SHA-256" : bits == 384 ? "SHA-384" : "SHA-512";
}

/* PSS as the KMS makes it: MGF1 with the message hash, salt its length. */
static CK_RV check_pss(const CK_MECHANISM *m, int *hash_bits)
{
	if (!m->pParameter || m->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS))
		return CKR_MECHANISM_PARAM_INVALID;
	const CK_RSA_PKCS_PSS_PARAMS *p = m->pParameter;
	int bits = p->hashAlg == CKM_SHA256 ? 256 : p->hashAlg == CKM_SHA384 ? 384 : p->hashAlg == CKM_SHA512 ? 512 : 0;
	CK_RSA_PKCS_MGF_TYPE mgf = bits == 256 ? CKG_MGF1_SHA256 : bits == 384 ? CKG_MGF1_SHA384 : CKG_MGF1_SHA512;
	if (!bits || p->mgf != mgf || p->sLen != (CK_ULONG)bits / 8 || (*hash_bits && *hash_bits != bits))
		return CKR_MECHANISM_PARAM_INVALID;
	*hash_bits = bits;
	return CKR_OK;
}

/* sig_init checks a sign or verify operation; g_mu held. */
static CK_RV sig_init(session *s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE hKey, int op)
{
	if (!g_logged_in)
		return CKR_USER_NOT_LOGGED_IN;
	if (s->op != OP_NONE)
		return CKR_OPERATION_ACTIVE;
	if (!m)
		return CKR_ARGUMENTS_BAD;
	object *o = get_object(hKey);
	if (!o)
		return CKR_KEY_HANDLE_INVALID;
	int mi = mech_index(m->mechanism);
	if (mi < 0 || mechs[mi].kind == K_AES)
		return CKR_MECHANISM_INVALID;
	if (mechs[mi].kind != o->k->kind)
		return CKR_KEY_TYPE_INCONSISTENT;
	if (op == OP_SIGN && (o->cls != CKO_PRIVATE_KEY || !o->k->usable))
		return CKR_KEY_FUNCTION_NOT_PERMITTED;
	if (op == OP_VERIFY && o->cls == CKO_SECRET_KEY)
		return CKR_KEY_FUNCTION_NOT_PERMITTED;
	int bits = mechs[mi].hash_bits;
	if (o->k->kind == K_RSA) {
		CK_RV rv = check_pss(m, &bits);
		if (rv != CKR_OK)
			return rv;
	} else if (m->pParameter || m->ulParameterLen) {
		return CKR_MECHANISM_PARAM_INVALID;
	}
	keyinfo *k = o->k;
	CK_RV rv = ensure_pub(s, k);
	if (rv != CKR_OK)
		return rv;
	if (s->op != OP_NONE)
		return CKR_OPERATION_ACTIVE; /* another thread started one meanwhile */
	s->op = op;
	s->mech = m->mechanism;
	s->key = k;
	/* For CKM_RSA_PKCS_PSS the caller passes a digest of the params' hash. */
	s->hash_bits = mechs[mi].hash_bits;
	if (s->hash_bits)
		sha2_init(&s->sha, s->hash_bits);
	else if (k->kind == K_RSA)
		s->sha.bits = bits; /* only the expected digest length */
	return CKR_OK;
}

static size_t sig_len(const keyinfo *k)
{
	return k->kind == K_EC ? 2 * (((size_t)k->pub.curve_bits + 7) / 8) : k->pub.modulus_len;
}

/* digest produces what the KMS signs, from the hashed or buffered data. */
static CK_RV digest(session *s, unsigned char *out, size_t *n, int *bits)
{
	if (s->hash_bits) {
		sha2_ctx c = s->sha;
		sha2_final(&c, out);
		*n = (size_t)s->hash_bits / 8;
		*bits = s->hash_bits;
		return CKR_OK;
	}
	size_t want = s->key->kind == K_RSA ? (size_t)s->sha.bits / 8 : 0;
	if (s->data.n != 32 && s->data.n != 48 && s->data.n != 64)
		return CKR_DATA_LEN_RANGE;
	if (want && s->data.n != want)
		return CKR_DATA_LEN_RANGE;
	memcpy(out, s->data.p, s->data.n);
	*n = s->data.n;
	*bits = (int)s->data.n * 8;
	return CKR_OK;
}

static CK_RV sig_update(session *s, const unsigned char *d, size_t n)
{
	if (s->hash_bits) {
		sha2_update(&s->sha, d, n);
		return CKR_OK;
	}
	if (s->data.n + n > 64 || buf_append(&s->data, d, n))
		return CKR_DATA_LEN_RANGE;
	return CKR_OK;
}

/* sign_finish signs the operation's data into sig; g_mu held. */
static CK_RV sign_finish(session *s, CK_BYTE_PTR sig, CK_ULONG_PTR sig_n)
{
	if (!sig_n) {
		op_end(s);
		return CKR_ARGUMENTS_BAD;
	}
	size_t L = sig_len(s->key);
	if (!sig) {
		*sig_n = L;
		return CKR_OK;
	}
	if (*sig_n < L) {
		*sig_n = L;
		return CKR_BUFFER_TOO_SMALL;
	}
	unsigned char dg[64];
	size_t dn;
	int bits;
	CK_RV rv = digest(s, dg, &dn, &bits);
	if (rv != CKR_OK) {
		op_end(s);
		return rv;
	}
	char *id = strdup(s->key->id);
	int kind = s->key->kind;
	if (!id) {
		op_end(s);
		return CKR_HOST_MEMORY;
	}
	unsigned char *out = NULL;
	size_t outn = 0;
	kms_err e;
	s->busy++;
	pthread_mutex_unlock(&g_mu);
	int rc = kms_sign_digest(g_kms, id, hash_name(bits), dg, dn, &out, &outn, &e);
	pthread_mutex_lock(&g_mu);
	free(id);
	secure_zero(dg, sizeof(dg));
	int closing = s->closing;
	release(s);
	if (closing) {
		free(out);
		return CKR_SESSION_CLOSED;
	}
	op_end(s);
	if (rc)
		return map_err(&e, CKR_FUNCTION_FAILED);
	if (kind == K_EC) {
		rc = ecdsa_der_to_raw(out, outn, L / 2, sig);
	} else if (outn <= L) {
		memset(sig, 0, L - outn);
		memcpy(sig + L - outn, out, outn);
	} else {
		rc = -1;
	}
	free(out);
	if (rc)
		return CKR_DEVICE_ERROR;
	*sig_n = L;
	return CKR_OK;
}

static CK_RV verify_finish(session *s, CK_BYTE_PTR sig, CK_ULONG sig_n)
{
	size_t L = sig_len(s->key);
	if (!sig) {
		op_end(s);
		return CKR_ARGUMENTS_BAD;
	}
	if (sig_n != L) {
		op_end(s);
		return CKR_SIGNATURE_LEN_RANGE;
	}
	unsigned char dg[64];
	size_t dn;
	int bits;
	CK_RV rv = digest(s, dg, &dn, &bits);
	buf_t der = {0};
	if (rv == CKR_OK && s->key->kind == K_EC && ecdsa_raw_to_der(sig, L / 2, &der))
		rv = CKR_HOST_MEMORY;
	char *id = rv == CKR_OK ? strdup(s->key->id) : NULL;
	if (rv == CKR_OK && !id)
		rv = CKR_HOST_MEMORY;
	if (rv != CKR_OK) {
		buf_free(&der);
		op_end(s);
		return rv;
	}
	const unsigned char *send = der.n ? der.p : sig;
	size_t sendn = der.n ? der.n : L;
	int ok = 0;
	kms_err e;
	s->busy++;
	pthread_mutex_unlock(&g_mu);
	int rc = kms_verify_digest(g_kms, id, hash_name(bits), dg, dn, send, sendn, &ok, &e);
	pthread_mutex_lock(&g_mu);
	free(id);
	buf_free(&der);
	int closing = s->closing;
	release(s);
	if (closing)
		return CKR_SESSION_CLOSED;
	op_end(s);
	if (rc)
		return map_err(&e, CKR_SIGNATURE_INVALID);
	return ok ? CKR_OK : CKR_SIGNATURE_INVALID;
}

/* gcm_init checks an AES-GCM operation; g_mu held. Both the v2.40
 * CK_GCM_PARAMS layouts are taken: with ulIvBits (the errata header) and
 * without (the original). */
static CK_RV gcm_init(session *s, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE hKey, int op)
{
	if (!g_logged_in)
		return CKR_USER_NOT_LOGGED_IN;
	if (s->op != OP_NONE)
		return CKR_OPERATION_ACTIVE;
	if (!m)
		return CKR_ARGUMENTS_BAD;
	object *o = get_object(hKey);
	if (!o)
		return CKR_KEY_HANDLE_INVALID;
	if (m->mechanism != CKM_AES_GCM)
		return CKR_MECHANISM_INVALID;
	if (o->k->kind != K_AES)
		return CKR_KEY_TYPE_INCONSISTENT;
	if (op == OP_ENCRYPT && !o->k->usable)
		return CKR_KEY_FUNCTION_NOT_PERMITTED;
	CK_BYTE_PTR iv, aad;
	CK_ULONG ivn, aadn, tag;
	if (m->pParameter && m->ulParameterLen == sizeof(CK_GCM_PARAMS)) {
		const CK_GCM_PARAMS *p = m->pParameter;
		iv = p->pIv, ivn = p->ulIvLen, aad = p->pAAD, aadn = p->ulAADLen, tag = p->ulTagBits;
	} else if (m->pParameter && m->ulParameterLen == 5 * sizeof(CK_ULONG)) {
		const struct {
			CK_BYTE_PTR pIv;
			CK_ULONG ulIvLen;
			CK_BYTE_PTR pAAD;
			CK_ULONG ulAADLen, ulTagBits;
		} *p = m->pParameter;
		iv = p->pIv, ivn = p->ulIvLen, aad = p->pAAD, aadn = p->ulAADLen, tag = p->ulTagBits;
	} else {
		return CKR_MECHANISM_PARAM_INVALID;
	}
	/* The KMS's AES-GCM: 96-bit IVs, 128-bit tags. */
	if (!iv || ivn != 12 || tag != 128 || (aadn && !aad) || aadn > (1u << 20))
		return CKR_MECHANISM_PARAM_INVALID;
	op_end(s);
	if (aadn && buf_append(&s->aad, aad, aadn))
		return CKR_HOST_MEMORY;
	memcpy(s->iv, iv, 12);
	s->iv_out = op == OP_ENCRYPT && g_cfg.generated_iv ? iv : NULL;
	s->op = op;
	s->mech = CKM_AES_GCM;
	s->key = o->k;
	return CKR_OK;
}

/* gcm_finish encrypts or decrypts s->data into out; g_mu held. */
static CK_RV gcm_finish(session *s, CK_BYTE_PTR out, CK_ULONG_PTR out_n)
{
	int enc = s->op == OP_ENCRYPT;
	if (!out_n) {
		op_end(s);
		return CKR_ARGUMENTS_BAD;
	}
	if (!enc && s->data.n < 16) {
		op_end(s);
		return CKR_ENCRYPTED_DATA_LEN_RANGE;
	}
	size_t L = enc ? s->data.n + 16 : s->data.n - 16;
	if (!out) {
		*out_n = L;
		return CKR_OK;
	}
	if (*out_n < L) {
		*out_n = L;
		return CKR_BUFFER_TOO_SMALL;
	}
	char *id = strdup(s->key->id);
	if (!id) {
		op_end(s);
		return CKR_HOST_MEMORY;
	}
	buf_t data = s->data, aad = s->aad;
	unsigned char iv[12], gen_iv[12];
	memcpy(iv, s->iv, 12);
	int generated = enc && s->iv_out;
	s->data = (buf_t){0};
	s->aad = (buf_t){0};
	unsigned char *res = NULL;
	size_t resn = 0;
	kms_err e;
	s->busy++;
	pthread_mutex_unlock(&g_mu);
	int rc = enc ? kms_encrypt(g_kms, id, data.p, data.n, generated ? NULL : iv, 12, aad.p, aad.n, &res, &resn,
				   gen_iv, &e)
		     : kms_decrypt(g_kms, id, data.p, data.n, iv, 12, aad.p, aad.n, &res, &resn, &e);
	pthread_mutex_lock(&g_mu);
	free(id);
	buf_free(&data);
	buf_free(&aad);
	int closing = s->closing;
	CK_BYTE_PTR iv_out = s->iv_out;
	release(s);
	if (closing) {
		if (res) {
			secure_zero(res, resn);
			free(res);
		}
		return CKR_SESSION_CLOSED;
	}
	op_end(s);
	if (rc) {
		if (!enc && e.http == 400)
			return CKR_ENCRYPTED_DATA_INVALID;
		return map_err(&e, CKR_MECHANISM_PARAM_INVALID);
	}
	CK_RV rv = CKR_OK;
	if (resn != L) {
		rv = CKR_DEVICE_ERROR;
	} else {
		memcpy(out, res, L);
		*out_n = L;
		if (generated)
			memcpy(iv_out, gen_iv, 12);
	}
	secure_zero(res, resn);
	free(res);
	return rv;
}

/* Entry-point plumbing. */

#define ENTER()                                                                                                        \
	pthread_mutex_lock(&g_mu);                                                                                     \
	if (!g_init) {                                                                                                 \
		pthread_mutex_unlock(&g_mu);                                                                           \
		return CKR_CRYPTOKI_NOT_INITIALIZED;                                                                   \
	}
#define RETURN(rv)                                                                                                     \
	do {                                                                                                           \
		CK_RV r_ = (rv);                                                                                       \
		pthread_mutex_unlock(&g_mu);                                                                           \
		return r_;                                                                                             \
	} while (0)
#define SESSION(h)                                                                                                     \
	session *s = get_session(h);                                                                                   \
	if (!s)                                                                                                        \
	RETURN(CKR_SESSION_HANDLE_INVALID)

CK_RV C_Initialize(CK_VOID_PTR pInitArgs)
{
	if (pInitArgs) {
		CK_C_INITIALIZE_ARGS *a = pInitArgs;
		int fns = (a->CreateMutex != NULL) + (a->DestroyMutex != NULL) + (a->LockMutex != NULL) +
			  (a->UnlockMutex != NULL);
		if (a->pReserved || (fns != 0 && fns != 4))
			return CKR_ARGUMENTS_BAD;
		/* libcurl may resolve names on its own thread. */
		if (a->flags & CKF_LIBRARY_CANT_CREATE_OS_THREADS)
			return CKR_NEED_TO_CREATE_THREADS;
		/* With or without the application's mutex functions, the module
		 * locks with the operating system's. */
	}
	pthread_mutex_lock(&g_mu);
	if (g_init)
		RETURN(CKR_CRYPTOKI_ALREADY_INITIALIZED);
	char err[512];
	if (kms_config_load(&g_cfg, err, sizeof(err)) != 0) {
		fprintf(stderr, "vecta-pkcs11: %s\n", err);
		RETURN(CKR_GENERAL_ERROR);
	}
	if (!(g_kms = kms_new(&g_cfg))) {
		kms_config_free(&g_cfg);
		RETURN(CKR_HOST_MEMORY);
	}
	pthread_once(&g_fork_once, register_fork);
	g_init = 1;
	kms_log(g_kms, "initialized for %s, tenant %s", g_cfg.url, g_cfg.tenant);
	RETURN(CKR_OK);
}

CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
	if (pReserved)
		return CKR_ARGUMENTS_BAD;
	ENTER();
	logout_all();
	while (g_nsess)
		drop_session(0);
	free(g_sess);
	g_sess = NULL;
	for (size_t i = 0; i < g_nkeys; i++) {
		free(g_keys[i]->id);
		free(g_keys[i]->name);
		free(g_keys[i]->kcv);
		free(g_keys[i]->spki);
		free(g_keys[i]);
	}
	free(g_keys);
	g_keys = NULL;
	g_nkeys = 0;
	free(g_objs);
	g_objs = NULL;
	g_nobjs = 0;
	kms_free(g_kms);
	g_kms = NULL;
	kms_config_free(&g_cfg);
	g_init = 0;
	RETURN(CKR_OK);
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
	ENTER();
	if (!pInfo)
		RETURN(CKR_ARGUMENTS_BAD);
	memset(pInfo, 0, sizeof(*pInfo));
	pInfo->cryptokiVersion = (CK_VERSION){2, 40};
	pad(pInfo->manufacturerID, sizeof(pInfo->manufacturerID), "Vecta KMS");
	pad(pInfo->libraryDescription, sizeof(pInfo->libraryDescription), "Vecta KMS PKCS#11 module");
	pInfo->libraryVersion = lib_version();
	RETURN(CKR_OK);
}

static CK_FUNCTION_LIST function_list;

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	if (!ppFunctionList)
		return CKR_ARGUMENTS_BAD;
	*ppFunctionList = &function_list;
	return CKR_OK;
}

/* PKCS#11 3.0's discovery entry points, answered with this v2.40 list.
 * Without them, dlsym(module, "C_GetInterface") finds the one in a
 * library the module depends on (libcurl -> GnuTLS -> p11-kit exports
 * p11-kit's proxy), and the application talks to the wrong module. */
typedef struct {
	CK_CHAR *pInterfaceName;
	CK_VOID_PTR pFunctionList;
	CK_FLAGS flags;
} vecta_interface;

static vecta_interface interface = {(CK_CHAR *)"PKCS 11", &function_list, 0};

__attribute__((visibility("default"))) CK_RV C_GetInterfaceList(vecta_interface *pInterfacesList, CK_ULONG_PTR pulCount)
{
	if (!pulCount)
		return CKR_ARGUMENTS_BAD;
	if (pInterfacesList) {
		if (*pulCount < 1) {
			*pulCount = 1;
			return CKR_BUFFER_TOO_SMALL;
		}
		pInterfacesList[0] = interface;
	}
	*pulCount = 1;
	return CKR_OK;
}

__attribute__((visibility("default"))) CK_RV C_GetInterface(CK_UTF8CHAR_PTR pInterfaceName, CK_VERSION_PTR pVersion,
							      vecta_interface **ppInterface, CK_FLAGS flags)
{
	if (!ppInterface)
		return CKR_ARGUMENTS_BAD;
	if ((pInterfaceName && strcmp((const char *)pInterfaceName, "PKCS 11")) ||
	    (pVersion && (pVersion->major != 2 || pVersion->minor != 40)) || flags)
		return CKR_ARGUMENTS_BAD; /* only PKCS 11 v2.40, no special flags */
	*ppInterface = &interface;
	return CKR_OK;
}

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
	(void)tokenPresent;
	ENTER();
	if (!pulCount)
		RETURN(CKR_ARGUMENTS_BAD);
	if (!pSlotList) {
		*pulCount = 1;
		RETURN(CKR_OK);
	}
	if (*pulCount < 1) {
		*pulCount = 1;
		RETURN(CKR_BUFFER_TOO_SMALL);
	}
	pSlotList[0] = SLOT_ID;
	*pulCount = 1;
	RETURN(CKR_OK);
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	ENTER();
	if (slotID != SLOT_ID)
		RETURN(CKR_SLOT_ID_INVALID);
	if (!pInfo)
		RETURN(CKR_ARGUMENTS_BAD);
	memset(pInfo, 0, sizeof(*pInfo));
	char desc[256];
	snprintf(desc, sizeof(desc), "Vecta KMS %s", g_cfg.url + 8);
	pad(pInfo->slotDescription, sizeof(pInfo->slotDescription), desc);
	pad(pInfo->manufacturerID, sizeof(pInfo->manufacturerID), "Vecta KMS");
	pInfo->flags = CKF_TOKEN_PRESENT;
	pInfo->hardwareVersion = pInfo->firmwareVersion = lib_version();
	RETURN(CKR_OK);
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	ENTER();
	if (slotID != SLOT_ID)
		RETURN(CKR_SLOT_ID_INVALID);
	if (!pInfo)
		RETURN(CKR_ARGUMENTS_BAD);
	memset(pInfo, 0, sizeof(*pInfo));
	pad(pInfo->label, sizeof(pInfo->label), g_cfg.label);
	pad(pInfo->manufacturerID, sizeof(pInfo->manufacturerID), "Vecta KMS");
	pad(pInfo->model, sizeof(pInfo->model), "REST client");
	/* The serial number names the tenant: one token per tenant. */
	unsigned char h[32];
	char serial[17];
	sha2_ctx c;
	sha2_init(&c, 256);
	sha2_update(&c, (const unsigned char *)g_cfg.tenant, strlen(g_cfg.tenant));
	sha2_final(&c, h);
	for (int i = 0; i < 8; i++)
		snprintf(serial + 2 * i, 3, "%02x", h[i]);
	pad(pInfo->serialNumber, sizeof(pInfo->serialNumber), serial);
	pInfo->flags = CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED;
	CK_ULONG rw = 0;
	for (size_t i = 0; i < g_nsess; i++)
		rw += (g_sess[i]->flags & CKF_RW_SESSION) != 0;
	pInfo->ulMaxSessionCount = pInfo->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
	pInfo->ulSessionCount = g_nsess;
	pInfo->ulRwSessionCount = rw;
	pInfo->ulMaxPinLen = 8192;
	pInfo->ulMinPinLen = 1;
	pInfo->ulTotalPublicMemory = pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulTotalPrivateMemory = pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->hardwareVersion = pInfo->firmwareVersion = lib_version();
	memset(pInfo->utcTime, ' ', sizeof(pInfo->utcTime));
	RETURN(CKR_OK);
}

CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pList, CK_ULONG_PTR pulCount)
{
	ENTER();
	if (slotID != SLOT_ID)
		RETURN(CKR_SLOT_ID_INVALID);
	if (!pulCount)
		RETURN(CKR_ARGUMENTS_BAD);
	if (pList && *pulCount < NMECHS) {
		*pulCount = NMECHS;
		RETURN(CKR_BUFFER_TOO_SMALL);
	}
	for (size_t i = 0; pList && i < NMECHS; i++)
		pList[i] = mechs[i].m;
	*pulCount = NMECHS;
	RETURN(CKR_OK);
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
	ENTER();
	if (slotID != SLOT_ID)
		RETURN(CKR_SLOT_ID_INVALID);
	if (!pInfo)
		RETURN(CKR_ARGUMENTS_BAD);
	int i = mech_index(type);
	if (i < 0)
		RETURN(CKR_MECHANISM_INVALID);
	pInfo->ulMinKeySize = mechs[i].min;
	pInfo->ulMaxKeySize = mechs[i].max;
	pInfo->flags = mechs[i].flags;
	RETURN(CKR_OK);
}

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify,
		    CK_SESSION_HANDLE_PTR phSession)
{
	(void)pApplication;
	(void)Notify;
	ENTER();
	if (slotID != SLOT_ID)
		RETURN(CKR_SLOT_ID_INVALID);
	if (!(flags & CKF_SERIAL_SESSION))
		RETURN(CKR_SESSION_PARALLEL_NOT_SUPPORTED);
	if (!phSession)
		RETURN(CKR_ARGUMENTS_BAD);
	session **g = realloc(g_sess, (g_nsess + 1) * sizeof(session *));
	if (!g)
		RETURN(CKR_HOST_MEMORY);
	g_sess = g;
	session *s = calloc(1, sizeof(session));
	if (!s)
		RETURN(CKR_HOST_MEMORY);
	s->h = g_next_sess++;
	s->flags = flags & (CKF_SERIAL_SESSION | CKF_RW_SESSION);
	g_sess[g_nsess++] = s;
	*phSession = s->h;
	RETURN(CKR_OK);
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
	ENTER();
	for (size_t i = 0; i < g_nsess; i++) {
		if (g_sess[i]->h == hSession) {
			drop_session(i);
			if (g_nsess == 0)
				logout_all(); /* the last session closed: logged out */
			RETURN(CKR_OK);
		}
	}
	RETURN(CKR_SESSION_HANDLE_INVALID);
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
	ENTER();
	if (slotID != SLOT_ID)
		RETURN(CKR_SLOT_ID_INVALID);
	while (g_nsess)
		drop_session(0);
	logout_all();
	RETURN(CKR_OK);
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	ENTER();
	SESSION(hSession);
	if (!pInfo)
		RETURN(CKR_ARGUMENTS_BAD);
	int rw = (s->flags & CKF_RW_SESSION) != 0;
	pInfo->slotID = SLOT_ID;
	pInfo->state = g_logged_in ? (rw ? CKS_RW_USER_FUNCTIONS : CKS_RO_USER_FUNCTIONS)
				   : (rw ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION);
	pInfo->flags = s->flags;
	pInfo->ulDeviceError = 0;
	RETURN(CKR_OK);
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	ENTER();
	SESSION(hSession);
	if (userType != CKU_USER)
		RETURN(CKR_USER_TYPE_INVALID); /* no security officer: the KMS administers */
	if (g_logged_in)
		RETURN(CKR_USER_ALREADY_LOGGED_IN);
	if (!pPin || ulPinLen == 0)
		RETURN(CKR_ARGUMENTS_BAD);
	char *pin = malloc(ulPinLen);
	if (!pin)
		RETURN(CKR_HOST_MEMORY);
	memcpy(pin, pPin, ulPinLen);
	kms_err e;
	s->busy++;
	pthread_mutex_unlock(&g_mu);
	int rc = kms_login(g_kms, pin, ulPinLen, &e);
	secure_zero(pin, ulPinLen);
	free(pin);
	pthread_mutex_lock(&g_mu);
	release(s);
	if (rc) {
		kms_log(g_kms, "login refused: %ld %s (request %s)", e.http, e.code, e.request_id);
		RETURN(e.http == 401 || e.http == 403 ? CKR_PIN_INCORRECT : map_err(&e, CKR_PIN_INCORRECT));
	}
	if (g_logged_in) { /* another thread logged in meanwhile */
		RETURN(CKR_USER_ALREADY_LOGGED_IN);
	}
	g_logged_in = 1;
	session *again = get_session(hSession);
	CK_RV rv = again ? refresh(again, 1) : CKR_OK;
	if (rv != CKR_OK)
		logout_all();
	RETURN(rv);
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
	ENTER();
	SESSION(hSession);
	(void)s;
	if (!g_logged_in)
		RETURN(CKR_USER_NOT_LOGGED_IN);
	logout_all();
	RETURN(CKR_OK);
}

static int template_matches(const object *o, CK_ATTRIBUTE_PTR t, CK_ULONG n)
{
	for (CK_ULONG i = 0; i < n; i++) {
		buf_t v = {0};
		int r = attr(o, t[i].type, &v);
		int ok = r == A_OK && v.n == t[i].ulValueLen && (v.n == 0 || (t[i].pValue && !memcmp(v.p, t[i].pValue, v.n)));
		buf_free(&v);
		if (!ok)
			return 0;
	}
	return 1;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	ENTER();
	SESSION(hSession);
	if (s->finding)
		RETURN(CKR_OPERATION_ACTIVE);
	if (ulCount && !pTemplate)
		RETURN(CKR_ARGUMENTS_BAD);
	CK_RV rv = refresh(s, 0);
	if (rv != CKR_OK)
		RETURN(rv);
	if (!get_session(hSession))
		RETURN(CKR_SESSION_CLOSED);
	int pub_needed = 0;
	for (CK_ULONG i = 0; i < ulCount; i++)
		pub_needed |= needs_pub(pTemplate[i].type);
	/* Handles are copied first: reading public keys lets go of the lock. */
	size_t n = g_nobjs;
	CK_OBJECT_HANDLE *cand = calloc(n ? n : 1, sizeof(CK_OBJECT_HANDLE));
	if (!cand)
		RETURN(CKR_HOST_MEMORY);
	for (size_t i = 0; i < n; i++)
		cand[i] = g_objs[i].h;
	size_t found = 0;
	for (size_t i = 0; i < n && g_logged_in; i++) {
		object *o = get_object(cand[i]);
		if (!o)
			continue;
		if (pub_needed && o->cls != CKO_SECRET_KEY) {
			keyinfo *k = o->k;
			rv = ensure_pub(s, k);
			if (rv != CKR_OK) {
				free(cand);
				RETURN(rv);
			}
			if (!(o = get_object(cand[i])))
				continue;
		}
		if (template_matches(o, pTemplate, ulCount))
			cand[found++] = cand[i];
	}
	if (!get_session(hSession)) {
		free(cand);
		RETURN(CKR_SESSION_CLOSED);
	}
	s->found = cand;
	s->nfound = found;
	s->pos = 0;
	s->finding = 1;
	RETURN(CKR_OK);
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount,
		    CK_ULONG_PTR pulObjectCount)
{
	ENTER();
	SESSION(hSession);
	if (!s->finding)
		RETURN(CKR_OPERATION_NOT_INITIALIZED);
	if (!phObject || !pulObjectCount)
		RETURN(CKR_ARGUMENTS_BAD);
	CK_ULONG k = 0;
	while (k < ulMaxObjectCount && s->pos < s->nfound)
		phObject[k++] = s->found[s->pos++];
	*pulObjectCount = k;
	RETURN(CKR_OK);
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
	ENTER();
	SESSION(hSession);
	if (!s->finding)
		RETURN(CKR_OPERATION_NOT_INITIALIZED);
	find_end(s);
	RETURN(CKR_OK);
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
			  CK_ULONG ulCount)
{
	ENTER();
	SESSION(hSession);
	if (ulCount && !pTemplate)
		RETURN(CKR_ARGUMENTS_BAD);
	object *o = get_object(hObject);
	if (!o)
		RETURN(CKR_OBJECT_HANDLE_INVALID);
	for (CK_ULONG i = 0; i < ulCount; i++) {
		if (needs_pub(pTemplate[i].type) && o->cls != CKO_SECRET_KEY) {
			CK_RV rv = ensure_pub(s, o->k);
			if (rv != CKR_OK)
				RETURN(rv);
			if (!(o = get_object(hObject)))
				RETURN(CKR_OBJECT_HANDLE_INVALID);
			break;
		}
	}
	CK_RV rv = CKR_OK;
	for (CK_ULONG i = 0; i < ulCount; i++) {
		buf_t v = {0};
		int r = attr(o, pTemplate[i].type, &v);
		if (r == A_SENSITIVE) {
			pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
			rv = CKR_ATTRIBUTE_SENSITIVE;
		} else if (r == A_INVALID) {
			pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
			rv = CKR_ATTRIBUTE_TYPE_INVALID;
		} else if (!pTemplate[i].pValue) {
			pTemplate[i].ulValueLen = v.n;
		} else if (pTemplate[i].ulValueLen >= v.n) {
			if (v.n)
				memcpy(pTemplate[i].pValue, v.p, v.n);
			pTemplate[i].ulValueLen = v.n;
		} else {
			pTemplate[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
			rv = CKR_BUFFER_TOO_SMALL;
		}
		buf_free(&v);
	}
	RETURN(rv);
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	ENTER();
	SESSION(hSession);
	RETURN(sig_init(s, pMechanism, hKey, OP_SIGN));
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
	     CK_ULONG_PTR pulSignatureLen)
{
	ENTER();
	SESSION(hSession);
	if (s->op != OP_SIGN)
		RETURN(CKR_OPERATION_NOT_INITIALIZED);
	if (s->multipart)
		RETURN(CKR_OPERATION_ACTIVE);
	if (!pulSignatureLen || (!pData && ulDataLen)) {
		op_end(s);
		RETURN(CKR_ARGUMENTS_BAD);
	}
	/* A length query, or a buffer too small, leaves the operation as it was. */
	size_t L = sig_len(s->key);
	if (!pSignature || *pulSignatureLen < L) {
		*pulSignatureLen = L;
		RETURN(pSignature ? CKR_BUFFER_TOO_SMALL : CKR_OK);
	}
	CK_RV rv = sig_update(s, pData, ulDataLen);
	if (rv != CKR_OK) {
		op_end(s);
		RETURN(rv);
	}
	RETURN(sign_finish(s, pSignature, pulSignatureLen));
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	ENTER();
	SESSION(hSession);
	if (s->op != OP_SIGN)
		RETURN(CKR_OPERATION_NOT_INITIALIZED);
	if (!pPart && ulPartLen) {
		op_end(s);
		RETURN(CKR_ARGUMENTS_BAD);
	}
	CK_RV rv = sig_update(s, pPart, ulPartLen);
	if (rv != CKR_OK)
		op_end(s);
	else
		s->multipart = 1;
	RETURN(rv);
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	ENTER();
	SESSION(hSession);
	if (s->op != OP_SIGN)
		RETURN(CKR_OPERATION_NOT_INITIALIZED);
	RETURN(sign_finish(s, pSignature, pulSignatureLen));
}

CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	ENTER();
	SESSION(hSession);
	RETURN(sig_init(s, pMechanism, hKey, OP_VERIFY));
}

CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
	       CK_ULONG ulSignatureLen)
{
	ENTER();
	SESSION(hSession);
	if (s->op != OP_VERIFY)
		RETURN(CKR_OPERATION_NOT_INITIALIZED);
	if (s->multipart)
		RETURN(CKR_OPERATION_ACTIVE);
	if (!pData && ulDataLen) {
		op_end(s);
		RETURN(CKR_ARGUMENTS_BAD);
	}
	CK_RV rv = sig_update(s, pData, ulDataLen);
	if (rv != CKR_OK) {
		op_end(s);
		RETURN(rv);
	}
	RETURN(verify_finish(s, pSignature, ulSignatureLen));
}

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	ENTER();
	SESSION(hSession);
	if (s->op != OP_VERIFY)
		RETURN(CKR_OPERATION_NOT_INITIALIZED);
	if (!pPart && ulPartLen) {
		op_end(s);
		RETURN(CKR_ARGUMENTS_BAD);
	}
	CK_RV rv = sig_update(s, pPart, ulPartLen);
	if (rv != CKR_OK)
		op_end(s);
	else
		s->multipart = 1;
	RETURN(rv);
}

CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	ENTER();
	SESSION(hSession);
	if (s->op != OP_VERIFY)
		RETURN(CKR_OPERATION_NOT_INITIALIZED);
	RETURN(verify_finish(s, pSignature, ulSignatureLen));
}

static CK_RV gcm_single(session *s, int op, CK_BYTE_PTR in, CK_ULONG in_n, CK_BYTE_PTR out, CK_ULONG_PTR out_n)
{
	if (s->op != op)
		return CKR_OPERATION_NOT_INITIALIZED;
	if (s->multipart)
		return CKR_OPERATION_ACTIVE;
	if ((!in && in_n) || in_n > MAX_BUFFERED) {
		op_end(s);
		return in_n > MAX_BUFFERED ? CKR_DATA_LEN_RANGE : CKR_ARGUMENTS_BAD;
	}
	s->data.n = 0;
	if (buf_append(&s->data, in, in_n)) {
		op_end(s);
		return CKR_HOST_MEMORY;
	}
	return gcm_finish(s, out, out_n);
}

static CK_RV gcm_update(session *s, int op, CK_BYTE_PTR in, CK_ULONG in_n, CK_ULONG_PTR out_n)
{
	if (s->op != op)
		return CKR_OPERATION_NOT_INITIALIZED;
	if ((!in && in_n) || !out_n) {
		op_end(s);
		return CKR_ARGUMENTS_BAD;
	}
	if (s->data.n + in_n > MAX_BUFFERED) {
		op_end(s);
		return CKR_DATA_LEN_RANGE;
	}
	if (buf_append(&s->data, in, in_n)) {
		op_end(s);
		return CKR_HOST_MEMORY;
	}
	s->multipart = 1;
	*out_n = 0; /* AES-GCM output comes at the end */
	return CKR_OK;
}

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	ENTER();
	SESSION(hSession);
	RETURN(gcm_init(s, pMechanism, hKey, OP_ENCRYPT));
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData,
		CK_ULONG_PTR pulEncryptedDataLen)
{
	ENTER();
	SESSION(hSession);
	RETURN(gcm_single(s, OP_ENCRYPT, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen));
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
		      CK_ULONG_PTR pulEncryptedPartLen)
{
	(void)pEncryptedPart;
	ENTER();
	SESSION(hSession);
	RETURN(gcm_update(s, OP_ENCRYPT, pPart, ulPartLen, pulEncryptedPartLen));
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
{
	ENTER();
	SESSION(hSession);
	if (s->op != OP_ENCRYPT)
		RETURN(CKR_OPERATION_NOT_INITIALIZED);
	RETURN(gcm_finish(s, pLastEncryptedPart, pulLastEncryptedPartLen));
}

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	ENTER();
	SESSION(hSession);
	RETURN(gcm_init(s, pMechanism, hKey, OP_DECRYPT));
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData,
		CK_ULONG_PTR pulDataLen)
{
	ENTER();
	SESSION(hSession);
	RETURN(gcm_single(s, OP_DECRYPT, pEncryptedData, ulEncryptedDataLen, pData, pulDataLen));
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
		      CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	(void)pPart;
	ENTER();
	SESSION(hSession);
	RETURN(gcm_update(s, OP_DECRYPT, pEncryptedPart, ulEncryptedPartLen, pulPartLen));
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{
	ENTER();
	SESSION(hSession);
	if (s->op != OP_DECRYPT)
		RETURN(CKR_OPERATION_NOT_INITIALIZED);
	RETURN(gcm_finish(s, pLastPart, pulLastPartLen));
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen)
{
	ENTER();
	SESSION(hSession);
	if (!RandomData && ulRandomLen)
		RETURN(CKR_ARGUMENTS_BAD);
	if (!g_logged_in)
		RETURN(CKR_USER_NOT_LOGGED_IN);
	kms_err e;
	s->busy++;
	pthread_mutex_unlock(&g_mu);
	int rc = kms_random(g_kms, RandomData, ulRandomLen, &e);
	pthread_mutex_lock(&g_mu);
	release(s);
	RETURN(rc ? map_err(&e, CKR_FUNCTION_FAILED) : CKR_OK);
}

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
	(void)pSeed;
	(void)ulSeedLen;
	ENTER();
	SESSION(hSession);
	(void)s;
	RETURN(CKR_RANDOM_SEED_NOT_SUPPORTED);
}

CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
	(void)hSession;
	return CKR_FUNCTION_NOT_PARALLEL;
}

CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession)
{
	(void)hSession;
	return CKR_FUNCTION_NOT_PARALLEL;
}

/* Not offered: the KMS creates, changes and destroys keys (its API and
 * dashboard, with their policies, approvals and audit), not this token. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#define UNSUPPORTED(name, ...)                                                                                         \
	CK_RV name(__VA_ARGS__)                                                                                        \
	{                                                                                                              \
		return CKR_FUNCTION_NOT_SUPPORTED;                                                                     \
	}
UNSUPPORTED(C_InitToken, CK_SLOT_ID a, CK_UTF8CHAR_PTR b, CK_ULONG c, CK_UTF8CHAR_PTR d)
UNSUPPORTED(C_InitPIN, CK_SESSION_HANDLE a, CK_UTF8CHAR_PTR b, CK_ULONG c)
UNSUPPORTED(C_SetPIN, CK_SESSION_HANDLE a, CK_UTF8CHAR_PTR b, CK_ULONG c, CK_UTF8CHAR_PTR d, CK_ULONG e)
UNSUPPORTED(C_GetOperationState, CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG_PTR c)
UNSUPPORTED(C_SetOperationState, CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c, CK_OBJECT_HANDLE d, CK_OBJECT_HANDLE e)
UNSUPPORTED(C_CreateObject, CK_SESSION_HANDLE a, CK_ATTRIBUTE_PTR b, CK_ULONG c, CK_OBJECT_HANDLE_PTR d)
UNSUPPORTED(C_CopyObject, CK_SESSION_HANDLE a, CK_OBJECT_HANDLE b, CK_ATTRIBUTE_PTR c, CK_ULONG d, CK_OBJECT_HANDLE_PTR e)
UNSUPPORTED(C_DestroyObject, CK_SESSION_HANDLE a, CK_OBJECT_HANDLE b)
UNSUPPORTED(C_GetObjectSize, CK_SESSION_HANDLE a, CK_OBJECT_HANDLE b, CK_ULONG_PTR c)
UNSUPPORTED(C_SetAttributeValue, CK_SESSION_HANDLE a, CK_OBJECT_HANDLE b, CK_ATTRIBUTE_PTR c, CK_ULONG d)
UNSUPPORTED(C_DigestInit, CK_SESSION_HANDLE a, CK_MECHANISM_PTR b)
UNSUPPORTED(C_Digest, CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c, CK_BYTE_PTR d, CK_ULONG_PTR e)
UNSUPPORTED(C_DigestUpdate, CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c)
UNSUPPORTED(C_DigestKey, CK_SESSION_HANDLE a, CK_OBJECT_HANDLE b)
UNSUPPORTED(C_DigestFinal, CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG_PTR c)
UNSUPPORTED(C_SignRecoverInit, CK_SESSION_HANDLE a, CK_MECHANISM_PTR b, CK_OBJECT_HANDLE c)
UNSUPPORTED(C_SignRecover, CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c, CK_BYTE_PTR d, CK_ULONG_PTR e)
UNSUPPORTED(C_VerifyRecoverInit, CK_SESSION_HANDLE a, CK_MECHANISM_PTR b, CK_OBJECT_HANDLE c)
UNSUPPORTED(C_VerifyRecover, CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c, CK_BYTE_PTR d, CK_ULONG_PTR e)
UNSUPPORTED(C_DigestEncryptUpdate, CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c, CK_BYTE_PTR d, CK_ULONG_PTR e)
UNSUPPORTED(C_DecryptDigestUpdate, CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c, CK_BYTE_PTR d, CK_ULONG_PTR e)
UNSUPPORTED(C_SignEncryptUpdate, CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c, CK_BYTE_PTR d, CK_ULONG_PTR e)
UNSUPPORTED(C_DecryptVerifyUpdate, CK_SESSION_HANDLE a, CK_BYTE_PTR b, CK_ULONG c, CK_BYTE_PTR d, CK_ULONG_PTR e)
UNSUPPORTED(C_GenerateKey, CK_SESSION_HANDLE a, CK_MECHANISM_PTR b, CK_ATTRIBUTE_PTR c, CK_ULONG d, CK_OBJECT_HANDLE_PTR e)
UNSUPPORTED(C_GenerateKeyPair, CK_SESSION_HANDLE a, CK_MECHANISM_PTR b, CK_ATTRIBUTE_PTR c, CK_ULONG d,
	    CK_ATTRIBUTE_PTR e, CK_ULONG f, CK_OBJECT_HANDLE_PTR g, CK_OBJECT_HANDLE_PTR h)
UNSUPPORTED(C_WrapKey, CK_SESSION_HANDLE a, CK_MECHANISM_PTR b, CK_OBJECT_HANDLE c, CK_OBJECT_HANDLE d, CK_BYTE_PTR e,
	    CK_ULONG_PTR f)
UNSUPPORTED(C_UnwrapKey, CK_SESSION_HANDLE a, CK_MECHANISM_PTR b, CK_OBJECT_HANDLE c, CK_BYTE_PTR d, CK_ULONG e,
	    CK_ATTRIBUTE_PTR f, CK_ULONG g, CK_OBJECT_HANDLE_PTR h)
UNSUPPORTED(C_DeriveKey, CK_SESSION_HANDLE a, CK_MECHANISM_PTR b, CK_OBJECT_HANDLE c, CK_ATTRIBUTE_PTR d, CK_ULONG e,
	    CK_OBJECT_HANDLE_PTR f)
UNSUPPORTED(C_WaitForSlotEvent, CK_FLAGS a, CK_SLOT_ID_PTR b, CK_VOID_PTR c)
#pragma GCC diagnostic pop

/* The function list, in pkcs11f.h's order, from pkcs11f.h itself. */
static CK_FUNCTION_LIST function_list = {
	{2, 40},
#define CK_PKCS11_FUNCTION_INFO(name) name,
#include "pkcs11f.h"
#undef CK_PKCS11_FUNCTION_INFO
};

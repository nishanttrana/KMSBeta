/* The contract driver: loads the module as an application does (dlopen,
 * C_GetFunctionList) and checks every path against a real keycore.
 * TestPKCS11AgainstKeycore (services/keycore) runs it; the environment
 * names the keys and the expected answers. */
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
#define NULL_PTR 0
#include "pkcs11.h"

static CK_FUNCTION_LIST_PTR p;

#define WANT(call, want)                                                                                               \
	do {                                                                                                           \
		CK_RV r_ = (call);                                                                                     \
		if (r_ != (CK_RV)(want)) {                                                                             \
			fprintf(stderr, "FAIL %s:%d: %s = 0x%lx, want 0x%lx\n", __FILE__, __LINE__, #call,             \
				(unsigned long)r_, (unsigned long)(want));                                             \
			exit(1);                                                                                       \
		}                                                                                                      \
	} while (0)
#define OK(call) WANT(call, CKR_OK)
#define TRUE_(cond)                                                                                                    \
	do {                                                                                                           \
		if (!(cond)) {                                                                                         \
			fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                                \
			exit(1);                                                                                       \
		}                                                                                                      \
	} while (0)

static const char *env(const char *n)
{
	const char *v = getenv(n);
	if (!v) {
		fprintf(stderr, "FAIL: %s is not set\n", n);
		exit(1);
	}
	return v;
}

static size_t unhex(const char *s, unsigned char *out, size_t max)
{
	size_t n = strlen(s) / 2;
	TRUE_(n <= max);
	for (size_t i = 0; i < n; i++) {
		unsigned v;
		TRUE_(sscanf(s + 2 * i, "%2x", &v) == 1);
		out[i] = (unsigned char)v;
	}
	return n;
}

static CK_OBJECT_HANDLE find1(CK_SESSION_HANDLE s, CK_OBJECT_CLASS cls, const char *label)
{
	CK_ATTRIBUTE t[] = {{CKA_CLASS, &cls, sizeof(cls)}, {CKA_LABEL, (void *)label, strlen(label)}};
	CK_OBJECT_HANDLE h[4];
	CK_ULONG n = 0;
	OK(p->C_FindObjectsInit(s, t, 2));
	OK(p->C_FindObjects(s, h, 4, &n));
	OK(p->C_FindObjectsFinal(s));
	if (n != 1) {
		fprintf(stderr, "FAIL: %lu objects of class %lu labelled %s\n", (unsigned long)n, (unsigned long)cls, label);
		exit(1);
	}
	return h[0];
}

static CK_ULONG count_all(CK_SESSION_HANDLE s)
{
	CK_OBJECT_HANDLE h[64];
	CK_ULONG n = 0;
	OK(p->C_FindObjectsInit(s, NULL, 0));
	OK(p->C_FindObjects(s, h, 64, &n));
	OK(p->C_FindObjectsFinal(s));
	return n;
}

static void sign_verify(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE priv, CK_OBJECT_HANDLE pub, CK_MECHANISM *m,
			const unsigned char *data, size_t n, size_t want_len)
{
	unsigned char sig[1024];
	CK_ULONG sl = 0;
	OK(p->C_SignInit(s, m, priv));
	OK(p->C_Sign(s, (CK_BYTE_PTR)data, n, NULL, &sl)); /* length query */
	TRUE_(sl == want_len);
	sl = 1;
	WANT(p->C_Sign(s, (CK_BYTE_PTR)data, n, sig, &sl), CKR_BUFFER_TOO_SMALL);
	TRUE_(sl == want_len);
	sl = sizeof(sig);
	OK(p->C_Sign(s, (CK_BYTE_PTR)data, n, sig, &sl));
	TRUE_(sl == want_len);
	WANT(p->C_Sign(s, (CK_BYTE_PTR)data, n, sig, &sl), CKR_OPERATION_NOT_INITIALIZED); /* ended */
	OK(p->C_VerifyInit(s, m, pub));
	OK(p->C_Verify(s, (CK_BYTE_PTR)data, n, sig, sl));
	sig[sl / 2] ^= 1;
	OK(p->C_VerifyInit(s, m, pub));
	WANT(p->C_Verify(s, (CK_BYTE_PTR)data, n, sig, sl), CKR_SIGNATURE_INVALID);
}

typedef struct {
	CK_OBJECT_HANDLE priv, pub;
	int failures;
} thread_arg;

static void *worker(void *a)
{
	thread_arg *t = a;
	CK_SESSION_HANDLE s;
	CK_MECHANISM m = {CKM_ECDSA_SHA256, NULL, 0};
	unsigned char sig[64];
	if (p->C_OpenSession(1, CKF_SERIAL_SESSION, NULL, NULL, &s) != CKR_OK) {
		t->failures++;
		return NULL;
	}
	for (int i = 0; i < 5; i++) {
		CK_ULONG sl = sizeof(sig);
		if (p->C_SignInit(s, &m, t->priv) || p->C_Sign(s, (CK_BYTE_PTR) "threads", 7, sig, &sl) ||
		    p->C_VerifyInit(s, &m, t->pub) || p->C_Verify(s, (CK_BYTE_PTR) "threads", 7, sig, sl))
			t->failures++;
	}
	p->C_CloseSession(s);
	return NULL;
}

int main(void)
{
	void *lib = dlopen(env("P11_MODULE"), RTLD_NOW | RTLD_LOCAL);
	if (!lib) {
		fprintf(stderr, "FAIL: dlopen: %s\n", dlerror());
		return 1;
	}
	CK_C_GetFunctionList gfl = (CK_C_GetFunctionList)dlsym(lib, "C_GetFunctionList");
	TRUE_(gfl);
	OK(gfl(&p));
	TRUE_(p->version.major == 2 && p->version.minor == 40);
	/* PKCS#11 3.0 discovery finds this module's list, not a dependency's. */
	typedef struct {
		CK_CHAR *name;
		CK_VOID_PTR list;
		CK_FLAGS flags;
	} iface;
	CK_RV (*gi)(CK_UTF8CHAR_PTR, CK_VERSION_PTR, iface **, CK_FLAGS) =
		(CK_RV(*)(CK_UTF8CHAR_PTR, CK_VERSION_PTR, iface **, CK_FLAGS))dlsym(lib, "C_GetInterface");
	iface *ip = NULL;
	TRUE_(gi && gi(NULL, NULL, &ip, 0) == CKR_OK && ip->list == (CK_VOID_PTR)p);

	CK_SLOT_ID slots[2];
	CK_ULONG ns = 2;
	WANT(p->C_GetSlotList(CK_TRUE, slots, &ns), CKR_CRYPTOKI_NOT_INITIALIZED);
	CK_C_INITIALIZE_ARGS args = {0};
	args.flags = CKF_OS_LOCKING_OK;
	OK(p->C_Initialize(&args));
	WANT(p->C_Initialize(NULL), CKR_CRYPTOKI_ALREADY_INITIALIZED);

	CK_INFO info;
	OK(p->C_GetInfo(&info));
	TRUE_(!memcmp(info.manufacturerID, "Vecta KMS ", 10));
	OK(p->C_GetSlotList(CK_TRUE, NULL, &ns));
	TRUE_(ns == 1);
	OK(p->C_GetSlotList(CK_TRUE, slots, &ns));
	CK_TOKEN_INFO ti;
	OK(p->C_GetTokenInfo(slots[0], &ti));
	TRUE_(ti.flags & CKF_LOGIN_REQUIRED);
	TRUE_(!memcmp(ti.label, env("P11_TOKEN_LABEL"), strlen(env("P11_TOKEN_LABEL"))));
	CK_MECHANISM_TYPE mlist[32];
	CK_ULONG nm = 32;
	OK(p->C_GetMechanismList(slots[0], mlist, &nm));
	TRUE_(nm == 9);
	CK_MECHANISM_INFO mi;
	OK(p->C_GetMechanismInfo(slots[0], CKM_AES_GCM, &mi));
	TRUE_(mi.flags & CKF_ENCRYPT);
	WANT(p->C_GetMechanismInfo(slots[0], CKM_RSA_PKCS, &mi), CKR_MECHANISM_INVALID);

	CK_SESSION_HANDLE s;
	WANT(p->C_OpenSession(slots[0], 0, NULL, NULL, &s), CKR_SESSION_PARALLEL_NOT_SUPPORTED);
	OK(p->C_OpenSession(slots[0], CKF_SERIAL_SESSION, NULL, NULL, &s));
	TRUE_(count_all(s) == 0); /* nothing before login */
	const char *bad = env("P11_BAD_PIN"), *pin = env("P11_PIN");
	WANT(p->C_Login(s, CKU_USER, (CK_UTF8CHAR_PTR)bad, strlen(bad)), CKR_PIN_INCORRECT);
	WANT(p->C_Login(s, CKU_SO, (CK_UTF8CHAR_PTR)pin, strlen(pin)), CKR_USER_TYPE_INVALID);
	OK(p->C_Login(s, CKU_USER, (CK_UTF8CHAR_PTR)pin, strlen(pin)));
	WANT(p->C_Login(s, CKU_USER, (CK_UTF8CHAR_PTR)pin, strlen(pin)), CKR_USER_ALREADY_LOGGED_IN);
	CK_SESSION_INFO si;
	OK(p->C_GetSessionInfo(s, &si));
	TRUE_(si.state == CKS_RO_USER_FUNCTIONS);

	/* Every key the client may see, and none it may not. */
	TRUE_(count_all(s) == (CK_ULONG)atol(env("P11_EXPECT_OBJECTS")));
	printf("ok: login and objects\n");

	/* An EC key pair: attributes. */
	CK_OBJECT_HANDLE ecpriv = find1(s, CKO_PRIVATE_KEY, "signer"), ecpub = find1(s, CKO_PUBLIC_KEY, "signer");
	CK_KEY_TYPE kt = 0;
	CK_BBOOL can_sign = 0;
	unsigned char id[128], params[16], point[80], value[8];
	CK_ATTRIBUTE a[] = {{CKA_KEY_TYPE, &kt, sizeof(kt)},
			    {CKA_ID, id, sizeof(id)},
			    {CKA_EC_PARAMS, params, sizeof(params)},
			    {CKA_SIGN, &can_sign, sizeof(can_sign)}};
	OK(p->C_GetAttributeValue(s, ecpriv, a, 4));
	const char *sign_id = env("P11_SIGN_ID");
	TRUE_(kt == CKK_EC && can_sign && a[1].ulValueLen == strlen(sign_id) && !memcmp(id, sign_id, a[1].ulValueLen));
	static const unsigned char p256[] = {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
	TRUE_(a[2].ulValueLen == sizeof(p256) && !memcmp(params, p256, sizeof(p256)));
	CK_ATTRIBUTE secret[] = {{CKA_VALUE, value, sizeof(value)}, {CKA_LABEL, NULL, 0}};
	WANT(p->C_GetAttributeValue(s, ecpriv, secret, 2), CKR_ATTRIBUTE_SENSITIVE);
	TRUE_(secret[0].ulValueLen == CK_UNAVAILABLE_INFORMATION && secret[1].ulValueLen == strlen("signer"));
	CK_ATTRIBUTE pt[] = {{CKA_EC_POINT, point, sizeof(point)}};
	OK(p->C_GetAttributeValue(s, ecpub, pt, 1));
	TRUE_(pt[0].ulValueLen == 67 && point[0] == 0x04 && point[1] == 65 && point[2] == 0x04);
	CK_ATTRIBUTE tiny[] = {{CKA_EC_POINT, point, 3}};
	WANT(p->C_GetAttributeValue(s, ecpub, tiny, 1), CKR_BUFFER_TOO_SMALL);
	printf("ok: attributes\n");

	/* ECDSA: hashed here, the digest signed in the KMS. */
	CK_MECHANISM ecdsa_sha256 = {CKM_ECDSA_SHA256, NULL, 0}, ecdsa = {CKM_ECDSA, NULL, 0};
	sign_verify(s, ecpriv, ecpub, &ecdsa_sha256, (const unsigned char *)"release v1", 10, 64);
	unsigned char dg[64];
	size_t dn = unhex(env("P11_DIGEST_HEX"), dg, sizeof(dg));
	sign_verify(s, ecpriv, ecpub, &ecdsa, dg, dn, 64);
	/* Prehashed and hashed agree: CKM_ECDSA over SHA-256(m) verifies as
	 * CKM_ECDSA_SHA256 over m. */
	unsigned char sig[512];
	CK_ULONG sl = sizeof(sig);
	OK(p->C_SignInit(s, &ecdsa, ecpriv));
	OK(p->C_Sign(s, dg, dn, sig, &sl));
	OK(p->C_VerifyInit(s, &ecdsa_sha256, ecpub));
	OK(p->C_Verify(s, (CK_BYTE_PTR) "release v1", 10, sig, sl));
	/* Multi-part. */
	OK(p->C_SignInit(s, &ecdsa_sha256, ecpriv));
	OK(p->C_SignUpdate(s, (CK_BYTE_PTR) "release ", 8));
	OK(p->C_SignUpdate(s, (CK_BYTE_PTR) "v1", 2));
	sl = sizeof(sig);
	OK(p->C_SignFinal(s, sig, &sl));
	OK(p->C_VerifyInit(s, &ecdsa_sha256, ecpub));
	OK(p->C_Verify(s, (CK_BYTE_PTR) "release v1", 10, sig, sl));
	OK(p->C_SignInit(s, &ecdsa, ecpriv));
	WANT(p->C_Sign(s, dg, 20, sig, &sl), CKR_DATA_LEN_RANGE);
	WANT(p->C_SignInit(s, &ecdsa, ecpub), CKR_KEY_FUNCTION_NOT_PERMITTED);
	printf("ok: ecdsa\n");

	/* RSA-PSS, as the KMS signs: MGF1 with the hash, salt its length. */
	CK_OBJECT_HANDLE rsapriv = find1(s, CKO_PRIVATE_KEY, "rsa-signer"), rsapub = find1(s, CKO_PUBLIC_KEY, "rsa-signer");
	CK_RSA_PKCS_PSS_PARAMS pss = {CKM_SHA256, CKG_MGF1_SHA256, 32};
	CK_MECHANISM rsa_sha256 = {CKM_SHA256_RSA_PKCS_PSS, &pss, sizeof(pss)}, rsa = {CKM_RSA_PKCS_PSS, &pss, sizeof(pss)};
	CK_ULONG bits = 0;
	CK_ATTRIBUTE mb[] = {{CKA_MODULUS_BITS, &bits, sizeof(bits)}};
	OK(p->C_GetAttributeValue(s, rsapub, mb, 1));
	TRUE_(bits == 2048);
	sign_verify(s, rsapriv, rsapub, &rsa_sha256, (const unsigned char *)"release v1", 10, 256);
	sign_verify(s, rsapriv, rsapub, &rsa, dg, 32, 256);
	CK_RSA_PKCS_PSS_PARAMS salt20 = {CKM_SHA256, CKG_MGF1_SHA256, 20};
	CK_MECHANISM rsa_salt20 = {CKM_SHA256_RSA_PKCS_PSS, &salt20, sizeof(salt20)};
	WANT(p->C_SignInit(s, &rsa_salt20, rsapriv), CKR_MECHANISM_PARAM_INVALID);
	WANT(p->C_SignInit(s, &ecdsa, rsapriv), CKR_KEY_TYPE_INCONSISTENT);
	printf("ok: rsa-pss\n");

	/* AES-GCM. */
	CK_OBJECT_HANDLE aes = find1(s, CKO_SECRET_KEY, "owned");
	CK_ULONG vlen = 0;
	CK_ATTRIBUTE vl[] = {{CKA_VALUE_LEN, &vlen, sizeof(vlen)}};
	OK(p->C_GetAttributeValue(s, aes, vl, 1));
	TRUE_(vlen == 32);
	const char *iv_mode = env("P11_IV_MODE");
	unsigned char iv[12], aad[] = "row-1", ct[256], out[256];
	memcpy(iv, "0123456789ab", 12);
	CK_GCM_PARAMS gcm = {iv, 12, 96, aad, 5, 128};
	CK_MECHANISM m_gcm = {CKM_AES_GCM, &gcm, sizeof(gcm)};
	const char *msg = "card 4111 1111";
	CK_ULONG cl = 0, ol = 0;
	OK(p->C_EncryptInit(s, &m_gcm, aes));
	OK(p->C_Encrypt(s, (CK_BYTE_PTR)msg, strlen(msg), NULL, &cl));
	TRUE_(cl == strlen(msg) + 16);
	cl = sizeof(ct);
	if (!strcmp(iv_mode, "refused")) {
		/* FIPS strict mode: no caller IV for AES-GCM (SP 800-38D). */
		WANT(p->C_Encrypt(s, (CK_BYTE_PTR)msg, strlen(msg), ct, &cl), CKR_MECHANISM_PARAM_INVALID);
		printf("ok: aes-gcm caller IV refused\n");
	} else {
		OK(p->C_Encrypt(s, (CK_BYTE_PTR)msg, strlen(msg), ct, &cl));
		TRUE_(cl == strlen(msg) + 16);
		if (!strcmp(iv_mode, "generated"))
			TRUE_(memcmp(iv, "0123456789ab", 12) != 0); /* the KMS's IV, written back */
		else
			TRUE_(!memcmp(iv, "0123456789ab", 12));
		OK(p->C_DecryptInit(s, &m_gcm, aes));
		ol = sizeof(out);
		OK(p->C_Decrypt(s, ct, cl, out, &ol));
		TRUE_(ol == strlen(msg) && !memcmp(out, msg, ol));
		/* Multi-part decrypt: the output comes at the end. */
		OK(p->C_DecryptInit(s, &m_gcm, aes));
		CK_ULONG part = sizeof(out);
		OK(p->C_DecryptUpdate(s, ct, 7, out, &part));
		TRUE_(part == 0);
		OK(p->C_DecryptUpdate(s, ct + 7, cl - 7, out, &part));
		ol = sizeof(out);
		OK(p->C_DecryptFinal(s, out, &ol));
		TRUE_(ol == strlen(msg) && !memcmp(out, msg, ol));
		gcm.pAAD = (CK_BYTE_PTR) "row-2";
		OK(p->C_DecryptInit(s, &m_gcm, aes));
		ol = sizeof(out);
		WANT(p->C_Decrypt(s, ct, cl, out, &ol), CKR_ENCRYPTED_DATA_INVALID);
		gcm.pAAD = aad;
		printf("ok: aes-gcm (%s IV)\n", iv_mode);
	}
	CK_GCM_PARAMS short_tag = {iv, 12, 96, NULL, 0, 96};
	CK_MECHANISM m_short = {CKM_AES_GCM, &short_tag, sizeof(short_tag)};
	WANT(p->C_EncryptInit(s, &m_short, aes), CKR_MECHANISM_PARAM_INVALID);

	/* A ciphertext from before the key rotated still decrypts. */
	CK_OBJECT_HANDLE rotated = find1(s, CKO_SECRET_KEY, "rotated");
	unsigned char riv[12], rct[256];
	size_t rivn = unhex(env("P11_ROTATED_IV"), riv, sizeof(riv)), rctn = unhex(env("P11_ROTATED_CT"), rct, sizeof(rct));
	CK_GCM_PARAMS rg = {riv, rivn, rivn * 8, NULL, 0, 128};
	CK_MECHANISM m_rg = {CKM_AES_GCM, &rg, sizeof(rg)};
	OK(p->C_DecryptInit(s, &m_rg, rotated));
	ol = sizeof(out);
	OK(p->C_Decrypt(s, rct, rctn, out, &ol));
	TRUE_(ol == strlen(env("P11_ROTATED_PT")) && !memcmp(out, env("P11_ROTATED_PT"), ol));
	printf("ok: decrypt after rotation\n");

	unsigned char rnd[48] = {0}, zero[48] = {0};
	OK(p->C_GenerateRandom(s, rnd, sizeof(rnd)));
	TRUE_(memcmp(rnd, zero, sizeof(rnd)) != 0);
	WANT(p->C_GenerateKey(s, &ecdsa, NULL, 0, &aes), CKR_FUNCTION_NOT_SUPPORTED);

	/* Threads: sessions of their own, at once. */
	pthread_t th[4];
	thread_arg ta[4];
	for (int i = 0; i < 4; i++) {
		ta[i] = (thread_arg){ecpriv, ecpub, 0};
		TRUE_(pthread_create(&th[i], NULL, worker, &ta[i]) == 0);
	}
	for (int i = 0; i < 4; i++) {
		pthread_join(th[i], NULL);
		TRUE_(ta[i].failures == 0);
	}
	printf("ok: threads\n");

	/* Fork: the child signs on its own connections; the parent still works. */
	fflush(stdout);
	pid_t pid = fork();
	if (pid == 0) {
		CK_ULONG l = sizeof(sig);
		if (p->C_SignInit(s, &ecdsa_sha256, ecpriv) || p->C_Sign(s, (CK_BYTE_PTR) "child", 5, sig, &l) ||
		    p->C_GenerateRandom(s, rnd, 16))
			_exit(1);
		_exit(0);
	}
	int status = 0;
	TRUE_(pid > 0 && waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
	sl = sizeof(sig);
	OK(p->C_SignInit(s, &ecdsa_sha256, ecpriv));
	OK(p->C_Sign(s, (CK_BYTE_PTR) "parent", 6, sig, &sl));
	printf("ok: fork\n");

	OK(p->C_Logout(s));
	TRUE_(count_all(s) == 0);
	WANT(p->C_SignInit(s, &ecdsa_sha256, ecpriv), CKR_USER_NOT_LOGGED_IN);
	OK(p->C_CloseSession(s));
	WANT(p->C_CloseSession(s), CKR_SESSION_HANDLE_INVALID);
	OK(p->C_Finalize(NULL));
	WANT(p->C_GetSlotList(CK_TRUE, NULL, &ns), CKR_CRYPTOKI_NOT_INITIALIZED);
	printf("p11check ok\n");
	return 0;
}

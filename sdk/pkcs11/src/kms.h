/* The KMS's REST API, as the PKCS#11 module uses it: one REST client,
 * TLS 1.3 only, through libcurl. Every call is safe from any thread. */
#ifndef VECTA_KMS_H
#define VECTA_KMS_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
	char *url;       /* https://host[:port] */
	char *tenant;
	char *client_id; /* NULL: the PIN is a bearer token, not an API key */
	char *ca_file;
	char *label;     /* the token label; default the tenant */
	char *log_file;
	int generated_iv; /* gcm_iv = generated: the KMS makes every AES-GCM IV */
} kms_config;

/* Reads the file named by VECTA_PKCS11_CONF (default
 * /etc/vecta/pkcs11.conf, optional), then the environment over it. 0, or
 * -1 with a reason in err. */
int kms_config_load(kms_config *c, char *err, size_t errn);
void kms_config_free(kms_config *c);

typedef struct {
	long http; /* 0: no answer (network, TLS) */
	char code[64];
	char message[256];
	char request_id[64];
} kms_err;

typedef struct kms kms;

kms *kms_new(const kms_config *c);
void kms_free(kms *k);
/* In a forked child: new connections; the parent's are never touched. */
void kms_after_fork(kms *k);
void kms_log(kms *k, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

/* The credential is the PIN: an API key (client_id set) or a bearer
 * token. Login checks it with the KMS. */
int kms_login(kms *k, const char *pin, size_t n, kms_err *e);
void kms_logout(kms *k);

typedef struct {
	char *id, *name, *algorithm, *key_type, *purpose, *status, *kcv;
	int64_t version;
} kms_key;

/* Every key the client can see. */
int kms_list_keys(kms *k, kms_key **keys, size_t *n, kms_err *e);
void kms_keys_free(kms_key *keys, size_t n);
int kms_public_key(kms *k, const char *id, unsigned char **der, size_t *n, int64_t *version, kms_err *e);
/* hash: "SHA-256", "SHA-384", "SHA-512". Signatures as the KMS makes
 * them: DER for ECDSA, PSS for RSA. */
int kms_sign_digest(kms *k, const char *id, const char *hash, const unsigned char *digest, size_t dn,
		    unsigned char **sig, size_t *sn, kms_err *e);
int kms_verify_digest(kms *k, const char *id, const char *hash, const unsigned char *digest, size_t dn,
		      const unsigned char *sig, size_t sn, int *ok, kms_err *e);
/* iv NULL: the KMS generates it, returned in iv_out (12 bytes). */
int kms_encrypt(kms *k, const char *id, const unsigned char *pt, size_t pn, const unsigned char *iv, size_t ivn,
		const unsigned char *aad, size_t an, unsigned char **ct, size_t *cn, unsigned char *iv_out,
		kms_err *e);
/* Any version of the key that opens it (any_version). */
int kms_decrypt(kms *k, const char *id, const unsigned char *ct, size_t cn, const unsigned char *iv, size_t ivn,
		const unsigned char *aad, size_t an, unsigned char **pt, size_t *pn, kms_err *e);
int kms_random(kms *k, unsigned char *out, size_t n, kms_err *e);

#endif

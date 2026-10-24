#define _GNU_SOURCE /* secure_getenv */
#include "kms.h"

#include <ctype.h>
#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "json.h"
#include "util.h"

#define TOKEN_TTL 300      /* seconds asked of the KMS */
#define TOKEN_RENEW 30     /* renew this long before it expires */
#define MAX_RESPONSE (16u << 20)

static const char *env(const char *name)
{
#ifdef __GLIBC__
	return secure_getenv(name); /* nothing from the environment in setuid programs */
#else
	return getenv(name);
#endif
}

static int set_str(char **dst, const char *v)
{
	char *c = strdup(v);
	if (!c)
		return -1;
	free(*dst);
	*dst = c;
	return 0;
}

static char *trim(char *s)
{
	while (*s && isspace((unsigned char)*s))
		s++;
	char *e = s + strlen(s);
	while (e > s && isspace((unsigned char)e[-1]))
		*--e = 0;
	return s;
}

void kms_config_free(kms_config *c)
{
	free(c->url);
	free(c->tenant);
	free(c->client_id);
	free(c->ca_file);
	free(c->label);
	free(c->log_file);
	memset(c, 0, sizeof(*c));
}

int kms_config_load(kms_config *c, char *err, size_t errn)
{
	memset(c, 0, sizeof(*c));
	const char *path = env("VECTA_PKCS11_CONF");
	int explicit_path = path != NULL;
	if (!path)
		path = "/etc/vecta/pkcs11.conf";
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	FILE *f = fd >= 0 ? fdopen(fd, "r") : NULL;
	if (fd >= 0 && !f)
		close(fd);
	if (!f && explicit_path) {
		snprintf(err, errn, "can't read %s: %s", path, strerror(errno));
		return -1;
	}
	char line[4096];
	int lineno = 0;
	while (f && fgets(line, sizeof(line), f)) {
		lineno++;
		char *s = trim(line);
		if (!*s || *s == '#')
			continue;
		char *eq = strchr(s, '=');
		if (!eq) {
			snprintf(err, errn, "%s:%d: want key = value", path, lineno);
			goto fail;
		}
		*eq = 0;
		for (char *h = eq + 1; *h; h++) /* a comment after the value */
			if (*h == '#' && (h == eq + 1 || isspace((unsigned char)h[-1]))) {
				*h = 0;
				break;
			}
		char *key = trim(s), *val = trim(eq + 1);
		char **dst = !strcmp(key, "url")	   ? &c->url
			     : !strcmp(key, "tenant_id")   ? &c->tenant
			     : !strcmp(key, "client_id")   ? &c->client_id
			     : !strcmp(key, "ca_file")	   ? &c->ca_file
			     : !strcmp(key, "token_label") ? &c->label
			     : !strcmp(key, "log_file")	   ? &c->log_file
							   : NULL;
		if (!strcmp(key, "gcm_iv")) {
			if (strcmp(val, "caller") && strcmp(val, "generated")) {
				snprintf(err, errn, "%s:%d: gcm_iv is caller or generated", path, lineno);
				goto fail;
			}
			c->generated_iv = !strcmp(val, "generated");
			continue;
		}
		if (!dst) {
			snprintf(err, errn, "%s:%d: unknown setting %s", path, lineno, key);
			goto fail;
		}
		if (set_str(dst, val))
			goto oom;
	}
	if (f)
		fclose(f);
	f = NULL;
	static const struct {
		const char *name;
		size_t off;
	} envs[] = {
		{"VECTA_URL", offsetof(kms_config, url)},
		{"VECTA_TENANT_ID", offsetof(kms_config, tenant)},
		{"VECTA_CLIENT_ID", offsetof(kms_config, client_id)},
		{"VECTA_CA_FILE", offsetof(kms_config, ca_file)},
		{"VECTA_PKCS11_LOG", offsetof(kms_config, log_file)},
	};
	for (size_t i = 0; i < sizeof(envs) / sizeof(envs[0]); i++) {
		const char *v = env(envs[i].name);
		if (v && *v && set_str((char **)((char *)c + envs[i].off), v))
			goto oom;
	}
	if (c->client_id && !*c->client_id) {
		free(c->client_id);
		c->client_id = NULL;
	}
	if (!c->url || strncmp(c->url, "https://", 8) != 0 || !c->url[8] || strchr(c->url + 8, '/') ||
	    strchr(c->url, '?') || strchr(c->url, '@')) {
		snprintf(err, errn, "url must be https://host[:port] (VECTA_URL or %s)", path);
		goto fail;
	}
	if (!c->tenant || !*c->tenant) {
		snprintf(err, errn, "tenant_id is required (VECTA_TENANT_ID or %s)", path);
		goto fail;
	}
	if (!c->label && set_str(&c->label, c->tenant))
		goto oom;
	return 0;
oom:
	snprintf(err, errn, "out of memory");
fail:
	if (f)
		fclose(f);
	kms_config_free(c);
	return -1;
}

typedef struct {
	CURLSH *sh;
	pthread_mutex_t mu[CURL_LOCK_DATA_LAST];
} share_t;

struct kms {
	kms_config cfg;
	pthread_mutex_t mu; /* the credential and token */
	char *secret;       /* the PIN */
	char *token;        /* the bearer in use */
	time_t token_expires;
	int logged_in;
	share_t *share;
};

static pthread_once_t curl_once = PTHREAD_ONCE_INIT;
static int curl_ok;

static void curl_init_once(void)
{
#ifdef __APPLE__
	/* macOS's libcurl defaults to SecureTransport, which can't require
	 * TLS 1.3; it carries LibreSSL too. Too late when the application
	 * already started libcurl: then a TLS 1.3 call fails and says why. */
	(void)curl_global_sslset(CURLSSLBACKEND_OPENSSL, NULL, NULL);
#endif
	curl_ok = curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK;
}

static void share_lock(CURL *h, curl_lock_data d, curl_lock_access a, void *p)
{
	(void)h;
	(void)a;
	pthread_mutex_lock(&((share_t *)p)->mu[d]);
}

static void share_unlock(CURL *h, curl_lock_data d, void *p)
{
	(void)h;
	pthread_mutex_unlock(&((share_t *)p)->mu[d]);
}

static share_t *share_new(void)
{
	share_t *s = calloc(1, sizeof(*s));
	if (!s || !(s->sh = curl_share_init())) {
		free(s);
		return NULL;
	}
	for (int i = 0; i < CURL_LOCK_DATA_LAST; i++)
		pthread_mutex_init(&s->mu[i], NULL);
	curl_share_setopt(s->sh, CURLSHOPT_LOCKFUNC, share_lock);
	curl_share_setopt(s->sh, CURLSHOPT_UNLOCKFUNC, share_unlock);
	curl_share_setopt(s->sh, CURLSHOPT_USERDATA, s);
	curl_share_setopt(s->sh, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);
	curl_share_setopt(s->sh, CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION);
	curl_share_setopt(s->sh, CURLSHOPT_SHARE, CURL_LOCK_DATA_CONNECT);
	return s;
}

static int copy_config(kms_config *d, const kms_config *s)
{
	memset(d, 0, sizeof(*d));
	d->generated_iv = s->generated_iv;
	const char *src[] = {s->url, s->tenant, s->client_id, s->ca_file, s->label, s->log_file};
	char **dst[] = {&d->url, &d->tenant, &d->client_id, &d->ca_file, &d->label, &d->log_file};
	for (size_t i = 0; i < 6; i++)
		if (src[i] && set_str(dst[i], src[i]))
			return -1;
	return 0;
}

kms *kms_new(const kms_config *c)
{
	pthread_once(&curl_once, curl_init_once);
	if (!curl_ok)
		return NULL;
	kms *k = calloc(1, sizeof(*k));
	if (!k)
		return NULL;
	if (copy_config(&k->cfg, c) || !(k->share = share_new())) {
		kms_config_free(&k->cfg);
		free(k);
		return NULL;
	}
	pthread_mutex_init(&k->mu, NULL);
	return k;
}

static void free_secret(char **s)
{
	if (*s) {
		secure_zero(*s, strlen(*s));
		free(*s);
		*s = NULL;
	}
}

void kms_free(kms *k)
{
	if (!k)
		return;
	kms_logout(k);
	if (k->share) {
		curl_share_cleanup(k->share->sh);
		free(k->share);
	}
	pthread_mutex_destroy(&k->mu);
	kms_config_free(&k->cfg);
	free(k);
}

void kms_after_fork(kms *k)
{
	/* The parent's connections stay the parent's: closing them here would
	 * end its TLS sessions. The child starts its own. */
	pthread_mutex_init(&k->mu, NULL);
	k->share = share_new();
}

void kms_log(kms *k, const char *fmt, ...)
{
	if (!k || !k->cfg.log_file)
		return;
	int fd = open(k->cfg.log_file, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
	if (fd < 0)
		return;
	char line[1024], ts[32];
	time_t now = time(NULL);
	struct tm tm;
	gmtime_r(&now, &tm);
	strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm);
	int n = snprintf(line, sizeof(line), "%s vecta-pkcs11[%ld]: ", ts, (long)getpid());
	va_list ap;
	va_start(ap, fmt);
	if (n > 0 && (size_t)n < sizeof(line))
		n += vsnprintf(line + n, sizeof(line) - (size_t)n, fmt, ap);
	va_end(ap);
	if (n > (int)sizeof(line) - 2)
		n = (int)sizeof(line) - 2;
	if (n > 0) {
		line[n++] = '\n';
		ssize_t w = write(fd, line, (size_t)n);
		(void)w;
	}
	close(fd);
}

static size_t on_body(char *d, size_t sz, size_t nm, void *p)
{
	buf_t *b = p;
	size_t n = sz * nm;
	if (b->n + n > MAX_RESPONSE || buf_append(b, d, n))
		return 0; /* aborts the transfer */
	return n;
}

static void set_err(kms_err *e, long http, const char *code, const char *msg)
{
	memset(e, 0, sizeof(*e));
	e->http = http;
	snprintf(e->code, sizeof(e->code), "%s", code ? code : "");
	snprintf(e->message, sizeof(e->message), "%s", msg ? msg : "");
}

/* http sends one request; the response body is in *resp (any status). */
static int http(kms *k, const char *method, const char *path, const buf_t *body, const char *auth_header,
		buf_t *resp, long *status, kms_err *e)
{
	CURL *h = curl_easy_init();
	if (!h) {
		set_err(e, 0, "client_error", "curl_easy_init failed");
		return -1;
	}
	buf_t url = {0}, tenant = {0};
	struct curl_slist *hdr = NULL;
	int rc = -1;
	if (buf_appends(&url, k->cfg.url) || buf_appends(&url, path) || buf_appends(&tenant, "X-Tenant-ID: ") ||
	    buf_appends(&tenant, k->cfg.tenant)) {
		set_err(e, 0, "client_error", "out of memory");
		goto out;
	}
	hdr = curl_slist_append(hdr, "Accept: application/json");
	hdr = curl_slist_append(hdr, (const char *)tenant.p);
	if (auth_header)
		hdr = curl_slist_append(hdr, auth_header);
	if (body)
		hdr = curl_slist_append(hdr, "Content-Type: application/json");
	curl_easy_setopt(h, CURLOPT_URL, (const char *)url.p);
	curl_easy_setopt(h, CURLOPT_HTTPHEADER, hdr);
	curl_easy_setopt(h, CURLOPT_SHARE, k->share->sh);
	curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(h, CURLOPT_SSLVERSION, (long)CURL_SSLVERSION_TLSv1_3);
	curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 1L);
	curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, 2L);
	if (k->cfg.ca_file)
		curl_easy_setopt(h, CURLOPT_CAINFO, k->cfg.ca_file);
#if LIBCURL_VERSION_NUM >= 0x075500
	curl_easy_setopt(h, CURLOPT_PROTOCOLS_STR, "https");
#else
	curl_easy_setopt(h, CURLOPT_PROTOCOLS, (long)CURLPROTO_HTTPS);
#endif
	curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, 0L);
	curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT, 10L);
	curl_easy_setopt(h, CURLOPT_TIMEOUT, 30L);
	curl_easy_setopt(h, CURLOPT_USERAGENT, "vecta-pkcs11/" VECTA_VERSION);
	curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, on_body);
	curl_easy_setopt(h, CURLOPT_WRITEDATA, resp);
	if (!strcmp(method, "POST")) {
		curl_easy_setopt(h, CURLOPT_POST, 1L);
		curl_easy_setopt(h, CURLOPT_POSTFIELDS, body ? (const char *)body->p : "");
		curl_easy_setopt(h, CURLOPT_POSTFIELDSIZE, body ? (long)body->n : 0L);
	}
	CURLcode cc = curl_easy_perform(h);
	if (cc != CURLE_OK) {
		set_err(e, 0, "unreachable", curl_easy_strerror(cc));
		if (cc == CURLE_NOT_BUILT_IN)
			snprintf(e->message, sizeof(e->message), "this libcurl can't require TLS 1.3 (its TLS library is too old, or SecureTransport)");
		kms_log(k, "%s %s: %s", method, path, e->message);
		goto out;
	}
	curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, status);
	rc = 0;
out:
	curl_slist_free_all(hdr);
	curl_easy_cleanup(h);
	buf_free(&url);
	buf_free(&tenant);
	return rc;
}

static void error_from(kms *k, const char *method, const char *path, long status, const buf_t *resp, kms_err *e)
{
	jval v;
	set_err(e, status, "", "");
	if (resp->n && json_parse((const char *)resp->p, resp->n, &v) == 0) {
		const jval *er = json_get(&v, "error");
		const char *code = json_str(er, "code"), *msg = json_str(er, "message"), *rid = json_str(er, "request_id");
		snprintf(e->code, sizeof(e->code), "%s", code ? code : "");
		snprintf(e->message, sizeof(e->message), "%s", msg ? msg : "");
		snprintf(e->request_id, sizeof(e->request_id), "%s", rid ? rid : "");
		json_free(&v);
	}
	kms_log(k, "%s %s: %ld %s %s (request %s)", method, path, status, e->code, e->message, e->request_id);
}

static time_t now_mono(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec;
}

/* exchange trades the API key for a token. Called with k->mu held. */
static int exchange(kms *k, kms_err *e)
{
	buf_t body = {0}, key = {0}, resp = {0};
	long status = 0;
	int rc = -1;
	char ttl[32];
	snprintf(ttl, sizeof(ttl), "%d", TOKEN_TTL);
	if (buf_appends(&body, "{\"tenant_id\":") || json_put_str(&body, k->cfg.tenant) ||
	    buf_appends(&body, ",\"client_id\":") || json_put_str(&body, k->cfg.client_id) ||
	    buf_appends(&body, ",\"ttl_seconds\":") || buf_appends(&body, ttl) || buf_appends(&body, "}") ||
	    buf_appends(&key, "X-API-Key: ") || buf_appends(&key, k->secret)) {
		set_err(e, 0, "client_error", "out of memory");
		goto out;
	}
	if (http(k, "POST", "/svc/auth/auth/client-token", &body, (const char *)key.p, &resp, &status, e))
		goto out;
	if (status / 100 != 2) {
		error_from(k, "POST", "/svc/auth/auth/client-token", status, &resp, e);
		goto out;
	}
	jval v;
	if (json_parse((const char *)resp.p, resp.n, &v) != 0 || !json_str(&v, "access_token")) {
		if (resp.n)
			json_free(&v);
		set_err(e, status, "bad_response", "the KMS issued no token");
		goto out;
	}
	free_secret(&k->token);
	k->token = strdup(json_str(&v, "access_token"));
	json_free(&v);
	if (!k->token) {
		set_err(e, 0, "client_error", "out of memory");
		goto out;
	}
	k->token_expires = now_mono() + TOKEN_TTL - TOKEN_RENEW;
	rc = 0;
out:
	buf_free(&body);
	buf_free(&key);
	buf_free(&resp);
	return rc;
}

/* bearer writes "Authorization: Bearer <token>" into hdr. */
static int bearer(kms *k, int renew, buf_t *hdr, kms_err *e)
{
	pthread_mutex_lock(&k->mu);
	int rc = -1;
	if (!k->secret) {
		set_err(e, 401, "not_logged_in", "log in first");
		goto out;
	}
	if (k->cfg.client_id && (renew || !k->token || now_mono() >= k->token_expires) && exchange(k, e))
		goto out;
	const char *t = k->cfg.client_id ? k->token : k->secret;
	if (buf_appends(hdr, "Authorization: Bearer ") || buf_appends(hdr, t)) {
		set_err(e, 0, "client_error", "out of memory");
		goto out;
	}
	rc = 0;
out:
	pthread_mutex_unlock(&k->mu);
	return rc;
}

/* call is one authenticated API call: 0 with the parsed 2xx answer in
 * out, or -1 with e. A 401 renews an exchanged token once. */
static int call(kms *k, const char *method, const char *path, const buf_t *body, jval *out, kms_err *e)
{
	memset(out, 0, sizeof(*out));
	for (int attempt = 0;; attempt++) {
		buf_t hdr = {0}, resp = {0};
		long status = 0;
		if (bearer(k, attempt > 0, &hdr, e)) {
			buf_free(&hdr);
			return -1;
		}
		int rc = http(k, method, path, body, (const char *)hdr.p, &resp, &status, e);
		buf_free(&hdr);
		if (rc) {
			buf_free(&resp);
			return -1;
		}
		if (status == 401 && attempt == 0 && k->cfg.client_id) {
			buf_free(&resp);
			continue;
		}
		if (status / 100 != 2) {
			error_from(k, method, path, status, &resp, e);
			buf_free(&resp);
			return -1;
		}
		rc = json_parse(resp.n ? (const char *)resp.p : "{}", resp.n ? resp.n : 2, out);
		buf_free(&resp);
		if (rc) {
			set_err(e, status, "bad_response", "the KMS answer isn't JSON");
			return -1;
		}
		return 0;
	}
}

int kms_login(kms *k, const char *pin, size_t n, kms_err *e)
{
	char *s = malloc(n + 1);
	if (!s) {
		set_err(e, 0, "client_error", "out of memory");
		return -1;
	}
	memcpy(s, pin, n);
	s[n] = 0;
	if (strlen(s) != n || n == 0) {
		free_secret(&s);
		set_err(e, 401, "bad_pin", "the PIN is empty or holds a NUL");
		return -1;
	}
	pthread_mutex_lock(&k->mu);
	free_secret(&k->secret);
	free_secret(&k->token);
	k->secret = s;
	pthread_mutex_unlock(&k->mu);
	/* The cheapest call that proves the credential: one key, or none. */
	buf_t path = {0};
	jval v;
	int rc = -1;
	if (buf_appends(&path, "/svc/keycore/keys?limit=1&tenant_id=") == 0) {
		char *t = curl_easy_escape(NULL, k->cfg.tenant, 0);
		if (t && buf_appends(&path, t) == 0)
			rc = call(k, "GET", (const char *)path.p, NULL, &v, e);
		curl_free(t);
	}
	buf_free(&path);
	if (rc) {
		kms_logout(k);
		return -1;
	}
	json_free(&v);
	return 0;
}

void kms_logout(kms *k)
{
	pthread_mutex_lock(&k->mu);
	free_secret(&k->secret);
	free_secret(&k->token);
	pthread_mutex_unlock(&k->mu);
}

/* key_path is /svc/keycore/keys/<id><suffix>?tenant_id=<tenant>. */
static int key_path(kms *k, buf_t *p, const char *id, const char *suffix)
{
	char *eid = curl_easy_escape(NULL, id, 0), *et = curl_easy_escape(NULL, k->cfg.tenant, 0);
	int rc = !eid || !et || buf_appends(p, "/svc/keycore/keys/") || buf_appends(p, eid) || buf_appends(p, suffix) ||
		 buf_appends(p, "?tenant_id=") || buf_appends(p, et);
	curl_free(eid);
	curl_free(et);
	return rc ? -1 : 0;
}

static int put_b64(buf_t *b, const char *name, const unsigned char *d, size_t n)
{
	char *s = b64_encode(d, n);
	int rc = !s || buf_appends(b, ",\"") || buf_appends(b, name) || buf_appends(b, "\":\"") || buf_appends(b, s) ||
		 buf_appends(b, "\"");
	if (s) {
		secure_zero(s, strlen(s));
		free(s);
	}
	return rc ? -1 : 0;
}

static int body_start(kms *k, buf_t *b)
{
	return buf_appends(b, "{\"tenant_id\":") || json_put_str(b, k->cfg.tenant) ? -1 : 0;
}

static int get_b64(const jval *v, const char *name, unsigned char **out, size_t *n, kms_err *e)
{
	const char *s = json_str(v, name);
	if (!s || b64_decode(s, strlen(s), out, n)) {
		set_err(e, 200, "bad_response", "the KMS answer has no valid field");
		snprintf(e->message, sizeof(e->message), "the KMS answer has no valid %s", name);
		return -1;
	}
	return 0;
}

static int oom(kms_err *e)
{
	set_err(e, 0, "client_error", "out of memory");
	return -1;
}

static void free_key(kms_key *x)
{
	free(x->id);
	free(x->name);
	free(x->algorithm);
	free(x->key_type);
	free(x->purpose);
	free(x->status);
	free(x->kcv);
}

void kms_keys_free(kms_key *keys, size_t n)
{
	for (size_t i = 0; i < n; i++)
		free_key(&keys[i]);
	free(keys);
}

int kms_list_keys(kms *k, kms_key **keys, size_t *n, kms_err *e)
{
	*keys = NULL;
	*n = 0;
	size_t cap = 0;
	char *after_at = NULL, *after_id = NULL;
	int rc = -1;
	for (int page = 0; page < 1000; page++) {
		buf_t path = {0};
		char *et = curl_easy_escape(NULL, k->cfg.tenant, 0);
		int bad = !et || buf_appends(&path, "/svc/keycore/keys?limit=200&tenant_id=") || buf_appends(&path, et);
		curl_free(et);
		if (!bad && after_at) {
			char *a = curl_easy_escape(NULL, after_at, 0), *b = curl_easy_escape(NULL, after_id, 0);
			bad = !a || !b || buf_appends(&path, "&after_created_at=") || buf_appends(&path, a) ||
			      buf_appends(&path, "&after_id=") || buf_appends(&path, b);
			curl_free(a);
			curl_free(b);
		}
		jval v;
		if (bad) {
			buf_free(&path);
			oom(e);
			goto out;
		}
		int crc = call(k, "GET", (const char *)path.p, NULL, &v, e);
		buf_free(&path);
		if (crc)
			goto out;
		const jval *items = json_get(&v, "items");
		for (size_t i = 0; items && items->t == J_ARR && i < items->n; i++) {
			const jval *it = &items->items[i];
			const char *id = json_str(it, "id");
			if (!id)
				continue;
			if (*n == cap) {
				size_t nc = cap ? cap * 2 : 32;
				kms_key *g = realloc(*keys, nc * sizeof(kms_key));
				if (!g) {
					json_free(&v);
					oom(e);
					goto out;
				}
				*keys = g;
				cap = nc;
			}
			kms_key *x = &(*keys)[*n];
			memset(x, 0, sizeof(*x));
			const char *f[] = {id, json_str(it, "name"), json_str(it, "algorithm"), json_str(it, "key_type"),
					   json_str(it, "purpose"), json_str(it, "status"), json_str(it, "kcv")};
			char **d[] = {&x->id, &x->name, &x->algorithm, &x->key_type, &x->purpose, &x->status, &x->kcv};
			int fail = 0;
			for (int j = 0; j < 7; j++)
				if (!(*d[j] = strdup(f[j] ? f[j] : "")))
					fail = 1;
			(*n)++;
			if (json_int(it, "current_version", &x->version))
				x->version = 0;
			if (fail) {
				json_free(&v);
				oom(e);
				goto out;
			}
		}
		const jval *next = json_get(&v, "next_cursor");
		int more = json_true(&v, "has_more") && json_str(next, "after_created_at") && json_str(next, "after_id");
		free(after_at);
		free(after_id);
		after_at = more ? strdup(json_str(next, "after_created_at")) : NULL;
		after_id = more ? strdup(json_str(next, "after_id")) : NULL;
		json_free(&v);
		if (!more) {
			rc = 0;
			goto out;
		}
		if (!after_at || !after_id) {
			oom(e);
			goto out;
		}
	}
	set_err(e, 0, "client_error", "too many pages of keys");
out:
	free(after_at);
	free(after_id);
	if (rc) {
		kms_keys_free(*keys, *n);
		*keys = NULL;
		*n = 0;
	}
	return rc;
}

int kms_public_key(kms *k, const char *id, unsigned char **der, size_t *n, int64_t *version, kms_err *e)
{
	buf_t path = {0};
	jval v;
	if (key_path(k, &path, id, "/public-key"))
		return oom(e);
	int rc = call(k, "GET", (const char *)path.p, NULL, &v, e);
	buf_free(&path);
	if (rc)
		return -1;
	const char *pem = json_str(&v, "public_key_pem");
	if (!pem || pem_public_key_der(pem, der, n)) {
		json_free(&v);
		set_err(e, 200, "bad_response", "the public key isn't PEM");
		return -1;
	}
	if (json_int(&v, "version", version))
		*version = 0;
	json_free(&v);
	return 0;
}

int kms_sign_digest(kms *k, const char *id, const char *hash, const unsigned char *digest, size_t dn,
		    unsigned char **sig, size_t *sn, kms_err *e)
{
	buf_t path = {0}, body = {0};
	jval v;
	if (key_path(k, &path, id, "/sign") || body_start(k, &body) || put_b64(&body, "data", digest, dn) ||
	    buf_appends(&body, ",\"algorithm\":") || json_put_str(&body, hash) ||
	    buf_appends(&body, ",\"prehashed\":true}")) {
		buf_free(&path);
		buf_free(&body);
		return oom(e);
	}
	int rc = call(k, "POST", (const char *)path.p, &body, &v, e);
	buf_free(&path);
	buf_free(&body);
	if (rc)
		return -1;
	rc = get_b64(&v, "signature", sig, sn, e);
	json_free(&v);
	return rc;
}

int kms_verify_digest(kms *k, const char *id, const char *hash, const unsigned char *digest, size_t dn,
		      const unsigned char *sig, size_t sn, int *ok, kms_err *e)
{
	buf_t path = {0}, body = {0};
	jval v;
	if (key_path(k, &path, id, "/verify") || body_start(k, &body) || put_b64(&body, "data", digest, dn) ||
	    put_b64(&body, "signature", sig, sn) || buf_appends(&body, ",\"algorithm\":") ||
	    json_put_str(&body, hash) || buf_appends(&body, ",\"prehashed\":true}")) {
		buf_free(&path);
		buf_free(&body);
		return oom(e);
	}
	int rc = call(k, "POST", (const char *)path.p, &body, &v, e);
	buf_free(&path);
	buf_free(&body);
	if (rc)
		return -1;
	*ok = json_true(&v, "verified");
	json_free(&v);
	return 0;
}

int kms_encrypt(kms *k, const char *id, const unsigned char *pt, size_t pn, const unsigned char *iv, size_t ivn,
		const unsigned char *aad, size_t an, unsigned char **ct, size_t *cn, unsigned char *iv_out,
		kms_err *e)
{
	buf_t path = {0}, body = {0};
	jval v;
	int bad = key_path(k, &path, id, "/encrypt") || body_start(k, &body) ||
		  (pn ? put_b64(&body, "plaintext", pt, pn) : buf_appends(&body, ",\"plaintext\":\"\"")) ||
		  (an && put_b64(&body, "aad", aad, an)) ||
		  (iv && (put_b64(&body, "iv", iv, ivn) || buf_appends(&body, ",\"iv_mode\":\"external\""))) ||
		  buf_appends(&body, "}");
	if (bad) {
		buf_free(&path);
		buf_free(&body);
		return oom(e);
	}
	int rc = call(k, "POST", (const char *)path.p, &body, &v, e);
	buf_free(&path);
	buf_free(&body);
	if (rc)
		return -1;
	unsigned char *giv = NULL;
	size_t givn = 0;
	rc = get_b64(&v, "ciphertext", ct, cn, e);
	if (rc == 0 && !iv) {
		if (get_b64(&v, "iv", &giv, &givn, e) || givn != 12) {
			set_err(e, 200, "bad_response", "the KMS returned no 12-byte IV");
			free(*ct);
			*ct = NULL;
			rc = -1;
		} else {
			memcpy(iv_out, giv, 12);
		}
		free(giv);
	}
	json_free(&v);
	return rc;
}

int kms_decrypt(kms *k, const char *id, const unsigned char *ct, size_t cn, const unsigned char *iv, size_t ivn,
		const unsigned char *aad, size_t an, unsigned char **pt, size_t *pn, kms_err *e)
{
	buf_t path = {0}, body = {0};
	jval v;
	if (key_path(k, &path, id, "/decrypt") || body_start(k, &body) || put_b64(&body, "ciphertext", ct, cn) ||
	    put_b64(&body, "iv", iv, ivn) || (an && put_b64(&body, "aad", aad, an)) ||
	    buf_appends(&body, ",\"any_version\":true}")) {
		buf_free(&path);
		buf_free(&body);
		return oom(e);
	}
	int rc = call(k, "POST", (const char *)path.p, &body, &v, e);
	buf_free(&path);
	buf_free(&body);
	if (rc)
		return -1;
	const char *s = json_str(&v, "plaintext");
	if (s && !*s) { /* an empty plaintext */
		*pt = malloc(1);
		*pn = 0;
		rc = *pt ? 0 : oom(e);
	} else {
		rc = get_b64(&v, "plaintext", pt, pn, e);
	}
	json_free(&v);
	return rc;
}

int kms_random(kms *k, unsigned char *out, size_t n, kms_err *e)
{
	while (n > 0) {
		size_t take = n > 4096 ? 4096 : n;
		buf_t body = {0};
		jval v;
		char len[32];
		snprintf(len, sizeof(len), "%zu", take);
		if (body_start(k, &body) || buf_appends(&body, ",\"length\":") || buf_appends(&body, len) ||
		    buf_appends(&body, "}")) {
			buf_free(&body);
			return oom(e);
		}
		buf_t path = {0};
		char *et = curl_easy_escape(NULL, k->cfg.tenant, 0);
		int bad = !et || buf_appends(&path, "/svc/keycore/crypto/random?tenant_id=") || buf_appends(&path, et);
		curl_free(et);
		if (bad) {
			buf_free(&body);
			buf_free(&path);
			return oom(e);
		}
		int rc = call(k, "POST", (const char *)path.p, &body, &v, e);
		buf_free(&body);
		buf_free(&path);
		if (rc)
			return -1;
		unsigned char *b = NULL;
		size_t bn = 0;
		rc = get_b64(&v, "bytes", &b, &bn, e);
		json_free(&v);
		if (rc)
			return -1;
		if (bn != take) {
			free(b);
			set_err(e, 200, "bad_response", "the KMS returned a different number of random bytes");
			return -1;
		}
		memcpy(out, b, take);
		secure_zero(b, bn);
		free(b);
		out += take;
		n -= take;
	}
	return 0;
}

#include "json.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
	const char *p, *end;
	int depth;
} parser;

static void skip_ws(parser *ps)
{
	while (ps->p < ps->end && (*ps->p == ' ' || *ps->p == '\t' || *ps->p == '\n' || *ps->p == '\r'))
		ps->p++;
}

static int lit(parser *ps, const char *w)
{
	size_t n = strlen(w);
	if ((size_t)(ps->end - ps->p) < n || memcmp(ps->p, w, n) != 0)
		return -1;
	ps->p += n;
	return 0;
}

static int hex4(const char *p, unsigned *v)
{
	*v = 0;
	for (int i = 0; i < 4; i++) {
		char c = p[i];
		*v <<= 4;
		if (c >= '0' && c <= '9')
			*v |= (unsigned)(c - '0');
		else if (c >= 'a' && c <= 'f')
			*v |= (unsigned)(c - 'a' + 10);
		else if (c >= 'A' && c <= 'F')
			*v |= (unsigned)(c - 'A' + 10);
		else
			return -1;
	}
	return 0;
}

static int put_utf8(buf_t *b, unsigned cp)
{
	unsigned char u[4];
	size_t n;
	if (cp < 0x80) {
		u[0] = (unsigned char)cp;
		n = 1;
	} else if (cp < 0x800) {
		u[0] = (unsigned char)(0xc0 | cp >> 6);
		u[1] = (unsigned char)(0x80 | (cp & 0x3f));
		n = 2;
	} else if (cp < 0x10000) {
		u[0] = (unsigned char)(0xe0 | cp >> 12);
		u[1] = (unsigned char)(0x80 | (cp >> 6 & 0x3f));
		u[2] = (unsigned char)(0x80 | (cp & 0x3f));
		n = 3;
	} else {
		u[0] = (unsigned char)(0xf0 | cp >> 18);
		u[1] = (unsigned char)(0x80 | (cp >> 12 & 0x3f));
		u[2] = (unsigned char)(0x80 | (cp >> 6 & 0x3f));
		u[3] = (unsigned char)(0x80 | (cp & 0x3f));
		n = 4;
	}
	return buf_append(b, u, n);
}

static int parse_string(parser *ps, char **out, size_t *outn)
{
	buf_t b = {0};
	if (ps->p >= ps->end || *ps->p != '"')
		return -1;
	ps->p++;
	for (;;) {
		if (ps->p >= ps->end)
			goto bad;
		unsigned char c = (unsigned char)*ps->p++;
		if (c == '"')
			break;
		if (c < 0x20)
			goto bad;
		if (c != '\\') {
			if (buf_append(&b, &c, 1))
				goto bad;
			continue;
		}
		if (ps->p >= ps->end)
			goto bad;
		char e = *ps->p++;
		const char *simple = "\"\\/bfnrt", *real = "\"\\/\b\f\n\r\t", *at = strchr(simple, e);
		if (e && at) {
			if (buf_append(&b, real + (at - simple), 1))
				goto bad;
			continue;
		}
		if (e != 'u' || ps->end - ps->p < 4)
			goto bad;
		unsigned cp, lo;
		if (hex4(ps->p, &cp))
			goto bad;
		ps->p += 4;
		if (cp >= 0xd800 && cp <= 0xdbff) {
			if (ps->end - ps->p < 6 || ps->p[0] != '\\' || ps->p[1] != 'u' || hex4(ps->p + 2, &lo) ||
			    lo < 0xdc00 || lo > 0xdfff)
				goto bad;
			ps->p += 6;
			cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
		} else if (cp >= 0xdc00 && cp <= 0xdfff) {
			goto bad;
		}
		if (put_utf8(&b, cp))
			goto bad;
	}
	if (!b.p && buf_append(&b, "", 0) == 0) {
		b.p = malloc(1);
		if (!b.p)
			return -1;
		b.p[0] = 0;
	}
	*out = (char *)b.p;
	*outn = b.n;
	return 0;
bad:
	buf_free(&b);
	return -1;
}

static int parse_number(parser *ps, jval *v)
{
	const char *start = ps->p;
	int neg = 0, frac = 0;
	if (ps->p < ps->end && *ps->p == '-') {
		neg = 1;
		ps->p++;
	}
	if (ps->p >= ps->end)
		return -1;
	if (*ps->p == '0') {
		ps->p++;
	} else if (*ps->p >= '1' && *ps->p <= '9') {
		while (ps->p < ps->end && *ps->p >= '0' && *ps->p <= '9')
			ps->p++;
	} else {
		return -1;
	}
	const char *int_end = ps->p;
	if (ps->p < ps->end && *ps->p == '.') {
		frac = 1;
		ps->p++;
		if (ps->p >= ps->end || *ps->p < '0' || *ps->p > '9')
			return -1;
		while (ps->p < ps->end && *ps->p >= '0' && *ps->p <= '9')
			ps->p++;
	}
	if (ps->p < ps->end && (*ps->p == 'e' || *ps->p == 'E')) {
		frac = 1;
		ps->p++;
		if (ps->p < ps->end && (*ps->p == '+' || *ps->p == '-'))
			ps->p++;
		if (ps->p >= ps->end || *ps->p < '0' || *ps->p > '9')
			return -1;
		while (ps->p < ps->end && *ps->p >= '0' && *ps->p <= '9')
			ps->p++;
	}
	v->t = J_NUM;
	if (frac)
		return 0;
	uint64_t acc = 0;
	for (const char *d = start + neg; d < int_end; d++) {
		unsigned digit = (unsigned)(*d - '0');
		if (acc > (UINT64_MAX - digit) / 10)
			return 0; /* too large: a number, not an integer */
		acc = acc * 10 + digit;
	}
	if (!neg && acc <= INT64_MAX) {
		v->i = (int64_t)acc;
		v->is_int = 1;
	} else if (neg && acc <= (uint64_t)INT64_MAX + 1) {
		v->i = acc == (uint64_t)INT64_MAX + 1 ? INT64_MIN : -(int64_t)acc;
		v->is_int = 1;
	}
	return 0;
}

static int parse_value(parser *ps, jval *v);

static int grow(jval *v, size_t *cap, int obj)
{
	if (v->n < *cap)
		return 0;
	size_t nc = *cap ? *cap * 2 : 8;
	jval *items = realloc(v->items, nc * sizeof(jval));
	if (!items)
		return -1;
	v->items = items;
	if (obj) {
		char **keys = realloc(v->keys, nc * sizeof(char *));
		if (!keys)
			return -1;
		v->keys = keys;
	}
	*cap = nc;
	return 0;
}

static int parse_container(parser *ps, jval *v, int obj)
{
	size_t cap = 0;
	char close = obj ? '}' : ']';
	v->t = obj ? J_OBJ : J_ARR;
	if (++ps->depth > 32)
		return -1;
	ps->p++;
	skip_ws(ps);
	if (ps->p < ps->end && *ps->p == close) {
		ps->p++;
		ps->depth--;
		return 0;
	}
	for (;;) {
		if (grow(v, &cap, obj))
			return -1;
		char *key = NULL;
		size_t keyn;
		if (obj) {
			skip_ws(ps);
			if (parse_string(ps, &key, &keyn))
				return -1;
			skip_ws(ps);
			if (ps->p >= ps->end || *ps->p != ':') {
				free(key);
				return -1;
			}
			ps->p++;
		}
		memset(&v->items[v->n], 0, sizeof(jval));
		if (obj)
			v->keys[v->n] = key;
		v->n++; /* counted before parsing, so json_free frees a partial value */
		if (parse_value(ps, &v->items[v->n - 1]))
			return -1;
		skip_ws(ps);
		if (ps->p >= ps->end)
			return -1;
		if (*ps->p == ',') {
			ps->p++;
			continue;
		}
		if (*ps->p != close)
			return -1;
		ps->p++;
		ps->depth--;
		return 0;
	}
}

static int parse_value(parser *ps, jval *v)
{
	skip_ws(ps);
	if (ps->p >= ps->end)
		return -1;
	switch (*ps->p) {
	case '{':
		return parse_container(ps, v, 1);
	case '[':
		return parse_container(ps, v, 0);
	case '"':
		v->t = J_STR;
		return parse_string(ps, &v->s, &v->slen);
	case 't':
		v->t = J_BOOL;
		v->b = 1;
		return lit(ps, "true");
	case 'f':
		v->t = J_BOOL;
		return lit(ps, "false");
	case 'n':
		v->t = J_NULL;
		return lit(ps, "null");
	default:
		return parse_number(ps, v);
	}
}

int json_parse(const char *s, size_t n, jval *out)
{
	parser ps = {s, s + n, 0};
	memset(out, 0, sizeof(*out));
	if (parse_value(&ps, out) == 0) {
		skip_ws(&ps);
		if (ps.p == ps.end)
			return 0;
	}
	json_free(out);
	return -1;
}

void json_free(jval *v)
{
	if (!v)
		return;
	if (v->s) {
		secure_zero(v->s, v->slen);
		free(v->s);
	}
	for (size_t i = 0; i < v->n; i++) {
		json_free(&v->items[i]);
		if (v->keys)
			free(v->keys[i]);
	}
	free(v->items);
	free(v->keys);
	memset(v, 0, sizeof(*v));
}

const jval *json_get(const jval *obj, const char *key)
{
	if (!obj || obj->t != J_OBJ)
		return NULL;
	for (size_t i = 0; i < obj->n; i++)
		if (obj->keys[i] && strcmp(obj->keys[i], key) == 0)
			return &obj->items[i];
	return NULL;
}

const char *json_str(const jval *obj, const char *key)
{
	const jval *v = json_get(obj, key);
	return v && v->t == J_STR ? v->s : NULL;
}

int json_int(const jval *obj, const char *key, int64_t *out)
{
	const jval *v = json_get(obj, key);
	if (!v || v->t != J_NUM || !v->is_int)
		return -1;
	*out = v->i;
	return 0;
}

int json_true(const jval *obj, const char *key)
{
	const jval *v = json_get(obj, key);
	return v && v->t == J_BOOL && v->b;
}

int json_put_str(buf_t *b, const char *s)
{
	static const char hex[] = "0123456789abcdef";
	if (buf_append(b, "\"", 1))
		return -1;
	for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
		char esc[7] = {'\\', 0};
		size_t n = 2;
		switch (*p) {
		case '"':
			esc[1] = '"';
			break;
		case '\\':
			esc[1] = '\\';
			break;
		case '\n':
			esc[1] = 'n';
			break;
		case '\r':
			esc[1] = 'r';
			break;
		case '\t':
			esc[1] = 't';
			break;
		default:
			if (*p < 0x20) {
				esc[1] = 'u';
				esc[2] = '0';
				esc[3] = '0';
				esc[4] = hex[*p >> 4];
				esc[5] = hex[*p & 15];
				n = 6;
			} else {
				if (buf_append(b, p, 1))
					return -1;
				continue;
			}
		}
		if (buf_append(b, esc, n))
			return -1;
	}
	return buf_append(b, "\"", 1);
}

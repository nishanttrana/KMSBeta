/* A strict JSON reader for KMS responses (RFC 8259), and string escaping
 * for requests. Integers only: the module reads no fractions, so number
 * parsing never depends on the process's locale. */
#ifndef VECTA_JSON_H
#define VECTA_JSON_H

#include <stddef.h>
#include <stdint.h>

#include "util.h"

typedef enum { J_NULL, J_BOOL, J_NUM, J_STR, J_ARR, J_OBJ } jtype;

typedef struct jval {
	jtype t;
	int b;              /* J_BOOL */
	int is_int;         /* J_NUM: an integer that fits int64 */
	int64_t i;          /* J_NUM */
	char *s;            /* J_STR, NUL-terminated (may hold NULs: slen) */
	size_t slen;
	struct jval *items; /* J_ARR elements, J_OBJ values */
	char **keys;        /* J_OBJ keys */
	size_t n;
} jval;

/* 0, or -1 for invalid JSON, nesting deeper than 32, or no memory. */
int json_parse(const char *s, size_t n, jval *out);
void json_free(jval *v);

const jval *json_get(const jval *obj, const char *key);
/* The string member, or NULL when absent or not a string. */
const char *json_str(const jval *obj, const char *key);
/* 0 and *v, or -1 when absent or not an integer. */
int json_int(const jval *obj, const char *key, int64_t *v);
/* 1 for true, 0 for false or absent. */
int json_true(const jval *obj, const char *key);

/* Appends s as a JSON string literal, quotes included. */
int json_put_str(buf_t *b, const char *s);

#endif

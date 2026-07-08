/*
 * here_source.c — HERE Traffic API v7 flow + incidents JSON parser (jsmn-based).
 * See here_source.h. Pure C99; builds with QNX ntoarmv7-gcc and host clang/gcc.
 */
#include "here_source.h"

#include <stdlib.h>
#include <string.h>

#define JSMN_STATIC
#include "jsmn.h"

/* ---- jsmn token navigation helpers ------------------------------------- */

static int tok_streq(const char *js, const jsmntok_t *t, const char *s) {
    int n = t->end - t->start;
    return t->type == JSMN_STRING &&
           (int)strlen(s) == n &&
           strncmp(js + t->start, s, n) == 0;
}

static void tok_copy(const char *js, const jsmntok_t *t, char *buf, size_t bufsz) {
    size_t n = (size_t)(t->end - t->start);
    if (bufsz == 0) return;
    if (n >= bufsz) n = bufsz - 1;
    memcpy(buf, js + t->start, n);
    buf[n] = '\0';
}

static double tok_double(const char *js, const jsmntok_t *t) {
    char tmp[32];
    tok_copy(js, t, tmp, sizeof tmp);
    return atof(tmp);
}

static int tok_is_true(const char *js, const jsmntok_t *t) {
    return t->type == JSMN_PRIMITIVE && (js[t->start] == 't');
}

/* Index of the token immediately after the whole subtree rooted at i. */
static int tok_skip(const jsmntok_t *t, int i) {
    int j, k, n;
    switch (t[i].type) {
    case JSMN_OBJECT:
        n = t[i].size;
        j = i + 1;
        for (k = 0; k < n; k++) {
            j = tok_skip(t, j); /* key   */
            j = tok_skip(t, j); /* value */
        }
        return j;
    case JSMN_ARRAY:
        n = t[i].size;
        j = i + 1;
        for (k = 0; k < n; k++) j = tok_skip(t, j);
        return j;
    default: /* STRING / PRIMITIVE — leaf */
        return i + 1;
    }
}

/* Within object token `oi`, return value token index for member `key`, or -1. */
static int obj_get(const char *js, const jsmntok_t *t, int oi, const char *key) {
    int n, j, k, keytok, valtok;
    if (oi < 0 || t[oi].type != JSMN_OBJECT) return -1;
    n = t[oi].size;
    j = oi + 1;
    for (k = 0; k < n; k++) {
        keytok = j;
        valtok = keytok + 1;              /* value follows key */
        if (tok_streq(js, &t[keytok], key)) return valtok;
        j = tok_skip(t, valtok);          /* next member */
    }
    return -1;
}

/* Copy string value of object member `key` into buf. Returns 1 if found. */
static int obj_get_str(const char *js, const jsmntok_t *t, int oi,
                       const char *key, char *buf, size_t bufsz) {
    int v = obj_get(js, t, oi, key);
    if (v < 0) { if (bufsz) buf[0] = '\0'; return 0; }
    tok_copy(js, &t[v], buf, bufsz);
    return 1;
}

/* ---- token buffer sizing / parse ---------------------------------------- */

static jsmntok_t *parse_all(const char *json, size_t len, int *ntok_out) {
    jsmn_parser p;
    int ntok;
    jsmntok_t *toks;

    jsmn_init(&p);
    ntok = jsmn_parse(&p, json, len, NULL, 0);
    if (ntok < 0) return NULL;

    toks = (jsmntok_t *)malloc((size_t)ntok * sizeof(jsmntok_t));
    if (!toks) return NULL;

    jsmn_init(&p);
    if (jsmn_parse(&p, json, len, toks, (unsigned int)ntok) < 0) {
        free(toks);
        return NULL;
    }
    *ntok_out = ntok;
    return toks;
}

/* ---- public parsers ----------------------------------------------------- */

int here_parse_flow(const char *json, size_t len,
                    here_flow_t *out, int max, int *count) {
    int ntok = 0, results, n, j, k;
    jsmntok_t *t;

    if (count) *count = 0;
    t = parse_all(json, len, &ntok);
    if (!t) return -1;
    if (t[0].type != JSMN_OBJECT) { free(t); return -2; }

    results = obj_get(json, t, 0, "results");
    if (results < 0 || t[results].type != JSMN_ARRAY) { free(t); return 0; }

    n = t[results].size;
    j = results + 1;
    for (k = 0; k < n; k++, j = tok_skip(t, j)) {
        int loc = obj_get(json, t, j, "location");
        int cf  = obj_get(json, t, j, "currentFlow");
        int stored = (count ? *count : 0);

        if (stored < max) {
            here_flow_t *f = &out[stored];
            int olrv;
            memset(f, 0, sizeof *f);
            olrv = (loc >= 0) ? obj_get(json, t, loc, "olr") : -1;
            if (olrv >= 0) {
                tok_copy(json, &t[olrv], f->olr, sizeof f->olr);
                f->has_olr = 1;
            }
            if (loc >= 0) {
                int lv = obj_get(json, t, loc, "length");
                if (lv >= 0) f->length = tok_double(json, &t[lv]);
            }
            if (cf >= 0) {
                int v;
                if ((v = obj_get(json, t, cf, "jamFactor")) >= 0) f->jam_factor = tok_double(json, &t[v]);
                if ((v = obj_get(json, t, cf, "speed"))     >= 0) f->speed      = tok_double(json, &t[v]);
                if ((v = obj_get(json, t, cf, "freeFlow"))  >= 0) f->free_flow  = tok_double(json, &t[v]);
            }
        }
        if (count) (*count)++;
    }

    free(t);
    return 0;
}

int here_parse_incidents(const char *json, size_t len,
                         here_incident_t *out, int max, int *count) {
    int ntok = 0, results, n, j, k;
    jsmntok_t *t;

    if (count) *count = 0;
    t = parse_all(json, len, &ntok);
    if (!t) return -1;
    if (t[0].type != JSMN_OBJECT) { free(t); return -2; }

    results = obj_get(json, t, 0, "results");
    if (results < 0 || t[results].type != JSMN_ARRAY) { free(t); return 0; }

    n = t[results].size;
    j = results + 1;
    for (k = 0; k < n; k++, j = tok_skip(t, j)) {
        int loc = obj_get(json, t, j, "location");
        int det = obj_get(json, t, j, "incidentDetails");
        int stored = (count ? *count : 0);

        if (stored < max) {
            here_incident_t *inc = &out[stored];
            int olrv, rc, desc;
            memset(inc, 0, sizeof *inc);
            olrv = (loc >= 0) ? obj_get(json, t, loc, "olr") : -1;
            if (olrv >= 0) {
                tok_copy(json, &t[olrv], inc->olr, sizeof inc->olr);
                inc->has_olr = 1;
            }
            if (det >= 0) {
                obj_get_str(json, t, det, "type",        inc->type,        sizeof inc->type);
                obj_get_str(json, t, det, "criticality", inc->criticality, sizeof inc->criticality);
                obj_get_str(json, t, det, "startTime",   inc->start_time,  sizeof inc->start_time);
                obj_get_str(json, t, det, "endTime",     inc->end_time,    sizeof inc->end_time);
                rc = obj_get(json, t, det, "roadClosed");
                if (rc >= 0) inc->road_closed = tok_is_true(json, &t[rc]);
                /* description is a nested object {"value":"..","language":".."} */
                desc = obj_get(json, t, det, "description");
                if (desc >= 0 && t[desc].type == JSMN_OBJECT)
                    obj_get_str(json, t, desc, "value", inc->description, sizeof inc->description);
                else if (desc >= 0)
                    tok_copy(json, &t[desc], inc->description, sizeof inc->description);
            }
        }
        if (count) (*count)++;
    }

    free(t);
    return 0;
}

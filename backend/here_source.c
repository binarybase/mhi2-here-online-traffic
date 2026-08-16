/*
 * here_source.c — HERE Traffic API v7 flow + incidents JSON parser (jsmn-based).
 * See here_source.h. Pure C99; builds with QNX ntoarmv7-gcc and host clang/gcc.
 */
#include "here_source.h"

#include <stdlib.h>
#include <string.h>

/* JSMN_PARENT_LINKS makes jsmn store each token's parent index, turning the
 * "find enclosing container" step into an O(1) pointer hop. Without it jsmn
 * rescans the whole token array backwards for every token it closes, which is
 * O(n^2) — ~41 ms just to tokenise a 1.1 MB HERE payload. With it, tokenising
 * is linear (~a couple ms) and the parser beats a full cJSON DOM build while
 * doing zero per-node allocation. Must be defined before including jsmn.h. */
#define JSMN_PARENT_LINKS
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

/* Parse a token as a base-16 unsigned value (HERE ebuCountryCode is a single
 * hex digit string, e.g. "2" or "A"). Non-hex -> 0. */
static int tok_hex(const char *js, const jsmntok_t *t) {
    char tmp[16];
    tok_copy(js, t, tmp, sizeof tmp);
    return (int)strtol(tmp, NULL, 16);
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

/* Tokenise the whole document in a SINGLE pass.
 *
 * The old approach called jsmn_parse twice over the full buffer: once with a
 * NULL sink just to count tokens, then again to fill them. For HERE's multi-MB
 * flow payloads that second full scan is pure overhead. Instead we estimate the
 * token count from the input size and grow geometrically only if we guessed too
 * low. HERE v7 responses are dominated by long OLR base64 strings (one token
 * spanning many bytes), so len/8 tokens comfortably fits on the first try in
 * practice; the grow-on-NOMEM loop keeps us correct for unusually token-dense
 * input, and an allocation failure naturally bounds the memory ceiling. */
static jsmntok_t *parse_all(const char *json, size_t len, int *ntok_out) {
    jsmn_parser p;
    jsmntok_t *toks = NULL;
    size_t cap = len / 8 + 64;
    int attempts;

    for (attempts = 0; attempts < 8; attempts++) {
        jsmntok_t *grown = (jsmntok_t *)realloc(toks, cap * sizeof(jsmntok_t));
        int r;
        if (!grown) { free(toks); return NULL; }
        toks = grown;

        jsmn_init(&p);
        r = jsmn_parse(&p, json, len, toks, (unsigned int)cap);
        if (r >= 0) { *ntok_out = r; return toks; }
        if (r != JSMN_ERROR_NOMEM) { free(toks); return NULL; } /* INVAL/PART */
        cap *= 2;                                               /* undersized */
    }
    free(toks);
    return NULL;
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
            /* TMC location reference (location.tmc) — the only flow the head
             * unit can render (it resolves TMC natively, not OpenLR). */
            {
                int tmcv = (loc >= 0) ? obj_get(json, t, loc, "tmc") : -1;
                if (tmcv >= 0 && t[tmcv].type == JSMN_OBJECT) {
                    int v;
                    if ((v = obj_get(json, t, tmcv, "ebuCountryCode")) >= 0)
                        f->tmc_cc = tok_hex(json, &t[v]);
                    if ((v = obj_get(json, t, tmcv, "tableId")) >= 0)
                        f->tmc_ltn = (int)tok_double(json, &t[v]);
                    if ((v = obj_get(json, t, tmcv, "locationId")) >= 0)
                        f->tmc_loc = (int)tok_double(json, &t[v]);
                    if ((v = obj_get(json, t, tmcv, "extent")) >= 0)
                        f->tmc_extent = (int)tok_double(json, &t[v]);
                    /* HERE queuingDirection is INVERTED vs the car's TMC table
                     * direction bit: byte-level diff against native TomTom shows
                     * HERE "+" resolves as the car's negative direction and vice
                     * versa (13/13 single-direction failures were the opposite
                     * of native's rendered direction). Map "+"->1, "-"->0. */
                    if ((v = obj_get(json, t, tmcv, "queuingDirection")) >= 0)
                        f->tmc_dir = (json[t[v].start] == '-') ? 0 : 1;
                    if (f->tmc_ltn > 0 && f->tmc_loc > 0)
                        f->has_tmc = 1;
                }
            }
            if (cf >= 0) {
                int v;
                if ((v = obj_get(json, t, cf, "jamFactor")) >= 0) f->jam_factor = tok_double(json, &t[v]);
                if ((v = obj_get(json, t, cf, "speed"))     >= 0) f->speed      = tok_double(json, &t[v]);
                if ((v = obj_get(json, t, cf, "freeFlow"))  >= 0) f->free_flow  = tok_double(json, &t[v]);
                /* currentFlow.subSegments[]: metric sub-ranges with per-range
                 * flow. Kept for native-style multi-section flow encoding. */
                {
                    int ss = obj_get(json, t, cf, "subSegments");
                    if (ss >= 0 && t[ss].type == JSMN_ARRAY) {
                        int sn = t[ss].size, si, sj = ss + 1, w = 0;
                        for (si = 0; si < sn && w < HERE_MAX_SUBSEG;
                             si++, sj = tok_skip(t, sj)) {
                            here_subseg_t *g = &f->subseg[w];
                            int u;
                            if (t[sj].type != JSMN_OBJECT) continue;
                            g->length = g->jam_factor = g->speed = g->free_flow = 0.0;
                            if ((u = obj_get(json, t, sj, "length"))    >= 0) g->length     = tok_double(json, &t[u]);
                            if ((u = obj_get(json, t, sj, "jamFactor")) >= 0) g->jam_factor = tok_double(json, &t[u]);
                            if ((u = obj_get(json, t, sj, "speed"))     >= 0) g->speed      = tok_double(json, &t[u]);
                            if ((u = obj_get(json, t, sj, "freeFlow"))  >= 0) g->free_flow  = tok_double(json, &t[u]);
                            w++;
                        }
                        f->n_subseg = w;
                    }
                }
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
            /* TMC location reference (location.tmc). Resolvable natively on the
             * head unit (on-device TMC table) — the reliable display path. */
            {
                int tmcv = (loc >= 0) ? obj_get(json, t, loc, "tmc") : -1;
                if (tmcv >= 0 && t[tmcv].type == JSMN_OBJECT) {
                    int v;
                    if ((v = obj_get(json, t, tmcv, "ebuCountryCode")) >= 0)
                        inc->tmc_cc = tok_hex(json, &t[v]);
                    if ((v = obj_get(json, t, tmcv, "tableId")) >= 0)
                        inc->tmc_ltn = (int)tok_double(json, &t[v]);
                    if ((v = obj_get(json, t, tmcv, "locationId")) >= 0)
                        inc->tmc_loc = (int)tok_double(json, &t[v]);
                    if ((v = obj_get(json, t, tmcv, "extent")) >= 0)
                        inc->tmc_extent = (int)tok_double(json, &t[v]);
                    /* Same direction inversion as flow (see above): "+"->1, "-"->0. */
                    if ((v = obj_get(json, t, tmcv, "queuingDirection")) >= 0)
                        inc->tmc_dir = (json[t[v].start] == '-') ? 0 : 1;
                    /* A usable reference needs a location table + code. */
                    if (inc->tmc_ltn > 0 && inc->tmc_loc > 0)
                        inc->has_tmc = 1;
                }
            }
            if (det >= 0) {
                obj_get_str(json, t, det, "type",        inc->type,        sizeof inc->type);
                obj_get_str(json, t, det, "criticality", inc->criticality, sizeof inc->criticality);
                obj_get_str(json, t, det, "startTime",   inc->start_time,  sizeof inc->start_time);
                obj_get_str(json, t, det, "endTime",     inc->end_time,    sizeof inc->end_time);
                rc = obj_get(json, t, det, "roadClosed");
                if (rc >= 0) inc->road_closed = tok_is_true(json, &t[rc]);
                /* codes[]: AlertC/TMC event codes (ISO 14819-2), primary first.
                 * The head unit maps our TEC cause -> TMC event -> list label,
                 * so the primary AlertC code lets us pick the closest TEC cause. */
                {
                    int codesv = obj_get(json, t, det, "codes");
                    if (codesv >= 0 && t[codesv].type == JSMN_ARRAY && t[codesv].size > 0)
                        inc->alertc_code = (int)tok_double(json, &t[codesv + 1]);
                }
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

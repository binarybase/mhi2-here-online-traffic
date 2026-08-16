/*
 * tpeg_encode_test.c — host round-trip test for tpeg_encode.
 * Builds a stream from a few real HERE incidents (fixed OpenLR fixtures) and
 * writes it to a file, which backend/tools/tpeg_parse.py then validates.
 *
 *   cc -std=c99 -I. tpeg_encode_test.c tpeg_encode.c -o /tmp/tpeg_enc_test
 *   /tmp/tpeg_enc_test /tmp/out.tpg
 *   python3 tools/tpeg_parse.py /tmp/out.tpg
 */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "tpeg_encode.h"

static here_incident_t mk(const char *type, int closed, const char *olr) {
    here_incident_t inc;
    memset(&inc, 0, sizeof inc);
    strncpy(inc.type, type, sizeof inc.type - 1);
    inc.road_closed = closed;
    strncpy(inc.olr, olr, sizeof inc.olr - 1);
    inc.has_olr = 1;
    return inc;
}

/* TMC-referenced incident (the path the head unit resolves natively). */
static here_incident_t mk_tmc(const char *type, int closed,
                              int cc, int ltn, int loc, int dir, int extent) {
    here_incident_t inc;
    memset(&inc, 0, sizeof inc);
    strncpy(inc.type, type, sizeof inc.type - 1);
    inc.road_closed = closed;
    inc.tmc_cc = cc;
    inc.tmc_ltn = ltn;
    inc.tmc_loc = loc;
    inc.tmc_dir = dir;
    inc.tmc_extent = extent;
    inc.has_tmc = 1;
    return inc;
}

static here_flow_t mkflow(double speed_ms, double jam, const char *olr) {
    here_flow_t fl;
    memset(&fl, 0, sizeof fl);
    fl.speed = speed_ms;
    fl.jam_factor = jam;
    strncpy(fl.olr, olr, sizeof fl.olr - 1);
    fl.has_olr = 1;
    return fl;
}

static here_flow_t mkflow_tmc(double speed_ms, double free_ms, double jam,
                              double length_m, int cc, int ltn, int loc,
                              int dir, int extent) {
    here_flow_t fl;
    memset(&fl, 0, sizeof fl);
    fl.speed = speed_ms;
    fl.free_flow = free_ms;
    fl.jam_factor = jam;
    fl.length = length_m;
    fl.tmc_cc = cc;
    fl.tmc_ltn = ltn;
    fl.tmc_loc = loc;
    fl.tmc_dir = dir;
    fl.tmc_extent = extent;
    fl.has_tmc = 1;
    return fl;
}

/* Attach a sub-segment (metric range with its own flow) to a TMC flow item,
 * exercising the native-style multi-section FlowVector path. */
static void add_subseg(here_flow_t *fl, double length_m, double jam,
                       double speed_ms, double free_ms) {
    if (fl->n_subseg >= HERE_MAX_SUBSEG) return;
    here_subseg_t *g = &fl->subseg[fl->n_subseg++];
    g->length = length_m;
    g->jam_factor = jam;
    g->speed = speed_ms;
    g->free_flow = free_ms;
}

int main(int argc, char **argv) {
    const char *out = argc > 1 ? argv[1] : "/tmp/out.tpg";

    here_incident_t incs[5];
    incs[0] = mk("disabledVehicle", 0,
        "CD4BEAA6OQpStiLanQAJBQQAAfwACgUEAOA4ACn/GX4ACQUEAAGOAHABFTYl9QAJBQQAASkACgUEANYPAIFfTg==");
    incs[1] = mk("construction", 1,
        "CCkBEAAlJApMNyKmpQAJBQQDAxQACgUEA4EuAABxAIoACQUEAwOUADAKCg==");
    incs[2] = mk("construction", 0,
        "CCkBEAAlJApAICK84wAJBQQCA1AACgUEAoVwAAOw/vkACQUEAgPPADAAAA==");
    /* TMC-referenced (real HERE Czech shape: cc=2, ltn=25). */
    incs[3] = mk_tmc("roadClosure", 1, 2, 25, 23023, 0, 1);
    incs[4] = mk_tmc("construction", 0, 2, 25, 46372, 1, 6);

    here_flow_t flows[6];
    /* OLR-only flow is skipped (unit cannot resolve OpenLR line locations). */
    flows[0] = mkflow(18.61111, 0.0,
        "CFABEABMSwpDNiK8XgAJBQQCA/8ACgUEAodzAP+o/3kACQUEAQMvAHACBKIAgQAJBQQCA0kACgUEAsZsAAhA5AkACQUEAQNuAAoFBAGBeAAAAA==");
    /* dir 0 segments 7251,7252,7253 -- with chaining disabled
     * (TPEG_FLOW_CHAIN_EMIT_MAX=1) each is emitted as its own extent=1 point. */
    flows[1] = mkflow_tmc(25.0, 27.78, 0.5, 6452.0, 2, 25, 7251, 0, 1); /* free   */
    flows[2] = mkflow_tmc(8.0,  25.00, 5.5,  127.0, 2, 25, 7252, 0, 1); /* slow   */
    flows[3] = mkflow_tmc(0.0,  22.22, 9.8, 6728.0, 2, 25, 7253, 0, 1); /* jammed */
    /* dir 1 segments 7252,7253 -- also emitted individually as extent=1. */
    flows[4] = mkflow_tmc(20.0, 25.00, 1.0, 6452.0, 2, 25, 7252, 1, 1);
    flows[5] = mkflow_tmc(15.0, 25.00, 2.0,  127.0, 2, 25, 7253, 1, 1);
    /* Sub-segments are still parsed by here_source; keep one to exercise the
     * parser helper. */
    add_subseg(&flows[1], 226.0, 0.0, 13.89, 13.61);

    tpeg_enc_t e;
    if (tpeg_enc_init(&e)) { fprintf(stderr, "init failed\n"); return 1; }
    tpeg_enc_begin(&e);
    unsigned int gen = (unsigned int)time(NULL);
    for (int i = 0; i < 5; ++i) {
        int rc = tpeg_enc_add_incident(&e, gen, 1, &incs[i]);
        printf("incident %d (%s closed=%d) -> %s\n", i, incs[i].type,
               incs[i].road_closed, rc == 0 ? "written" : "skipped");
    }
    int fw = tpeg_enc_add_flows(&e, gen, 1, flows, 6);
    printf("flows: %d chain message(s) written from 6 segments\n", fw);
    tpeg_enc_finish(&e);

    if (e.error) { fprintf(stderr, "encoder error\n"); tpeg_enc_free(&e); return 1; }

    FILE *f = fopen(out, "wb");
    if (!f) { perror("fopen"); tpeg_enc_free(&e); return 1; }
    fwrite(e.buf, 1, e.len, f);
    fclose(f);
    printf("wrote %lu bytes, %d messages -> %s\n",
           (unsigned long)e.len, e.count, out);

    tpeg_enc_free(&e);
    return 0;
}

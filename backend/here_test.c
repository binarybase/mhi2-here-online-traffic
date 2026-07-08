/*
 * here_test.c — host test harness for here_source. Reads sample JSON files and
 * prints the parsed flow segments / incidents. Not deployed to the device.
 *
 * Build & run (host):
 *   cc -O2 -Wall -o /tmp/here_test here_test.c here_source.c && \
 *     /tmp/here_test samples/flow.json samples/incidents.json
 */
#include "here_source.h"

#include <stdio.h>
#include <stdlib.h>

static char *slurp(const char *path, size_t *len_out) {
    FILE *f = fopen(path, "rb");
    long n;
    char *buf;
    if (!f) { perror(path); return NULL; }
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = (char *)malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) { fclose(f); free(buf); return NULL; }
    buf[n] = '\0';
    fclose(f);
    *len_out = (size_t)n;
    return buf;
}

int main(int argc, char **argv) {
    const char *flow_path = (argc > 1) ? argv[1] : "samples/flow.json";
    const char *inc_path  = (argc > 2) ? argv[2] : "samples/incidents.json";
    size_t len;
    char *js;
    int i, count, rc;

    static here_flow_t flows[4096];
    static here_incident_t incs[512];

    /* ---- FLOW ---- */
    js = slurp(flow_path, &len);
    if (js) {
        rc = here_parse_flow(js, len, flows, (int)(sizeof flows / sizeof flows[0]), &count);
        printf("== FLOW: rc=%d total=%d (showing congested, jamFactor>=1.0) ==\n", rc, count);
        int shown = 0;
        int stored = count < (int)(sizeof flows / sizeof flows[0]) ? count : (int)(sizeof flows / sizeof flows[0]);
        for (i = 0; i < stored; i++) {
            if (flows[i].jam_factor < 1.0) continue;
            printf("  jam=%.1f speed=%.1f free=%.1f len=%.0fm olr=%.28s%s\n",
                   flows[i].jam_factor, flows[i].speed, flows[i].free_flow,
                   flows[i].length, flows[i].olr, flows[i].has_olr ? "" : " (NO OLR)");
            if (++shown >= 20) { printf("  ...\n"); break; }
        }
        free(js);
    }

    /* ---- INCIDENTS ---- */
    js = slurp(inc_path, &len);
    if (js) {
        rc = here_parse_incidents(js, len, incs, (int)(sizeof incs / sizeof incs[0]), &count);
        printf("== INCIDENTS: rc=%d total=%d ==\n", rc, count);
        int stored = count < (int)(sizeof incs / sizeof incs[0]) ? count : (int)(sizeof incs / sizeof incs[0]);
        for (i = 0; i < stored; i++) {
            printf("  [%s/%s] closed=%d \"%s\"\n     olr=%.36s%s\n     %s .. %s\n",
                   incs[i].type, incs[i].criticality, incs[i].road_closed,
                   incs[i].description, incs[i].olr, incs[i].has_olr ? "" : " (NO OLR)",
                   incs[i].start_time, incs[i].end_time);
        }
        free(js);
    }

    return 0;
}

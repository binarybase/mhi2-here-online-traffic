/*
 * here_source.h — HERE Traffic API v7 flow + incidents parser.
 *
 * Parses the JSON returned by:
 *   GET https://data.traffic.hereapi.com/v7/flow      (in=<geo>&locationReferencing=olr)
 *   GET https://data.traffic.hereapi.com/v7/incidents (in=<geo>&locationReferencing=olr)
 * into flat C structs the TPEG2 encoder consumes. Location referencing = OpenLR
 * ("olr" field, base64 TISA TPEGOpenLR) — the same scheme libTpegBusinessLogic
 * uses on the head unit, so no proprietary TMC location table is needed.
 *
 * Pure C99, no heap beyond one token buffer; safe for QNX 6.5 / gcc 4.x.
 */
#ifndef HERE_SOURCE_H
#define HERE_SOURCE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HERE_OLR_MAX   512   /* base64 OpenLR is short (<100B) but be generous */
#define HERE_DESC_MAX  160
#define HERE_TYPE_MAX   48
#define HERE_CRIT_MAX   16
#define HERE_TIME_MAX   32

/* One real-time flow segment. */
typedef struct {
    char   olr[HERE_OLR_MAX]; /* base64 OpenLR location reference           */
    double length;            /* segment length (m)                         */
    double jam_factor;        /* 0.0 (free) .. 10.0 (blocked)               */
    double speed;             /* current speed (m/s)                        */
    double free_flow;         /* free-flow speed (m/s)                      */
    int    has_olr;           /* 1 if olr was present                       */
} here_flow_t;

/* One traffic incident. */
typedef struct {
    char olr[HERE_OLR_MAX];       /* base64 OpenLR location reference        */
    char type[HERE_TYPE_MAX];     /* roadClosure|congestion|accident|...     */
    char criticality[HERE_CRIT_MAX]; /* critical|major|minor|low             */
    char description[HERE_DESC_MAX]; /* human text (description.value)        */
    char start_time[HERE_TIME_MAX];
    char end_time[HERE_TIME_MAX];
    int  road_closed;             /* 0/1                                     */
    int  has_olr;
} here_incident_t;

/*
 * Parse a HERE /v7/flow response.
 *   json,len : response body.
 *   out,max  : caller buffer; up to `max` items written.
 *   count    : out — number of items parsed (may exceed `max`; only `max` stored).
 * Returns 0 on success, negative on JSON error.
 */
int here_parse_flow(const char *json, size_t len,
                    here_flow_t *out, int max, int *count);

/* Parse a HERE /v7/incidents response. Same contract. */
int here_parse_incidents(const char *json, size_t len,
                         here_incident_t *out, int max, int *count);

#ifdef __cplusplus
}
#endif

#endif /* HERE_SOURCE_H */

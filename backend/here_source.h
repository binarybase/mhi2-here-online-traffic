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
#define HERE_MAX_SUBSEG 12   /* cap so multi-section msg component lengths stay <128B */

/* One HERE currentFlow.subSegments[] entry — a metric sub-range of the TMC
 * location with its own flow status. Emitted as one TPEG FlowVectorSection so
 * our stream mirrors native TomTom's multi-section flow (see tpeg_enc_add_flow). */
typedef struct {
    double length;            /* sub-segment length (m)                     */
    double jam_factor;        /* 0.0 (free) .. 10.0 (blocked)               */
    double speed;             /* current speed (m/s)                        */
    double free_flow;         /* free-flow speed (m/s)                      */
} here_subseg_t;

/* One real-time flow segment. */
typedef struct {
    char   olr[HERE_OLR_MAX]; /* base64 OpenLR location reference           */
    double length;            /* segment length (m)                         */
    double jam_factor;        /* 0.0 (free) .. 10.0 (blocked)               */
    double speed;             /* current speed (m/s)                        */
    double free_flow;         /* free-flow speed (m/s)                      */
    int    has_olr;           /* 1 if olr was present                       */
    /* currentFlow.subSegments[]: metric breakdown of the flow along the TMC
     * location. When >=2 present, the encoder emits a native-style multi-section
     * FlowVector (one section per sub-segment) instead of a single section.     */
    int          n_subseg;
    here_subseg_t subseg[HERE_MAX_SUBSEG];
    /* TMC location reference (location.tmc). The head unit resolves TMC
     * location codes natively but cannot decode OpenLR, so only TMC-referenced
     * flow renders. Populated only when HERE returns a tmc object.            */
    int    has_tmc;
    int    tmc_cc;            /* ebuCountryCode, hex digit -> int (CZ = 2)   */
    int    tmc_ltn;           /* tableId / location table number (CZ = 25)   */
    int    tmc_loc;           /* locationId (16-bit TMC location code)       */
    int    tmc_dir;           /* TMC direction bit, INVERTED from HERE's
                                queuingDirection: "+" -> 1, "-" -> 0          */
    int    tmc_extent;        /* extent (number of TMC steps)               */
    /* First absolute coordinate decoded from the OLR reference (HERE's OLR is
     * a 7-byte header followed by lon(3 BE signed) lat(3 BE signed), each
     * deg = int*360/2^24). Used to order emitted flow by distance to the car
     * so near-car roads (on the visible map) are always emitted first. 0 if
     * the OLR could not be decoded.                                          */
    int    has_coord;         /* 1 if lat/lon decoded from OLR              */
    double lat;               /* first-point latitude (deg)                 */
    double lon;               /* first-point longitude (deg)                */
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
    int  alertc_code;             /* codes[0]: AlertC/TMC event (ISO 14819-2),
                                     0 if absent. Primary/most-specific code. */
    int  has_olr;
    /* TMC location reference (location.tmc). The head unit resolves TMC
     * location codes natively (on-device TMC table) — unlike OpenLR which it
     * cannot decode. Populated only when HERE returns a tmc object.           */
    int  has_tmc;
    int  tmc_cc;                  /* ebuCountryCode, hex digit -> int (CZ = 2) */
    int  tmc_ltn;                 /* tableId / location table number (CZ = 25) */
    int  tmc_loc;                 /* locationId (16-bit TMC location code)     */
    int  tmc_dir;                 /* TMC direction bit, INVERTED from HERE's
                                     queuingDirection: "+" -> 1, "-" -> 0      */
    int  tmc_extent;             /* extent (number of TMC steps)              */
    /* First absolute coordinate decoded from the OLR reference (see here_flow_t),
     * used to order the emitted incidents by distance to the car so the head
     * unit's message list is sorted nearest-first like native. 0 if undecoded. */
    int    has_coord;             /* 1 if lat/lon decoded from OLR             */
    double lat;                   /* first-point latitude (deg)                */
    double lon;                   /* first-point longitude (deg)               */
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

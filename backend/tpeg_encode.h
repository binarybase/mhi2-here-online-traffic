/*
 * tpeg_encode.h — build a decrypted TPEG2 stream (the on-disk form the MHI2
 * online-traffic bundle feeds to libTpegBusinessLogic) from HERE Traffic API v7
 * data. This is the inverse of backend/tools/tpeg_parse.py.
 *
 * The stream layout was reverse-engineered from live captures
 * (backend/samples/) and cross-referenced against the TISA TPEG2 evaluation-kit
 * reference parser (gitlab.tisa.org/published/evaluation-kit), which validates
 * the CRCs the head unit's libTpegBusinessLogic enforces:
 *
 *   Transport    ff 0f | svcLen16(BE) | hdrCRC(BE) | 01 | 00 00 00 | 00
 *                (svcLen16 = total_bytes - 7; hdrCRC over hdr + first 11 payload)
 *   SNI frame    SCID=0 | fieldlen | hdrCRC | msgCount | SNI comps | dataCRC
 *                (static: "TTS TPEG" / "TomTom TPEG traffic service" + svc table)
 *   TEC frame*   SCID=1 | fieldlen | hdrCRC | 00(prio) | msgCount | message* | dataCRC
 *                (built dynamically; chunked <=250 messages; hdr+data CRC computed)
 *   Message      00 | CompLen | 00 | MMC | Event | LRC
 *                MMC   = 01 | len | attrlen | msgID(varint) ver(u8) expiry(u32BE) flag
 *                Event = 03 | len | attrlen | effectCode 08 lenAffected(varint) 04 04 03 cause warn dc
 *                LRC   = 02 | 8+n | 00 08 5+n 01 10 00 1+n n | <OpenLR n bytes>
 *
 * Every component-frame hdrCRC and dataCRC is computed with TPEG_CRC (the TISA
 * "CCITT" variant, tpeg_hdr_crc below) — never replayed.
 *
 * Pure C99, single malloc'd growable buffer; safe for QNX 6.5 / gcc 4.x.
 */
#ifndef TPEG_ENCODE_H
#define TPEG_ENCODE_H

#include <stddef.h>
#include "here_source.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    unsigned char *buf;
    size_t         len;
    size_t         cap;
    int            error;   /* non-zero once any append failed (OOM/oversize) */
    int            count;   /* messages written                              */
    /* Pending TEC component-frame message bytes. Messages accumulate here and
     * are flushed as a properly-CRC'd SCID=1 component frame (<=250 msgs each)
     * into buf by flush_tec_frame(); see tpeg_encode.c. */
    unsigned char *mbuf;
    size_t         mlen;
    size_t         mcap;
    int            mcount;  /* messages pending in the current TEC frame       */
    /* Pending TFP component-frame message bytes. Flushed as a properly-CRC'd
     * SCID=2 component frame (<=250 msgs each) by flush_tfp_frame(). */
    unsigned char *fbuf;
    size_t         flen;
    size_t         fcap;
    int            fcount;  /* messages pending in the current TFP frame       */
} tpeg_enc_t;

/* Initialise an encoder. Returns 0 on success, -1 on allocation failure. */
int  tpeg_enc_init(tpeg_enc_t *e);

/* Release the internal buffer. */
void tpeg_enc_free(tpeg_enc_t *e);

/* Write the envelope + service header. Call once, before adding messages. */
void tpeg_enc_begin(tpeg_enc_t *e);

/*
 * Append one traffic incident as a TEC message.
 *   gen_time : Unix time to stamp the message (u32).
 *   version  : message version (increments per real update of the same id).
 * The 32-bit messageID is derived (stable hash) from inc->... location, so the
 * head unit dedupes/updates correctly across polls.
 * Returns 0 on success, -1 if skipped (no OpenLR, oversize, or prior error).
 */
int  tpeg_enc_add_incident(tpeg_enc_t *e, unsigned int gen_time,
                           unsigned char version, const here_incident_t *inc);

/*
 * Append one real-time flow segment as a TFP message (Shape A: single link,
 * absolute OpenLR location). The current speed (km/h) and a jam/LOS level are
 * derived from the HERE flow item. Returns 0 on success, -1 if skipped.
 */
int  tpeg_enc_add_flow(tpeg_enc_t *e, unsigned int gen_time,
                       unsigned char version, const here_flow_t *fl);

/*
 * Merge the parsed HERE flow segments into native-style multi-step TMC chains
 * and append one TFP FlowVector message per chain. HERE returns granular
 * single-step (extent=1) TMC references that mostly fail on-device resolution;
 * consecutive same-direction locationIds are the same road, so they are
 * concatenated into a primary + extent reference (mirroring native TomTom's
 * 1..30 extents) with one FlowVectorSection per step. Prefer this over calling
 * tpeg_enc_add_flow per item. Returns the number of messages written.
 *
 * ref_lat/ref_lon is the car position. When the candidate chains exceed the
 * single-frame budget, the nearest chains (by OLR-decoded coordinate) are
 * emitted first so the roads on the visible map are always covered — native
 * TomTom likewise prioritises flow closest to the vehicle.
 */
int  tpeg_enc_add_flows(tpeg_enc_t *e, unsigned int gen_time,
                        unsigned char version, const here_flow_t *flows, int n,
                        double ref_lat, double ref_lon);

/* Backpatch the envelope length. Call once, after all messages. */
void tpeg_enc_finish(tpeg_enc_t *e);

#ifdef __cplusplus
}
#endif

#endif /* TPEG_ENCODE_H */

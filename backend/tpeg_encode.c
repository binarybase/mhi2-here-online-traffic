/*
 * tpeg_encode.c — see tpeg_encode.h. Emits the decrypted TPEG2 stream the MHI2
 * online-traffic decoder accepts, built from HERE Traffic API v7 incidents.
 */
#include "tpeg_encode.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

/* ---- growable byte buffer ------------------------------------------------ */

static int ensure(tpeg_enc_t *e, size_t extra) {
    if (e->error) return -1;
    if (e->len + extra <= e->cap) return 0;
    size_t ncap = e->cap ? e->cap * 2 : 1024;
    while (ncap < e->len + extra) ncap *= 2;
    unsigned char *n = (unsigned char *)realloc(e->buf, ncap);
    if (!n) { e->error = 1; return -1; }
    e->buf = n;
    e->cap = ncap;
    return 0;
}

static void put1(tpeg_enc_t *e, unsigned char b) {
    if (ensure(e, 1)) return;
    e->buf[e->len++] = b;
}

static void putn(tpeg_enc_t *e, const void *p, size_t n) {
    if (ensure(e, n)) return;
    memcpy(e->buf + e->len, p, n);
    e->len += n;
}

/* ---- pending-message buffer (accumulates one TEC frame's messages) ------- */

static int mensure(tpeg_enc_t *e, size_t extra) {
    if (e->error) return -1;
    if (e->mlen + extra <= e->mcap) return 0;
    size_t ncap = e->mcap ? e->mcap * 2 : 1024;
    while (ncap < e->mlen + extra) ncap *= 2;
    unsigned char *n = (unsigned char *)realloc(e->mbuf, ncap);
    if (!n) { e->error = 1; return -1; }
    e->mbuf = n;
    e->mcap = ncap;
    return 0;
}

static void mput1(tpeg_enc_t *e, unsigned char b) {
    if (mensure(e, 1)) return;
    e->mbuf[e->mlen++] = b;
}

static void mputn(tpeg_enc_t *e, const void *p, size_t n) {
    if (mensure(e, n)) return;
    memcpy(e->mbuf + e->mlen, p, n);
    e->mlen += n;
}

/* ---- pending TFP-message buffer (accumulates one TFP frame's messages) --- */

static int fensure(tpeg_enc_t *e, size_t extra) {
    if (e->error) return -1;
    if (e->flen + extra <= e->fcap) return 0;
    size_t ncap = e->fcap ? e->fcap * 2 : 1024;
    while (ncap < e->flen + extra) ncap *= 2;
    unsigned char *n = (unsigned char *)realloc(e->fbuf, ncap);
    if (!n) { e->error = 1; return -1; }
    e->fbuf = n;
    e->fcap = ncap;
    return 0;
}

static void fput1(tpeg_enc_t *e, unsigned char b) {
    if (fensure(e, 1)) return;
    e->fbuf[e->flen++] = b;
}

static void fputn(tpeg_enc_t *e, const void *p, size_t n) {
    if (fensure(e, n)) return;
    memcpy(e->fbuf + e->flen, p, n);
    e->flen += n;
}

/* base-128 big-endian varint (high bit = continue), matching tpeg_parse.varint */
static int varint_len(unsigned int v) {
    int n = 1;
    while (v >= 0x80) { v >>= 7; n++; }
    return n;
}

/* Write a base-128 big-endian varint into a plain buffer; returns byte count. */
static int varint_to(unsigned char *out, unsigned int v) {
    unsigned char tmp[5];
    int n = 0, w = 0;
    tmp[n++] = (unsigned char)(v & 0x7f);
    while (v >= 0x80) { v >>= 7; tmp[n++] = (unsigned char)(0x80 | (v & 0x7f)); }
    for (int i = n - 1; i >= 0; --i) out[w++] = tmp[i];
    return w;
}

/* ---- base64 decode (standard + url alphabet, ignores padding/whitespace) - */

static int b64val(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return -1;
}

/* Returns number of bytes written to out (<= outmax), or -1 on overflow. */
static int b64decode(const char *s, unsigned char *out, int outmax) {
    int acc = 0, nbits = 0, olen = 0;
    for (; *s; ++s) {
        int v = b64val((unsigned char)*s);
        if (v < 0) continue;          /* skip '=', newlines, etc. */
        acc = (acc << 6) | v;
        nbits += 6;
        if (nbits >= 8) {
            nbits -= 8;
            if (olen >= outmax) return -1;
            out[olen++] = (unsigned char)((acc >> nbits) & 0xff);
        }
    }
    return olen;
}

/* ---- TPEG2-OLR line-reference offset-tail normaliser --------------------- */
/* Read a base-128 big-endian varint; returns byte count consumed or -1. */
static int be_varint_read(const unsigned char *p, int max, unsigned int *out) {
    unsigned int v = 0;
    int n = 0;
    for (;;) {
        if (n >= max || n >= 5) return -1;
        unsigned char b = p[n++];
        v = (v << 7) | (b & 0x7f);
        if (!(b & 0x80)) break;
    }
    *out = v;
    return n;
}

/* HERE's TPEG2-OLR line references always flag BOTH a positive and a negative
 * offset (tail byte 0x30) even when the offset value is zero. The native TomTom
 * stream instead OMITS an offset whose value is zero: flag bit 0x10 = positive
 * present, 0x20 = negative present, and a bare 0x00 byte means "no offsets".
 * Captures show native NEVER emits a present-flag with a zero value, whereas
 * every HERE OLR does (53/153 are `30 00 00`). The head unit's strict parser
 * desyncs on the phantom offsets ("out of buffer bounds"), discarding the whole
 * TEC stream. Rewrite the tail to native convention: drop zero-valued offsets
 * and clear their present-flag bits. On any structural surprise, leave the OLR
 * untouched (safer to ship the original than a corrupted length). See
 * /memories/repo/tpeg-capture.md. */
static void olr_fix_offsets(unsigned char *olr, int *olrn) {
    int n = *olrn, p = 7;
    if (n < 9 || olr[6] != 0x00) return;          /* not the expected layout  */
    if (olr[p] != 0x09) return;                   /* LineProperties (id 9)    */
    p += 2 + olr[p + 1]; if (p + 1 >= n) return;
    if (olr[p] != 0x0a) return;                   /* PathProperties (id 10)   */
    p += 2 + olr[p + 1]; if (p > n) return;
    for (;;) {
        if (n - p < 8) break;                     /* only the offset tail left */
        p += 5;                                    /* relCoord(4) + altSel(1)  */
        if (p + 1 >= n || olr[p] != 0x09) return; /* LineProperties           */
        p += 2 + olr[p + 1]; if (p > n) return;
        if (p < n && olr[p] == 0x0a) {            /* PathProperties -> more   */
            if (p + 1 >= n) return;
            p += 2 + olr[p + 1]; if (p > n) return;
        } else {
            break;                                 /* last shape, no path      */
        }
    }
    if (p >= n) return;                            /* no tail present          */
    unsigned char flag = olr[p];
    if ((flag & 0x30) == 0) return;                /* already native form      */
    int q = p + 1, pl = 0, nl = 0;
    unsigned int pos = 0, neg = 0;
    if (flag & 0x10) { pl = be_varint_read(olr + q, n - q, &pos); if (pl < 0) return; q += pl; }
    if (flag & 0x20) { nl = be_varint_read(olr + q, n - q, &neg); if (nl < 0) return; q += nl; }
    if (q != n) return;                            /* unexpected trailing bytes */
    unsigned char nb[16];
    int w = 0;
    unsigned char nf = (unsigned char)(flag & ~0x30);
    if (pos) nf |= 0x10;
    if (neg) nf |= 0x20;
    nb[w++] = nf;
    if (pos) w += varint_to(nb + w, pos);
    if (neg) w += varint_to(nb + w, neg);
    memcpy(olr + p, nb, (size_t)w);
    *olrn = p + w;
}

/* ---- HERE type -> TPEG2-TEC cause byte (COMP_DIRECTCAUSE) ---------------- */
/* The head unit's libTpegBusinessLogic.so parses this byte as the standard
 * TPEG2-TEC CauseCode, converts it to a TMC event (TECToTMC::Convert) and
 * renders the matching icon/label in the traffic list. The lib holds NO cause
 * text itself, so the numeric code fully determines what the driver sees.
 *
 * Codes are the standard TPEG2-TEC CauseCodes, cross-verified against:
 *   - ITSTF17001 v1.0 (EU 886/2013 SRTI DATEX/DENM/TMC/TPEG-TEC correlation),
 *   - our captured native TomTom stream (0x03/0x05/0x0d proven to render),
 *   - on-map Czech labels from screenshots.
 * See /memories/repo/tpeg-capture.md ("TPEG2-TEC CauseCode table EXTRACTED").
 *
 * NOTE: 0x03/0x05/0x0d are capture-proven. 0x02/0x06/0x09/0x0a/0x0b/0x0c/0x0e
 * are the EU-mandated SRTI safety causes a compliant TPEG2-TEC decoder must
 * support, but were not seen in our captures — validate on-device (a wrong
 * cause can make the decoder drop the message) before shipping to the car. */
#define TEC_CONGESTION 0x01   /* traffic congestion                          */
#define TEC_ACCIDENT   0x02   /* accident (ITSTF cat c / TMC 857)            */
#define TEC_WORKS      0x03   /* roadworks (capture-proven)                  */
#define TEC_CLOSURE    0x05   /* impassability / road blocked (capture 0x05) */
#define TEC_WEATHER    0x06   /* adverse weather / slippery road (ITSTF a)   */
#define TEC_HAZARD     0x09   /* hazardous location: flood/rockfall (ITSTF)  */
#define TEC_OBSTACLE   0x0a   /* obstacle / object on road (ITSTF b)         */
#define TEC_ANIMALS    0x0b   /* animals on road (ITSTF b)                   */
#define TEC_PEOPLE     0x0c   /* people on road (ITSTF b)                    */
#define TEC_BROKENDOWN 0x0d   /* broken-down vehicle (capture 0x0d)          */
#define TEC_WRONGWAY   0x0e   /* wrong-way driver (ITSTF f / TMC 1401)       */

static unsigned char cause_code(const here_incident_t *inc) {
    const char *ty = inc->type;

    /* A closed road always reads as impassability regardless of type. */
    if (inc->road_closed || !strcmp(ty, "roadClosure"))
        return TEC_CLOSURE;

    if (!strcmp(ty, "accident"))          return TEC_ACCIDENT;
    if (!strcmp(ty, "disabledVehicle"))   return TEC_BROKENDOWN;
    if (!strcmp(ty, "construction"))      return TEC_WORKS;
    if (!strcmp(ty, "laneRestriction"))   return TEC_WORKS;   /* narrow/lane works */
    if (!strcmp(ty, "congestion"))        return TEC_CONGESTION;
    if (!strcmp(ty, "weather"))           return TEC_WEATHER;

    /* roadHazard is generic in HERE — refine via the primary AlertC code where
     * the ISO 14819-2 event class is unambiguous, else fall back to obstacle. */
    if (!strcmp(ty, "roadHazard")) {
        int a = inc->alertc_code;
        /* AlertC event-code neighbourhoods (ISO 14819-2 / ITSTF17001):
         *   animals-on-road ~ 923,944,948,1067; people-on-road ~ 945-947,1482-1484;
         *   flooding/rockfall/landslip ~ 880,892,894,998,999; ice/slippery ~ 977-996. */
        if (a == 923 || a == 944 || a == 948 || a == 1067)          return TEC_ANIMALS;
        if ((a >= 945 && a <= 947) || (a >= 1482 && a <= 1484))     return TEC_PEOPLE;
        if (a == 880 || a == 892 || a == 894 || a == 998 || a == 999) return TEC_HAZARD;
        if (a >= 977 && a <= 996)                                   return TEC_WEATHER;
        return TEC_OBSTACLE;
    }

    /* massTransit, plannedEvent, other, unknown -> keep visible with a safe,
     * capture-proven code rather than risk the decoder dropping the message. */
    return TEC_WORKS;
}

/* FNV-1a 32-bit hash of a string (used to derive stable messageIDs). */
static unsigned int hash_str(const char *p) {
    unsigned int h = 2166136261u;
    for (; *p; ++p) { h ^= (unsigned char)*p; h *= 16777619u; }
    if (h == 0) h = 1;
    return h;
}

/* Stable messageID for a HERE incident. Uses the OpenLR reference (unique per
 * location+direction) so the same incident keeps the same id across polls,
 * letting the head unit update rather than duplicate. */
static unsigned int msg_id(const here_incident_t *inc) {
    /* TMC-only incidents carry no OpenLR string; hashing inc->type there would
     * collide every incident of the same type onto one id (the head unit would
     * then keep overwriting them). Derive the id from the TMC location tuple
     * (country/table/code/direction) instead, which is unique per incident. */
    if (inc->has_tmc) {
        char key[40];
        snprintf(key, sizeof key, "T%d,%d,%d,%d",
                 inc->tmc_cc, inc->tmc_ltn, inc->tmc_loc, inc->tmc_dir);
        return hash_str(key);
    }
    return hash_str(inc->olr[0] ? inc->olr : inc->type);
}

/* ---- public API ---------------------------------------------------------- */

/* Fixed service header: 44 2c 4e 03 00 00 | nblen | 08"TTS TPEG" 1b"TomTom..." */
static const unsigned char SERVICE_HDR[] = {
    0x44, 0x2c, 0x4e, 0x03, 0x00, 0x00, 0x25,
    0x08, 'T','T','S',' ','T','P','E','G',
    0x1b, 'T','o','m','T','o','m',' ','T','P','E','G',' ',
          't','r','a','f','f','i','c',' ','s','e','r','v','i','c','e'
};

/* Tail of the SNI service-frame field (bytes 41..67 of the 68-byte field): the
 * SNI service-table (fast-tuning) and versioning components that map SCID 1 ->
 * AID 5 (TEC) and SCID 2 -> AID 7 (TFP), ending in the SNI frame's data CRC
 * 0x70FF. Together with SERVICE_HDR[3:] this is one complete, correctly-CRC'd
 * SNI component frame (SCID=0, fieldlen=68, hdrCRC=0x2C4E) copied verbatim from
 * a native TomTom stream. NOTE: the old static "SETUP_FRAME" appended 7 more
 * bytes (01 37 2e b0 e8 00 e6) that were the CORRUPT replayed start of a TEC
 * frame — the very hdrCRC=0xB0E8 the head unit rejected. Those are gone: the
 * TEC frame is now built dynamically with computed CRCs (flush_tec_frame). */
static const unsigned char SNI_TAIL[] = {
    0x01, 0x00, 0x0c, 0x00, 0x7d, 0x01, 0x00, 0x00, 0x00, 0x05,
    0x02, 0x00, 0x00, 0x00, 0x07, 0x0e, 0x00, 0x07, 0x00, 0x01,
    0x03, 0x01, 0x02, 0x01, 0x00, 0x70, 0xff
};

int tpeg_enc_init(tpeg_enc_t *e) {
    memset(e, 0, sizeof *e);
    return ensure(e, 1024) ? -1 : 0;
}

void tpeg_enc_free(tpeg_enc_t *e) {
    free(e->buf);
    free(e->mbuf);
    free(e->fbuf);
    memset(e, 0, sizeof *e);
}

void tpeg_enc_begin(tpeg_enc_t *e) {
    /* Transport(6) + type + SID + EncID + SCID0 + fieldlen_hi:
     * ff 0f | len16(placeholder) | hdrCRC(placeholder) | 01 | 00 00 00 | 00 | 00 | 00 */
    static const unsigned char ENV[] = {
        0xff, 0x0f, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    putn(e, ENV, sizeof ENV);           /* ...ENV[11]=SCID0, ENV[12]=fieldlen_hi */
    putn(e, SERVICE_HDR, sizeof SERVICE_HDR); /* 44=fieldlen_lo, 2c 4e=hdrCRC, +field */
    putn(e, SNI_TAIL, sizeof SNI_TAIL); /* completes 68-byte SNI field incl dataCRC */
}

/* Emit one TEC message into the pending message buffer (later wrapped by
 * flush_tec_frame into a CRC'd SCID=1 component frame):
 *   00 | CompLen | 00 | 01 | MMClen | attrlen | <ident> | <rest>
 * ident = messageID(varint) ver(u8) expiry(u32 BE) flag(0x00). rest = the TEC
 * Event + LocationReferencing components. Returns 0 on success, -1 if oversize. */
static void flush_tec_frame(tpeg_enc_t *e);
static void flush_tfp_frame(tpeg_enc_t *e);

static int emit_message(tpeg_enc_t *e, unsigned int id, unsigned char version,
                        unsigned int gen_time, const unsigned char *rest, int r) {
    int identlen = varint_len(id) + 6;   /* varint id + ver + expiry(4) + flag */
    int L = identlen + 1;
    int mmc_len = 4 + identlen + r;      /* 00 01 + L + L-1 + ident + rest    */
    if (mmc_len > 0xff) return -1;

    /* Keep each TEC frame's messageCount within one byte (<=250). */
    if (e->mcount >= 250) flush_tec_frame(e);

    mput1(e, 0x00);                      /* TEC message CompID (0)            */
    mput1(e, (unsigned char)mmc_len);    /* message CompLen                   */
    mput1(e, 0x00);                      /* leading byte of message body      */
    mput1(e, 0x01);                      /* MMC component id                  */
    mput1(e, (unsigned char)L);          /* MMC CompLen                       */
    mput1(e, (unsigned char)identlen);   /* MMC attribute-block length        */
    {
        unsigned char vb[5];
        int vn = varint_to(vb, id);
        mputn(e, vb, (size_t)vn);        /* messageID (varint)                */
    }
    mput1(e, version);                   /* versionID                         */
    mput1(e, (unsigned char)(gen_time >> 24));
    mput1(e, (unsigned char)(gen_time >> 16));
    mput1(e, (unsigned char)(gen_time >> 8));
    mput1(e, (unsigned char)(gen_time));  /* messageExpiryTime (u32 BE)       */
    mput1(e, 0x00);                      /* flag 0x00 = full (not cancelled)  */
    mputn(e, rest, (size_t)r);           /* Event + LRC                       */

    if (!e->error) { e->count++; e->mcount++; }
    return e->error ? -1 : 0;
}


int tpeg_enc_add_incident(tpeg_enc_t *e, unsigned int gen_time,
                          unsigned char version, const here_incident_t *inc) {
    if (e->error) return -1;
    /* Need at least one location reference. Prefer TMC (the head unit resolves
     * TMC location codes natively and renders them) and fall back to OpenLR
     * (kept working for incidents that only carry OLR, and for the day the
     * on-device OLR resolver is wired up). */
    if (!inc->has_tmc && !(inc->has_olr && inc->olr[0])) return -1;

    unsigned char code = cause_code(inc);
    int closed = inc->road_closed || !strcmp(inc->type, "roadClosure");
    /* effectCode: 07 = "no traffic flow" (closed/impassable), else 01 = unknown.
     * lengthAffected is informational (metres); HERE gives no incident length so
     * emit 0 (single-byte varint) — the location reference carries the extent. */
    unsigned char effect = closed ? 0x07 : 0x01;
    unsigned int  len_affected = 0;

    /* Validity window. The byte after effectCode in the TEC Event component is a
     * selector BitArray (TPEG2-TEC TEC_Event, TISA reference parser), NOT a
     * "lengthAffected tag". Bit meaning (0x80 = continuation, data bits MSB..LSB
     * map to is_set(0)=0x40 startTime, is_set(1)=0x20 stopTime, is_set(2)=0x10
     * tendency, is_set(3)=0x08 lengthAffected, ...). The old encoder emitted
     * 0x08 = lengthAffected only, so NO start/stop times were sent; the head unit
     * then defaults startTime==stopTime==processing-time, giving every message a
     * zero-length validity window, and TtiDataManager::ExpiryTimeFilter drops the
     * whole list (proven on-device, eso trace 213: 119 messages removed). Emit an
     * explicit ~60min window (matches native) so incidents persist until the next
     * poll refreshes them. DateTime = 4-byte big-endian Unix timestamp. */
    unsigned int start_time = gen_time;
    unsigned int stop_time  = gen_time + 3600u;

    /* --- rest = TEC Event component + LocationReferencing component ---
     * Byte-for-byte the shape the native TomTom stream (and the TISA reference
     * parser) expect; see tpeg_encode.h and /memories/repo/tpeg-capture.md. */
    unsigned char rest[24 + HERE_OLR_MAX];
    int r = 0;

    /* Event (CompID 03):
     *   attrlen | effectCode | selector | startTime(4) stopTime(4) lenAffected | DirectCause
     * selector 0x68 = startTime(0x40) | stopTime(0x20) | lengthAffected(0x08). */
    unsigned char la_vb[5];
    int la_n = varint_to(la_vb, len_affected);
    int ev_attrlen = 1 + 1 + 4 + 4 + la_n;     /* effectCode+selector+start+stop+len */
    int ev_complen = 1 + ev_attrlen + 6;       /* attrlen byte + attrs + DirectCause(6) */
    rest[r++] = 0x03;                          /* Event component id             */
    rest[r++] = (unsigned char)ev_complen;     /* Event CompLen                  */
    rest[r++] = (unsigned char)ev_attrlen;     /* Event attribute-block length   */
    rest[r++] = effect;                        /* effectCode                     */
    rest[r++] = 0x68;                          /* selector: startTime|stopTime|lengthAffected */
    rest[r++] = (unsigned char)(start_time >> 24);
    rest[r++] = (unsigned char)(start_time >> 16);
    rest[r++] = (unsigned char)(start_time >> 8);
    rest[r++] = (unsigned char)(start_time);   /* startTime (DateTime u32 BE)    */
    rest[r++] = (unsigned char)(stop_time >> 24);
    rest[r++] = (unsigned char)(stop_time >> 16);
    rest[r++] = (unsigned char)(stop_time >> 8);
    rest[r++] = (unsigned char)(stop_time);    /* stopTime (DateTime u32 BE)     */
    memcpy(rest + r, la_vb, (size_t)la_n); r += la_n;  /* lengthAffected         */
    rest[r++] = 0x04;                          /* DirectCause component id       */
    rest[r++] = 0x04;                          /* DirectCause CompLen            */
    rest[r++] = 0x03;                          /* DirectCause attr-block length   */
    rest[r++] = code;                          /* mainCause                      */
    rest[r++] = 0x01;                          /* warningLevel = informative     */
    rest[r++] = 0x00;                          /* flags (verified)               */

    if (inc->has_tmc) {
        /* LocationReferencing (CompID 02) -> LR_TMC (method 02). Reverse of the
         * native TomTom online stream (dominant path, 364/368 containers):
         *   LRC     = 02 <payloadlen> <payload>
         *   payload = 00 02 <mlen> <ref>            (00 subid, 02 = TMC method)
         *   ref     = <L=len(ref)-1> <loc16 BE> <cc> <ltn> <flags> <extent>
         *   flags   = 0x10 base | (dir ? 0x40 : 0)  (bit 0x40 = queuing "-")
         * cc/ltn come straight from HERE (ebuCountryCode/tableId) and match the
         * on-device table exactly (CZ = 2/25). See /memories/repo/tpeg-capture.md */
        unsigned char loc_hi = (unsigned char)((inc->tmc_loc >> 8) & 0xff);
        unsigned char loc_lo = (unsigned char)(inc->tmc_loc & 0xff);
        unsigned char cc     = (unsigned char)(inc->tmc_cc & 0xff);
        unsigned char ltn    = (unsigned char)(inc->tmc_ltn & 0xff);
        unsigned char flags  = (unsigned char)(0x10 | (inc->tmc_dir ? 0x40 : 0));
        int ext = inc->tmc_extent;
        if (ext < 0) ext = 0;
        if (ext > 30) ext = 30;                /* native extent range 1..30      */
        rest[r++] = 0x02;                      /* LRC component id               */
        rest[r++] = 0x0a;                      /* LRC CompLen (10)               */
        rest[r++] = 0x00;                      /* LRC leading byte (subid)       */
        rest[r++] = 0x02;                      /* LR_TMC method id               */
        rest[r++] = 0x07;                      /* method content length (7)      */
        rest[r++] = 0x06;                      /* ref length prefix (6)          */
        rest[r++] = loc_hi;                    /* TMC location code hi (BE)      */
        rest[r++] = loc_lo;                    /* TMC location code lo           */
        rest[r++] = cc;                        /* TMC country code (CZ = 0x02)   */
        rest[r++] = ltn;                       /* location table number (0x19)   */
        rest[r++] = flags;                     /* direction flags                */
        rest[r++] = (unsigned char)ext;        /* extent                         */
    } else {
        /* Decode HERE OpenLR (base64). HERE returns the location reference
         * already wrapped as a complete LRC_OLR component (08 <len> 01 10 00 00
         * <len> <len> <coordinate content>), exactly the layer we rebuild below.
         * The native TomTom stream embeds only the coordinate content under a
         * SINGLE such wrapper, so embedding HERE's bytes verbatim double-wraps
         * the reference and shifts the whole line location by 7 bytes — the head
         * unit's strict TPEG2-OLR parser then desyncs ("wrong OLR type", "out of
         * buffer bounds") and discards the entire TEC stream. Strip HERE's inner
         * LRC_OLR wrapper so we emit coordinate-first content like native. */
        unsigned char olr[HERE_OLR_MAX];
        int olrn = b64decode(inc->olr, olr, (int)sizeof olr);
        if (olrn < 3 || olrn > 0x7d) return -1;     /* keep container len < 0x80 */

        unsigned char *olrp = olr;
        if (olrn >= 8 && olrp[0] == 0x08 && olrp[2] == 0x01 && olrp[3] == 0x10) {
            /* HERE double-wraps its reference in an LRC_OLR component; strip it
             * so we embed the coordinate content directly like native. Only the
             * standard BaseComp (id 0x00) maps to native's single-wrap line
             * reference. Any other inner base component (e.g. id 0x02, seen
             * ~1/150) is a HERE variant with extra nested structure we can't
             * guarantee the head unit parses; drop that incident rather than let
             * one malformed OLR desync the whole TEC stream. */
            if (olrp[4] != 0x00) return -1;
            int inner = olrp[6];                    /* BaseComp attr-block length  */
            if (inner < 3 || inner > olrn - 7) return -1;
            olrp += 7; olrn = inner;
        }

        /* Normalise the OLR offset tail to the native TomTom convention (drop
         * zero-valued offset flags) so the head unit's strict TPEG2-OLR parser
         * accepts it instead of desyncing the whole TEC stream. */
        olr_fix_offsets(olrp, &olrn);

        /* LocationReferencing (CompID 02) -> LRC_OLR(08, v1.0) -> BaseComp(00) */
        rest[r++] = 0x02;                          /* LRC component id           */
        rest[r++] = (unsigned char)(8 + olrn);     /* LRC CompLen                */
        rest[r++] = 0x00;                          /* LRC leading byte           */
        rest[r++] = 0x08;                          /* LRC_OLR component id       */
        rest[r++] = (unsigned char)(5 + olrn);     /* LRC_OLR CompLen            */
        rest[r++] = 0x01;                          /* LRC_OLR attr-block length  */
        rest[r++] = 0x10;                          /* OpenLR version 1.0         */
        rest[r++] = 0x00;                          /* BaseComp component id      */
        rest[r++] = (unsigned char)(1 + olrn);     /* BaseComp CompLen           */
        rest[r++] = (unsigned char)olrn;           /* BaseComp attr-block length */
        memcpy(rest + r, olrp, (size_t)olrn); r += olrn;
    }

    return emit_message(e, msg_id(inc), version, gen_time, rest, r);
}

/* Emit one TFP (flow) message into the pending TFP buffer (later wrapped by
 * flush_tfp_frame into a CRC'd SCID=2 component frame). The MMC wrapper is
 * byte-identical to a TEC message; only the components (FlowMatrix vs Event)
 * and the target frame differ. Returns 0 on success, -1 if oversize. */
static int emit_flow_message(tpeg_enc_t *e, unsigned int id, unsigned char version,
                             unsigned int gen_time, const unsigned char *rest, int r) {
    int identlen = varint_len(id) + 6;   /* varint id + ver + expiry(4) + flag */
    int L = identlen + 1;
    int mmc_len = 4 + identlen + r;      /* 00 01 + L + L-1 + ident + rest    */
    if (mmc_len > 0xff) return -1;

    /* Keep each TFP frame's messageCount within one byte (<=250). */
    if (e->fcount >= 250) flush_tfp_frame(e);

    fput1(e, 0x00);                      /* TFP message CompID (0)            */
    fput1(e, (unsigned char)mmc_len);    /* message CompLen                   */
    fput1(e, 0x00);                      /* leading byte of message body      */
    fput1(e, 0x01);                      /* MMC component id                  */
    fput1(e, (unsigned char)L);          /* MMC CompLen                       */
    fput1(e, (unsigned char)identlen);   /* MMC attribute-block length        */
    {
        unsigned char vb[5];
        int vn = varint_to(vb, id);
        fputn(e, vb, (size_t)vn);        /* messageID (varint)                */
    }
    fput1(e, version);                   /* versionID                         */
    fput1(e, (unsigned char)(gen_time >> 24));
    fput1(e, (unsigned char)(gen_time >> 16));
    fput1(e, (unsigned char)(gen_time >> 8));
    fput1(e, (unsigned char)(gen_time));  /* messageExpiryTime (u32 BE)       */
    fput1(e, 0x00);                      /* flag 0x00 = full (not cancelled)  */
    fputn(e, rest, (size_t)r);           /* FlowMatrix + LRC                  */

    if (!e->error) { e->count++; e->fcount++; }
    return e->error ? -1 : 0;
}

/* Real-time flow (TPEG2-TFP, AID 7 / SCID 2). One HERE flow segment becomes one
 * TFP message: a FlowMatrix (comp 06) holding a single FlowVector (comp 07) with
 * one FlowVectorSection, plus a TMC LocationReferencing container (comp 02).
 *
 * Byte layout (all lengths single-byte; validated against the native TomTom
 * stream, see /memories/repo/tpeg-capture.md "TFP GRAMMAR FULLY DECODED"):
 *   06 L6 | 06 startTime(4=0) optSel(00) spatialRes(00=TMCLocations)
 *         | 07 L7 | A7 timeOffset(00) count(01)
 *                 | spatialOffset statusSel(70) LOS avgSpeed ffTT(varint) sectionSel(00)
 *                 | trailer(00)
 *   02 0a 00 02 07 06 loc_hi loc_lo cc ltn flags extent
 *
 * Only TMC-referenced flow is emitted; this head unit cannot resolve OpenLR
 * line locations, so OLR-only flow would never render (and is skipped). */
int tpeg_enc_add_flow(tpeg_enc_t *e, unsigned int gen_time,
                      unsigned char version, const here_flow_t *fl) {
    if (e->error) return -1;
    if (!fl->has_tmc) return -1;

    /* LevelOfService (tfp003) from HERE jamFactor 0..10 (Table 16). */
    double jf = fl->jam_factor;
    unsigned char los;
    if      (jf < 2.0)  los = 0x01;   /* free traffic        */
    else if (jf < 4.0)  los = 0x02;   /* heavy traffic       */
    else if (jf < 6.0)  los = 0x03;   /* slow traffic        */
    else if (jf < 8.0)  los = 0x04;   /* queuing traffic     */
    else if (jf < 10.0) los = 0x05;   /* stationary traffic  */
    else                los = 0x06;   /* no traffic flow     */

    /* averageSpeed (IntUnTi, km/h) from HERE speed (m/s). */
    int spd_kmh = (int)(fl->speed * 3.6 + 0.5);
    if (spd_kmh < 0)   spd_kmh = 0;
    if (spd_kmh > 254) spd_kmh = 254;

    /* freeFlowTravelTime (IntUnLoMB, seconds) = length / free-flow speed. */
    unsigned int ff_tt = 0;
    if (fl->free_flow > 0.1 && fl->length > 0.0) {
        double s = fl->length / fl->free_flow + 0.5;
        if (s < 0.0)     s = 0.0;
        if (s > 65535.0) s = 65535.0;
        ff_tt = (unsigned int)s;
    }

    /* spatialOffset (TMC extents): one section spanning the whole location. */
    int ext = fl->tmc_extent;
    if (ext < 1)  ext = 1;
    if (ext > 30) ext = 30;

    unsigned char ff_vb[5];
    int ff_n = varint_to(ff_vb, ff_tt);

    /* Size the nested components (all fit in one length byte). */
    int sec_n = 1 + 1 + 1 + 1 + ff_n + 1;   /* off+statusSel+LOS+spd+ffTT+sectionSel */
    int a7    = 1 + 1 + sec_n + 1;           /* timeOffset+count+section+trailer      */
    int l7    = 1 + a7;                      /* attrlen byte + attrs                  */
    int a6    = 6;                           /* startTime(4)+optSel+spatialRes        */
    int l6    = 1 + a6 + (2 + l7);           /* attrlen byte + attrs + nested comp07  */

    unsigned char rest[64];
    int r = 0;

    /* comp 06 FlowMatrix */
    rest[r++] = 0x06;
    rest[r++] = (unsigned char)l6;
    rest[r++] = (unsigned char)a6;
    rest[r++] = 0x00; rest[r++] = 0x00; rest[r++] = 0x00; rest[r++] = 0x00; /* startTime = 0 */
    rest[r++] = 0x00;                        /* optSelector: no duration       */
    rest[r++] = 0x00;                        /* spatialResolution 000 = TMCLoc  */
    /* comp 07 FlowVector (nested inside FlowMatrix) */
    rest[r++] = 0x07;
    rest[r++] = (unsigned char)l7;
    rest[r++] = (unsigned char)a7;
    rest[r++] = 0x00;                        /* timeOffset = 0 (current status) */
    rest[r++] = 0x01;                        /* count = 1 section               */
    rest[r++] = (unsigned char)ext;          /* spatialOffset (TMC extents)     */
    rest[r++] = 0x70;                        /* statusSel: LOS+avgSpeed+ffTT     */
    rest[r++] = los;                         /* LevelOfService                  */
    rest[r++] = (unsigned char)spd_kmh;      /* averageSpeed (km/h)             */
    memcpy(rest + r, ff_vb, (size_t)ff_n); r += ff_n;  /* freeFlowTravelTime    */
    rest[r++] = 0x00;                        /* sectionSelector: no optionals   */
    rest[r++] = 0x00;                        /* trailer: no spatialResolutionVec */

    /* comp 02 TMC LocationReferencing (identical to the incident TMC path). */
    {
        unsigned char loc_hi = (unsigned char)((fl->tmc_loc >> 8) & 0xff);
        unsigned char loc_lo = (unsigned char)(fl->tmc_loc & 0xff);
        unsigned char cc     = (unsigned char)(fl->tmc_cc & 0xff);
        unsigned char ltn    = (unsigned char)(fl->tmc_ltn & 0xff);
        unsigned char flags  = (unsigned char)(0x10 | (fl->tmc_dir ? 0x40 : 0));
        rest[r++] = 0x02; rest[r++] = 0x0a; rest[r++] = 0x00; rest[r++] = 0x02;
        rest[r++] = 0x07; rest[r++] = 0x06; rest[r++] = loc_hi; rest[r++] = loc_lo;
        rest[r++] = cc; rest[r++] = ltn; rest[r++] = flags; rest[r++] = (unsigned char)ext;
    }

    /* Stable messageID from the TMC tuple; the "F" prefix keeps flow ids
     * disjoint from incident ids ("T"), so flow and incidents never collide. */
    {
        char key[40];
        snprintf(key, sizeof key, "F%d,%d,%d,%d",
                 fl->tmc_cc, fl->tmc_ltn, fl->tmc_loc, fl->tmc_dir);
        return emit_flow_message(e, hash_str(key), version, gen_time, rest, r);
    }
}

/* TPEG header CRC-16 (TISA "CCITT" variant), per the TPEG2 evaluation-kit
 * (Base/TPEG_CRC.py). Computed over the transport-frame header + first 11 bytes
 * of the service-frame payload only -- NOT the whole frame. The stored value is
 * verified byte-exact against native TomTom captures (15/15 frames). */
static unsigned int tpeg_hdr_crc(const unsigned char *data, int n) {
    unsigned int crc = 0xFFFF;
    int i;
    for (i = 0; i < n; i++) {
        unsigned int tmp = ((crc << 8) | (crc >> 8)) & 0xFFFF;
        crc = (tmp ^ data[i]) & 0xFFFF;
        crc ^= (crc & 0x00FF) >> 4;
        tmp = ((crc & 0x00FF) << 8) | ((crc & 0x00FF) >> 8);
        crc = ((crc ^ (tmp << 4)) ^ ((crc & 0x00FF) << 5)) & 0xFFFF;
    }
    return crc ^ 0xFFFF;
}

/* Wrap a pending message block into one TPEG2 component frame (ProtectedPrio-
 * Counted) and append it to the output, computing both the header CRC and the
 * trailing data CRC over the actual bytes:
 *   SCID | fieldlen(2 BE) | hdrCRC(2 BE) | 00(groupPriority) | msgCount | msgs | dataCRC(2 BE)
 *   hdrCRC  = TPEG_CRC([SCID, flen_hi, flen_lo] + field[:min(13,fieldlen)])
 *   dataCRC = TPEG_CRC(field[:-2])  (i.e. groupPriority + msgCount + msgs)
 * SCID 1 = TEC (incidents), SCID 2 = TFP (flow); both share this framing. */
static void emit_component_frame(tpeg_enc_t *e, unsigned char scid,
                                 const unsigned char *msgs, size_t msglen,
                                 int mcount) {
    size_t P = e->len;                       /* offset of this component frame */
    put1(e, scid);                           /* SCID                           */
    put1(e, 0x00); put1(e, 0x00);            /* fieldlen  (backpatched)        */
    put1(e, 0x00); put1(e, 0x00);            /* hdrCRC    (backpatched)        */
    put1(e, 0x00);                           /* groupPriority                  */
    put1(e, (unsigned char)mcount);          /* messageCount (<=250)           */
    putn(e, msgs, msglen);                    /* the messages                   */
    if (e->error) return;

    /* dataCRC over the field content emitted so far (excludes the 2 CRC bytes) */
    {
        int datalen = (int)(e->len - (P + 5));
        unsigned int dcrc = tpeg_hdr_crc(&e->buf[P + 5], datalen);
        put1(e, (unsigned char)(dcrc >> 8));
        put1(e, (unsigned char)(dcrc & 0xff));
    }
    if (e->error) return;

    /* backpatch fieldlen and hdrCRC now that the whole field is present */
    {
        unsigned int fieldlen = (unsigned int)(e->len - (P + 5));
        unsigned char in[16];
        int m = 0, flen, i;
        e->buf[P + 1] = (unsigned char)(fieldlen >> 8);
        e->buf[P + 2] = (unsigned char)(fieldlen & 0xff);
        in[m++] = e->buf[P];                 /* SCID */
        in[m++] = (unsigned char)(fieldlen >> 8);
        in[m++] = (unsigned char)(fieldlen & 0xff);
        flen = fieldlen < 13 ? (int)fieldlen : 13;
        for (i = 0; i < flen; i++) in[m++] = e->buf[P + 5 + i];
        unsigned int hcrc = tpeg_hdr_crc(in, m);
        e->buf[P + 3] = (unsigned char)(hcrc >> 8);
        e->buf[P + 4] = (unsigned char)(hcrc & 0xff);
    }
}

/* Flush pending TEC (SCID=1) messages as one component frame. No-op if empty. */
static void flush_tec_frame(tpeg_enc_t *e) {
    if (e->error || e->mcount == 0) return;
    emit_component_frame(e, 0x01, e->mbuf, e->mlen, e->mcount);
    e->mlen = 0;
    e->mcount = 0;
}

/* Flush pending TFP (SCID=2) messages as one component frame. No-op if empty. */
static void flush_tfp_frame(tpeg_enc_t *e) {
    if (e->error || e->fcount == 0) return;
    emit_component_frame(e, 0x02, e->fbuf, e->flen, e->fcount);
    e->flen = 0;
    e->fcount = 0;
}

void tpeg_enc_finish(tpeg_enc_t *e) {
    flush_tec_frame(e);                      /* emit any pending TEC messages  */
    flush_tfp_frame(e);                      /* then any pending TFP messages  */
    if (e->error || e->len < 4) return;
    /* len16 (bytes[2:4], BE) = total_bytes - 7  (see tpeg_parse.parse_envelope) */
    unsigned int len16 = (unsigned int)(e->len - 7);
    e->buf[2] = (unsigned char)(len16 >> 8);
    e->buf[3] = (unsigned char)(len16 & 0xff);
    /* Header CRC (bytes[4:6], BE): CRC-16 over sync(2) + len16(2) +
     * ServiceFrameType(buf[6]) + first min(11,len16) service-frame bytes.
     * The two CRC bytes themselves are excluded from the input. */
    {
        unsigned char in[16];
        int m = 0, flen, i;
        in[m++] = 0xff;
        in[m++] = 0x0f;
        in[m++] = (unsigned char)(len16 >> 8);
        in[m++] = (unsigned char)(len16 & 0xff);
        in[m++] = e->buf[6];                 /* ServiceFrameType */
        flen = (int)len16 < 11 ? (int)len16 : 11;
        for (i = 0; i < flen && (7 + i) < (int)e->len; i++)
            in[m++] = e->buf[7 + i];
        unsigned int crc = tpeg_hdr_crc(in, m);
        e->buf[4] = (unsigned char)(crc >> 8);
        e->buf[5] = (unsigned char)(crc & 0xff);
    }
}

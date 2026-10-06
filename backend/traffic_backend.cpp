/*
 * traffic_backend.cpp — native on-device online-traffic backend for Audi MHI2
 * (QNX Neutrino 6.5, ARMv7le / Tegra2). Cross-compiled with ntoarmv7-g++.
 *
 * ROLE
 *   The head unit's online-traffic OSGi bundle is patched (PatchOnlineTraffic)
 *   so that, after Audi mints a valid session (HR->SI remap), every getMessages
 *   request is sent to THIS server instead of tts-audivw.tomtom.com, and the
 *   AES key is nulled. With a null key the wire protocol degrades to:
 *
 *     request  body = gzip( XML )                (no AES, no length prefix)
 *     response body = raw TPEG bytes             (no AES, no gzip)
 *
 *   So this server:
 *     1. accepts the POST on uap0 (10.173.189.1) / loopback,
 *     2. gunzips the request body and logs the getMessages XML (position, tid),
 *     3. replies 200 with a valid (empty) TPEG envelope and the tid+1 header
 *        the bundle expects.
 *
 * MILESTONE 1 (this file): capture + echo.
 *   - Proves cross-compile + deploy + autostart + the redirect patch.
 *   - Captures the REAL request XML the bundle sends (saved under /tmp) so we
 *     can finalise the TomTom->TPEG encoder.
 *   - Keeps the head unit happy (valid empty container => "no traffic").
 *   TomTom fetch (TLS via mbedTLS) + real TPEG encoding are added next.
 *
 * DEPENDENCIES: POSIX sockets (-lsocket), zlib (-lz), libm (-lm). No C++ STL
 * beyond <string>; targets gcc 4.x / gnu++0x on QNX 6.5.
 *
 * Usage: traffic_backend [-b bind_ip] [-p port] [-l logfile]
 *        defaults: -b 0.0.0.0  -p 8099  -l /tmp/traffic_backend.log
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdarg>
#include <string>
#include <ctime>

#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <zlib.h>
#include <cmath>

#include "here_source.h"
#include "here_fetch.h"
#include "tpeg_encode.h"

// ── Empty TPEG envelope (raw, on-disk decrypted form). ────────────────────────
// Captured from the live SI session: a valid TISA TPEG2 container carrying zero
// messages. The native decoder parses this as "no traffic in area".
static const unsigned char EMPTY_TPEG[] = {
    0xff, 0x0f, 0x00, 0x04, 0x1e, 0x82, 0x01, 0x00, 0x00, 0x00, 0x00
};
static const int EMPTY_TPEG_LEN = (int) sizeof(EMPTY_TPEG);

// Last successfully built TPEG stream. On a transient fetch failure (cellular
// handover, tunnel, border crossing) we keep serving this instead of blanking
// the overlay to EMPTY_TPEG, up to LAST_TPEG_MAX_AGE_S old.
static std::string g_last_tpeg;
static time_t      g_last_tpeg_time = 0;
static const int   LAST_TPEG_MAX_AGE_S = 600;   // 10 min
// Number of fetch attempts per poll before giving up (covers brief drops).
static const int   HERE_FETCH_ATTEMPTS = 3;
// If the incidents fetch (incl. retries) already burned this many ms, skip the
// optional flow overlay this poll so a degraded link can't stack a second
// multi-second stall — incidents matter more than flow colouring.
static const long  FLOW_SKIP_AFTER_MS = 30000;

// Update intervals advertised back to the bundle (seconds).
static const int FREQ_LONG_S  = 120;
static const int FREQ_SHORT_S = 30;

// Radius (metres) of the HERE query circle around the head unit's position.
// Native Audi Connect lists ~220 incidents spanning ~60 km around the car.
// 50 km is HERE's maximum allowed circle radius and returns ~180 incidents,
// covering a comparable region.
static const int  HERE_RADIUS_M = 50000;
// Adaptive flow circle. HERE's flow response balloons in dense cities: ~6 MB
// decoded (1.1 MB gzipped) at 50 km over Prague, vs ~2.5 MB at 15 km, and rural
// 50 km is small (few segments). A multi-MB burst every poll over the car's
// tethered link destabilises it, so we shrink the FLOW radius hard where
// incidents are dense and only keep the full 50 km where they're sparse
// (rural/highway, where the payload is small anyway). Incidents always use the
// full HERE_RADIUS_M so the message list stays comparable to native.
static const int  FLOW_RADIUS_URBAN_M = 15000;
static const int  FLOW_RADIUS_MID_M   = 30000;
static const int  FLOW_RADIUS_RURAL_M = 50000;
// Max incidents pulled per request.
static const int  HERE_MAX_INCIDENTS = 256;
// Flow candidate pool the encoder fills the emit budget from, nearest-first.
// Sized to hold the whole urban 15 km circle (~4950 segments) without HERE-order
// truncation, so the nearest-first selection sees every near-car segment before
// picking the emit budget. Only ~9% of Czech (table 25) codes resolve on this
// unit's TMC table, so this is a generous candidate pool, not the emitted count
// (that is TPEG_FLOW_MSG_MAX).
static const int  HERE_MAX_FLOW = 5120;

static FILE* g_log = NULL;
static const char* g_logfile = NULL;   // log path, for size-capped rotation
// /tmp is /dev/shmem (RAM) on this unit, so an unbounded log would consume RAM
// over a long drive. Truncate it once it passes this size.
static const long LOG_MAX_BYTES = 256 * 1024;
// Per-poll request/response dumps to /tmp (also RAM). OFF by default so a long
// drive can't fill shmem; enable for bench debugging via OT_CAPTURE or the flag
// file /tmp/ot_capture (checked once at startup).
static bool g_capture = false;
static std::string g_here_key;   // HERE apiKey (loaded at startup; never logged)

static void logf(const char* fmt, ...) {
    char ts[32];
    time_t now = time(NULL);
    struct tm tmv;
    gmtime_r(&now, &tmv);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tmv);

    // Write to the log file if open, otherwise to stderr (foreground use).
    // Not both: the daemon redirects stderr into the same file, which would
    // otherwise duplicate every line.
    FILE* out = g_log ? g_log : stderr;
    va_list ap;
    va_start(ap, fmt);
    fprintf(out, "[%s] ", ts);
    vfprintf(out, fmt, ap);
    fprintf(out, "\n");
    fflush(out);
    va_end(ap);

    // Keep the RAM-backed log bounded: truncate in place when it grows too big.
    if (g_log && g_logfile && ftell(g_log) > LOG_MAX_BYTES) {
        FILE* nf = freopen(g_logfile, "w", g_log);
        if (nf) g_log = nf;
    }
}

// ── zlib gunzip (auto-detects gzip or zlib headers). ──────────────────────────
static bool gunzip(const unsigned char* in, size_t in_len, std::string& out) {
    if (in_len == 0) { out.clear(); return true; }
    z_stream zs;
    memset(&zs, 0, sizeof(zs));
    // 15 window bits + 32 => auto-detect gzip/zlib header.
    if (inflateInit2(&zs, 15 + 32) != Z_OK) return false;

    zs.next_in  = (Bytef*) in;
    zs.avail_in = (uInt) in_len;

    char buf[8192];
    int rc;
    do {
        zs.next_out  = (Bytef*) buf;
        zs.avail_out = sizeof(buf);
        rc = inflate(&zs, Z_NO_FLUSH);
        if (rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) {
            inflateEnd(&zs);
            return false;
        }
        out.append(buf, sizeof(buf) - zs.avail_out);
        if (rc == Z_BUF_ERROR && zs.avail_in == 0) break;
    } while (rc != Z_STREAM_END);

    inflateEnd(&zs);
    return true;
}

// ── zlib gzip (deflate with gzip header). Used only by the self-test client. ──
static bool gzip(const unsigned char* in, size_t in_len, std::string& out) {
    z_stream zs;
    memset(&zs, 0, sizeof(zs));
    // 15 window bits + 16 => write a gzip header/trailer.
    if (deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8,
                     Z_DEFAULT_STRATEGY) != Z_OK) return false;
    zs.next_in  = (Bytef*) in;
    zs.avail_in = (uInt) in_len;
    char buf[8192];
    int rc;
    do {
        zs.next_out  = (Bytef*) buf;
        zs.avail_out = sizeof(buf);
        rc = deflate(&zs, Z_FINISH);
        if (rc != Z_OK && rc != Z_STREAM_END) { deflateEnd(&zs); return false; }
        out.append(buf, sizeof(buf) - zs.avail_out);
    } while (rc != Z_STREAM_END);
    deflateEnd(&zs);
    return true;
}

// ── Read exactly n bytes (blocking). ──────────────────────────────────────────
static bool read_n(int fd, char* buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = recv(fd, buf + got, n - got, 0);
        if (r <= 0) return false;
        got += (size_t) r;
    }
    return true;
}

static bool write_all(int fd, const char* buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = send(fd, buf + sent, n - sent, 0);
        if (w <= 0) return false;
        sent += (size_t) w;
    }
    return true;
}

// Case-insensitive header lookup. Returns value (trimmed) or "".
static std::string header_value(const std::string& headers, const char* name) {
    std::string lname(name);
    for (size_t i = 0; i < lname.size(); ++i) lname[i] = (char) tolower(lname[i]);

    size_t pos = 0;
    while (pos < headers.size()) {
        size_t eol = headers.find("\r\n", pos);
        if (eol == std::string::npos) eol = headers.size();
        std::string line = headers.substr(pos, eol - pos);
        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string key = line.substr(0, colon);
            for (size_t i = 0; i < key.size(); ++i) key[i] = (char) tolower(key[i]);
            if (key == lname) {
                std::string val = line.substr(colon + 1);
                size_t b = val.find_first_not_of(" \t");
                size_t e = val.find_last_not_of(" \t");
                if (b == std::string::npos) return "";
                return val.substr(b, e - b + 1);
            }
        }
        pos = eol + 2;
    }
    return "";
}

// Extract "tid" from the request target query string (?tid=N or &tid=N).
static int parse_tid(const std::string& target) {
    size_t p = target.find("tid=");
    if (p == std::string::npos) return -1;
    return atoi(target.c_str() + p + 4);
}

// Extract first lat/lon from the getMessages XML (best-effort, for logging).
static void log_position(const std::string& xml) {
    size_t la = xml.find("<lat>");
    size_t lo = xml.find("<lon>");
    if (la != std::string::npos && lo != std::string::npos) {
        std::string lat = xml.substr(la + 5, xml.find("</lat>", la) - (la + 5));
        std::string lon = xml.substr(lo + 5, xml.find("</lon>", lo) - (lo + 5));
        logf("  position: lat=%s lon=%s", lat.c_str(), lon.c_str());
    }
    size_t sid = xml.find("<sessionId>");
    if (sid != std::string::npos) {
        std::string s = xml.substr(sid + 11, xml.find("</sessionId>", sid) - (sid + 11));
        logf("  sessionId: %s", s.c_str());
    }
}

// Parse the first <lat>/<lon> pair from the getMessages XML into doubles.
// Returns true if both were present and look like plausible coordinates.
static bool parse_position(const std::string& xml, double& lat, double& lon) {
    size_t la = xml.find("<lat>");
    size_t lo = xml.find("<lon>");
    if (la == std::string::npos || lo == std::string::npos) return false;
    lat = atof(xml.c_str() + la + 5);
    lon = atof(xml.c_str() + lo + 5);
    if (lat < -90.0 || lat > 90.0 || lon < -180.0 || lon > 180.0) return false;
    if (lat == 0.0 && lon == 0.0) return false;
    return true;
}

// Order incidents nearest-to-car first so the head unit lists the closest
// incidents at the top, like native TomTom (which sorts by distance). qsort
// has no user-data argument, so the reference position is passed via file-scope
// statics (the server is single-threaded, one request at a time).
static double g_inc_ref_lat = 0.0, g_inc_ref_lon = 0.0, g_inc_coslat = 1.0;
static int inc_dist_cmp(const void *pa, const void *pb) {
    const here_incident_t *a = (const here_incident_t *)pa;
    const here_incident_t *b = (const here_incident_t *)pb;
    if (a->has_coord != b->has_coord) return a->has_coord ? -1 : 1;
    if (!a->has_coord) return 0;
    double adx = (a->lon - g_inc_ref_lon) * g_inc_coslat, ady = a->lat - g_inc_ref_lat;
    double bdx = (b->lon - g_inc_ref_lon) * g_inc_coslat, bdy = b->lat - g_inc_ref_lat;
    double da = adx * adx + ady * ady, db = bdx * bdx + bdy * bdy;
    if (da < db) return -1;
    if (da > db) return 1;
    return 0;
}

// Choose the flow query radius from local incident density: the distance to the
// k-th nearest incident is small in a city and large in open country. `incs`
// must already be sorted nearest-first; incidents without a decoded coordinate
// sort last, so a far/absent k-th point safely falls back to the rural radius.
static int pick_flow_radius(const here_incident_t* incs, int n,
                            double lat, double lon) {
    const int K = 150;                       // need this many to call it "urban"
    if (n < K) return FLOW_RADIUS_RURAL_M;
    double coslat = cos(lat * (3.14159265358979323846 / 180.0));
    double dx = (incs[K - 1].lon - lon) * coslat, dy = incs[K - 1].lat - lat;
    double dk_km = sqrt(dx * dx + dy * dy) * 111.32;   // degrees -> km
    if (dk_km <= 30.0) return FLOW_RADIUS_URBAN_M;     // 150 incidents in 30 km
    if (dk_km <= 60.0) return FLOW_RADIUS_MID_M;
    return FLOW_RADIUS_RURAL_M;
}

// Fetch HERE incidents around (lat,lon), encode them into a TPEG stream.
// Returns true and fills `out` on success; false => caller falls back to empty.
static bool build_tpeg_response(double lat, double lon, std::string& out) {

    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    std::string json;
    int status = 0;
    for (int attempt = 0; attempt < HERE_FETCH_ATTEMPTS; ++attempt) {
        status = here_fetch("incidents", lat, lon, HERE_RADIUS_M,
                            g_here_key.c_str(), json);
        if (status == 200 && !json.empty()) break;
        if (attempt + 1 < HERE_FETCH_ATTEMPTS) {
            logf("  HERE incidents fetch attempt %d failed (status=%d); retrying",
                 attempt + 1, status);
            usleep(500000);   // 0.5s backoff before retry
        }
    }
    if (status != 200 || json.empty()) {
        logf("  HERE fetch failed (status=%d, %lu bytes)",
             status, (unsigned long) json.size());
        return false;
    }

    here_incident_t* incs =
        (here_incident_t*) malloc(sizeof(here_incident_t) * HERE_MAX_INCIDENTS);
    if (!incs) return false;

    int count = 0;
    int rc = here_parse_incidents(json.data(), json.size(),
                                  incs, HERE_MAX_INCIDENTS, &count);
    if (rc != 0) {
        logf("  HERE JSON parse error (rc=%d)", rc);
        free(incs);
        return false;
    }

    int n = count < HERE_MAX_INCIDENTS ? count : HERE_MAX_INCIDENTS;

    // Sort incidents nearest-first so the head unit's message list matches
    // native's distance ordering (the list follows the stream order).
    g_inc_ref_lat = lat;
    g_inc_ref_lon = lon;
    g_inc_coslat  = cos(lat * (3.14159265358979323846 / 180.0));
    qsort(incs, (size_t) n, sizeof(here_incident_t), inc_dist_cmp);

    tpeg_enc_t enc;
    if (tpeg_enc_init(&enc)) { free(incs); return false; }
    tpeg_enc_begin(&enc);
    // Stamp messages with real UTC time. The head unit's own clock reads ~1970
    // until it gets a GPS fix, which would make the stream look stale; fall back
    // to the wall-clock time HERE reports in its Date header.
    unsigned int gen = (unsigned int) time(NULL);
    if (gen < 1577836800u) {                 // < 2020-01-01 => local clock unset
        time_t srv = here_last_server_time();
        if (srv > 0) gen = (unsigned int) srv;
    }
    int written = 0;
    for (int i = 0; i < n; ++i) {
        if (tpeg_enc_add_incident(&enc, gen, 1, &incs[i]) == 0) written++;
    }

    // Real-time flow overlay (best-effort; failure just omits flow).
    // Skip it entirely if the incidents fetch already ran long, so a degraded
    // link doesn't stack a second multi-second stall onto this poll.
    int flow_written = 0;
    int flow_radius_km = 0;
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long inc_ms = (t1.tv_sec - t0.tv_sec) * 1000L +
                  (t1.tv_nsec - t0.tv_nsec) / 1000000L;
    if (inc_ms >= FLOW_SKIP_AFTER_MS) {
        logf("  incidents fetch took %ld ms; skipping flow overlay this poll",
             inc_ms);
    } else {
        std::string fjson;
        int flow_radius = pick_flow_radius(incs, n, lat, lon);
        flow_radius_km = flow_radius / 1000;
        int fstatus = here_fetch("flow", lat, lon, flow_radius,
                                 g_here_key.c_str(), fjson);
        if (fstatus == 200 && !fjson.empty()) {
            here_flow_t* flows =
                (here_flow_t*) malloc(sizeof(here_flow_t) * HERE_MAX_FLOW);
            if (flows) {
                int fcount = 0;
                if (here_parse_flow(fjson.data(), fjson.size(),
                                    flows, HERE_MAX_FLOW, &fcount) == 0) {
                    int fn = fcount < HERE_MAX_FLOW ? fcount : HERE_MAX_FLOW;
                    /* Emit HERE segments as native-style TMC chains, nearest to
                     * the car first so the visible map is always covered. */
                    flow_written += tpeg_enc_add_flows(&enc, gen, 1, flows, fn,
                                                       lat, lon);
                }
                free(flows);
            }
        } else if (fstatus != 200) {
            logf("  HERE flow fetch failed (status=%d)", fstatus);
        }
    }

    tpeg_enc_finish(&enc);

    bool ok = !enc.error && enc.len > 0;
    if (ok) out.assign((const char*) enc.buf, enc.len);

    struct timespec t2;
    clock_gettime(CLOCK_MONOTONIC, &t2);
    long total_ms = (t2.tv_sec - t0.tv_sec) * 1000L +
                    (t2.tv_nsec - t0.tv_nsec) / 1000000L;
    logf("  HERE: %d incidents (%d w/OLR) + %d flow (flowR %d km) -> %lu-byte TPEG "
         "(inc %ld ms, total %ld ms)",
         count, written, flow_written, flow_radius_km, (unsigned long) enc.len,
         inc_ms, total_ms);

    tpeg_enc_free(&enc);
    free(incs);
    return ok;
}


// Persist the raw + inflated request for offline analysis / encoder work.
static void save_capture(int tid, const unsigned char* raw, size_t raw_len,
                         const std::string& xml) {
    char path[64];
    snprintf(path, sizeof(path), "/tmp/ot_req_%d.gz", tid);
    FILE* f = fopen(path, "wb");
    if (f) { fwrite(raw, 1, raw_len, f); fclose(f); }
    if (!xml.empty()) {
        snprintf(path, sizeof(path), "/tmp/ot_req_%d.xml", tid);
        f = fopen(path, "wb");
        if (f) { fwrite(xml.data(), 1, xml.size(), f); fclose(f); }
    }
}

// Persist the generated TPEG response so it can be diffed against the native
// service's decrypted stream (/tmp/traffic_data.N).
static void save_response(int tid, const unsigned char* tpeg, size_t len) {
    char path[64];
    snprintf(path, sizeof(path), "/tmp/ot_resp_%d.tpg", tid);
    FILE* f = fopen(path, "wb");
    if (f) { fwrite(tpeg, 1, len, f); fclose(f); }
}

// ── Handle one connection. ────────────────────────────────────────────────────
static void handle_conn(int fd) {
    // Read headers up to the blank line.
    std::string buf;
    char tmp[2048];
    size_t hdr_end = std::string::npos;
    while (hdr_end == std::string::npos) {
        ssize_t r = recv(fd, tmp, sizeof(tmp), 0);
        if (r <= 0) return;
        buf.append(tmp, (size_t) r);
        hdr_end = buf.find("\r\n\r\n");
        if (buf.size() > 65536) return; // header flood guard
    }

    std::string head = buf.substr(0, hdr_end);
    size_t line_end = head.find("\r\n");
    std::string request_line = (line_end == std::string::npos) ? head : head.substr(0, line_end);
    std::string headers = (line_end == std::string::npos) ? "" : head.substr(line_end + 2);

    // Parse request line: METHOD SP target SP HTTP/x
    std::string method, target;
    {
        size_t s1 = request_line.find(' ');
        size_t s2 = (s1 == std::string::npos) ? std::string::npos : request_line.find(' ', s1 + 1);
        if (s1 != std::string::npos) method = request_line.substr(0, s1);
        if (s1 != std::string::npos && s2 != std::string::npos)
            target = request_line.substr(s1 + 1, s2 - s1 - 1);
    }

    int tid = parse_tid(target);
    logf("%s %s (tid=%d)", method.c_str(), target.c_str(), tid);

    // Read body per Content-Length.
    long clen = 0;
    std::string cl = header_value(headers, "Content-Length");
    if (!cl.empty()) clen = atol(cl.c_str());

    std::string body = buf.substr(hdr_end + 4);
    if ((long) body.size() < clen) {
        size_t need = (size_t) clen - body.size();
        std::string rest;
        rest.resize(need);
        if (read_n(fd, &rest[0], need)) body += rest;
    }

    // Inflate + log the request payload (null-key path => plain gzip(XML)).
    std::string req_xml;
    if (!body.empty()) {
        std::string xml;
        bool ok = gunzip((const unsigned char*) body.data(), body.size(), xml);
        if (ok && !xml.empty()) {
            logf("  request XML (%lu bytes gz -> %lu bytes):",
                 (unsigned long) body.size(), (unsigned long) xml.size());
            log_position(xml);
            if (g_capture)
                save_capture(tid, (const unsigned char*) body.data(), body.size(), xml);
            req_xml = xml;
        } else {
            logf("  request body not gzip (%lu bytes) — key may still be set",
                 (unsigned long) body.size());
            if (g_capture)
                save_capture(tid, (const unsigned char*) body.data(), body.size(), std::string());
        }
    }

    // Build the response body. Null-key path => RAW TPEG (no gzip, no AES).
    // If we can read the head unit's position and have a HERE key, fetch live
    // incidents and encode them; otherwise fall back to the empty envelope.
    std::string tpeg;
    // DEBUG replay hook: if /tmp/replay.tpg exists, serve it verbatim. Lets us
    // feed the decoder a known-good native stream to isolate encoder vs. plumbing.
    {
        FILE* rf = fopen("/tmp/replay.tpg", "rb");
        if (rf) {
            fseek(rf, 0, SEEK_END); long rn = ftell(rf); fseek(rf, 0, SEEK_SET);
            if (rn > 0) {
                tpeg.resize((size_t) rn);
                if (fread(&tpeg[0], 1, (size_t) rn, rf) != (size_t) rn) tpeg.clear();
            }
            fclose(rf);
            if (!tpeg.empty()) logf("  REPLAY: serving /tmp/replay.tpg (%ld bytes)", rn);
        }
    }
    double lat, lon;
    if (tpeg.empty() && !req_xml.empty() && parse_position(req_xml, lat, lon)) {
        build_tpeg_response(lat, lon, tpeg);
    }
    // Serve the last good stream on a transient failure so the traffic overlay
    // doesn't blink out during a handover/tunnel/border crossing.
    if (!tpeg.empty()) {
        g_last_tpeg = tpeg;
        g_last_tpeg_time = time(NULL);
    } else if (!g_last_tpeg.empty() &&
               (time(NULL) - g_last_tpeg_time) <= LAST_TPEG_MAX_AGE_S) {
        tpeg = g_last_tpeg;
        logf("  fetch failed; serving cached TPEG (%ld s old, %lu bytes)",
             (long)(time(NULL) - g_last_tpeg_time),
             (unsigned long) tpeg.size());
    }
    const unsigned char* resp_body;
    int resp_body_len;
    if (!tpeg.empty()) {
        resp_body = (const unsigned char*) tpeg.data();
        resp_body_len = (int) tpeg.size();
    } else {
        resp_body = EMPTY_TPEG;
        resp_body_len = EMPTY_TPEG_LEN;
    }

    int resp_tid = (tid >= 0) ? tid + 1 : 1;

    char date[64];
    time_t now = time(NULL);
    struct tm tmv;
    gmtime_r(&now, &tmv);
    strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S GMT", &tmv);

    char hdr[512];
    int hlen = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %d\r\n"
        "tid: %d\r\n"
        "frequency: %d\r\n"
        "frequency-short: %d\r\n"
        "Date: %s\r\n"
        "Connection: close\r\n"
        "\r\n",
        resp_body_len, resp_tid, FREQ_LONG_S, FREQ_SHORT_S, date);

    write_all(fd, hdr, (size_t) hlen);
    write_all(fd, (const char*) resp_body, (size_t) resp_body_len);
    if (g_capture && !tpeg.empty()) save_response(tid, resp_body, (size_t) resp_body_len);
    logf("  -> 200 OK, %d-byte TPEG, tid=%d", resp_body_len, resp_tid);
}

// ── Self-test client: POST a synthetic gzip(getMessages) to host:port. ────────
static bool selftest_client(const char* host, int port) {
    const char* xml =
        "<?xml version='1.0' encoding='UTF-8'?>"
        "<getMessages version=\"1\"><sessionId>SELFTEST</sessionId>"
        "<locations><loc><order>0</order><lat>45.815</lat><lon>15.9819</lon>"
        "<country>HR</country></loc></locations>"
        "<heading>0</heading><roaming>false</roaming></getMessages>";

    std::string body;
    if (!gzip((const unsigned char*) xml, strlen(xml), body)) {
        fprintf(stderr, "SELFTEST: gzip failed\n");
        return false;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { fprintf(stderr, "SELFTEST: socket: %s\n", strerror(errno)); return false; }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short) port);
    addr.sin_addr.s_addr = inet_addr(host);
    if (connect(fd, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        fprintf(stderr, "SELFTEST: connect %s:%d: %s\n", host, port, strerror(errno));
        close(fd);
        return false;
    }

    char hdr[256];
    int hlen = snprintf(hdr, sizeof(hdr),
        "POST /traffic?tid=5 HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %lu\r\n"
        "Connection: close\r\n"
        "\r\n",
        host, port, (unsigned long) body.size());
    if (!write_all(fd, hdr, (size_t) hlen) ||
        !write_all(fd, body.data(), body.size())) {
        fprintf(stderr, "SELFTEST: send failed\n");
        close(fd);
        return false;
    }

    // Read the whole response.
    std::string resp;
    char buf[2048];
    for (;;) {
        ssize_t r = recv(fd, buf, sizeof(buf), 0);
        if (r <= 0) break;
        resp.append(buf, (size_t) r);
    }
    close(fd);

    size_t he = resp.find("\r\n\r\n");
    std::string rhead = (he == std::string::npos) ? resp : resp.substr(0, he);
    std::string rbody = (he == std::string::npos) ? "" : resp.substr(he + 4);

    printf("SELFTEST: sent %lu-byte gzip request (%lu-byte XML) to %s:%d\n",
           (unsigned long) body.size(), (unsigned long) strlen(xml), host, port);
    printf("--- response headers ---\n%s\n", rhead.c_str());
    printf("--- response body (%lu bytes) ---\n", (unsigned long) rbody.size());
    size_t dump_n = rbody.size() < 64 ? rbody.size() : 64;
    for (size_t i = 0; i < dump_n; ++i)
        printf("%02x ", (unsigned char) rbody[i]);
    if (dump_n < rbody.size()) printf("... (+%lu more)",
                                      (unsigned long)(rbody.size() - dump_n));
    printf("\n");

    bool status_ok = (rhead.find("200") != std::string::npos);
    bool tid_ok    = (header_value(rhead.substr(rhead.find("\r\n") + 2), "tid") == "6");
    // A valid response is a TISA TPEG2 container (envelope magic ff 0f ..): either
    // the empty envelope (no traffic) or a populated stream. Both are acceptable.
    bool is_envelope = (rbody.size() >= (size_t) EMPTY_TPEG_LEN) &&
                       ((unsigned char) rbody[0] == 0xff &&
                        (unsigned char) rbody[1] == 0x0f);
    bool is_empty    = (rbody.size() == (size_t) EMPTY_TPEG_LEN) &&
                       (memcmp(rbody.data(), EMPTY_TPEG, EMPTY_TPEG_LEN) == 0);
    bool body_ok     = is_envelope;
    const char* body_kind = is_empty ? "OK(empty-envelope)"
                          : is_envelope ? "OK(populated-stream)" : "FAIL";
    printf("SELFTEST: status=%s tid=%s body=%s => %s\n",
           status_ok ? "OK" : "FAIL", tid_ok ? "OK(6)" : "FAIL",
           body_kind,
           (status_ok && tid_ok && body_ok) ? "PASS" : "FAIL");
    return status_ok && tid_ok && body_ok;
}

// One-shot dump mode (-D lat lon outfile): fetch HERE for a position, encode a
// TPEG stream, write it to a file and exit. Used to generate an "ours" stream on
// the head unit for direct comparison against the native /tmp/traffic_data.N.
static int dump_mode(double lat, double lon, const char* outfile) {
    if (g_here_key.empty()) {
        fprintf(stderr, "DUMP: no HERE key (use -k or $HERE_KEY)\n");
        return 1;
    }
    std::string tpeg;
    if (!build_tpeg_response(lat, lon, tpeg) || tpeg.empty()) {
        fprintf(stderr, "DUMP: build_tpeg_response failed\n");
        return 1;
    }
    FILE* f = fopen(outfile, "wb");
    if (!f) { fprintf(stderr, "DUMP: cannot open %s\n", outfile); return 1; }
    fwrite(tpeg.data(), 1, tpeg.size(), f);
    fclose(f);
    printf("DUMP: wrote %lu-byte TPEG for %.5f,%.5f -> %s\n",
           (unsigned long) tpeg.size(), lat, lon, outfile);
    return 0;
}

// Load the HERE apiKey from (in order): explicit path, $HERE_KEY, or a default
// key file. The value is stored in g_here_key and never logged.
static void load_here_key(const char* path) {
    if (path && *path) {
        FILE* f = fopen(path, "rb");
        if (f) {
            char b[256]; size_t n = fread(b, 1, sizeof(b) - 1, f); fclose(f);
            b[n] = 0;
            while (n && (b[n-1] == '\n' || b[n-1] == '\r' || b[n-1] == ' ')) b[--n] = 0;
            if (n) { g_here_key = b; return; }
        }
    }
    const char* env = getenv("HERE_KEY");
    if (env && *env) { g_here_key = env; return; }
}

int main(int argc, char** argv) {
    const char* bind_ip = "0.0.0.0";
    int port = 8099;
    const char* logfile = "/tmp/traffic_backend.log";
    bool logfile_explicit = false;
    const char* keyfile = "/mnt/app/armle/etc/here.key";
    bool selftest = false;
    bool dump = false;
    double dump_lat = 0, dump_lon = 0;
    const char* dump_out = "/tmp/ot_ours.tpg";

    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "-b") && i + 1 < argc) bind_ip = argv[++i];
        else if (!strcmp(argv[i], "-p") && i + 1 < argc) port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-l") && i + 1 < argc) { logfile = argv[++i]; logfile_explicit = true; }
        else if (!strcmp(argv[i], "-k") && i + 1 < argc) keyfile = argv[++i];
        else if (!strcmp(argv[i], "-T")) selftest = true;
        else if (!strcmp(argv[i], "-D") && i + 3 < argc) {
            dump = true;
            dump_lat = atof(argv[++i]);
            dump_lon = atof(argv[++i]);
            dump_out = argv[++i];
        }
    }

    load_here_key(keyfile);

    signal(SIGPIPE, SIG_IGN);

    if (dump) return dump_mode(dump_lat, dump_lon, dump_out);

    // ── Self-test client mode (-T): exercise a running server over loopback. ──
    // Builds a synthetic gzip(getMessages XML) request identical in shape to the
    // one the online bundle sends, POSTs it, and validates the response. Runs on
    // the device itself, so it works even when the port is firewalled externally.
    if (selftest) {
        const char* host = strcmp(bind_ip, "0.0.0.0") ? bind_ip : "127.0.0.1";
        return selftest_client(host, port) ? 0 : 1;
    }

    // File logging goes to /tmp (RAM-backed shmem), so it's opt-in to avoid
    // filling RAM on a long drive. Enabled by an explicit -l, OT_LOG, or the
    // flag file /tmp/ot_log. Otherwise logf() falls through to stderr (which the
    // daemon sends to /dev/null), so nothing is written to /tmp.
    if (logfile_explicit || getenv("OT_LOG") || access("/tmp/ot_log", F_OK) == 0) {
        g_log = fopen(logfile, "a");
        g_logfile = logfile;
    }
    // Per-poll /tmp dumps are opt-in (bench only) so they can't fill shmem on a
    // long drive. Enable with OT_CAPTURE=1 or by creating /tmp/ot_capture.
    if (getenv("OT_CAPTURE") || access("/tmp/ot_capture", F_OK) == 0)
        g_capture = true;

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { logf("socket() failed: %s", strerror(errno)); return 1; }

    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short) port);
    addr.sin_addr.s_addr = inet_addr(bind_ip);
    if (addr.sin_addr.s_addr == INADDR_NONE) addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(srv, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        logf("bind(%s:%d) failed: %s", bind_ip, port, strerror(errno));
        return 1;
    }
    if (listen(srv, 8) < 0) {
        logf("listen() failed: %s", strerror(errno));
        return 1;
    }

    logf("traffic_backend listening on %s:%d (HERE key: %s)", bind_ip, port,
         g_here_key.empty() ? "MISSING — empty-TPEG only" : "loaded");

    for (;;) {
        struct sockaddr_in cli;
        socklen_t clen = sizeof(cli);
        int fd = accept(srv, (struct sockaddr*) &cli, &clen);
        if (fd < 0) {
            if (errno == EINTR) continue;
            logf("accept() failed: %s", strerror(errno));
            continue;
        }
        logf("--- connection from %s ---", inet_ntoa(cli.sin_addr));
        handle_conn(fd);
        close(fd);
    }
    return 0;
}

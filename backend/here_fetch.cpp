// here_fetch.cpp — HTTPS GET against HERE Traffic API v7 over the vendored
// mbedTLS TlsStream. Sends "Connection: close", reads the whole response,
// splits headers/body, and de-chunks if Transfer-Encoding: chunked.
#include "here_fetch.h"
#include "tls_stream.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cctype>
#include <time.h>

#include <zlib.h>

static const char* HERE_HOST = "data.traffic.hereapi.com";
static const int   HERE_PORT = 443;

// Last real UTC wall-clock time learned from a HERE "Date:" response header.
// 0 until the first successful fetch. Used to stamp genTimes when the head
// unit's own clock is unset (reads ~1970 before a GPS fix).
static time_t g_here_server_time = 0;

time_t here_last_server_time(void) { return g_here_server_time; }

// Days since 1970-01-01 for a proleptic-Gregorian y/m/d (Howard Hinnant's
// algorithm). Avoids timegm(), which is unreliable/absent on this QNX.
static long days_from_civil(int y, int m, int d) {
    y -= m <= 2;
    long era = (y >= 0 ? y : y - 399) / 400;
    unsigned yoe = (unsigned)(y - era * 400);
    unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097L + (long)doe - 719468L;
}

// Parse an RFC 1123 HTTP date ("Sat, 18 Jul 2026 17:52:00 GMT") to a Unix
// epoch (UTC). Returns 0 on failure.
static time_t parse_http_date(const std::string& s) {
    static const char* mon[12] = {"Jan","Feb","Mar","Apr","May","Jun",
                                  "Jul","Aug","Sep","Oct","Nov","Dec"};
    int day = 0, year = 0, hh = 0, mm = 0, ss = 0;
    char mname[4] = {0};
    // Skip the leading weekday token ("Sat, ").
    size_t c = s.find(',');
    const char* p = (c == std::string::npos) ? s.c_str() : s.c_str() + c + 1;
    if (sscanf(p, " %d %3s %d %d:%d:%d", &day, mname, &year, &hh, &mm, &ss) != 6)
        return 0;
    int month = -1;
    for (int i = 0; i < 12; ++i) if (!strncmp(mname, mon[i], 3)) { month = i + 1; break; }
    if (month < 1 || day < 1 || year < 1970) return 0;
    long days = days_from_civil(year, month, day);
    return (time_t)(days * 86400L + hh * 3600L + mm * 60L + ss);
}

// Inflate a gzip (or zlib) stream via zlib. Returns true on success. HERE's
// flow payload is ~2.7 MB of JSON that compresses ~5x, so gzip cuts the on-wire
// transfer from >100 s to ~10 s on the head unit's slow cellular link.
static bool gunzip_buf(const std::string& in, std::string& out) {
    out.clear();
    if (in.empty()) return false;
    // gzip streams carry the uncompressed size (mod 2^32) in the last 4 bytes
    // (ISIZE, little-endian). Reserve it up front so appending the inflated MBs
    // doesn't trigger a chain of geometric string reallocations + copies.
    if (in.size() > 18 &&
        (unsigned char)in[0] == 0x1f && (unsigned char)in[1] == 0x8b) {
        size_t n = in.size();
        unsigned int isize = (unsigned int)(unsigned char)in[n - 4]
                           | ((unsigned int)(unsigned char)in[n - 3] << 8)
                           | ((unsigned int)(unsigned char)in[n - 2] << 16)
                           | ((unsigned int)(unsigned char)in[n - 1] << 24);
        if (isize > 0 && isize <= (32u << 20)) out.reserve(isize);
    }
    z_stream zs;
    memset(&zs, 0, sizeof(zs));
    // 15 + 32 => auto-detect gzip or zlib header.
    if (inflateInit2(&zs, 15 + 32) != Z_OK) return false;
    zs.next_in = (Bytef*) in.data();
    zs.avail_in = (uInt) in.size();
    char buf[16384];
    int ret;
    do {
        zs.next_out = (Bytef*) buf;
        zs.avail_out = sizeof(buf);
        ret = inflate(&zs, Z_NO_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END && ret != Z_BUF_ERROR) {
            inflateEnd(&zs);
            return false;
        }
        out.append(buf, sizeof(buf) - zs.avail_out);
        if (out.size() > (32u << 20)) { inflateEnd(&zs); return false; }  // 32 MiB guard
    } while (ret != Z_STREAM_END && zs.avail_in > 0);
    inflateEnd(&zs);
    return ret == Z_STREAM_END;
}

// Case-insensitive search for a header value in a header block. Returns "" if
// absent. `block` is the text before the blank line (no request line stripping
// needed here — status line has no colon-space header we match).
static std::string find_header(const std::string& block, const char* name) {
    std::string lname(name);
    for (size_t i = 0; i < lname.size(); ++i) lname[i] = (char)tolower(lname[i]);
    size_t pos = 0;
    while (pos < block.size()) {
        size_t eol = block.find("\r\n", pos);
        if (eol == std::string::npos) eol = block.size();
        std::string line = block.substr(pos, eol - pos);
        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string key = line.substr(0, colon);
            for (size_t i = 0; i < key.size(); ++i) key[i] = (char)tolower(key[i]);
            if (key == lname) {
                std::string val = line.substr(colon + 1);
                size_t b = val.find_first_not_of(" \t");
                size_t e = val.find_last_not_of(" \t");
                if (b == std::string::npos) return "";
                return val.substr(b, e - b + 1);
            }
        }
        if (eol == block.size()) break;
        pos = eol + 2;
    }
    return "";
}

// De-chunk an HTTP/1.1 chunked body.
static std::string dechunk(const std::string& in) {
    std::string out;
    size_t p = 0;
    while (p < in.size()) {
        size_t eol = in.find("\r\n", p);
        if (eol == std::string::npos) break;
        // chunk size is hex, up to an optional ';' extension.
        std::string sizeline = in.substr(p, eol - p);
        size_t semi = sizeline.find(';');
        if (semi != std::string::npos) sizeline = sizeline.substr(0, semi);
        long n = strtol(sizeline.c_str(), NULL, 16);
        if (n <= 0) break;                 // 0 chunk => end
        size_t start = eol + 2;
        if (start + (size_t)n > in.size()) { out.append(in, start, in.size() - start); break; }
        out.append(in, start, (size_t)n);
        p = start + (size_t)n + 2;         // skip data + trailing CRLF
    }
    return out;
}

int here_fetch(const char* endpoint, double lat, double lon, int radius_m,
               const char* api_key, std::string& out) {
    out.clear();

    char path[512];
    snprintf(path, sizeof(path),
        "/v7/%s?in=circle:%.5f,%.5f;r=%d&locationReferencing=tmc,olr&apiKey=%s",
        endpoint, lat, lon, radius_m, api_key);

    TlsStream* s = tls_stream_create();
    if (!s) return 0;
    if (!s->connect(HERE_HOST, HERE_PORT, true)) { s->close(); delete s; return 0; }

    char req[768];
    int rn = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: mhi2-traffic/1.0\r\n"
        "Accept: application/json\r\n"
        "Accept-Encoding: gzip\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, HERE_HOST);
    if (!s->write_all(req, (size_t)rn)) { s->close(); delete s; return 0; }

    std::string resp;
    resp.reserve(256 * 1024);              // typical gzipped HERE payload size
    char buf[16384];
    for (;;) {
        int r = s->read(buf, sizeof(buf));
        if (r <= 0) break;
        resp.append(buf, (size_t)r);
        if (resp.size() > (8u << 20)) break;   // 8 MiB guard
    }
    s->close();
    delete s;

    if (resp.empty()) return 0;

    // Status code from "HTTP/1.1 NNN ..."
    int status = 0;
    {
        size_t sp = resp.find(' ');
        if (sp != std::string::npos) status = atoi(resp.c_str() + sp + 1);
    }

    size_t he = resp.find("\r\n\r\n");
    if (he == std::string::npos) return status;
    std::string headers = resp.substr(0, he);
    std::string body = resp.substr(he + 4);

    // HERE's response carries a real UTC Date header. Capture it as an
    // authoritative wall-clock source: the head unit's own clock reads 1970
    // until it gets a GPS fix, so we use this to stamp fresh genTimes.
    {
        std::string d = find_header(headers, "Date");
        time_t t = parse_http_date(d);
        if (t > 0) g_here_server_time = t;
    }

    std::string te = find_header(headers, "Transfer-Encoding");
    for (size_t i = 0; i < te.size(); ++i) te[i] = (char)tolower(te[i]);
    if (te.find("chunked") != std::string::npos) {
        out = dechunk(body);
    } else {
        std::string cl = find_header(headers, "Content-Length");
        if (!cl.empty()) {
            long n = atol(cl.c_str());
            if (n >= 0 && (size_t)n <= body.size()) body.resize((size_t)n);
        }
        out = body;
    }

    // Content-Encoding is applied to the payload before transfer chunking, so
    // inflate after de-chunking. On failure keep the raw bytes (caller's JSON
    // parse will then fail cleanly rather than crashing).
    std::string ce = find_header(headers, "Content-Encoding");
    for (size_t i = 0; i < ce.size(); ++i) ce[i] = (char)tolower(ce[i]);
    if (ce.find("gzip") != std::string::npos || ce.find("deflate") != std::string::npos) {
        std::string inflated;
        if (gunzip_buf(out, inflated)) out.swap(inflated);
    }
    return status;
}

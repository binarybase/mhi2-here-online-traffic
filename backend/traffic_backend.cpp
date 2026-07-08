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

// ── Empty TPEG envelope (raw, on-disk decrypted form). ────────────────────────
// Captured from the live SI session: a valid TISA TPEG2 container carrying zero
// messages. The native decoder parses this as "no traffic in area".
static const unsigned char EMPTY_TPEG[] = {
    0xff, 0x0f, 0x00, 0x04, 0x1e, 0x82, 0x01, 0x00, 0x00, 0x00, 0x00
};
static const int EMPTY_TPEG_LEN = (int) sizeof(EMPTY_TPEG);

// Update intervals advertised back to the bundle (seconds).
static const int FREQ_LONG_S  = 120;
static const int FREQ_SHORT_S = 30;

static FILE* g_log = NULL;

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
    if (!body.empty()) {
        std::string xml;
        bool ok = gunzip((const unsigned char*) body.data(), body.size(), xml);
        if (ok && !xml.empty()) {
            logf("  request XML (%lu bytes gz -> %lu bytes):",
                 (unsigned long) body.size(), (unsigned long) xml.size());
            log_position(xml);
            save_capture(tid, (const unsigned char*) body.data(), body.size(), xml);
        } else {
            logf("  request body not gzip (%lu bytes) — key may still be set",
                 (unsigned long) body.size());
            save_capture(tid, (const unsigned char*) body.data(), body.size(), std::string());
        }
    }

    // Build response. Null-key path => body is RAW TPEG (no gzip, no AES).
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
        EMPTY_TPEG_LEN, resp_tid, FREQ_LONG_S, FREQ_SHORT_S, date);

    write_all(fd, hdr, (size_t) hlen);
    write_all(fd, (const char*) EMPTY_TPEG, (size_t) EMPTY_TPEG_LEN);
    logf("  -> 200 OK, %d-byte empty TPEG, tid=%d", EMPTY_TPEG_LEN, resp_tid);
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
    for (size_t i = 0; i < rbody.size(); ++i)
        printf("%02x ", (unsigned char) rbody[i]);
    printf("\n");

    bool status_ok = (rhead.find("200") != std::string::npos);
    bool tid_ok    = (header_value(rhead.substr(rhead.find("\r\n") + 2), "tid") == "6");
    bool body_ok   = (rbody.size() == (size_t) EMPTY_TPEG_LEN) &&
                     (memcmp(rbody.data(), EMPTY_TPEG, EMPTY_TPEG_LEN) == 0);
    printf("SELFTEST: status=%s tid=%s body=%s => %s\n",
           status_ok ? "OK" : "FAIL", tid_ok ? "OK(6)" : "FAIL",
           body_ok ? "OK(empty-envelope)" : "FAIL",
           (status_ok && tid_ok && body_ok) ? "PASS" : "FAIL");
    return status_ok && tid_ok && body_ok;
}

int main(int argc, char** argv) {
    const char* bind_ip = "0.0.0.0";
    int port = 8099;
    const char* logfile = "/tmp/traffic_backend.log";
    bool selftest = false;

    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "-b") && i + 1 < argc) bind_ip = argv[++i];
        else if (!strcmp(argv[i], "-p") && i + 1 < argc) port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-l") && i + 1 < argc) logfile = argv[++i];
        else if (!strcmp(argv[i], "-T")) selftest = true;
    }

    signal(SIGPIPE, SIG_IGN);

    // ── Self-test client mode (-T): exercise a running server over loopback. ──
    // Builds a synthetic gzip(getMessages XML) request identical in shape to the
    // one the online bundle sends, POSTs it, and validates the response. Runs on
    // the device itself, so it works even when the port is firewalled externally.
    if (selftest) {
        const char* host = strcmp(bind_ip, "0.0.0.0") ? bind_ip : "127.0.0.1";
        return selftest_client(host, port) ? 0 : 1;
    }

    g_log = fopen(logfile, "a");

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

    logf("traffic_backend listening on %s:%d (empty-TPEG echo + capture)", bind_ip, port);

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

// tls_mbedtls.cpp — mbedTLS implementation of TlsStream. Vendored from
// mmi-webradio (common/src/tls_mbedtls.cpp). Links against the same mbedTLS
// static lib already built on the QNX VM (/tmp/libmbedcrypto.a, headers under
// /tmp/mbedtls/). Certificate verification is disabled (VERIFY_NONE) — the head
// unit has no CA bundle and the endpoint is a fixed HERE host.
#include "tls_stream.h"

#include <cstring>
#include <cstdio>

#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

// Bounded timeouts so a cellular handover (e.g. crossing a border) can never
// hang the single-threaded server. TCP connect gets its own budget; the TLS
// handshake and every subsequent read/write inherit the socket SO_*TIMEO.
static const int TLS_CONNECT_TIMEOUT_MS = 8000;
static const int TLS_IO_TIMEOUT_MS      = 10000;

// Connect with a bounded timeout using a temporarily non-blocking socket.
// Returns true on success; leaves the socket in blocking mode on return.
static bool connect_timeout(int fd, const struct sockaddr* addr,
                            socklen_t addrlen, int timeout_ms) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return false;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return false;

    int rc = ::connect(fd, addr, addrlen);
    if (rc == 0) {
        fcntl(fd, F_SETFL, flags);         // connected immediately
        return true;
    }
    if (errno != EINPROGRESS) {
        fcntl(fd, F_SETFL, flags);
        return false;
    }

    fd_set wset;
    FD_ZERO(&wset);
    FD_SET(fd, &wset);
    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int sel = select(fd + 1, NULL, &wset, NULL, &tv);
    if (sel <= 0) { fcntl(fd, F_SETFL, flags); return false; }  // timeout/error

    int soerr = 0;
    socklen_t slen = sizeof(soerr);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) < 0 || soerr != 0) {
        fcntl(fd, F_SETFL, flags);
        return false;
    }
    fcntl(fd, F_SETFL, flags);             // restore blocking
    return true;
}

class MbedTlsStream : public TlsStream {
public:
    MbedTlsStream() : fd_(-1), tls_init_(false) {}
    ~MbedTlsStream() { close(); }

    bool connect(const char* host, int port, bool use_tls) {
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        char port_str[8];
        snprintf(port_str, sizeof(port_str), "%d", port);
        if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) return false;

        fd_ = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (fd_ < 0) { freeaddrinfo(res); return false; }

        if (!connect_timeout(fd_, res->ai_addr, res->ai_addrlen,
                             TLS_CONNECT_TIMEOUT_MS)) {
            freeaddrinfo(res);
            ::close(fd_); fd_ = -1;
            return false;
        }
        freeaddrinfo(res);

        // Bound every subsequent recv/send (TLS handshake and body reads) so a
        // silent peer after a handover can't wedge the server. A timed-out
        // recv surfaces as MBEDTLS_ERR_SSL_WANT_READ and aborts the request.
        struct timeval iotv;
        iotv.tv_sec  = TLS_IO_TIMEOUT_MS / 1000;
        iotv.tv_usec = (TLS_IO_TIMEOUT_MS % 1000) * 1000;
        setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &iotv, sizeof(iotv));
        setsockopt(fd_, SOL_SOCKET, SO_SNDTIMEO, &iotv, sizeof(iotv));

        if (use_tls) {
            tls_init_ = true;
            mbedtls_ssl_init(&ssl_);
            mbedtls_ssl_config_init(&conf_);
            mbedtls_entropy_init(&entropy_);
            mbedtls_ctr_drbg_init(&ctr_drbg_);
            mbedtls_net_init(&net_ctx_);

            mbedtls_ctr_drbg_seed(&ctr_drbg_, mbedtls_entropy_func, &entropy_, NULL, 0);
            mbedtls_ssl_config_defaults(&conf_, MBEDTLS_SSL_IS_CLIENT,
                MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
            mbedtls_ssl_conf_authmode(&conf_, MBEDTLS_SSL_VERIFY_NONE);
            mbedtls_ssl_conf_rng(&conf_, mbedtls_ctr_drbg_random, &ctr_drbg_);
            mbedtls_ssl_setup(&ssl_, &conf_);
            mbedtls_ssl_set_hostname(&ssl_, host);

            net_ctx_.fd = fd_;
            mbedtls_ssl_set_bio(&ssl_, &net_ctx_, mbedtls_net_send, mbedtls_net_recv, NULL);

            int ret = mbedtls_ssl_handshake(&ssl_);
            if (ret != 0) {
                close();
                return false;
            }
        }
        return true;
    }

    bool write_all(const void* data, size_t len) {
        const uint8_t* p = (const uint8_t*)data;
        size_t done = 0;
        while (done < len) {
            int n;
            if (tls_init_)
                n = mbedtls_ssl_write(&ssl_, p + done, len - done);
            else
                n = send(fd_, (const char*)(p + done), len - done, 0);
            if (n <= 0) return false;
            done += n;
        }
        return true;
    }

    int read(void* buf, size_t len) {
        if (tls_init_)
            return mbedtls_ssl_read(&ssl_, (uint8_t*)buf, len);
        return recv(fd_, buf, len, 0);
    }

    int socket_fd() const { return fd_; }

    void close() {
        if (tls_init_) {
            mbedtls_ssl_close_notify(&ssl_);
            mbedtls_ssl_free(&ssl_);
            mbedtls_ssl_config_free(&conf_);
            mbedtls_entropy_free(&entropy_);
            mbedtls_ctr_drbg_free(&ctr_drbg_);
            mbedtls_net_free(&net_ctx_);
            tls_init_ = false;
        }
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

private:
    int fd_;
    bool tls_init_;
    mbedtls_ssl_context ssl_;
    mbedtls_ssl_config conf_;
    mbedtls_entropy_context entropy_;
    mbedtls_ctr_drbg_context ctr_drbg_;
    mbedtls_net_context net_ctx_;
};

TlsStream* tls_stream_create() {
    return new MbedTlsStream();
}

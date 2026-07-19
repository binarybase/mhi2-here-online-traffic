// tls_stream.h — abstract TLS/plain TCP stream. Vendored from mmi-webradio
// (common/include/common/tls_stream.h) so the traffic backend reuses the same
// mbedTLS wrapper already built for the QNX head unit.
#pragma once

#include <cstdint>
#include <cstddef>

class TlsStream {
public:
    virtual ~TlsStream() {}

    // Connect to host:port. If use_tls, perform TLS handshake.
    virtual bool connect(const char* host, int port, bool use_tls) = 0;

    // Send all bytes (blocking).
    virtual bool write_all(const void* data, size_t len) = 0;

    // Read up to len bytes. Returns bytes read, 0 on EOF, <0 on error.
    virtual int read(void* buf, size_t len) = 0;

    // Get the underlying socket fd (for poll).
    virtual int socket_fd() const = 0;

    // Close connection and free resources.
    virtual void close() = 0;
};

// Factory — implemented in tls_mbedtls.cpp.
TlsStream* tls_stream_create();

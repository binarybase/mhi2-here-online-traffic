// here_fetch.h — minimal HTTPS GET against the HERE Traffic API v7, using the
// vendored mbedTLS TlsStream. Returns the raw JSON body for a circle query.
#pragma once

#include <string>
#include <ctime>

// Fetch HERE /v7/<endpoint> (endpoint = "incidents" or "flow") for a circle of
// radius_m metres around lat/lon, with locationReferencing=olr.
//   api_key : HERE apiKey (never logged).
//   out     : response body (JSON) on success.
// Returns the HTTP status code (200 on success), or 0 on connection/TLS failure.
int here_fetch(const char* endpoint, double lat, double lon, int radius_m,
               const char* api_key, std::string& out);

// Real UTC wall-clock (Unix epoch) learned from the most recent HERE response's
// Date header, or 0 if no successful fetch yet. Lets the backend stamp fresh
// genTimes even when the head unit's own clock is unset (~1970 before GPS fix).
time_t here_last_server_time(void);

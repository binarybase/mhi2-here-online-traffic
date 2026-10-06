# mhi2-here-online-traffic

Restore live online traffic on an **Audi MHI2 (CLU7, QNX 6.5 / ARMv7)** head unit
in regions the factory backend refuses to serve (e.g. Croatia), using
**[HERE Traffic API v7](https://docs.here.com/traffic-api)** as the data source
— **fully independent of Audi Connect**.

The factory `createTrafficSession` call returns HTTP 502 whenever the session
country is `HR`, and more generally it depends on Audi's service-discovery
(`serviceList`) backend, which is unreachable without an active Audi Connect
data subscription. This project works around both by:

1. **Patching the online-traffic OSGi bundle** so the session is **minted
   locally** (no Audi `serviceList` round-trip) and the traffic data feed is
   redirected to a small server we control, with AES disabled so the wire
   protocol is plain `gzip(XML)` request / raw TPEG response.
2. **Running a native on-device backend** (QNX C++) that fetches real traffic
   from HERE (flow + incidents) over TLS and re-encodes it into the TPEG2
   stream the head unit's decoder (`libTpegBusinessLogic`) already understands.

> **Status (2026-10-06):** deployed and **road-tested working** on the car — the
> head unit mints its traffic session locally and renders live HERE traffic with
> Audi Connect's `serviceList` unreachable. The native backend fetches HERE over
> mbedTLS and emits a valid TPEG2 stream on-device. See
> [Project status](#project-status).

---

## ⚠️ Legal / safety

- This is an independent research project. It is **not** affiliated with or
  endorsed by Audi, Volkswagen Group, HERE, or TomTom.
- **No proprietary firmware is included.** You must extract the Audi bundle jars
  (`service.onlinetraffic_*.jar`, `service.lib.util_*.jar`) from *your own*
  device. They are gitignored here.
- **No API keys are included.** Provide your own HERE key (see below).
- Modifying your head unit can break navigation and is entirely at your own
  risk. Test on the bench, keep backups, and comply with HERE's API terms and
  your local regulations.

---

## Repository layout

| Path | Purpose |
|------|---------|
| `PatchOnlineTraffic.java` | javassist bytecode patcher for the online-traffic bundle (offline session mint + HR→SI remap, data-URL redirect + null AES key, optional capture mode). |
| `build.sh` | Builds/verifies (class version 46) and optionally deploys the patched bundle jar. |
| `backend/traffic_backend.cpp` | Native QNX HTTP server: receives the head unit's `getMessages`, fetches HERE, returns TPEG2. |
| `backend/here_fetch.{cpp,h}` | HTTPS GET to HERE v7 (flow/incidents) via mbedTLS; learns wall-clock from the `Date` header. |
| `backend/here_source.{c,h}` | HERE Traffic API v7 flow + incidents JSON parser (OpenLR + TMC refs, jam factor, subsegments). |
| `backend/tpeg_encode.{c,h}` | HERE structs → decrypted TPEG2 stream (Transport/SNI/TEC/TFP frames, CRCs). |
| `backend/tls_mbedtls.cpp`, `tls_stream.h` | Minimal TLS stream wrapper over mbedTLS. |
| `backend/jsmn.h` | Minimal MIT-licensed JSON tokenizer (vendored). |
| `backend/here_test.c`, `tpeg_encode_test.c` | Host unit tests (parser; encoder round-trip). |
| `backend/here_probe.sh` | Validates a HERE key and captures a real flow/incidents sample (key redacted). |
| `backend/build.sh` | Cross-compile (Docker GCC 8.5 **or** legacy QNX VM), deploy, autostart, and host-test helpers. |
| `backend/build_qnx_docker.sh` | Container-side cross-build run inside the GCC 8.5 QNX toolchain image. |
| `backend/tools/` | Python analysis helpers (`tpeg_parse.py` reference parser, TMC/OLR scanners). |

---

## Prerequisites

- **HERE API key** — free tier at <https://platform.here.com>
  (Access Manager → Apps → create API key). Save it *without* committing:
  ```bash
  umask 077 && printf '%s' 'YOUR_HERE_KEY' > here.key
  ```
- **Audi firmware jars** from your device, placed in `./firmware/`:
  - `service.onlinetraffic_1.0.0.*.jar`
  - `service.lib.util_2.7.4.*.jar` (needed only for capture mode)
- **JDK** (8–21) + [javassist](https://www.javassist.org/) for the patcher.
- **Native backend cross-toolchain**, either:
  - **Docker GCC 8.5 QNX toolchain** (`qnx65-armv7-toolchain:8.5`) — preferred,
    no VM; or
  - **QNX SDP 6.5** (`ntoarmv7-g++`) in a QEMU VM — legacy fallback.
- SSH access to the head unit (default alias `mhi2w` → `10.173.189.1`).

---

## Quick start

### 1. Validate your HERE key
```bash
./backend/here_probe.sh                 # Zagreb; or: ./backend/here_probe.sh <lat> <lon> <radius_m>
```

### 2. Test the HERE parser on the host
```bash
cd backend && ./build.sh here-test
```

### 3. Build the patched bundle
```bash
# Remap HR→SI and redirect the feed to the on-device backend (default):
./build.sh

# Remap only, no redirect:
REDIRECT_URL=none ./build.sh

# Capture mode — force requests to a busy point to grab a real TPEG sample:
REDIRECT_URL=none CAPTURE_LATLON=46.0569,14.5058 ./build.sh
```
Deploy (backs up the original on the device, then prompts to reboot):
```bash
DEPLOY=1 ./build.sh
```

### 4. Build / deploy the native backend
```bash
cd backend
./build.sh compile-docker    # cross-compile ARM ELF via GCC 8.5 Docker toolchain (preferred)
./build.sh all-docker        # compile-docker + deploy to car
./build.sh compile           # legacy: cross-compile on the QNX VM
./build.sh deploy            # scp binary + here.key to the car
./build.sh start             # run it
./build.sh log               # tail the log
./build.sh autostart-install # start on boot (idempotent, backed up)
```

The redirect/bypass is gated by a flag file on the car
(`/mnt/persist/traffic_backend_here`): **present** → local session mint + our
backend + null AES key; **absent** → stock Audi/TomTom behaviour. Toggling the
backend URL/key needs no reboot; applying a newly deployed **bundle** does (OSGi
loads bundles at boot).

---

## Architecture

```
Head unit (JVM online-traffic bundle)
   │  getMessages (gzip XML, plain HTTP, AES key nulled by patch)
   ▼
traffic_backend (native QNX, uap0:8099)
   │  HTTPS GET /v7/flow + /v7/incidents (locationReferencing=olr)
   ▼
HERE Traffic API  ──►  flow segments + incidents (OpenLR)
   ▲
   └── re-encoded as TPEG2 ──► back to head unit ──► libTpegBusinessLogic ──► map overlay
```

HERE returns **OpenLR** location references (the same TISA scheme the decoder
uses) alongside **TMC** references. Note: this specific head unit resolves **TMC**
location codes natively but **cannot decode OpenLR**, so only TMC-referenced
flow/incidents actually render — a constraint that shapes the encoder design.

---

## Project status

- [x] Root-cause the `HR` 502 and the session/data protocol
- [x] Bundle patcher: HR→SI remap, data-URL redirect + null AES key, capture mode
- [x] **Offline session mint** — independence from Audi Connect `serviceList`
- [x] Native backend (POSIX sockets + zlib), self-test on device
- [x] HERE flow + incidents parser (host-tested, cross-compiled for QNX ARM)
- [x] TLS fetch to HERE from the backend (mbedTLS)
- [x] TPEG2 encoder (HERE flow/incidents → TPEG2 messages, CRC-validated)
- [x] GCC 8.5 Docker cross-toolchain (self-contained ELF, no VM)
- [x] **End-to-end: head unit renders live HERE traffic, deployed & road-tested**

---

## Credits

- [jsmn](https://github.com/zserge/jsmn) — MIT-licensed JSON tokenizer.

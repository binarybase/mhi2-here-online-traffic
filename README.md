# mhi2-here-online-traffic

Restore live online traffic on an **Audi MHI2 (CLU7, QNX 6.5 / ARMv7)** head unit
in regions the factory backend refuses to serve (e.g. Croatia), using
**[HERE Traffic API v7](https://docs.here.com/traffic-api)** as the data source.

The factory `createTrafficSession` call returns HTTP 502 whenever the session
country is `HR`. This project works around that by:

1. **Patching the online-traffic OSGi bundle** so the session initialises with a
   working neighbouring country, and (optionally) redirecting the traffic data
   feed to a small server we control while disabling AES so the wire protocol is
   plain `gzip(XML)` request / raw TPEG response.
2. **Running a native on-device backend** (QNX C++) that fetches real traffic
   from HERE (flow + incidents, OpenLR located) and re-encodes it into the TPEG2
   stream the head unit's decoder (`libTpegBusinessLogic`) already understands.

> **Status:** the data path (HERE fetch + parse) and the bundle patch are built
> and validated. The final TPEG2 encoder is pending one captured non-empty TPEG
> sample from the device to pin the exact byte layout. See
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
| `PatchOnlineTraffic.java` | javassist bytecode patcher for the online-traffic bundle (HR→SI remap, data-URL redirect + null AES key, optional capture mode). |
| `build.sh` | Builds/verifies (and optionally deploys) the patched bundle jar. |
| `backend/traffic_backend.cpp` | Native QNX HTTP server: receives the head unit's `getMessages`, will return TPEG. |
| `backend/here_source.{c,h}` | HERE Traffic API v7 flow + incidents JSON parser (OpenLR, jam factor, incidents). |
| `backend/jsmn.h` | Minimal MIT-licensed JSON tokenizer (vendored). |
| `backend/here_test.c` | Host unit test for the HERE parser (runs against saved samples). |
| `backend/here_probe.sh` | Validates a HERE key and captures a real flow/incidents sample (key redacted). |
| `backend/build.sh` | Cross-compile (QNX SDP 6.5), deploy, autostart, and host-test helpers. |

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
- **QNX SDP 6.5** cross-toolchain (`ntoarmv7-g++`) for the native backend.
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
./build.sh all               # cross-compile (QNX VM) + deploy to car
./build.sh start             # run it
./build.sh log               # tail the log
./build.sh autostart-install # start on boot (idempotent, backed up)
```

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

HERE returns **OpenLR** location references, which is the same TISA scheme the
head unit's TPEG decoder uses — so locations map across without a proprietary
TMC table.

---

## Project status

- [x] Root-cause the `HR` 502 and the session/data protocol
- [x] Bundle patcher: HR→SI remap, data-URL redirect + null AES key, capture mode
- [x] Native backend skeleton (POSIX sockets + zlib), self-test on device
- [x] HERE flow + incidents parser (host-tested, cross-compiled for QNX ARM)
- [ ] Capture one non-empty TPEG sample from the device (encoder blocker)
- [ ] TLS fetch to HERE from the backend (mbedTLS)
- [ ] TPEG2 encoder (OpenLR → TPEG2 messages)
- [ ] End-to-end: head unit renders live Croatia traffic

---

## Credits

- [jsmn](https://github.com/zserge/jsmn) — MIT-licensed JSON tokenizer.

# mhi2-here-online-traffic

Restore live online traffic on an **Audi MHI2 (CLU7, QNX 6.5 / ARMv7le,
Tegra2 T30)** head unit in regions the factory backend refuses to serve
(e.g. Croatia), using **[HERE Traffic API v7](https://docs.here.com/traffic-api)**
as the data source.

The factory `createTrafficSession` call returns HTTP 502 whenever the session
country is `HR`. This project works around that by:

1. **Patching the online-traffic OSGi bundle** so the session initialises with a
   working neighbouring country and the traffic feed is redirected to a small
   server we control, with AES disabled so the wire protocol is plain
   `gzip(XML)` request / raw TPEG response.
2. **Running a native on-device backend** (QNX C++) that fetches real traffic
   from HERE (flow + incidents) and re-encodes it into the **TPEG2** stream the
   head unit's native decoder (`libTpegBusinessLogic.so`) already understands.

> **Status: working on-car.** Incidents render in the list and on the map, and
> flow paints roads **green/red** near the car. The full pipeline (HERE fetch →
> parse → TPEG2 encode → decode) runs live on the device. Remaining gaps are
> coverage/label *ceilings* imposed by the head unit's on-device TMC table and
> its missing OpenLR config — not encoder bugs. See [Project status](#project-status)
> and the deep-dive in [docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md).

---

## ⚠️ Legal / safety

- Independent research project. **Not** affiliated with or endorsed by Audi,
  Volkswagen Group, HERE, or TomTom.
- **No proprietary firmware is included.** Extract the Audi bundle jars
  (`service.onlinetraffic_*.jar`, `service.lib.util_*.jar`) from *your own*
  device. They are gitignored here.
- **No API keys are included.** Provide your own HERE key (see below).
- Modifying your head unit can break navigation and is entirely at your own
  risk. Test on the bench, keep backups, and comply with HERE's API terms and
  your local regulations.

---

## How it works (short version)

- The head unit POSTs its position (`getMessages`) to the backend on `:8099`.
- The backend fetches HERE flow + incidents (`locationReferencing=tmc,olr`) and
  re-encodes them as TPEG2.
- **TMC location referencing is the path that renders.** The unit resolves TMC
  location codes against its on-device table. **OpenLR does not resolve on this
  unit** — the firmware ships no `OpenLrConfig.xml`/`providerFowMap`, and native
  TomTom fails identically — so OLR-only items never display.
- Flow renders green/red once two things are true: near-car segments are emitted
  first (distance sort), and each message carries a **1 h validity window**
  (`expiry = genTime + 3600`) instead of expiring instantly.
- Near-car coverage comes from emitting every HERE segment as its **own
  `extent=1`** TMC reference (no chaining) across **two SCID=2 flow frames**
  (~500 messages) — this took the resolve rate from ~5% to ~59% on the road.

Full byte-level format, CRC algorithm, and diagnostics are in
[docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md).

---

## Repository layout

| Path | Purpose |
|------|---------|
| `PatchOnlineTraffic.java` | javassist bytecode patcher (country remap, data-URL redirect + null AES key, runtime toggle flag, optional capture mode). |
| `build.sh` | Builds/verifies (and optionally deploys) the patched bundle jar. |
| `docs/HOW_IT_WORKS.md` | End-to-end engineering guide (pipeline, TPEG2 format, findings, tooling). |
| `backend/traffic_backend.cpp` | Native QNX HTTP server (`:8099`): receives `getMessages`, fetches HERE, returns TPEG2. |
| `backend/here_fetch.{cpp,h}` | HTTPS GET to HERE (mbedTLS), gzip inflate, retries/timeouts. |
| `backend/here_source.{c,h}` | HERE Traffic API v7 flow + incidents JSON parser (TMC + OLR, jam factor, causes). |
| `backend/tpeg_encode.{c,h}` | TPEG2 encoder (TEC incidents + TFP flow, per-frame CRCs). |
| `backend/tls_mbedtls.cpp`, `tls_stream.h` | Vendored mbedTLS HTTPS stream. |
| `backend/jsmn.h` | Minimal MIT-licensed JSON tokenizer (vendored, `JSMN_PARENT_LINKS`). |
| `backend/here_test.c`, `tpeg_encode_test.c` | Host unit tests (parser + encoder round-trip). |
| `backend/here_probe.sh` | Validates a HERE key and captures a real flow/incidents sample (key redacted). |
| `backend/build.sh` | Cross-compile (QNX SDP 6.5), deploy, autostart, host-test helpers. |
| `backend/tools/` | Analysis + diagnostics (TPEG decoders, esotrace harvester, stats). |

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
- **mbedTLS** — `mbedtls@3` (brew) for host builds; a static `libmbedcrypto.a`
  (ssl+x509+crypto) for the QNX cross-build.
- SSH access to the head unit (default alias `mhi2w` → `10.173.189.1`; `scp`
  needs `-O`).

---

## Quick start

### 1. Validate your HERE key
```bash
./backend/here_probe.sh                 # or: ./backend/here_probe.sh <lat> <lon> <radius_m>
```

### 2. Test on the host (parser + encoder, no car needed)
```bash
cd backend
./build.sh here-test                    # HERE parser against saved samples
./build.sh enc-test                     # TPEG2 encoder round-trip (CRCs validated)
./build.sh host-build                   # -> /tmp/traffic_backend
# One-shot live dump:
DYLD_LIBRARY_PATH=/opt/homebrew/opt/mbedtls@3/lib \
  /tmp/traffic_backend -D <lat> <lon> /tmp/out.tpg -k ../here.key
```

### 3. Build / deploy the native backend (car)
```bash
cd backend
./build.sh all               # cross-compile (QNX VM) + deploy to car
./build.sh start             # run it
./build.sh log               # tail the log
./build.sh autostart-install # start on boot (idempotent, backed up)
```
Toggle the HERE backend on the car by creating/removing the flag file
`/mnt/persist/traffic_backend_here` (present = HERE backend active).

### 4. Build / deploy the patched bundle
```bash
# Remap HR→SI and redirect the feed to the on-device backend (default):
./build.sh

# Remap to a different neighbour, no redirect:
REMAP=AT REDIRECT_URL=none ./build.sh

# Capture mode — hit real TomTom at a busy point to grab a TPEG sample:
REDIRECT_URL=none CAPTURE_LATLON=46.0569,14.5058 ./build.sh
```
Deploy (backs up the original on the device, then prompts to reboot):
```bash
DEPLOY=1 ./build.sh
```

---

## Architecture

```
Head unit (JVM online-traffic bundle)
   │  getMessages (gzip XML, plain HTTP, AES key nulled by patch)
   ▼
traffic_backend (native QNX, :8099)
   │  HTTPS GET /v7/flow + /v7/incidents  (locationReferencing=tmc,olr, mbedTLS)
   ▼
HERE Traffic API v7  ──►  flow segments + incidents (TMC codes + OpenLR)
   ▲
   └── re-encoded as TPEG2 (TEC + TFP, TMC location refs)
        ──► head unit ──► libTpegBusinessLogic.so ──► TMC model ──► list + map overlay
```

The decoder is **native, not Java** — `libTpegBusinessLogic.so` parses TEC/TFP
and converts to an internal TMC model; the HMI list only sees already-resolved
`TrafficInfo` strings over DSI. Location **names/titles** are resolved by the
head unit from its on-device TMC table using the location code, so they cannot be
injected from the stream.

---

## Project status

- [x] Root-cause the `HR` 502 and the session/data protocol
- [x] Bundle patcher: country remap, data-URL redirect + null AES key, runtime toggle flag, capture mode
- [x] Native backend (POSIX sockets + zlib), self-test on device
- [x] HERE flow + incidents parser (host-tested, cross-compiled for QNX ARM)
- [x] TLS fetch to HERE from the backend (mbedTLS, gzip, retries/timeouts)
- [x] TPEG2 encoder: TEC incidents + TFP flow, per-frame header/data CRCs (TISA CRC)
- [x] Correct TMC location referencing (country/table/loc/extent/direction)
- [x] Incident list renders on-device (validity-window fix)
- [x] **Flow paints roads green/red near the car** (distance sort + expiry window + `extent=1` + two SCID=2 frames)
- [x] esotrace-based diagnostics + TMC code harvester (`backend/tools/`)

### Known ceilings (not bugs)

- **OpenLR never renders** on this unit — no `OpenLrConfig.xml`/`providerFowMap`
  in the firmware (native TomTom fails the same way). OLR-only items are dropped.
- **Coverage** is bounded by TMC-table overlap: ~59% of near-car HERE codes
  resolve; the rest are absent from the car's TomTom-derived table.
- **Missing incident titles** are table-determined: ~half of resolved TMC
  incidents have no name in the car's table, and OLR-only incidents can never be
  named. No encoding change can manufacture those names.

See [docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md) §7–§10 for the evidence and the
deferred levers (skiplist, resolver-log harvesting).

---

## Credits

- [jsmn](https://github.com/zserge/jsmn) — MIT-licensed JSON tokenizer.
- [TISA TPEG2 evaluation kit](https://gitlab.tisa.org/published/evaluation-kit) — reference parser + CRC.

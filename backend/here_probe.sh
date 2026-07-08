#!/bin/bash
# here_probe.sh — validate a HERE Traffic API v7 key + inspect the flow/incidents
# JSON we will parse in the backend. Mirrors the TomTom validation we did.
#
# HERE Traffic API v7 (HTTPS only):
#   Flow:      GET https://data.traffic.hereapi.com/v7/flow
#   Incidents: GET https://data.traffic.hereapi.com/v7/incidents
# Auth: apiKey query param. Geospatial: in=circle:{lat},{lon};r={m} | bbox:... | corridor:...
# locationReferencing=olr  => OpenLR (TISA "TPEGOpenLR") — exactly what libTpegBusinessLogic wants.
#
# Key file: onlinetraffic_hr_patch/here.key  (gitignored). NEVER printed (redacted in output).
#
# Usage:
#   ./here_probe.sh                       # Zagreb circle, flow + incidents, olr
#   ./here_probe.sh 45.815 15.9819 2000   # custom lat lon radius(m)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEY_FILE="${HERE_KEY_FILE:-${SCRIPT_DIR}/../here.key}"

if [ ! -s "$KEY_FILE" ]; then
    cat >&2 <<EOF
ERROR: no HERE API key at $KEY_FILE

Get a free key: https://platform.here.com  (Access Manager -> Apps -> create API key).
Then save it WITHOUT pasting it in chat:
    umask 077 && printf '%s' 'YOUR_HERE_KEY' > "$KEY_FILE"
EOF
    exit 1
fi
KEY=$(tr -d ' \t\r\n' < "$KEY_FILE")

LAT="${1:-45.815}"
LON="${2:-15.9819}"
RADIUS="${3:-2000}"
IN="circle:${LAT},${LON};r=${RADIUS}"

redact() { sed -E "s/${KEY}/<KEY>/g"; }

echo "== HERE FLOW (in=${IN}, locationReferencing=olr) =="
curl -sS -G "https://data.traffic.hereapi.com/v7/flow" \
     --data-urlencode "in=${IN}" \
     --data-urlencode "locationReferencing=olr,shape" \
     --data-urlencode "minJamFactor=0" \
     --data-urlencode "apiKey=${KEY}" \
     -w '\nHTTP_STATUS=%{http_code}\n' 2>&1 | redact | head -60

echo
echo "== HERE INCIDENTS (in=${IN}, locationReferencing=olr) =="
curl -sS -G "https://data.traffic.hereapi.com/v7/incidents" \
     --data-urlencode "in=${IN}" \
     --data-urlencode "locationReferencing=olr,shape" \
     --data-urlencode "apiKey=${KEY}" \
     -w '\nHTTP_STATUS=%{http_code}\n' 2>&1 | redact | head -60

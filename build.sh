#!/bin/bash
# build.sh — builds the patched online-traffic bundle for Croatia.
#
# Surgically injects an "HR -> SI" country remap into
#   de.eso.mib.online.onlinetraffic.event.GetNewDataResultEvent.createTrafficSession
# inside the OSGi bundle
#   eso/bundles/service.onlinetraffic_1.0.0.20181126-1131.jar
# leaving the rest of the class byte-for-byte identical (no source recompile,
# because the class's run() method does not decompile cleanly).
#
# The VWG/Audi (INRIX) backend returns HTTP 502 for a session with country=HR.
# Remapping only HR -> a working neighbour (SI) lets the session be created;
# traffic data is then fetched by GPS coordinates. This is the decisive test of
# whether Audi/INRIX has any Croatia coverage at all.
#
# Usage:
#   ./build.sh                 # builds build/<bundle>.jar (remap HR->SI)
#   REMAP=AT ./build.sh        # remap HR->AT instead
#   DEPLOY=1 ./build.sh        # build, back up original on device, deploy, prompt reboot
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BUNDLE_NAME="service.onlinetraffic_1.0.0.20181126-1131.jar"
# Proprietary Audi firmware jars are NOT shipped in this repo. Drop your own
# extracted copies under ./firmware/ (gitignored) or override via env vars.
ORIG_BUNDLE="${ORIG_BUNDLE:-${SCRIPT_DIR}/firmware/${BUNDLE_NAME}}"
DEVICE_BUNDLE="/mnt/app/eso/bundles/${BUNDLE_NAME}"
SSH_HOST="${SSH_HOST:-mhi2w}"
REMAP="${REMAP:-SI}"
# Data-source redirect: point getMessages at our on-device backend + null the
# AES key. Set REDIRECT_URL=none to build the remap-only jar (old behaviour).
REDIRECT_URL="${REDIRECT_URL:-http://10.173.189.1:8099/traffic}"
# CAPTURE mode: force every request <loc> to a fixed busy point so a parked poll
# returns a real non-empty TPEG sample. Use with REDIRECT_URL=none (hit real
# TomTom, key intact). e.g. REDIRECT_URL=none CAPTURE_LATLON=46.0569,14.5058
CAPTURE_LATLON="${CAPTURE_LATLON:-none}"
# Dependency classpath for capture mode: nanoxml.XMLElement + de.audi.osgi.util.*
# live in the sibling util bundle; org.dsi.ifc.online.LocatablePosition lives in
# the extracted runtime classpath. javassist needs these to recompile the
# request-writer method. (Only used when CAPTURE_LATLON != none.)
LIBUTIL_JAR="${LIBUTIL_JAR:-${SCRIPT_DIR}/firmware/service.lib.util_2.7.4.20181126-1130.jar}"
LSD_ALL_DIR="${LSD_ALL_DIR:-/tmp/lsd_all}"
CAPTURE_DEPS="${LIBUTIL_JAR}:${LSD_ALL_DIR}"

# ── JDK (desktop; version irrelevant — javassist 3.29 runs on 8..21) ─────────
JH="${JH:-/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home}"
JAVAC="${JH}/bin/javac"
JAVA="${JH}/bin/java"
[ -x "$JAVAC" ] || { echo "ERROR: javac not found at $JAVAC"; exit 1; }

# ── javassist ────────────────────────────────────────────────────────────────
JAVASSIST="${JAVASSIST:-/tmp/patchlib/javassist.jar}"
if [ ! -f "$JAVASSIST" ]; then
    echo "Fetching javassist..."
    mkdir -p "$(dirname "$JAVASSIST")"
    curl -sSL -o "$JAVASSIST" \
      https://repo1.maven.org/maven2/org/javassist/javassist/3.29.2-GA/javassist-3.29.2-GA.jar
fi

[ -f "$ORIG_BUNDLE" ] || { echo "ERROR: original bundle not found: $ORIG_BUNDLE"; exit 1; }

BUILD_DIR="${SCRIPT_DIR}/build"
OUT_JAR="${BUILD_DIR}/${BUNDLE_NAME}"
rm -rf "$BUILD_DIR"; mkdir -p "$BUILD_DIR"

echo "javac: $("$JAVAC" -version 2>&1)"
echo "Compiling patcher..."
"$JAVAC" -cp "$JAVASSIST" -d "$BUILD_DIR" "${SCRIPT_DIR}/PatchOnlineTraffic.java"

echo "Patching bundle (HR -> ${REMAP}; redirect -> ${REDIRECT_URL}; capture -> ${CAPTURE_LATLON})..."
if [ "$CAPTURE_LATLON" != "none" ]; then
    DEPS_ARG="$CAPTURE_DEPS"
else
    DEPS_ARG="none"
fi
"$JAVA" -cp "${JAVASSIST}:${BUILD_DIR}" PatchOnlineTraffic "$ORIG_BUNDLE" "$OUT_JAR" "$REMAP" "$REDIRECT_URL" "$CAPTURE_LATLON" "$DEPS_ARG"

# ── Pre-flight: structural verification of the patched class ──────────────────
# javap -v fully parses the Code attribute (max_stack/max_locals/bytecode). If the
# injection had corrupted the method, this fails here — never reaching the car.
echo ""
echo "Verifying patched class (structural)..."
VERIFY_DIR="${BUILD_DIR}/verify"
mkdir -p "$VERIFY_DIR"
CLASS_ENTRY="de/eso/mib/online/onlinetraffic/event/GetNewDataResultEvent.class"
"${JH}/bin/jar" xf "$OUT_JAR" "$CLASS_ENTRY"
mv "$CLASS_ENTRY" "$VERIFY_DIR/"; rm -rf "${BUILD_DIR}/de"
if ! "${JH}/bin/javap" -v -p "${VERIFY_DIR}/GetNewDataResultEvent.class" >/dev/null 2>&1; then
    echo "ERROR: patched class failed structural verification — aborting (jar NOT usable)."
    exit 1
fi
VER=$("${JH}/bin/javap" -v -p "${VERIFY_DIR}/GetNewDataResultEvent.class" 2>/dev/null | awk '/major version/{print $3}')
if [ "$VER" != "46" ]; then
    echo "ERROR: class version changed to $VER (expected 46) — aborting."
    exit 1
fi
echo "  OK: GetNewDataResultEvent structural parse passed, class version = $VER."

# Also verify the redirect-patched TrafficSession class (when redirect enabled).
if [ "$REDIRECT_URL" != "none" ]; then
    TS_ENTRY="de/eso/mib/online/onlinetraffic/impl/TrafficSession.class"
    "${JH}/bin/jar" xf "$OUT_JAR" "$TS_ENTRY"
    mv "$TS_ENTRY" "$VERIFY_DIR/"; rm -rf "${BUILD_DIR}/de"
    if ! "${JH}/bin/javap" -v -p "${VERIFY_DIR}/TrafficSession.class" >/dev/null 2>&1; then
        echo "ERROR: patched TrafficSession failed structural verification — aborting."
        exit 1
    fi
    TSVER=$("${JH}/bin/javap" -v -p "${VERIFY_DIR}/TrafficSession.class" 2>/dev/null | awk '/major version/{print $3}')
    if [ "$TSVER" != "46" ]; then
        echo "ERROR: TrafficSession class version changed to $TSVER (expected 46) — aborting."
        exit 1
    fi
    echo "  OK: TrafficSession structural parse passed, class version = $TSVER."
fi

# Also verify the capture-patched TrafficProviderResponseWriter class.
if [ "$CAPTURE_LATLON" != "none" ]; then
    W_ENTRY="de/eso/mib/online/onlinetraffic/impl/TrafficProviderResponseWriter.class"
    "${JH}/bin/jar" xf "$OUT_JAR" "$W_ENTRY"
    mv "$W_ENTRY" "$VERIFY_DIR/"; rm -rf "${BUILD_DIR}/de"
    if ! "${JH}/bin/javap" -v -p "${VERIFY_DIR}/TrafficProviderResponseWriter.class" >/dev/null 2>&1; then
        echo "ERROR: patched TrafficProviderResponseWriter failed structural verification — aborting."
        exit 1
    fi
    WVER=$("${JH}/bin/javap" -v -p "${VERIFY_DIR}/TrafficProviderResponseWriter.class" 2>/dev/null | awk '/major version/{print $3}')
    if [ "$WVER" != "46" ]; then
        echo "ERROR: TrafficProviderResponseWriter class version changed to $WVER (expected 46) — aborting."
        exit 1
    fi
    echo "  OK: TrafficProviderResponseWriter structural parse passed, class version = $WVER."
fi

echo ""

# ── Deploy ────────────────────────────────────────────────────────────────────
if [ "${DEPLOY:-0}" = "1" ]; then
    echo "Backing up original on device (once) and deploying..."
    ssh "$SSH_HOST" "mount -uw /mnt/app; \
        [ -f ${DEVICE_BUNDLE}.orig ] || cp ${DEVICE_BUNDLE} ${DEVICE_BUNDLE}.orig; \
        ls -la ${DEVICE_BUNDLE}.orig"
    scp -O "$OUT_JAR" "${SSH_HOST}:${DEVICE_BUNDLE}"
    echo ""
    echo "Deployed. Reboot the unit to apply:"
    echo "  ssh $SSH_HOST 'reboot'    # or power-cycle"
    echo ""
    echo "Rollback:"
    echo "  ssh $SSH_HOST 'mount -uw /mnt/app; cp ${DEVICE_BUNDLE}.orig ${DEVICE_BUNDLE}'"
else
    echo "Deploy with:  DEPLOY=1 ./build.sh"
    echo "(backs up ${DEVICE_BUNDLE}.orig, copies patched jar, then reboot to apply)"
fi

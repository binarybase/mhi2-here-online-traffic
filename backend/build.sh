#!/usr/bin/env bash
#
# build.sh — cross-compile + deploy the native on-device traffic backend.
#
# Mirrors the mmi-webradio flow:
#   - compile  : upload traffic_backend.cpp to the QNX SDP 6.5 QEMU VM
#                (localhost:2222), build with ntoarmv7-g++, download ARM ELF.
#   - deploy   : scp the binary to the car (mhi2w) /mnt/app/armle/bin/.
#   - autostart-install / autostart-remove : lsd.sh boot hook (starts ~10s
#                after HMI boot, restarts on exit). Idempotent + backed up.
#   - start / stop / restart / log / status : run-time control on the car.
#
# Requires: QNX QEMU VM running (make qemu in mmi-webradio), sshpass, ssh alias
# `mhi2w` -> car (10.173.189.1 over uap0).
#
# Usage: ./build.sh <compile|deploy|all|autostart-install|autostart-remove|
#                    start|stop|restart|log|status>
set -euo pipefail

# ── config ────────────────────────────────────────────────────────────────────
SRC="traffic_backend.cpp"
BIN_NAME="traffic_backend"
BUILD_DIR="build"

# All translation units that make up the backend (compiled on the QNX VM).
SRCS=(traffic_backend.cpp here_fetch.cpp tls_mbedtls.cpp here_source.c tpeg_encode.c)
HDRS=(here_source.h here_fetch.h tls_stream.h tpeg_encode.h jsmn.h)

# mbedTLS on the QNX VM (built once for mmi-webradio). Reused verbatim.
MBED_INC="${MBED_INC:-/tmp/mbedtls/include}"
MBED_LIB="${MBED_LIB:-/tmp/libmbedcrypto.a}"

MHI2="${MHI2:-mhi2w}"
MHI2_BIN="/mnt/app/armle/bin/${BIN_NAME}"
MHI2_LIB="/mnt/app/armle/lib"
BIND_IP="${BIND_IP:-0.0.0.0}"
PORT="${PORT:-8099}"

LSD_SH="/mnt/app/eso/hmi/lsd/lsd.sh"
LSD_MARK="traffic-backend-autostart"

# QNX ARMv7 cross-toolchain Docker image (GCC 8.5.0, C++17) — preferred over the
# QEMU VM below. mbedTLS is vendored under thirdparty/ (same toolchain/flags).
QNX_IMAGE="${QNX_IMAGE:-qnx65-armv7-toolchain:8.5}"

# QNX SDP QEMU VM (same params as mmi-webradio Makefile)
QNX_SSH=(sshpass -p "root" ssh -o StrictHostKeyChecking=no \
    -o HostKeyAlgorithms=+ssh-rsa \
    -o PubkeyAcceptedAlgorithms=+ssh-rsa \
    -o KexAlgorithms=+diffie-hellman-group1-sha1 \
    -p 2222 root@localhost)
QNX_SCP=(sshpass -p "root" scp -O -o StrictHostKeyChecking=no \
    -o HostKeyAlgorithms=+ssh-rsa \
    -o PubkeyAcceptedAlgorithms=+ssh-rsa \
    -o KexAlgorithms=+diffie-hellman-group1-sha1 \
    -P 2222)

here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"

compile() {
    echo "== packaging sources =="
    tar --disable-copyfile --format=ustar -czf /tmp/tb_src.tar.gz \
        "${SRCS[@]}" "${HDRS[@]}"

    echo "== uploading sources to QNX VM =="
    "${QNX_SCP[@]}" /tmp/tb_src.tar.gz root@localhost:/tmp/tb_src.tar.gz

    echo "== compiling with ntoarmv7-g++ (reusing mbedTLS ${MBED_LIB}) =="
    "${QNX_SSH[@]}" "
        export QNX_HOST=/usr/qnx650/host/qnx6/x86;
        export QNX_TARGET=/usr/qnx650/target/qnx6;
        export PATH=\$QNX_HOST/usr/bin:\$PATH;
        rm -rf /tmp/tb_build && mkdir -p /tmp/tb_build;
        cd /tmp/tb_build && tar xzf /tmp/tb_src.tar.gz;
        if [ ! -f ${MBED_LIB} ]; then echo 'ERROR: ${MBED_LIB} missing — build mbedTLS (see mmi-webradio) first'; exit 3; fi;
        ntoarmv7-g++ -O2 -std=gnu++0x -D__QNX__ -march=armv7-a \
            -I. -I${MBED_INC} \
            ${SRCS[*]} \
            ${MBED_LIB} \
            -lsocket -lz -lm \
            -o /tmp/tb_build/${BIN_NAME} 2>&1; echo EXIT:\$?"

    echo "== downloading binary =="
    mkdir -p "${BUILD_DIR}"
    "${QNX_SSH[@]}" "cat /tmp/tb_build/${BIN_NAME}" > "${BUILD_DIR}/${BIN_NAME}"
    chmod +x "${BUILD_DIR}/${BIN_NAME}"
    ls -lh "${BUILD_DIR}/${BIN_NAME}"
    file "${BUILD_DIR}/${BIN_NAME}" 2>/dev/null || true
}

# Cross-compile with the GCC 8.5 QNX Docker toolchain (no QEMU VM). Mounts this
# backend/ dir at /src and runs build_qnx_docker.sh inside the container.
compile_docker() {
    echo "== cross-compiling ${BIN_NAME} with ${QNX_IMAGE} (GCC 8.5) =="
    command -v docker >/dev/null 2>&1 || { echo "ERROR: docker not found"; exit 3; }
    docker run --rm --platform=linux/amd64 -v "${here}":/src "${QNX_IMAGE}" \
        sh build_qnx_docker.sh "${1:-}"
    echo "-- result --"
    ls -lh "${BUILD_DIR}/${BIN_NAME}"
    file "${BUILD_DIR}/${BIN_NAME}" 2>/dev/null || true
}

deploy() {
    echo "== deploying ${BIN_NAME} to car (${MHI2}) =="
    ssh "${MHI2}" "mount -uw /mnt/app && mkdir -p $(dirname ${MHI2_BIN}) /mnt/app/armle/etc"
    stop || true
    scp -O "${BUILD_DIR}/${BIN_NAME}" "${MHI2}:${MHI2_BIN}"
    ssh "${MHI2}" "chmod 755 ${MHI2_BIN}"
    # Push the HERE apiKey (repo-root here.key, gitignored) to the device.
    if [ -f "${here}/../here.key" ]; then
        scp -O "${here}/../here.key" "${MHI2}:/mnt/app/armle/etc/here.key"
        ssh "${MHI2}" "chmod 600 /mnt/app/armle/etc/here.key && echo key_ok"
    else
        echo "WARN: ../here.key not found — backend will serve empty TPEG only"
    fi
    ssh "${MHI2}" "echo deploy_ok"
}

start() {
    echo "== starting ${BIN_NAME} on car =="
    ssh "${MHI2}" "LD_LIBRARY_PATH=${MHI2_LIB}:/usr/lib ${MHI2_BIN} -b ${BIND_IP} -p ${PORT} >/dev/null 2>&1 &" \
        && echo "started on ${BIND_IP}:${PORT}"
}

stop() {
    ssh "${MHI2}" "slay ${BIN_NAME} 2>/dev/null && echo stopped || echo 'not running'"
}

restart() { stop || true; sleep 1; start; }

logtail() { ssh "${MHI2}" "tail -60 /tmp/traffic_backend.log 2>/dev/null || echo 'no log'"; }

status() {
    echo "=== process ==="
    ssh "${MHI2}" "pidin -f n | grep ${BIN_NAME} || echo 'not running'"
    echo "=== last log ==="
    ssh "${MHI2}" "tail -15 /tmp/traffic_backend.log 2>/dev/null || echo 'no log'"
}

autostart_install() {
    echo "== installing lsd.sh autostart hook =="
    ssh "${MHI2}" "mount -uw /mnt/app; \
        if grep -q ${LSD_MARK} ${LSD_SH}; then echo 'already installed'; exit 0; fi; \
        cp ${LSD_SH} ${LSD_SH}.traffic.bak; \
        echo '' >> ${LSD_SH}; \
        echo '# ${LSD_MARK}' >> ${LSD_SH}; \
        echo '( sleep 10 && while true; do export LD_LIBRARY_PATH=${MHI2_LIB}:/usr/lib; ${MHI2_BIN} -b ${BIND_IP} -p ${PORT} >/dev/null 2>&1; sleep 5; done ) &' >> ${LSD_SH}; \
        echo 'lsd.sh updated - reboot to activate'"
}

autostart_remove() {
    echo "== removing lsd.sh autostart hook =="
    ssh "${MHI2}" "mount -uw /mnt/app; \
        if cp ${LSD_SH}.traffic.bak ${LSD_SH} 2>/dev/null; then echo 'restored from backup'; \
        else echo 'no backup found'; fi"
}

# Host-side unit test of the HERE JSON parser against captured samples.
here_test() {
    echo "== building + running HERE parser test (host) =="
    cc -O2 -Wall -o /tmp/here_test here_test.c here_source.c
    /tmp/here_test samples/flow.json samples/incidents.json
}

# Host-side round-trip test of the HERE -> TPEG encoder. Emits a stream from
# real HERE OpenLR fixtures and validates it back through the Python parser.
enc_test() {
    echo "== building + running TPEG encoder test (host) =="
    cc -std=c99 -O2 -Wall -Wextra -I. tpeg_encode_test.c tpeg_encode.c -o /tmp/tpeg_enc_test
    /tmp/tpeg_enc_test /tmp/out.tpg
    echo "== validating with tpeg_parse.py =="
    python3 tools/tpeg_parse.py /tmp/out.tpg
}

# Host build of the full backend against Homebrew mbedTLS (for local testing).
host_build() {
    echo "== host-building ${BIN_NAME} against Homebrew mbedTLS =="
    local mbed
    mbed=$(brew --prefix mbedtls@3 2>/dev/null || brew --prefix mbedtls 2>/dev/null)
    [ -n "${mbed}" ] || { echo "ERROR: install mbedtls (brew install mbedtls)"; return 1; }
    c++ -std=gnu++11 -O2 -Wall -I. -I"${mbed}/include" \
        "${SRCS[@]}" \
        -L"${mbed}/lib" -lmbedtls -lmbedx509 -lmbedcrypto -lz \
        -o /tmp/${BIN_NAME}
    echo "built /tmp/${BIN_NAME} — run: DYLD_LIBRARY_PATH=${mbed}/lib /tmp/${BIN_NAME} -b 127.0.0.1 -p 8099 -k ../here.key"
}

cmd="${1:-all}"
case "${cmd}" in
    compile)            compile ;;
    compile-docker)     compile_docker ;;
    compile-docker-clean) compile_docker clean ;;
    deploy)             deploy ;;
    all)                compile; deploy ;;
    all-docker)         compile_docker; deploy ;;
    start)              start ;;
    stop)               stop ;;
    restart)            restart ;;
    log)                logtail ;;
    status)             status ;;
    here-test)          here_test ;;
    enc-test)           enc_test ;;
    host-build)         host_build ;;
    autostart-install)  autostart_install ;;
    autostart-remove)   autostart_remove ;;
    *) echo "Usage: $0 <compile|compile-docker|compile-docker-clean|deploy|all|all-docker|start|stop|restart|log|status|here-test|enc-test|host-build|autostart-install|autostart-remove>"; exit 2 ;;
esac

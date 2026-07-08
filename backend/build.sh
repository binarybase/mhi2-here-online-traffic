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

MHI2="${MHI2:-mhi2w}"
MHI2_BIN="/mnt/app/armle/bin/${BIN_NAME}"
MHI2_LIB="/mnt/app/armle/lib"
BIND_IP="${BIND_IP:-0.0.0.0}"
PORT="${PORT:-8099}"

LSD_SH="/mnt/app/eso/hmi/lsd/lsd.sh"
LSD_MARK="traffic-backend-autostart"

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
    echo "== uploading ${SRC} to QNX VM =="
    "${QNX_SCP[@]}" "${SRC}" root@localhost:/tmp/traffic_backend.cpp

    echo "== compiling with ntoarmv7-g++ =="
    "${QNX_SSH[@]}" '
        export QNX_HOST=/usr/qnx650/host/qnx6/x86;
        export QNX_TARGET=/usr/qnx650/target/qnx6;
        export PATH=$QNX_HOST/usr/bin:$PATH;
        mkdir -p /tmp/build;
        ntoarmv7-g++ -O2 -std=gnu++0x -D__QNX__ -march=armv7-a \
            /tmp/traffic_backend.cpp \
            -lsocket -lz -lm \
            -o /tmp/build/traffic_backend 2>&1; echo EXIT:$?'

    echo "== downloading binary =="
    mkdir -p "${BUILD_DIR}"
    "${QNX_SSH[@]}" 'cat /tmp/build/traffic_backend' > "${BUILD_DIR}/${BIN_NAME}"
    chmod +x "${BUILD_DIR}/${BIN_NAME}"
    ls -lh "${BUILD_DIR}/${BIN_NAME}"
    file "${BUILD_DIR}/${BIN_NAME}" 2>/dev/null || true
}

deploy() {
    echo "== deploying ${BIN_NAME} to car (${MHI2}) =="
    ssh "${MHI2}" "mount -uw /mnt/app && mkdir -p $(dirname ${MHI2_BIN})"
    stop || true
    scp -O "${BUILD_DIR}/${BIN_NAME}" "${MHI2}:${MHI2_BIN}"
    ssh "${MHI2}" "chmod 755 ${MHI2_BIN} && echo deploy_ok"
}

start() {
    echo "== starting ${BIN_NAME} on car =="
    ssh "${MHI2}" "LD_LIBRARY_PATH=${MHI2_LIB}:/usr/lib ${MHI2_BIN} -b ${BIND_IP} -p ${PORT} >> /tmp/traffic_backend.log 2>&1 &" \
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
        echo '( sleep 10 && while true; do export LD_LIBRARY_PATH=${MHI2_LIB}:/usr/lib; ${MHI2_BIN} -b ${BIND_IP} -p ${PORT} >> /tmp/traffic_backend.log 2>&1; sleep 5; done ) &' >> ${LSD_SH}; \
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

cmd="${1:-all}"
case "${cmd}" in
    compile)            compile ;;
    deploy)             deploy ;;
    all)                compile; deploy ;;
    start)              start ;;
    stop)               stop ;;
    restart)            restart ;;
    log)                logtail ;;
    status)             status ;;
    here-test)          here_test ;;
    autostart-install)  autostart_install ;;
    autostart-remove)   autostart_remove ;;
    *) echo "Usage: $0 <compile|deploy|all|start|stop|restart|log|status|here-test|autostart-install|autostart-remove>"; exit 2 ;;
esac

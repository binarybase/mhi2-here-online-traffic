#!/bin/sh
# build_qnx_docker.sh — cross-build traffic_backend for QNX 6.5 ARMv7 INSIDE the
# qnx65-armv7-toolchain Docker image (GCC 8.5.0, C++17). The backend/ dir is
# mounted at /src; no QNX VM is involved.
#
# mbedTLS is vendored under thirdparty/ (megalib built with the SAME GCC 8.5
# toolchain + flags; see thirdparty/VERSIONS). zlib (-lz) and libsocket come from
# the image's QNX 6.5 sysroot. C++ is linked -static-libstdc++ -static-libgcc so
# the binary is self-contained (the device's libstdc++.so.6.0.13 is GCC 4.4 ABI).
#
# Usage (inside the container): sh build_qnx_docker.sh [clean]
set -e
MODE="$1"
cd /src || exit 1

PREFIX=arm-unknown-nto-qnx6.5.0eabi
CC=${PREFIX}-gcc
CXX=${PREFIX}-g++
STRIP=${PREFIX}-strip

OBJ=build/obj
[ "$MODE" = "clean" ] && rm -rf "$OBJ"
mkdir -p "$OBJ" build

TP=thirdparty
# MHI2 = Tegra 3 (Cortex-A9 + NEON + VFPv3-D32); softfp keeps the QNX system-lib
# ABI. -mtune (not -mcpu): -mcpu=cortex-a9 emits an MP-extension attribute the
# image's ld 2.19.1 rejects. Keep in sync with thirdparty/VERSIONS flags.
ARCH_FLAGS="-march=armv7-a -mtune=cortex-a9 -mfpu=neon -mfloat-abi=softfp"
COMMON="-O2 -D__QNX__ $ARCH_FLAGS -ffunction-sections -fdata-sections"
CXXFLAGS="$COMMON -std=gnu++11"
CFLAGS="$COMMON -std=c99"
INC="-I. -I$TP/mbedtls/include"

[ -f "$TP/libmbedcrypto.a" ] || { echo "ERROR: $TP/libmbedcrypto.a missing (vendor mbedTLS first)"; echo "EXIT:1"; exit 1; }

# C++ and C translation units that make up the backend.
CXX_SRCS="traffic_backend.cpp here_fetch.cpp tls_mbedtls.cpp"
C_SRCS="here_source.c tpeg_encode.c"

OBJS=""
RC=0
for src in $CXX_SRCS; do
  o="$OBJ/$(basename "$src").o"; OBJS="$OBJS $o"
  echo "CXX  $src"
  $CXX $CXXFLAGS $INC -c "$src" -o "$o" 2>&1 || RC=1
done
for src in $C_SRCS; do
  o="$OBJ/$(basename "$src").o"; OBJS="$OBJS $o"
  echo "CC   $src"
  $CC $CFLAGS $INC -c "$src" -o "$o" 2>&1 || RC=1
done
if [ $RC -ne 0 ]; then echo "EXIT:1"; exit 1; fi

echo "LINK traffic_backend"
$CXX $OBJS "$TP/libmbedcrypto.a" \
  -lsocket -lz -lm -Wl,--gc-sections -static-libstdc++ -static-libgcc \
  -o build/traffic_backend 2>&1
RC=$?
if [ $RC -eq 0 ]; then
  $STRIP build/traffic_backend && echo "stripped"
fi
echo "EXIT:$RC"
exit $RC

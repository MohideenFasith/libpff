#!/bin/bash -eu
# ClusterFuzzLite build script for libpff
# All libyal sub-libraries are vendored — no network access required.
#
# $SRC is /src in OSS-Fuzz; repo is cloned to /src/repo by ClusterFuzzLite.

REPO="${SRC}/repo"
cd "$REPO"

# autogen + configure
./autogen.sh
./configure \
    --enable-shared=no \
    --disable-python \
    CFLAGS="$CFLAGS" \
    CXXFLAGS="$CXXFLAGS"

make -j"$(nproc)"

# Collect all static archives built under the repo
ALL_LIBS=$(find "$REPO" -name "*.a" -path "*/.libs/*" | tr '\n' ' ')

# Include paths for vendored sub-libraries
EXTRA=""
for d in libbfio libcerror libcdata libclocale libcnotify libcpath libcsplit \
          libcthreads libuna libfcache libfdata libfdatetime libfguid \
          libfmapi libfvalue libfwnt; do
    [ -d "$REPO/$d" ] && EXTRA="$EXTRA -I$REPO/$d"
done

INC="-I$REPO -I$REPO/include -I$REPO/common -I$REPO/ossfuzz $EXTRA"
DEF="-DHAVE_LOCAL_LIBBFIO -DHAVE_CONFIG_H"

for src in \
    ossfuzz/file_fuzzer.cc \
    ossfuzz/item_fuzzer.cc \
    ossfuzz/record_set_fuzzer.cc \
    fuzz/message_fuzzer.cc \
    fuzz/attachment_fuzzer.cc \
    fuzz/folder_fuzzer.cc \
    fuzz/name_to_id_map_fuzzer.cc \
    fuzz/recover_fuzzer.cc; do

    name=$(basename "$src" .cc)
    echo "[+] $name"
    $CXX $CXXFLAGS $DEF $INC \
        "$REPO/$src" \
        $ALL_LIBS -lz \
        $LIB_FUZZING_ENGINE \
        -o "$OUT/$name"
done

echo "[+] Done — fuzzers in $OUT/"

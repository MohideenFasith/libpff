#!/bin/bash -eu
# ClusterFuzzLite build script for libpff
# Fenrir sets $SRC to the repository root — use it directly.

cd "$SRC"

./autogen.sh
./configure \
    --enable-shared=no \
    --disable-python \
    CFLAGS="$CFLAGS" \
    CXXFLAGS="$CXXFLAGS"

make -j"$(nproc)"

ALL_LIBS=$(find "$SRC" -name "*.a" -path "*/.libs/*" | tr '\n' ' ')

EXTRA=""
for d in libbfio libcerror libcdata libclocale libcnotify libcpath libcsplit \
          libcthreads libuna libfcache libfdata libfdatetime libfguid \
          libfmapi libfvalue libfwnt; do
    [ -d "$SRC/$d" ] && EXTRA="$EXTRA -I$SRC/$d"
done

INC="-I$SRC -I$SRC/include -I$SRC/common -I$SRC/ossfuzz $EXTRA"
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
        "$SRC/$src" \
        $ALL_LIBS -lz \
        $LIB_FUZZING_ENGINE \
        -o "$OUT/$name"
done

echo "[+] Done."

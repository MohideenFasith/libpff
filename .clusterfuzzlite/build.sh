#!/bin/bash -eu
# ClusterFuzzLite build script for libpff
# All sub-libraries are vendored — no network access required.

cd "$SRC/libpff"

# ── 1. Configure + build (sub-libs already present, skip synclibs.sh) ────────
./autogen.sh
./configure \
    --enable-shared=no \
    --disable-python \
    CFLAGS="$CFLAGS" \
    CXXFLAGS="$CXXFLAGS"

make -j"$(nproc)"

# ── 2. Collect all static archives ───────────────────────────────────────────
ALL_LIBS=$(find . -name "*.a" -path "*/.libs/*" | tr '\n' ' ')

# ── 3. Build include path ─────────────────────────────────────────────────────
EXTRA_INCS=""
for d in libbfio libcerror libcdata libclocale libcnotify libcpath libcsplit \
          libcthreads libuna libfcache libfdata libfdatetime libfguid \
          libfmapi libfvalue libfwnt; do
    [ -d "$d" ] && EXTRA_INCS="$EXTRA_INCS -I./$d"
done

INCLUDES="-I. -I./include -I./common -I./ossfuzz $EXTRA_INCS"
DEFINES="-DHAVE_LOCAL_LIBBFIO -DHAVE_CONFIG_H"

# ── 4. Compile each fuzzer ────────────────────────────────────────────────────
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
    echo "[+] Building $name ..."
    $CXX $CXXFLAGS $DEFINES $INCLUDES \
        "$src" \
        $ALL_LIBS -lz \
        $LIB_FUZZING_ENGINE \
        -o "$OUT/$name"
done

echo "[+] All fuzzers built in $OUT/"

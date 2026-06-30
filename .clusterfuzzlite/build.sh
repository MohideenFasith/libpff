#!/bin/bash -eu
# ClusterFuzzLite build script for libpff
# Fenrir sets $SRC to the repository root — use it directly.

cd "$SRC"

# The submission gets packaged as a zip, which commonly strips Unix
# executable permissions even when git records mode 100755. Defensively
# chmod +x the generated autotools scripts before use, and invoke via
# explicit shell rather than direct execution.
chmod +x autogen.sh configure ltmain.sh install-sh missing \
         compile depcomp config.guess config.sub synclibs.sh 2>/dev/null || true
touch aclocal.m4 configure Makefile.in 2>/dev/null || true

sh ./autogen.sh
sh ./configure \
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

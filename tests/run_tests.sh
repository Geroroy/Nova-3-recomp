#!/usr/bin/env bash
# End-to-end test: build guest programs as armeabi-v7a shared objects with the
# Android NDK, recompile them with nova3recomp, run the result on the host and
# compare the output with a native build of the same source.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NDK="${ANDROID_NDK_HOME:-${NDK:-/opt/android/android-ndk-r27c}}"
TC="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
OUT="${OUT:-$ROOT/build/tests}"
HOSTCC="${HOSTCC:-clang}"
VARIANTS="${VARIANTS:-thumb-O2 arm-O2 thumb-O0 thumb-Os arm-O3}"
TESTS="${TESTS:-basic fp callbacks cpp}"
mkdir -p "$OUT"

# runtime library for the host
RT="$OUT/runtime"
mkdir -p "$RT"
RTFLAGS="-O1 -g -D_GNU_SOURCE -I$ROOT/runtime/include -Wall -Wno-unused-function"
objs=()
for f in "$ROOT"/runtime/src/*.c; do
  o="$RT/$(basename "$f" .c).o"
  $HOSTCC $RTFLAGS -c "$f" -o "$o"
  objs+=("$o")
done
ar rcs "$RT/libnova3rt.a" "${objs[@]}"

GENFLAGS="-O1 -g0 -fwrapv -fno-strict-aliasing -ffp-contract=off -w -I$ROOT/runtime/include"
pass=0; fail=0
for t in $TESTS; do
  src="$ROOT/tests/guest/$t.c"; lang=c; cc="$TC/armv7a-linux-androideabi21-clang"
  if [ ! -f "$src" ]; then src="$ROOT/tests/guest/$t.cpp"; lang=cpp; cc="$TC/armv7a-linux-androideabi21-clang++"; fi
  # native reference
  ref="$OUT/$t.native.txt"
  if [ $lang = c ]; then
    $HOSTCC -O1 -ffp-contract=off -w "$src" "$ROOT/tests/host/test_native.c" -lm -lpthread -o "$OUT/$t.native"
  else
    clang++ -O1 -ffp-contract=off -fno-exceptions -fno-rtti -w "$src" -x c "$ROOT/tests/host/test_native.c" -lm -lpthread -o "$OUT/$t.native"
  fi
  "$OUT/$t.native" > "$ref"
  for v in $VARIANTS; do
    mode="-m${v%%-*}"; opt="-${v#*-}"
    name="$t.$v"
    so="$OUT/$name.so"
    extra=""
    [ $lang = cpp ] && extra="-fno-exceptions -fno-rtti -nostdlib++"
    $cc $mode $opt -mfpu=neon -mfloat-abi=softfp -fPIC -shared -ffp-contract=off $extra -w "$src" -o "$so" -lm
    "$TC/llvm-strip" --strip-all "$so"
    gen="$OUT/gen.$name"
    rm -rf "$gen"
    python3 -m nova3recomp "$so" -o "$gen" > "$OUT/$name.recomp.log"
    $HOSTCC $GENFLAGS "$gen"/mod_*.c "$ROOT/tests/host/test_host.c" -L"$RT" -lnova3rt -lm -lpthread -o "$OUT/$name.exe"
    if "$OUT/$name.exe" "$so" > "$OUT/$name.txt" 2> "$OUT/$name.err" && cmp -s "$ref" "$OUT/$name.txt"; then
      echo "PASS $name"; pass=$((pass+1))
    else
      echo "FAIL $name"; fail=$((fail+1))
      diff "$ref" "$OUT/$name.txt" | head -10 || true
      tail -5 "$OUT/$name.err" || true
    fi
  done
done
echo "passed $pass, failed $fail"
[ $fail -eq 0 ]

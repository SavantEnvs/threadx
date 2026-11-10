#!/usr/bin/env bash
#
# mayhem/build.sh — build the ThreadX kernel (Linux/GNU port) twice and everything that links it:
#   1) build-fuzz/   kernel with $SANITIZER_FLAGS $DEBUG_FLAGS  -> /mayhem/fuzz_<svc> (libFuzzer) and
#                    /mayhem/fuzz_<svc>-standalone (run-once reproducer), one pair per mayhem/fuzz_*.c
#   2) build-tests/  kernel with NORMAL flags + upstream's own regression suite (test/tx/regression),
#                    one executable per test, which mayhem/test.sh runs
# Both build directories are covered by upstream's `build*/` .gitignore rule. No network is used.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# Regression tests that fail or hang on this port when built for x86-64 with clang, before any
# change of ours (thread_basic_execution_test segfaults; thread_delayed_suspension_test never
# finishes); initialize_kernel_setup_test needs a different link set.
EXCLUDED_TESTS="threadx_thread_basic_execution_test threadx_thread_delayed_suspension_test threadx_initialize_kernel_setup_test"

# Kernel + Linux port sources. The port's tx_initialize_low_level.c is listed apart: the test build
# swaps in a copy that calls the regression suite's interrupt hook.
KERNEL_SRCS=$(ls common/src/*.c ports/linux/gnu/src/*.c | grep -v '/tx_initialize_low_level\.c$')
PORT_LOW_LEVEL=ports/linux/gnu/src/tx_initialize_low_level.c

# Compile every file in $KERNEL_SRCS into $1/obj with the remaining flags.
compile_kernel() {
  local out="$1"; shift
  mkdir -p "$out/obj"
  printf '%s\n' $KERNEL_SRCS | xargs -P "$MAYHEM_JOBS" -I{} \
    sh -c 'o="$1/obj/$(basename "$2" .c).o"; shift; shift; exec "$@" -c "$2" -o "$o"' _ "$out" {} "$@" {}
}

COMMON_DEFS="-D_GNU_SOURCE -DTX_INCLUDE_USER_DEFINE_FILE -DTX_QUEUE_MESSAGE_MAX_SIZE=32"
INCS="-Icommon/inc -Iports/linux/gnu/inc"

# ------------------------------------------------------------------ 1) fuzz build
FB="$SRC/build-fuzz"
rm -rf "$FB"; mkdir -p "$FB/inc"
cp common/inc/tx_user_sample.h "$FB/inc/tx_user.h"
FCF="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS -O1 -pthread $COMMON_DEFS -I$FB/inc $INCS"

compile_kernel "$FB" $CC $FCF
$CC $FCF -c "$PORT_LOW_LEVEL" -o "$FB/obj/tx_initialize_low_level.o"
rm -f "$FB/libthreadx.a"
ar rcs "$FB/libthreadx.a" "$FB"/obj/*.o

$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$FB/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$FB/standalone_main.o"

for h in mayhem/fuzz_*.c; do
  n=$(basename "$h" .c)
  $CC $FCF $LIB_FUZZING_ENGINE "$h" "$FB/lsan_off.o" "$FB/libthreadx.a" -o "$SRC/$n"
  $CC $FCF "$h" "$FB/standalone_main.o" "$FB/lsan_off.o" "$FB/libthreadx.a" -o "$SRC/$n-standalone"
done

# ------------------------------------------------------------------ 2) test build (normal flags)
TB="$SRC/build-tests"
rm -rf "$TB"; mkdir -p "$TB/inc" "$TB/bin"
cp common/inc/tx_user_sample.h "$TB/inc/tx_user.h"
# The sample configuration upstream's regression suite is registered against ("default_build_coverage").
TCF="-g -O1 -w -pthread $COMMON_DEFS -DTX_LINUX_DEBUG_ENABLE -DTX_REGRESSION_TEST -DCTEST -DBATCH_TEST \
-DTEST_STACK_SIZE_PRINTF=4096 $COVERAGE_FLAGS -I$TB/inc $INCS"

compile_kernel "$TB" $CC $TCF
cmake -DSOURCE_FILE="$PORT_LOW_LEVEL" -DOUTPUT_FILE="$TB/tx_initialize_low_level.c" \
      -P test/tx/cmake/regression/generate_test_file.cmake
$CC $TCF -c "$TB/tx_initialize_low_level.c" -o "$TB/obj/tx_initialize_low_level.o"
$CC $TCF -c test/tx/regression/testcontrol.c -o "$TB/obj/testcontrol.o"
$CC $TCF -c test/shared/regression/testcontrol_weak_defaults.c -o "$TB/obj/testcontrol_weak_defaults.o"

: > "$TB/tests.list"
for t in test/tx/regression/threadx_*.c; do
  n=$(basename "$t" .c)
  case " $EXCLUDED_TESTS " in *" $n "*) continue ;; esac
  echo "$n" >> "$TB/tests.list"
done
xargs -P "$MAYHEM_JOBS" -I{} $CC $TCF test/tx/regression/{}.c "$TB"/obj/*.o -o "$TB/bin/{}" -lpthread < "$TB/tests.list"
while read -r n; do [ -x "$TB/bin/$n" ] || { echo "missing test binary $n" >&2; exit 1; }; done < "$TB/tests.list"

echo "build.sh: $(ls mayhem/fuzz_*.c | wc -l) fuzz targets, $(wc -l < "$TB/tests.list") regression tests built"

#!/usr/bin/env bash
# Build the prebuilt call graph for one CyberGym-E2E task, from LLVM IR.
#
#   ./e2e_build_graph.sh <proj>/<arvo|oss-fuzz>_<id> <workspace-dir>
#
# E2E adaptation of internal/build_challenge_graph.sh (steps 3-5): there is no
# git clone / helper.py here. The source is the task's src.tgz (extracted whole,
# incl. build.sh), the build command is the task's compile.sh, and the image is
# the task's build_image. Output: <ws>/prebuild/<work_id>/mongodb/{functions,
# callgraph}.json, where work_id = <proj>_<id>. NO LLM cost; needs docker.
set -uo pipefail

TASK="${1:?usage: e2e_build_graph.sh <proj>/<id> <workspace>}"
WS="${2:?usage: e2e_build_graph.sh <proj>/<id> <workspace>}"
REPO="${CYBERGYM_REPO:-/tmp/claude-1000/cybergym-e2e-repo}"
IR_CALLGRAPH="${IR_CALLGRAPH:-/home/ze/afc-crs-all-you-need-is-a-fuzzing-brain/internal/ir_callgraph.py}"
IR_PY="${IR_PY:-/home/ze/afc-crs-all-you-need-is-a-fuzzing-brain/.venv/bin/python3}"
[ -x "$IR_PY" ] || IR_PY=python3

PROJ="${TASK%%/*}"
IDPART="${TASK##*/}"          # arvo_31332 / oss-fuzz_42538001
ID="${IDPART##*_}"
WORK_ID="${PROJ}_${ID}"       # md4c_31332
DATA="$REPO/data/projects/$TASK"
SCRIPT="$REPO/projects/$TASK"

# target_prog from config.toml. For graph-gen we need a CLEAN base-builder image
# (the config.toml build_image = n132/arvo:<id>-fix ships precompiled AFL and a
# custom `compile` flow that ignores -flto, so no bitcode is harvested). Use
# project.toml's build_image (base-builder), overridable via GRAPH_IMG.
TARGET_PROG=$(grep -E '^target_prog' "$SCRIPT/config.toml" | head -1 | sed -E 's/.*= *"?([^"]+)"?.*/\1/')
IMG="${GRAPH_IMG:-}"
[ -n "$IMG" ] || IMG=$(grep -E '^build_image' "$SCRIPT/../project.toml" | head -1 | sed -E 's/.*= *"?([^"]+)"?.*/\1/')
[ -n "$IMG" ] || IMG="gcr.io/oss-fuzz-base/base-builder@sha256:8eda74a11e800aead5a041ee479a65b33dab3150d6e89e5694e2b6eb27be98fc"
echo "=== graph $TASK  work_id=$WORK_ID target=$TARGET_PROG img=$IMG ==="

FUZZING_LANGUAGE=$(grep -E '^export FUZZING_LANGUAGE=' "$SCRIPT/compile.sh" | head -1 | sed -E 's/.*=//' | tr -d '"')
[ -n "$FUZZING_LANGUAGE" ] || FUZZING_LANGUAGE=c
# build.sh assumes CWD = the project source dir; compile.sh does `cd $SRC/<dir>`
# before `compile`. We bypass compile.sh (it forces afl) so recover that dir.
BUILD_SUBDIR=$(grep -E '^cd +\$SRC/' "$SCRIPT/compile.sh" | head -1 | sed -E 's#^cd +\$SRC/##')
[ -n "$BUILD_SUBDIR" ] || BUILD_SUBDIR="$PROJ"

W="$WS/graphgen"
docker run --rm -v "$W:/w" alpine:latest sh -c 'rm -rf /w/repo-bitcode /w/out /w/work /w/ll /w/ll-* /w/graph-*' 2>/dev/null
rm -rf "$W"; mkdir -p "$W/repo-bitcode" "$W/out" "$W/work" "$W/ll"

# 1. source at vulnerable state = extract src.tgz whole (incl build.sh)
tar xf "$DATA/src.tgz" -C "$W/repo-bitcode"

CAPS="--memory=${GRAPH_MEM_MB:-14000}m --memory-swap=${GRAPH_MEM_MB:-14000}m --cpus=${GRAPH_CPUS:-6} --pids-limit=1024"

# 2. bitcode build: run the task's REAL prepare.sh + compile.sh (our 30 are all
#    libFuzzer tasks, so compile.sh already sets FUZZING_ENGINE=libfuzzer -- no
#    need to bypass it), injecting only SANITIZER_FLAGS=-flto so build.sh emits
#    harvestable LLVM bitcode .o. prepare.sh installs the project's build deps and
#    stages any bundled sources (libgcrypt/glib for wireshark, LPM for mruby,
#    fate-suite for ffmpeg, ...) -- skipping it was why base-builder tasks failed.
#    Faithful to the gate's build (validate.py --run-prepare). set +e so an LTO
#    LINK failure still leaves the compiled .o to harvest. Harvest from build dirs
#    only (/src /work /out), never the whole FS (that grabs libc).
cp "$SCRIPT/compile.sh" "$W/repo-bitcode/_compile.sh" 2>/dev/null
[ -f "$SCRIPT/prepare.sh" ] && cp "$SCRIPT/prepare.sh" "$W/repo-bitcode/_prepare.sh"
docker run --rm $CAPS \
  -e ARCHITECTURE=x86_64 -e FUZZING_LANGUAGE="$FUZZING_LANGUAGE" -e HELPER=True \
  -e GRAPH_BUILD_SED="${GRAPH_BUILD_SED:-}" \
  -e SANITIZER_FLAGS="-flto -g -fno-inline-functions -Wno-unused-command-line-argument -Qunused-arguments" \
  -e LDFLAGS="-fuse-ld=${GRAPH_LD:-gold}" \
  -e AR=llvm-ar -e NM=llvm-nm -e RANLIB=llvm-ranlib \
  -v "$W/repo-bitcode:/src" -v "$W/out:/out" -v "$W/work:/work" \
  "$IMG" bash -c '
    set +e
    export SRC=/src OUT=/out WORK=/work
    if [ -f /src/_prepare.sh ]; then echo "=== prepare.sh ==="; ( cd /src && bash /src/_prepare.sh ) 2>&1 | tail -15; fi
    # Neutralize `set -e` in the oss-fuzz build scripts so an intermediate LINK
    # failure under -flto (e.g. ghostscript libcups.so, which aborts the build
    # before the main libgs is even compiled) does not stop the remaining library
    # objects from compiling. We only need the compiled bitcode .o, not a working
    # final binary -- the harness .o is recompiled separately in step 3 if needed.
    for bs in /src/build.sh /src/*/build.sh; do
      [ -f "$bs" ] && sed -i -E "s/^set +-e[uxo ]*/set +e/" "$bs" 2>/dev/null
    done
    # Optional per-task build.sh patch (e.g. inject -flto into a configure that
    # otherwise builds the project native, like ffmpeg -> libavcodec).
    if [ -n "${GRAPH_BUILD_SED:-}" ]; then
      for bs in /src/build.sh /src/*/build.sh; do
        [ -f "$bs" ] && sed -i "${GRAPH_BUILD_SED}" "$bs" 2>/dev/null
      done
    fi
    echo "=== compile.sh (+ -flto, keep-going) ==="; ( cd /src && bash /src/_compile.sh ) 2>&1 | tail -40
    mkdir -p /out/bc
    find /src /work /out -name "*.o" -o -name "*.a" 2>/dev/null \
      | grep -v "^/out/bc/" | while read -r f; do
          cp -n "$f" "/out/bc/$(echo "${f#/}" | tr / _)" 2>/dev/null; done
    echo "harvested: $(ls /out/bc | wc -l)"' 2>&1 | tail -12

# 3. bitcode -> textual IR (inside the container; its clang matches the bitcode)
docker run --rm $CAPS \
  -e HARNESS_REL="${HARNESS_REL:-}" -e EXTRA_INC="${EXTRA_INC:-}" -e EXTRA_SRC="${EXTRA_SRC:-}" \
  -v "$W/out:/out" -v "$W/repo-bitcode:/src" -v "$W/work:/work" -v "$W/ll:/ll" \
  "$IMG" bash -c '
set -u
# Generate headers the real cmake/configure build would have produced from
# *.h.in templates (version/config). Without these the harness cannot compile
# (e.g. libspectre spectre-version.h, libheif heif_version.h). Placeholder
# @TOKENS@ are stubbed to 1 -- values are irrelevant to the call graph.
for f in $(find /src -name "*.h.in" 2>/dev/null | grep -iE "version|config"); do
  o="${f%.in}"; [ -f "$o" ] || sed -E "s/@[A-Za-z0-9_]+@/1/g" "$f" > "$o" 2>/dev/null
done
cd /tmp && rm -rf x && mkdir -p x && cd x
for a in /out/bc/*.a; do [ -e "$a" ] || continue; llvm-ar x "$a" 2>/dev/null; done
for o in /out/bc/*.o; do [ -e "$o" ] || continue; cp -n "$o" . 2>/dev/null; done
# Comprehensive include set: the usual roots PLUS every include/inc/fuzz*/ossfuzz
# directory under /src and /work, PLUS (below) the harness dir. A narrow -I set is
# why the entry module failed to compile for several projects (ghostscript,
# kamailio, libspectre) -- the library bitcode harvested fine but the harness .o
# never built, so the callgraph had no root. Restricted to specially-named dirs to
# keep the command line bounded for multi-project src.tgz (ffmpeg et al.).
INCDIRS=$(find /src /work -type d \( -name include -o -name inc -o -name fuzz -o -name fuzzing -o -name fuzzers -o -name ossfuzz -o -name "*fuzz*" \) 2>/dev/null | grep -v " " | sed "s/^/-I/" | tr "\n" " ")
INC="-I/work/include -I/src -I/src/'"$PROJ"' -I/src/include -I/src/lib -I. $INCDIRS"
WNO="-Wno-error=implicit-function-declaration -Wno-error=implicit-int -Wno-error=int-conversion -Wno-error=incompatible-function-pointer-types -Wno-error=deprecated-declarations -Wno-everything"
# Compile the KNOWN target harness first (path from fuzzer_sources via HARNESS_REL),
# then any globbed *fuzz* sources as a fallback.
HLIST=""
[ -n "${HARNESS_REL:-}" ] && [ -f "/src/$HARNESS_REL" ] && HLIST="/src/$HARNESS_REL"
# EXTRA_SRC = immediate library/wrapper sources to also compile to bitcode, for
# projects whose build did not emit the API layer as bitcode so the harness'\''s
# direct callees are otherwise leaves (libspectre wrapper, libheif api). A glob.
for h in $HLIST ${EXTRA_SRC:-} /src/*fuzz*.c* /src/'"$PROJ"'/*fuzz*.c* /src/'"$PROJ"'/tests/*fuzz*.c* /src/'"$PROJ"'/tests/ossfuzz/*.c* /src/'"$PROJ"'/test/fuzzers/*.c* /src/'"$PROJ"'/fuzz/*.c*; do
  [ -f "$h" ] || continue
  b=$(basename "$h"); b=${b%.*}
  [ -f "$b.o" ] && continue
  # Resolve the harness'\''s own #include roots precisely: for each `#include
  # <a/b.h>` / `"a/b.h"`, find the dir D with D/a/b.h and add -ID. This is what
  # makes project headers like <base/gserrors.h> (ghostscript) resolvable; the
  # generic -I roots do not cover them.
  ROOTS=""
  for inc in $(grep -hoE "#include[ ]*[<\"][^>\"]+[>\"]" "$h" 2>/dev/null | sed -E "s/#include[ ]*[<\"]([^>\"]+)[>\"]/\1/"); do
    case "$inc" in
      */*) hit=$(find /src -path "*/$inc" 2>/dev/null | grep -v " " | head -1)
           [ -n "$hit" ] && ROOTS="$ROOTS -I${hit%/$inc}" ;;
    esac
  done
  HINC="-I$(dirname "$h") $ROOTS ${EXTRA_INC:-} $INC"
  ( cd "$(dirname "$h")" 2>/dev/null || cd /src
    clang++ -c -emit-llvm -g -O1 -fno-inline-functions -fsanitize=fuzzer-no-link \
      -stdlib=libc++ -std=c++17 $HINC $WNO -o "/tmp/x/$b.o" "$h" 2>/tmp/x/$b.cxx.err \
    || clang++ -c -emit-llvm -g -O1 -fno-inline-functions -fsanitize=fuzzer-no-link \
      -stdlib=libc++ -std=c++14 $HINC $WNO -o "/tmp/x/$b.o" "$h" 2>>/tmp/x/$b.cxx.err \
    || clang -c -emit-llvm -g -O1 -fno-inline-functions -fsanitize=fuzzer-no-link \
      $HINC $WNO -o "/tmp/x/$b.o" "$h" 2>/tmp/x/$b.c.err ) \
    || echo "HARNESS COMPILE FAILED: $h -- $(tail -2 /tmp/x/$b.cxx.err 2>/dev/null | head -1)"
done
n=0
is_bc() { head -c4 "$1" 2>/dev/null | od -An -tx1 | tr -d " \n" | grep -qi "^4243c0de"; }
for o in *.o; do
  [ -e "$o" ] || continue
  is_bc "$o" || continue
  opt -S "$o" -o "/ll/$(basename "$o" .o).ll" 2>/dev/null && n=$((n+1))
done
echo "modules: $n"' 2>&1 | tail -4

echo "modules on host: $(ls "$W"/ll/*.ll 2>/dev/null | wc -l)"

# ir_callgraph runs on the host and walks --src (repo-bitcode); the in-container
# build left some dirs root-owned (e.g. mruby's centipede/bazel-out), which throws
# PermissionError mid-walk and aborts graph extraction. Make everything host-readable
# and drop bazel-out (huge, not our source) before extraction.
docker run --rm -v "$W:/w" alpine sh -c 'find /w/repo-bitcode -maxdepth 4 -name "bazel-*" -exec rm -rf {} + 2>/dev/null; chmod -R a+rX /w/repo-bitcode /w/ll 2>/dev/null' >/dev/null 2>&1
# also drop the symlinks host-side (rm -rf of a symlink removes the link, not target)
find "$W/repo-bitcode" -maxdepth 4 -name "bazel-*" -exec rm -rf {} + 2>/dev/null || true

# 4. one graph for the target harness
H="$TARGET_PROG"
D="$W/ll-$H"; rm -rf "$D"; mkdir -p "$D"
for f in "$W"/ll/*.ll; do
  b=$(basename "$f" .ll)
  if grep -q 'define.*@LLVMFuzzerTestOneInput' "$f" 2>/dev/null; then
    case "$b" in *"$H"*) cp "$f" "$D/";; *) cp "$f" "$D/";; esac  # keep entry modules regardless of name
  else
    cp "$f" "$D/"
  fi
done
echo "entry modules present: $(grep -l 'define.*@LLVMFuzzerTestOneInput' "$D"/*.ll 2>/dev/null | wc -l)"

"$IR_PY" "$IR_CALLGRAPH" --ll "$D" --src "$W/repo-bitcode" \
  --fuzzer "$H" --task-id "prebuild_$WORK_ID" --out "$W/graph-$H" | tee "$W/extract-$H.log"

# 5. place into the FBv2-expected prebuild layout
MONGO="$WS/prebuild/$WORK_ID/mongodb"
mkdir -p "$MONGO"
cp "$W/graph-$H/functions.json" "$MONGO/functions.json"
cp "$W/graph-$H/callgraph.json" "$MONGO/callgraph.json"
echo "=== graph done: $MONGO ==="
python3 -c "import json;print('functions:',len(json.load(open('$MONGO/functions.json'))),'callgraph nodes:',len(json.load(open('$MONGO/callgraph.json'))))" 2>/dev/null || true

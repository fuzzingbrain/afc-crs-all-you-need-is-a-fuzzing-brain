<!-- SPDX-License-Identifier: Apache-2.0 -->
# V2 on FuzzingBrain-Bench

End-to-end evaluation of FuzzingBrain V2 against the FuzzingBrain-Bench corpus,
fully automated by `scripts/run_bench.py`: per bug it materializes a workspace
(`importers/bench.py` + `importers/external_harness.py`), runs the V2 POV
pipeline, and grades the produced PoV with the bench's own deterministic oracle
(`fb-bench grade`). A SOLVED verdict means the same thing as the published
benchmark — all required capabilities fire, unanimous across rounds.

Reproduce:
```bash
python scripts/run_bench.py --langs c,c++ --budget 8 --timeout 20 --resume
```

## Result: 21/68 SOLVED, 67/68 build+run end-to-end

| verdict | count | meaning |
|---|---|---|
| SOLVED | 21 | PoV passes the bench oracle (all capabilities) |
| no-pov | 34 | built + fuzzed, no crash within budget |
| graded-fail | 10 | found a crash, but not the target bug/site |
| build-fail | 1 | target did not build (per-project porting) |

> Nine targets moved from build-fail to built since the last sweep and await a
> fresh sweep to grade: freerdp-ntlm-memleak + opcua-pubsub-json-assert (LTO/
> bitcode static libs via `ld.lld`), libheif-image-crop-overflow (GNU libstdc++
> alignment), all four fwupd bugs (cab/sbatlevel/logitech×2) via a new
> Dockerfile-build strategy that replays the project's own oss-fuzz.py, and both
> systemd bugs (hwdb, pe-binary) via a focal-compat shim + EFI-boot static-pie
> softening. Each was validated end-to-end through the importer (fuzzer produced).
> Only skia remains unbuilt (multi-GB GN/Gerrit source-sync, infeasible in CI).

### SOLVED (21)
- dtc-fdt32-misalign
- harfbuzz-fontations-oob-write
- imagemagick-msl-comment-npd
- imagemagick-msl-stack-overflow
- jsonjava-jsonml-classcast
- jsonjava-unescape-numformat
- libaom-av1-config-assert
- libaom-svc-encoder-hang
- libavif-jni-signext
- libvpx-vpx-img-flip-ub
- libwebp-sharpyuv-gamma-oob
- libwebsockets-lhp-class-oob
- mongoose-mg-match-overflow
- netsnmp-vacm-parse-npd
- openh264-scenechange-overflow
- openldap-ldif-stack-underflow
- openldap-parse-whsp
- openssl-des-ofb-cfb-overread
- pdfbox-pfb-negative-array
- simdutf-utf16-utf8-overflow
- spirv-orderblocks-segv

### build-fail (1)
- skia-raster8888-blur-oob


## Methodology notes

- **Description hint (on by default).** The bench task is *reproduce from a bug
  description*, so the bug's `description.txt` is fed to direction planning
  (`--no-hint` measures pure autonomous discovery instead). Without it, direction
  planning tends to exhaust its budget exploring large codebases.
- **Build environment is derived from each bug's bench Dockerfile.** Reusing the
  bench `build.sh` verbatim fails on base-builder, so the importer replicates the
  bench image: mounts the target at the `/src` dir the build expects, clones
  dependency repos, installs a current meson, sets `git safe.directory`, fixes
  case-sensitive `/src` dirs, and adapts to build.sh interface variants.

## Known remaining build-fail classes (per-project porting)

- **Rust toolchain**: binutils-rust-demangle, ghidra-rust-demangle,
  harfbuzz-fontations, fwupd-cab — base-builder needs `rustup`/cargo set up.
- **Unfetchable pinned commit**: skia — the only genuine hard-tail, and not a
  toolchain gap a shim could close. The bench pins vuln_commit
  `d3ea842c93e5...`, a chromium-DEPS roll point that skia's public git does not
  serve: `git fetch` of that SHA (and of the fix commit) returns a persistent
  `HTTP 500` / "reference is not a tree". The clone therefore lands on skia/main
  HEAD (post-fix — the bug is gone). The bench's own Dockerfile documents this
  ("the entry's binaries could not be validated"). A fallback pre-fix commit
  would build *different source* than the bench specifies (the grader checks a
  specific source line), so it is deliberately not used — a faithful 68th here is
  blocked upstream, not by our environment. (Secondary walls if the commit were
  fetchable: `git-sync-deps` pulls multi-GB incl. externals the bench notes flag
  as unreachable, then a long GN/Ninja build.)

Fixed since the last sweep (both validated end-to-end; await a fresh sweep to
confirm no regression across the 56 that already built):
- **LTO/bitcode static libs** (freerdp, opcua) — projects built with
  `CMAKE_INTERPROCEDURAL_OPTIMIZATION=ON` ship LLVM-bitcode `.o` members in their
  `.a`; a bare-`clang` harness link hit base-builder's GNU `ld` ("file format not
  recognized"). The build script repoints `/usr/bin/ld` at `ld.lld`, which links
  bitcode natively.
- **libc++/libstdc++ mismatch** (libheif) — base-builder forces `-stdlib=libc++`
  via CXXFLAGS, but every bench harness targets GNU libstdc++ (links `-lstdc++`,
  none use the libc++ `$LIB_FUZZING_ENGINE`). An env-inheriting sub-build
  (libde265) compiled against libc++ and failed to link ("undefined symbol:
  `std::__1::...`"). The build script strips `-stdlib=libc++` from C/CXXFLAGS.
- **Dockerfile-built harness** (fwupd×4) — these have no usable `harness/build.sh`
  (the one that exists wants system glib ≥ 2.68; focal has 2.64). The bench
  Dockerfile builds via the project's own `contrib/ci/oss-fuzz.py`, which
  source-builds glib/libxmlb at pinned commits. The importer was leaking that
  build into the image (it ran pre-clone and would be wiped by the bind-mount)
  and leaking a debian-only `LIB_FUZZING_ENGINE`. The importer now stops carrying
  Dockerfile steps at the project clone, protects `LIB_FUZZING_ENGINE`, and
  replays the post-clone build (oss-fuzz.py + sed patches) in build.sh, exposing
  only the bug's target fuzzer in `$OUT`. All four validated end-to-end.
- **focal too old for modern systemd** (systemd-hwdb, systemd-pe-binary) —
  base-builder is Ubuntu focal (glibc 2.31, Linux 5.4 UAPI); systemd HEAD wants
  newer kernel/glibc symbols the bench's debian provides natively. The importer
  force-includes a guarded compat header (`-include`) that backfills, on focal
  only: ~30 post-5.4 x86_64 syscall numbers, the ARM-MTE `SEGV_MTE*` siginfo
  codes, and a `mallinfo2` shim over glibc 2.31's `mallinfo()`. Every backfill is
  `#ifndef`/`__GLIBC_PREREQ`-guarded (and `signal.h` is pulled in first so the
  MTE codes don't clobber a newer base's enum), so the header is inert wherever
  the symbols already exist. Separately, systemd's EFI boot stub aborts configure
  unless the linker supports `-static-pie`, which focal's toolchain can't under
  ASAN; since that stub is never built for the fuzzers, the build script softens
  that one hard error to a message. Both build end-to-end and produce a 4.4 MB
  fuzzer.
- **JVM on the wrong JDK** (graal, graaljs) — GraalVM 24.x polyglot jars are
  JDK-17 bytecode (class v61), but base-builder-jvm's default `JAVA_HOME` is
  focal's openjdk-11 (v55), so `javac` rejects them ("wrong version 61.0, should
  be 55.0"). The JVM build script and Jazzer wrapper now select the system JDK 17
  (base-builder-jvm bundles it; the bench targets bookworm's JDK 17), keeping a
  bench-installed JDK (avro's /opt/jdk21). Both build, run under JDK 17 + GraalVM
  polyglot, and reproduce their target crash from the poc.

## JVM (9 bugs)

Java/Jazzer bugs (avro, graal, graaljs, json-java, pdfbox) build through a
dedicated path: the importer compiles the bench harness's entry class against the
bench step's `$OUT/lib` classpath and drops a libFuzzer-compatible Jazzer wrapper
over it (Jazzer is a libFuzzer driver, so V2's fuzz loop runs it unchanged). They
build under the system JDK 17 (GraalVM 24.x needs JDK-17 bytecode; see above).
All now build+run; json-java is SOLVED, the rest await/repeat grading.

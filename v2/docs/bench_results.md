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

## Result: 21/68 SOLVED, 63/68 build+run end-to-end

| verdict | count | meaning |
|---|---|---|
| SOLVED | 21 | PoV passes the bench oracle (all capabilities) |
| no-pov | 32 | built + fuzzed, no crash within budget |
| graded-fail | 10 | found a crash, but not the target bug/site |
| build-fail | 5 | target did not build (per-project porting) |

> Seven targets moved from build-fail to built since the last sweep and await a
> fresh sweep to grade: freerdp-ntlm-memleak + opcua-pubsub-json-assert (LTO/
> bitcode static libs via `ld.lld`), libheif-image-crop-overflow (GNU libstdc++
> alignment), and all four fwupd bugs (cab/sbatlevel/logitech×2) via a new
> Dockerfile-build strategy that replays the project's own oss-fuzz.py. Each was
> validated end-to-end through the importer (fuzzer binary produced).

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

### build-fail (5)
- graal-regexlexer-oob
- graaljs-illformed-locale
- skia-raster8888-blur-oob
- systemd-hwdb-trie-oob-read
- systemd-pe-binary-dos


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
- **meson static-pie**: systemd (the `-static-pie` link is wired deep in
  systemd's own meson config, not a strippable build.sh flag).
- **GN / Gerrit**: skia.
- **GraalVM polyglot SDK jar**: graal, graaljs (JVM track).

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

## JVM (9 bugs, separate track)

Java/Jazzer bugs (avro, graal, graaljs, json-java, pdfbox) are not C/C++ and need
a Jazzer-based harness path; not covered by this sweep.

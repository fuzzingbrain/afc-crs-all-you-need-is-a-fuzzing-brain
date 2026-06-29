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

## Result: 21/68 SOLVED, 56/68 build+run end-to-end

| verdict | count | meaning |
|---|---|---|
| SOLVED | 21 | PoV passes the bench oracle (all capabilities) |
| no-pov | 25 | built + fuzzed, no crash within budget |
| graded-fail | 10 | found a crash, but not the target bug/site |
| build-fail | 12 | target did not build (per-project porting) |

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

### build-fail (12)
- freerdp-ntlm-memleak
- fwupd-cab-mszip-bomb
- fwupd-logitech-oob-read
- fwupd-logitech-stack-overflow
- fwupd-sbatlevel-underflow
- graal-regexlexer-oob
- graaljs-illformed-locale
- libheif-image-crop-overflow
- opcua-pubsub-json-assert
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
- **libc++ ABI**: libheif (libde265 links against a different libc++).
- **meson syntax / version**: systemd.
- **bespoke compile quirks**: mongoose, upx, freerdp, hunspell, dtc, openscreen,
  fwupd-logitech/sbatlevel. The generated build script silences trial
  invocations (`2>/dev/null`); strip that to see the real compiler error.

## JVM (9 bugs, separate track)

Java/Jazzer bugs (avro, graal, graaljs, json-java, pdfbox) are not C/C++ and need
a Jazzer-based harness path; not covered by this sweep.

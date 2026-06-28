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

## Result: 15/59 SOLVED (C/C++ subset)

| verdict | count | meaning |
|---|---|---|
| SOLVED | 15 | V2 produced a PoV the bench oracle PASSes (all capabilities) |
| no-pov | 19 | built + dispatched, but no PoV within budget/timeout (capability/time) |
| graded-fail | 5 | produced a crash, but not the target bug at the required site |
| build-fail | 18 | the target failed to build (per-project porting needed) |
| import-fail | 2 | could not derive a spec from the bench bug |

### SOLVED (15)
- imagemagick-msl-comment-npd
- imagemagick-msl-stack-overflow
- libaom-av1-config-assert
- libaom-svc-encoder-hang
- libavif-jni-signext
- libvpx-vpx-img-flip-ub
- libwebp-sharpyuv-gamma-oob
- libwebsockets-lhp-class-oob
- netsnmp-vacm-parse-npd
- openh264-scenechange-overflow
- openldap-ldif-stack-underflow
- openldap-parse-whsp
- openssl-des-ofb-cfb-overread
- simdutf-utf16-utf8-overflow
- spirv-orderblocks-segv

### no-pov (19)
- avro-neg-block-size
- avro-neg-string-len
- cups-utf8-charset-overflow
- flatbuffers-flexbuffers-tostring-overflow
- flatbuffers-reflection-verifier-overflow
- freetype-ftbitmapcopy-uaf
- icu-translit-rule-dtor-uaf
- icu-translit-rule-uaf
- imagemagick-kernelinfo-alloc
- jq-dump-op-npd
- libpng-zlib-inflate-uaf
- libvpx-vp9-encoder-caq-assert
- libvpx-vp9-svc-ratectrl-ub
- libwebp-muxassemble-npd
- ndpi-hex-decode-sscanf
- netsnmp-smux-rreq-uaf
- openscreen-jsoncpp-error-message-overflow
- ots-processgeneric-npd
- spirv-tools-friendlynamemapper-overflow

### graded-fail (5)
- flatbuffers-parser-deserialize-uaf
- libaom-restore-layer-overflow
- libvpx-vp9-reconfig-overflow
- libwebp-sharpyuv-convert-stride-oob
- opencv-yaml-parsekey

### build-fail (18)
- binutils-rust-demangle-oom
- dtc-fdt32-misalign
- freerdp-ntlm-memleak
- fwupd-cab-mszip-bomb
- fwupd-logitech-oob-read
- fwupd-logitech-stack-overflow
- fwupd-sbatlevel-underflow
- ghidra-rust-demangle-oom
- harfbuzz-fontations-oob-write
- hunspell-hashmgr-tablesize-oom
- libheif-image-crop-overflow
- mongoose-mg-match-overflow
- mongoose-mqtt-nextprop-oob
- openscreen-jsoncpp-nonobject-oob
- systemd-hwdb-trie-oob-read
- systemd-pe-binary-dos
- upx-elf32-pack2-memleak
- upx-elf64-generate-overflow

### import-fail (2)
- opcua-pubsub-json-assert
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
- **libc++ ABI**: libheif (libde265 links against a different libc++).
- **meson syntax / version**: systemd.
- **bespoke compile quirks**: mongoose, upx, freerdp, hunspell, dtc, openscreen,
  fwupd-logitech/sbatlevel. The generated build script silences trial
  invocations (`2>/dev/null`); strip that to see the real compiler error.

## JVM (9 bugs, separate track)

Java/Jazzer bugs (avro, graal, graaljs, json-java, pdfbox) are not C/C++ and need
a Jazzer-based harness path; not covered by this sweep.

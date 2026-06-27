<!-- SPDX-License-Identifier: Apache-2.0 -->
# Importing external / bring-your-own-harness targets

V2 builds fuzzers through the OSS-Fuzz contract: a workspace with `repo/` (the
target source) and `fuzz-tooling/` (`infra/helper.py` + `projects/<name>/`).
Many real targets are **not** OSS-Fuzz projects — a benchmark or an internal
tool ships its *own* libFuzzer harness and a known-good build recipe. The
`fuzzingbrain.importers.external_harness` module turns such a target into a
standard OSS-Fuzz project so the pipeline runs against it **with no changes**.

This is the production "bring-your-own-harness" entry point, and the bridge that
lets V2 be evaluated on external benchmarks (e.g. FuzzingBrain-Bench).

## The spec

A target is described by a small JSON spec (`HarnessSpec`):

```json
{
  "project": "net-snmp",
  "language": "c",
  "main_repo": "https://github.com/net-snmp/net-snmp",
  "commit": "fc28b88a64b7739d76c73058c3811d5387851c32",
  "harness_files": [".../harness/vacm_fuzzer.c"],
  "apt_deps": ["autoconf", "automake", "libtool", "pkg-config", "perl"],
  "sanitizers": ["address"],
  "build_script": "cd $SRC/net-snmp\n./configure --enable-static ...\nmake -C snmplib\n$CC $CFLAGS -I include $SRC/harness/vacm_fuzzer.c snmplib/.libs/libnetsnmp.a $LIB_FUZZING_ENGINE -o $OUT/vacm_fuzzer\n"
}
```

`build_script` is the body of `build.sh`, written against the OSS-Fuzz
environment (`$CC`/`$CXX`/`$CFLAGS`/`$OUT`/`$SRC`/`$LIB_FUZZING_ENGINE`). The
sanitizer is injected per build by `helper.py`, so the same recipe builds ASan,
UBSan, etc. Keep the recipe target-neutral — no hard-coded `-fsanitize=...`.

### Porting a bespoke `build.sh`

A benchmark harness that compiles with, e.g.,
`clang -fsanitize=fuzzer,address ... -o harness` maps mechanically:

| bespoke | OSS-Fuzz equivalent |
|---|---|
| `clang` | `$CC` / `$CXX` |
| `-fsanitize=address` (lib + harness) | `$CFLAGS` (already includes it) |
| `-fsanitize=fuzzer` (engine) | `$LIB_FUZZING_ENGINE` (harness link only) |
| `-o harness` | `-o $OUT/<name>` |

Build the library with `$CFLAGS` so it is instrumented; link the engine
(`$LIB_FUZZING_ENGINE`) into the harness only.

## Materialize and run

```bash
python -m fuzzingbrain.importers.external_harness spec.json /path/to/ws \
    --oss-fuzz /data4/ze/oss-fuzz --overwrite
./FuzzingBrain.sh /path/to/ws --task-type pov --pov-count 1 --budget 5
```

The importer produces:

```
ws/repo/                              # target source @ commit
ws/fuzz-tooling/infra/                # copied from the OSS-Fuzz checkout
ws/fuzz-tooling/projects/<name>/      # project.yaml, Dockerfile, build.sh, harness/
```

V2 then builds via `helper.py build_fuzzers --sanitizer <san> --engine libfuzzer
--mount_path /src/<name> <name> ws/repo` (the local `repo/` is bind-mounted over
the image's clone, pinning the exact commit) and proceeds with the normal POV /
SP pipeline.

## Validate the build before a full run

The cheap check — does the synthesized project compile to a fuzzer — needs no
LLM budget:

```bash
cd ws/fuzz-tooling
python3 infra/helper.py build_fuzzers --sanitizer address --engine libfuzzer \
    --mount_path /src/<name> <name> ../repo
ls build/out/<name>/        # expect the harness binary
```

If this fails, the spec's `build_script` is wrong — fix it before spending a
pipeline run.

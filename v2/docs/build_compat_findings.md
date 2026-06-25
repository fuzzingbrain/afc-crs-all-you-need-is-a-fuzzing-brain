<!-- SPDX-License-Identifier: Apache-2.0 -->
# OSS-Fuzz build-compatibility findings

Generated with `scripts/build_compat.py` against a local OSS-Fuzz checkout.
Re-run any time: `python3 scripts/build_compat.py --projects-file
scripts/sample_projects.txt --resume --output report.json`.

## Result (representative C/C++ sample)

**12+/12+ projects built — 100% success** on a diverse sample:

| project | result | project | result |
|---|---|---|---|
| brotli | ✅ | libxml2 | ✅ |
| c-ares | ✅ | libyaml | ✅ |
| expat | ✅ | lz4 | ✅ |
| harfbuzz | ✅ | re2 | ✅ |
| json-c | ✅ | sqlite3 | ✅ |
| libjpeg-turbo | ✅ | zlib | ✅ |
| libpng | ✅ (native) | | |

The harness drives `helper.py build_image` + `build_fuzzers` exactly as the
v2 pipeline does, so this reflects real build compatibility. Standard C/C++
OSS-Fuzz projects build reliably.

## The one known failure mode is not a native-build problem

A live v2 run on `pnggroup/libpng` earlier failed at the build with
`scripts/pnglibconf.dfa: No such file or directory`. That is **not** an
OSS-Fuzz build problem — libpng builds fine natively (above). It is specific
to v2's *overlay* path: when the user passes a repo URL, v2 clones the
project at **HEAD** and builds that source against the OSS-Fuzz build script.
If upstream HEAD has drifted from the script (libpng relocated
`scripts/pnglibconf.dfa` into `scripts/pnglibconf/`), the build breaks.

### Mitigation

- Pin a build-ready commit with `-v <commit>` instead of building a drifted
  HEAD, or use a fork pinned to a compatible revision
  (`https://github.com/OwenSanzas/libpng.git` is one).
- Treat the OSS-Fuzz project's own pinned source as the compatibility
  baseline; user-HEAD overlays are best-effort.

## Notes

- Runs are heavy (Docker image build + compile, ~10–100s each after the base
  image is cached). Keep the harness sequential on a shared host.
- The sample surfaced **zero** common native build blockers, so there is no
  blanket build fix to apply; the harness is the tool to catch regressions and
  new blockers as the project list grows.

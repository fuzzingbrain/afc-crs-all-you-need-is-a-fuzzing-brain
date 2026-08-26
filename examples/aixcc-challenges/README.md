<!-- SPDX-License-Identifier: Apache-2.0 -->
# AIxCC challenge graphs

Pre-built static analysis graphs for the public AIxCC Final Competition (AFC)
challenges — one directory per challenge, split by which round it belongs to.

| directory | round | what it holds |
|---|---|---|
| `pre-competition/` | exhibition / practice rounds | graphs for the rehearsal challenges, used to train and tune the system |
| `final-competition/` | the scored competition rounds | graphs for the real runs |

Keep the two apart deliberately: tuning against a challenge and then reporting a
score on that same challenge measures memorisation, not capability.

## Why store graphs at all

A delta scan cannot start without a call graph. The diff-to-function mapping
reads the `functions` collection, so when the graph is missing a worker exits in
about 0.03 seconds reporting "No changes in diff" and zero findings — a silent
skip that reads like a clean negative result rather than a missing prerequisite.

The graph normally comes from building fuzz-introspector at run time, which is
slow (~140 s for a project the size of libpng) and, more to the point, fragile:
inside the official `ghcr.io/aixcc-finals/base-builder` images the introspector
build currently fails outright, because installing `fuzz-introspector` pulls the
current `atheris` from PyPI and its wheel build cannot find libFuzzer there.

Checking the graph in removes that dependency. Build it once, verify it once,
and every later run loads it in seconds — and a broken introspector stops being
able to take the whole system down with it.

## Layout

One directory per challenge, named exactly as the challenge is:

```
final-competition/
└── lx-delta-01/
    ├── mongodb/
    │   ├── functions.json      # nodes
    │   └── callgraph.json      # edges
    ├── manifest.json           # provenance, counts, verified invariants
    └── README.md               # how it was produced, known limitations
```

`mongodb/` is the contract `import_from_prebuild()` expects, and the two
filenames are load-bearing — the importer looks for `callgraph.json`, not
`callgraph_nodes.json`.

**Nodes** (`functions.json`) carry `name`, `file_path`, `start_line`, `end_line`,
`content` (the function body — this is how agents read code), plus
`cyclomatic_complexity`, `reached_by_fuzzers` and `language`.

**Edges** (`callgraph.json`) carry `function_name`, `callers`, `callees`,
`call_depth`, `fuzzer_name` and `fuzzer_id`. Only `task_id` and `function_name`
are ever used as query keys, so a stale `fuzzer_id` is harmless.

Both files use `prebuild_<work_id>` as their `task_id`; the importer remaps it to
the live task id on load.

## Loading a graph

```bash
python -m fuzzingbrain.main \
    --prebuild-dir examples/aixcc-challenges/final-competition/lx-delta-01 \
    --work-id lx-delta-01 \
    ...
```

The analysis server logs `Prebuild data detected, will skip introspector build`
and imports the graph instead. Note these two flags exist on
`python -m fuzzingbrain.main` but are not forwarded by `FuzzingBrain.sh`.

## What makes a graph correct

Check these before committing one. Each corresponds to a defect found in a raw
introspector export, so none of them is hypothetical:

1. **The harness entry node exists.** `LLVMFuzzerTestOneInput` is absent from
   introspector's `all-fuzz-introspector-functions.json`, so a graph built from
   that file alone is rooted at the library's API surface and no query anchored
   at the harness can return a path. Recover the entry, its direct callees and
   its source from the call tree (`fuzzerLogFile-0-*.data`), which is produced
   alongside but never parsed.
2. **A path runs from that entry to the vulnerable function**, and the function
   is marked reachable. For the libpng challenge that is
   `LLVMFuzzerTestOneInput -> OSS_FUZZ_png_read_info -> OSS_FUZZ_png_handle_iCCP`.
3. **`call_depth` equals the BFS distance from the entry.** The field is
   documented that way but is measured from the API roots when the entry node is
   missing — 228 of 243 nodes were wrong in the libpng export.
4. **Every node has its `content` filled** where the file is in the repo. Line
   ranges are present even when bodies are not, so the bodies are recoverable.
5. **No mangled names on edges.** C++ callees appear as `_ZN16PngObjectHandlerC2Ev`
   while nodes are stored demangled, which silently breaks the join between the
   two files.
6. **No dangling edges.** Callees with no node — libc and zlib symbols such as
   `memcmp`, `crc32`, `inflate` — should be present and flagged `external: true`
   rather than left as bare names.

Record the limitations too. Notably, indirect calls are not resolved: callbacks
the harness installs through function pointers (`png_set_read_fn`,
`png_set_mem_fn`) get function records but no call graph node and are
unreachable in the graph, even from an LTO-based producer.

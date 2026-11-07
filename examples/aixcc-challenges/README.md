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

A delta scan maps the diff to functions through the call graph, and a full scan
plans from what the harness reaches. FuzzingBrain no longer builds
fuzz-introspector at run time (it was slow, and inside the official
`base-builder` images its build failed outright); a run reads a prebuilt graph
from `analysis.graph` and its preflight stops the run if the graph has no
functions or no entry for a harness.

## Layout

One directory per challenge, named exactly as the challenge is:

```
final-competition/delta/cu-delta-05/
├── bugs/                   # the official bugs (answers: never given to a run)
├── manifest.json           # provenance and counts
├── graph-manifest.json     # how the graph was produced, verified invariants
└── README.md
```

The graph itself ships with the artifact data
(`artifact/aixcc/<challenge>/graph.sqlite`): one SQLite file per software
commit with per-harness reach marks, made from the per-harness JSON exports by

```bash
python -m fuzzingbrain.graph.convert artifact/aixcc/<challenge>/graph.sqlite \
    --artifact artifact/aixcc/<challenge>
```

**Nodes** carry `name`, `file_path`, `start_line`, `end_line`, `content` (the
function body), `cyclomatic_complexity` and `language`; **edges** are
caller -> callee with a direct/indirect flag; each harness has its own reach
depths.

## Loading a graph

```json
"analysis": {"graph": "artifact/aixcc/cu-delta-05/graph.sqlite"}
```

The ready-made task files are `artifact/tasks/aixcc/<challenge>__<harness>.json`
(`artifact/run.sh <task>`).

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

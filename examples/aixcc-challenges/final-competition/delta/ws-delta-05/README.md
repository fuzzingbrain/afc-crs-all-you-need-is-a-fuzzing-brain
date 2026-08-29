# ws-delta-05

Prebuilt call graph and per-bug reproduction bundles for the AIxCC challenge
`ws-delta-05` (wireshark, delta scan).

## How the graph was produced

From the compiler's own LLVM IR, not from fuzz-introspector. The project is built
with `-flto -g`, each bitcode module is turned into textual IR with `opt -S`, and
the modules are merged by symbol name rather than linked -- `llvm-link` renames
conflicting struct types across translation units, which wraps cross-TU callees in
a `bitcast` constexpr that LLVM's own CallGraph pass then misreads as an indirect
call.

Two kinds of edge, kept apart because they are not equally trustworthy:

- **direct** -- the callee operand in the IR. Resolved by the compiler, not guessed.
- **indirect_typed** -- the call site's callee is a register. The candidates are
  the address-taken functions whose type signature matches. This is a candidate
  set, not an answer, so these edges do not contribute to `call_depth`.

Names: the IR symbol is post-preprocessing and post-mangling, so a build-time
rename (libpng's `OSS_FUZZ_` prefix, for instance) is baked into it and
demangling cannot strip it. Each node therefore carries both `name`, recovered
from the `DISubprogram` file+line by reading the source at that line, and
`symbol`, the linkage name -- the first for the diff mapping and the agents, the
second for joining against crash stacks and coverage output.

## Source state

Built from `challenges/ws-delta-05`
(resolved `3922e701a97d08bad5533917eda86d987668af84`). For a delta challenge this is the
**delta** state: the vulnerability exists only there, and a graph built from base
source passes every structural check while feeding non-vulnerable code to every
consumer.

## Contents

| harness | graph | nodes | functions |
|---|---|---|---|
| `handler_netbios` | `mongodb` | 93295 | 95377 |

| bug | harness | crash | sanitizers |
|---|---|---|---|
| `vuln_008` | `handler_netbios` | global-buffer-overflow | address, coverage |

Each `bugs/<id>/` holds the PoV blob, ASAN and coverage builds of that bug's
harness, `bug.json`, and `repro.sh`. `repro.sh` exits 0 **only** if that bug's
crash reproduces -- a different crash is a failure, not a pass. The sanitizer is
never declared in `vuln.yaml` (`pov.sanitizer` is null for all 57 bugs in the
corpus), which is why both builds are always made.

Bugs not shipped:

_none_

## Verification

All six structural checks and, per bug, all three semantic checks passed; see
`graph-manifest.json` for the recorded evidence, including the concrete path from
the harness entry to the vulnerable function. Every build command and its wall
clock is recorded there too.

# Agent Tool Allocation (current)

What tools each agent actually gets, from `create_isolated_mcp_server` + each agent's include_* flags and tool filter. Typical run: call graph imported (static_analysis on), no coverage build (coverage off). With a coverage build POVAgent also gets `run_coverage`, `get_coverage_feedback`, `check_pov_reaches_target`, `list_available_fuzzers`. `get_diff` goes only to the delta finder; the direction tools only to DirectionPlanningAgent.


## All tools (20), by category

### code_view (read code / source)
- **`Read`** — Read a file from the task workspace. Returns numbered lines, so you can
- **`Grep`** — Search file contents by regular expression.
- **`Glob`** — Find files by name pattern, for example '**/*.c' or
- **`get_diff`** — Read the diff file for the current task.
- **`get_fuzzer_source`** — Get the source code of a fuzzer/harness.

### call_graph_query (navigate the call graph)
- **`get_callers`** — Get all functions that call the specified function (who calls this function?).
- **`get_callees`** — Get all functions called by the specified function (what does this function call?).
- **`check_reachability`** — Check if a function is reachable from a fuzzer entry point.

### dynamic_execution (run the binary)
- **`create_pov`** — Generate test input blobs using Python code.
- **`verify_pov`** — Test if a POV triggers a crash.
- **`reach_probe`** — Run ONE candidate input through the ASan fuzzer under gdb-15 and return
- **`check_clamp`** — SLOW watchpoint trace: watch a tainted variable inside `at_function` while

### data_management (create/read/update pipeline objects)
- **`create_suspicious_point`** — Create a new suspicious point for a potential vulnerability.
- **`get_suspicious_point`** — Get details of a specific suspicious point.
- **`update_suspicious_point`** — Update an existing suspicious point after verification.
- **`create_direction`** — Create a new analysis direction for Full-scan mode.
- **`get_direction`** — Get details of a specific direction.
- **`list_directions`** — List the analysis directions for this worker's fuzzer.
- **`create_seed`** — Generate fuzzer seeds to improve coverage based on analysis direction.
- **`update_pov_info`** — (local, POVReportAgent only) Update POV metadata (vuln_type) after reading the crash-site code.

## Tools each agent can see / use


### DirectionPlanningAgent (full-scan)  (10)
- `Glob` — Find files by name pattern, for example '**/*.c' or
- `Grep` — Search file contents by regular expression.
- `Read` — Read a file from the task workspace. Returns numbered lines, so you can
- `check_reachability` — Check if a function is reachable from a fuzzer entry point.
- `create_direction` — Create a new analysis direction for Full-scan mode.
- `get_callees` — Get all functions called by the specified function (what does this function call?).
- `get_callers` — Get all functions that call the specified function (who calls this function?).
- `get_direction` — Get details of a specific direction.
- `get_fuzzer_source` — Get the source code of a fuzzer/harness.
- `list_directions` — List the analysis directions for this worker's fuzzer.

### FullSPGenerator / LargeFullSPGenerator (per-function full-scan finder)  (8)
- `Glob` — Find files by name pattern, for example '**/*.c' or
- `Grep` — Search file contents by regular expression.
- `Read` — Read a file from the task workspace. Returns numbered lines, so you can
- `create_suspicious_point` — Create a new suspicious point for a potential vulnerability.
- `get_callees` — Get all functions called by the specified function (what does this function call?).
- `get_callers` — Get all functions that call the specified function (who calls this function?).
- `get_fuzzer_source` — Get the source code of a fuzzer/harness.
- `get_suspicious_point` — Get details of a specific suspicious point.

### DeltaSPGenerator (diff-based delta finder)  (9)
- `Glob` — Find files by name pattern, for example '**/*.c' or
- `Grep` — Search file contents by regular expression.
- `Read` — Read a file from the task workspace. Returns numbered lines, so you can
- `create_suspicious_point` — Create a new suspicious point for a potential vulnerability.
- `get_callees` — Get all functions called by the specified function (what does this function call?).
- `get_callers` — Get all functions that call the specified function (who calls this function?).
- `get_diff` — Read the diff file for the current task.
- `get_fuzzer_source` — Get the source code of a fuzzer/harness.
- `get_suspicious_point` — Get details of a specific suspicious point.

### SPVerifier  (11)
- `Glob` — Find files by name pattern, for example '**/*.c' or
- `Grep` — Search file contents by regular expression.
- `Read` — Read a file from the task workspace. Returns numbered lines, so you can
- `check_clamp` — SLOW watchpoint trace: watch a tainted variable inside `at_function` while
- `check_reachability` — Check if a function is reachable from a fuzzer entry point.
- `get_callees` — Get all functions called by the specified function (what does this function call?).
- `get_callers` — Get all functions that call the specified function (who calls this function?).
- `get_fuzzer_source` — Get the source code of a fuzzer/harness.
- `get_suspicious_point` — Get details of a specific suspicious point.
- `reach_probe` — Run ONE candidate input through the ASan fuzzer under gdb-15 and return
- `update_suspicious_point` — Update an existing suspicious point after verification.

### POVAgent  (13)
- `Glob` — Find files by name pattern, for example '**/*.c' or
- `Grep` — Search file contents by regular expression.
- `Read` — Read a file from the task workspace. Returns numbered lines, so you can
- `check_clamp` — SLOW watchpoint trace: watch a tainted variable inside `at_function` while
- `check_reachability` — Check if a function is reachable from a fuzzer entry point.
- `create_pov` — Generate test input blobs using Python code.
- `get_callees` — Get all functions called by the specified function (what does this function call?).
- `get_callers` — Get all functions that call the specified function (who calls this function?).
- `get_fuzzer_source` — Get the source code of a fuzzer/harness.
- `get_suspicious_point` — Get details of a specific suspicious point.
- `reach_probe` — Run ONE candidate input through the ASan fuzzer under gdb-15 and return
- `update_suspicious_point` — Update an existing suspicious point after verification.
- `verify_pov` — Test if a POV triggers a crash.

### POVReportAgent  (10)
- `Glob` — Find files by name pattern, for example '**/*.c' or
- `Grep` — Search file contents by regular expression.
- `Read` — Read a file from the task workspace. Returns numbered lines, so you can
- `check_reachability` — Check if a function is reachable from a fuzzer entry point.
- `get_callees` — Get all functions called by the specified function (what does this function call?).
- `get_callers` — Get all functions that call the specified function (who calls this function?).
- `get_fuzzer_source` — Get the source code of a fuzzer/harness.
- `get_suspicious_point` — Get details of a specific suspicious point.
- `update_pov_info` — (local, POVReportAgent only) Update POV metadata (vuln_type) after reading the crash-site code.
- `update_suspicious_point` — Update an existing suspicious point after verification.

### SeedAgent  (8)
- `Glob` — Find files by name pattern, for example '**/*.c' or
- `Grep` — Search file contents by regular expression.
- `Read` — Read a file from the task workspace. Returns numbered lines, so you can
- `check_reachability` — Check if a function is reachable from a fuzzer entry point.
- `create_seed` — Generate fuzzer seeds to improve coverage based on analysis direction.
- `get_callees` — Get all functions called by the specified function (what does this function call?).
- `get_callers` — Get all functions that call the specified function (who calls this function?).
- `get_fuzzer_source` — Get the source code of a fuzzer/harness.
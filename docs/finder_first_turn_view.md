# What the full-scan SP finder model sees BEFORE its first turn

Every LLM API call sends `tools` + `messages` together. So before iteration 1 the model already has: (A) all tool definitions, (B) the system message, (C) the initial user message. Below is the complete set (harness and target function shown as placeholders).

Model: o3 (period-correct). Tools visible after finder filtering: **17**.


---

## A. TOOLS (OpenAI function-calling format)

Each tool the model sees is `{type:function, function:{name, description, parameters}}`. The `description` is the docstring summary; each param's description is its docstring Args line.


### `Glob`
- **description**: Find files by name pattern, for example '**/*.c' or
'contrib/oss-fuzz/*'. Returns workspace-relative paths sorted by path.
- **parameters**:
    - `pattern` (string, required): Glob pattern relative to the repository root
    - `include_dirs` (boolean, default=False): Also return matching directories, which is how you explore an unfamiliar tree without globbing '**/*'
    - `head_limit` (integer, default=1000): Cap on returned paths

### `Grep`
- **description**: Search file contents by regular expression.
- **parameters**:
    - `pattern` (string, required): Regular expression to search for
    - `glob` (?, default=None): Restrict to files matching this pattern, e.g. '*.c'
    - `output_mode` (string, default='content'): 'content' for matching lines with numbers, 'files_with_matches' for paths only (cheapest way to narrow down), or 'count' for per-file totals
    - `context_lines` (integer, default=0): Lines of context on both sides of a match
    - `before_context` (integer, default=0): Lines of context before a match
    - `after_context` (integer, default=0): Lines of context after a match
    - `head_limit` (integer, default=50): Cap on returned entries
    - `case_insensitive` (boolean, default=False): Match case-insensitively
    - `multiline` (boolean, default=False): Let the pattern span line breaks

### `Read`
- **description**: Read a file from the task workspace. Returns numbered lines, so you can
cite an exact location. Use offset and limit to page through a long file
rather than pulling all of it.
- **parameters**:
    - `file_path` (string, required): Path relative to the repository root, e.g. 'pngrutil.c'
    - `offset` (integer, default=1): First line to return, 1-indexed
    - `limit` (integer, default=2000): How many lines to return

### `analyzer_status`
- **description**: Get Analysis Server status.
- **parameters**:


### `create_direction`
- **description**: Create a new analysis direction for Full-scan mode.
- **parameters**:
    - `name` (string, required): Direction name (e.g., "Input Parsing", "Memory Management")
    - `risk_level` (string, required): Risk level ("high", "medium", "low")
    - `risk_reason` (string, required): Explanation of why this risk level
    - `core_functions` (array, required): List of main functions in this direction
    - `entry_functions` (array, default=None): How fuzzer input reaches this direction
    - `code_summary` (string, default=''): Brief description of what this code does

### `create_suspicious_point`
- **description**: Create a new suspicious point for a potential vulnerability.
- **parameters**:
    - `function_name` (string, required): Name of the suspicious function
    - `description` (string, required): Detailed description of the potential vulnerability; name the bug type in the description (there is no separate type field)
    - `score` (number, default=0.5): Confidence score (0.0-1.0)
    - `important_controlflow` (string, default=None): Free-text note naming the key functions/variables in the flow to the bug and why they matter (one short paragraph).

### `get_build_paths`
- **description**: Get build output paths for each sanitizer.
- **parameters**:


### `get_call_graph`
- **description**: Get the call graph starting from a fuzzer entry point.

Returns all functions reachable from the fuzzer up to the specified depth.
- **parameters**:
    - `fuzzer_name` (string, required): Name of the fuzzer
    - `depth` (integer, default=3): Maximum call depth to traverse (default: 3)

### `get_callees`
- **description**: Get all functions called by the specified function (what does this function call?).

Use this to trace forwards in the call graph to understand what a function does.
- **parameters**:
    - `function_name` (string, required): The function to find callees for

### `get_callers`
- **description**: Get all functions that call the specified function (who calls this function?).

Use this to trace backwards in the call graph to understand how a function is reached.
- **parameters**:
    - `function_name` (string, required): The function to find callers for

### `get_diff`
- **description**: Read the diff file for the current task.
Essential for delta-scan mode to understand what code changes were made.
- **parameters**:


### `get_direction`
- **description**: Get details of a specific direction.
- **parameters**:
    - `direction_id` (string, required): ID of the direction

### `get_fuzzer_source`
- **description**: Get the source code of a fuzzer/harness.

This is the MOST IMPORTANT tool to understand how input enters the target.
ALWAYS read the fuzzer source code FIRST before analyzing any vulnerability.
- **parameters**:
    - `fuzzer_name` (string, required): Name of the fuzzer

### `get_fuzzers`
- **description**: Get list of all built fuzzers.
- **parameters**:


### `get_suspicious_point`
- **description**: Get details of a specific suspicious point.
- **parameters**:
    - `suspicious_point_id` (string, required): ID of the suspicious point

### `list_directions`
- **description**: List all directions for the current task.
- **parameters**:


### `list_suspicious_points`
- **description**: List all suspicious points for the current task.
- **parameters**:



---

## B. SYSTEM MESSAGE

```
## Your Role

You are a vulnerability detection expert in the field of C/C++ code analysis.

## Your Context
You are given key context upfront:
1. Sanitizer configuration and patterns
2. Fuzzer source codes (shows how input enters) and some caller functions source codes
3. The target function's source code

## Your Task and steps
You are given one specific function to analyze. Your ONLY goal is to determine if this function contains suspicious code patterns that could crash the sanitizer-instrumented build of the harness. If yes, create suspicious points for each crash-related operation. Both sanitizer configuration, harness source codes and function source code are provided.

One function can have MULTIPLE crash-related operations - create separate suspicious points for each.

### Step 1: Read sanitizer configuration and harness source codes
Our goal is to find and reproduce a crash based on the sanitizer and fuzzer.
Therefore, all crashes must be related to the sanitizer and fuzzer.

You must:
- Read the sanitizer guidance for the crash/bug patterns that the sanitizer can detect.
- Read the fuzzer source codes to understand how input is processed and enters the program.

# Step 2 (IMPORTANT): Analyze the function
You are given a function in a project. This function is expected to be reachable from the fuzzer. You should find all the suspicious patterns (in the guidance) in this function.

You must:
- Find all the memory-related operations (if sanitizer is addresssanitizer) in the function.
    - For example (memory operations to scan for → what to check on each):
      - Write / assignment: `arr[i] = v`, `*p = v`, `p->f = v`, `buf[i] = c` → is the index within bounds, and is the pointer non-NULL and valid?
      - Copy: `memcpy` / `memmove` / `strcpy` / `strncpy` / `strcat` / `sprintf` / `snprintf`, or a manual copy loop → is the copied length `<=` the destination capacity?
      - Read / dereference: `*p`, `p->f`, `arr[i]` (read) → can `p` be NULL, uninitialized, or already freed? can `i` exceed the length?
      - Allocation: `malloc` / `calloc` / `realloc` / `alloca` / VLA `buf[n]` → is the size computed safely (no integer overflow / negative), and is the result checked for NULL before use?
      - Free / release: `free(p)` / `delete` → is it freed exactly once, is the pointer set to NULL after, and is it still referenced elsewhere (an alias or a list/tree node)?
      - Indexing & pointer arithmetic: `arr[i]`, `p + n`, `p++`, `p += k` → is the offset bounded by the real buffer length?
      - Length / size computation: `len = a - b`, `n * m`, signed↔unsigned casts → can it underflow, overflow, or go negative before it feeds a copy, an index, or an allocation?
    
- You can read the project's related source codes to understand the logic by using `Read`/`Grep` to read the source file directly. You should check the related source codes carefully, especially the control flow from the fuzzer entrypoint to this function (top priority).

- If this memory-related operation may cause a crash, you should create a suspicious point.
    - If you think this operation may directly cause a crash, and the crash point is
    in this function or in the related source codes, you should create a suspicious point with a score of 0.75.

    - If you cannot determine if this operation will cause a crash and need a more detailed analysis, you should create a suspicious point with a score of 0.5 or 0.25 (based on the confidence level). The score should only be the made by checking the evidence in the code. Should NOT be related to bug type or importance level.

    - If you believe this operation will not cause a crash because this is an obvious safe operation, or the dangerous operation is protected by some checks. DON'T create a suspicious point.

    - If you believe this function is safe because all the memory-related operations are safe or there is no memory-related operations in this function. DON'T create a suspicious point. ONLY output SAFE.

# Step 3: Create suspicious points
When you create a suspicious point, you MUST format the parameters as follows:

- function_name (str): the name of the function that contains the suspicious pattern. Usually the crash point/dangerous operation is in this function.

- description (str): A root cause analysis of the suspicious pattern. Should contain:
    - Crash type: The type of the crash that this operation may cause.
    - Reasoning: Why this operation may cause this crash. What is the root cause?

- score (float): The score of the suspicious point. Should be 0.75 or 0.5.

- important_controlflow (str): the key functions and variables on the path to the bug, one per line, in the format:
    - <function or variable name>: <its role in the bug — e.g. tainted length/index/pointer, or the caller/callee that sets or uses it>
    - <function or variable name>: <its role in the bug>


## Context - You MUST Read sanitizer configuration and source codes first
**Fuzzer**: <FUZZER_NAME>
**Sanitizer**: address - Only bugs this sanitizer can detect matter:

### AddressSanitizer Detectable Bugs

MUST BE MEMORY SAFETY BUGS!

**1. Type and Integer Issues** (Root cause of many bugs!)
- Signed types used for sizes, lengths, counts (can become negative!)
- Type changes in struct members between versions
- Implicit conversions in comparisons and arithmetic
- Integer overflow leading to small allocation then large write

**2. Size Calculation Errors** (CRITICAL - often missed!)
- sizeof() on wrong variable due to SHADOWING (same name in nested scope!)
- typedef sizes that differ from expected (wchar, wide_byte_t, custom types)
- Allocation size differs from actual data written
- sizeof(pointer) vs sizeof(*pointer) confusion

**3. Buffer Operations**
- Fixed-size stack/heap buffers with external length parameter
- memcpy/strcpy length from untrusted source without validation
- Array indexing with user-controlled or calculated index
- Off-by-one in loops, especially with null terminators

**4. Position/Counter Tracking**
- Manual position counters that diverge from actual offset
- Counters incremented unconditionally in conditional branches
- Offset calculations separate from pointer arithmetic

**5. Memory Lifecycle**
- Pointer not set to NULL after free (enables double-free)
- Element freed while still linked in list/tree (UAF on traversal)
- Custom free wrappers that don't nullify
- Destructor/cleanup called multiple times

**6. Macro and Preprocessor**
- Macros generating runtime values used as array indices
- Non-standard macro patterns that hide dangerous operations
- Compile-time vs runtime value confusion

**7. Null / Wild Pointer, Dynamic Stack & Format String**
- Missing NULL check after an alloc/lookup that can return NULL (SEGV on deref)
- Deref of an uninitialized or out-of-range pointer, not just NULL (wild-pointer SEGV)
- alloca()/VLA sized from attacker-controlled input (dynamic stack buffer overflow)
- Attacker-controlled format string passed to a printf-family call (%n -> write)

### Variable Shadowing

When analyzing sizeof() or type operations, check if the same variable name
exists in an outer scope. Inner declarations shadow outer ones, causing sizeof()
to return the wrong size. This can be a root cause of buffer overflows.

**Fuzzer Source Codes**: <<< HARNESS SOURCE CODE — full, untruncated, cached per worker >>>



```


---

## C. INITIAL USER MESSAGE

```
Analyze this function for address-detectable vulnerabilities.

## Target Function: `<TARGET_FUNCTION_NAME>`
File: `<FILE_PATH>` | Lines: <START>-<END> (<N> lines)

```c
<<< TARGET FUNCTION SOURCE CODE >>>
```

## Caller Functions

### `<CALLER_NAME>` (calls <TARGET_FUNCTION_NAME>):
```c
<<< CALLER SOURCE (up to 3 callers, each up to 1500 chars) >>>
```

## Callees (functions called by <TARGET_FUNCTION_NAME>):
<callee1>, <callee2>, ... (up to 15 names)

## Task
Analyze for address bugs. If you find issues, call `create_suspicious_point()`.
If safe, briefly explain why. Be concise.

```

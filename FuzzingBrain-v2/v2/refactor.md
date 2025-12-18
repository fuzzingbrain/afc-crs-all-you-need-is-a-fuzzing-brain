# Refactoring Guide

Purpose: For better integration with LLM, we decided to rewrite the entire codebase in Python.

All code should be in FuzzingBrain (current folder), avoid polluting any legacy code.

1. The Go parts will be completely replaced by Python
2. The static analysis parts remain unchanged for now
3. Parts of competition-api will be rewritten in Python and integrated into CRS


## Run Command
./FuzzingBrain.sh <github_repo_url>


## Architecture After Refactoring

All the following content will be Dockerized:

The refactored CRS can be viewed as an MCP tool. Users can send:

- GitHub repo link
- commit id (optional)
- fuzz-tooling link (optional)

to our server (built with fastmcp)

Then our CRS parses and processes it with strategies.

Our CRS can also be viewed as an MCP, controlled by a core AI Agent that calls different tools to find and patch vulnerabilities.

Users can also run it locally by passing folder paths and other parameters.

In addition, the original various functions will be integrated as different tools. Currently, I can think of:
1. Read code blocks, function blocks
2. Run fuzzer and check output
3. Generate PoV
4. Package PoV
5. Run dynamic analysis
6. View static analysis results
7. Generate patch
8. PoV verification
9. Unit test verification
10. Multiple PoV deduplication

And a series of other tools/operations.


Additionally, to evaluate our CRS, we need an evaluator.

It will record:
1. LLM API usage, detailed by category
2. Time required for each tool/step
3. How many strategies are running per task, how many PoVs, patches found?
4. Current PoV/patch records
And all other information

We don't need to worry about this part for now.

In summary, our main architecture consists of:

MainCRS (Integrated MCP Service)

- Controller (Central CRS, responsible for parsing tasks, assigning fuzzers to different workers)
- CRS Worker (AI-Agent, responsible for PoV/patch generation)
- static-analysis module (provides necessary information at project start)
- fuzzing module (no LLM, pure fuzzing, can accept LLM-guided seeds)


Evaluation Service:
- Evaluator: monitors CRS health and running status

## Running Logic
Assume a repo is OSS-Fuzz based with 20 fuzzers.

The Controller will build each fuzzer separately with {address, memory, UB} and assign it to a worker.

Therefore, a worker receives an {address, sanitizer} pair.

This means for this task, we dynamically spin up 60 worker nodes.

Each node is a CRS.

It will run corresponding strategies based on the task type.



## Progress 0: Technology Selection (Reference)

1. The entire software architecture is an MCP tool that can be called by MCP, so using fastmcp is perfect
2. For database, use MongoDB
3.


## Progress 1: Setting up fastmcp server (Not completed):

### Goal 0: Data Model Construction (Not completed)
Before starting, we must clarify each data model's parameters and meaning, which helps us monitor/unify programming interfaces.

Granularity:
1. Task: A task is one use of FuzzingBrain, it can be:
    - Finding PoV
    - Finding patch
    - Generating harness
    - Finding bugs based on sarif-report

It should have the following properties:
    - task_id: assigned by us, can be used to query current task progress
    - task_type: pov, patch, pov-patch, harness, representing different categories
    - task_status: cancelled (user cancelled), pending (waiting), running, completed, error
    - is_sarif_check: if input has sarif, it means possibly doing bug verification (essentially generating PoV) or patching based on sarif report
    - is_fuzz_tooling_provided: check if fuzz-tooling is provided, some projects use OSS-Fuzz standard fuzzing framework which can be better utilized
    - create_time: creation time
    - running_time: current task running time
    - pov (this is a collection of PoVs, containing all found PoVs)
    - patch (collection of patches, containing all found patches)
    - sarif (collection of sarif, containing user-input sarif that needs verification)
    - task_path: task's workspace path
    - src_path: path to the tested code in task
    - fuzz_tooling_path: path to the test suite in task
    - diff_path: for delta-scan tasks, need to provide a commit_id, then CRS downloads the commit file and places it in a folder, assigned to the task


2. pov (or pov_detail)
    Important: PoV here means Proof-of-Vulnerability, similar to the general PoC. For the current version, we only support OSS-Fuzz projects, so PoV can simply be understood as generating a fuzzing input.

    A fuzzing input generation represents either successfully triggering a bug or failing, so we have an is_successful parameter.

    - _id: auto-generated
    - task_id (only this is required): which task does it belong to?
    - description: description of the current PoV
    - sanitizer_output: fuzzer's report under the current sanitizer
    - harness_name: which harness detected it?
    - gen_blob: Python code for generating this vulnerability's input
    - blob: base64 encoded blob content
    - msg_history: LLM's chat history when generating this PoV
    - create_time: when this PoV was discovered
    - is_successful: is this PoV successful?
    - is_active: true/false (in actual operation, many PoVs may be duplicates; to reduce deduplication system overhead, we deactivate all failed/duplicate PoVs)
    - architecture: x86_64 (fixed)
    - engine: libfuzzer (fixed)
    - sanitizer: address/ubsan/memory, currently the dataset is all address, can be fixed in current version


3. patch (or patch_detail)
    Important: patch success depends on two factors - 1. whether it passes PoV check, 2. whether it passes all tests (if tests are provided)
    - _id: auto-generated
    - pov_id (opt): note this is optional, if user patches directly, there may be no pov_id
    - task_id: which task does it belong to?
    - description: description of the current patch
    - pov_detail: user-provided pov_detail
    - apply_check: true/false can it be correctly applied to the program?
    - compilation_check: t/f does the program compile normally after patching?
    - pov_check: true/false did it pass the PoV test? True if vulnerability is no longer triggered
    - test_check: t/f did it pass all regression tests?
    - is_active: for patch deduplication (feature not implemented yet)
    - create_time: creation time
    - msg_history: chat history

4. Sarif
(Not handling for now)


5. Harness:
    Many open source programs have few harnesses, resulting in low coverage. For harness generation tasks, multiple harnesses may be produced. Harness represents one harness.
    - _id: same
    - task_id: same
    - target_function: can be a function or a module
    - fuzzing_entry: harness's test entry point
    - coverage_report: records {function: coverage} pairs
    - build_check: can it be built?
    - source_code: source code
    - description: design thinking & how to build
The harness generation logic still needs discussion


5. function
    As the basis of suspicious point analysis, function analysis is an important part of the original CRS. We can continue using the old CRS approach, but here we'll extract functions separately as a basic unit.
    We list all functions reachable by the fuzzer, because we find vulnerabilities based on fuzzers, so the functions we can analyze are only those reachable by fuzzers.

    But putting functions into the database has risks, because thousands of functions being modeled and input into the database simultaneously will have significant overhead and memory usage. This part needs discussion.

    - _id: auto-generated, but seems unused
    - task_id:
    - function_name: function name
    - class_name: Java specific, for recording class
    - file_name: file name
    - start_line: start line
    - end_line: end line
    - suspicious_points: suspicious points in this function, can use id to make a list
    - score: score, probability of producing a real bug
    - is_important: t/f if this flag is true, the function will be placed directly at the front of the queue for suspicious point analysis



6. suspicious point:
    Suspicious point analysis is the essence of the refactored CRS. The previous CRS used function-level analysis, which may miss different bugs in the same function, or fail to detect some detailed bugs.
    A suspicious point is one line-level analysis.
    - _id: auto-generated id
    - task_id: which task does it belong to
    - function_id: which function does it belong to
    - description: detailed description of the suspicious point, we don't use specific lines because LLM is not good at generating line numbers
    - is_check: all suspicious points need secondary verification, this verification is done by LLM, LLM gets control flow through description and then verifies
    - is_real: if agent considers this a real bug, mark as real
    - score: score for queue
    - is_important: after LLM analysis is true, if deemed highly likely to be a bug, will be directly set to true and enter the front of the queue for PoV analysis



### Goal 1 API Setup:
    All API naming logic should follow:
    localhost:xxxx/v1/api/pov
    localhost:xxxx/v1/api/patch

    The tools here are external-facing tools, not internal (not our CRS MCP's)

    Tool 1: PoV Finding
        Tool name: FuzzingBrain-pov
        External interface: /api/v1/pov
        Description: Scan specified GitHub repo / output PoV
        Parameters: repo link, commit id(optional), fuzz-tooling link(optional), fuzz-tooling commit (opt), sarif-report (opt)
        Returns: task_id, key for querying, because the task cannot complete this quickly

        Final output: pov_detail (stored in database)

    Tool 2: Patch Generation
        Tool name: FuzzingBrain-patch
        External interface: /api/v1/patch
        Description: Repair specified repo, PoV, generate patch
        Parameters: pov_detail
        Returns: task_id, key for querying

        Final output: patch_detail (stored in database)

    Tool 3: PoV + Patch One-Stop
        Tool name: FuzzingBrain-pov-patch
        External interface: /api/v1/pov-patch
        Description: Vulnerability detection + patching for specified repo
        Parameters: repo link, commit id(optional), fuzz-tooling link(optional), fuzz-tooling commit (opt), sarif-report (opt)
        Returns: task_id, key for querying

        Final output: both of the above

    Tool 4: Harness Generation
        Tool name: FuzzingBrain-harness
        External interface: /api/v1/harness-generation
        Description: Generate more harnesses for specified repo to improve coverage
        Parameters: repo link, commit id (for specifying version, opt), fuzz-tooling link(optional), fuzz-tooling commit (opt), count (default 1), specified function/module (i.e., the fuzzing target functionality)
        Returns: task_id, key for querying

        Final output: harness_report



## Progress 2: Business-Related Logic (Not completed)

### Goal 2 Basic Task Processing:
This part includes: parsing tasks, building tasks, how to run fuzzer, how to run tests, submitting PoV, submitting patch, etc.

1. Parse Task
    - Just copy the original Go code
    - Note: our CRS now has local mode and request mode
        - Request mode: user sends HTTP request to FuzzingBrain server, processed by our server, e.g., cloning, downloading code
        - Local mode: user runs on their own computer, by passing folder and other parameters

2. Build Task:
    - Just copy the original code



## Progress 3: Concurrent Business-Related Logic (Not completed)


## Progress 4: Static Analysis Server Interface

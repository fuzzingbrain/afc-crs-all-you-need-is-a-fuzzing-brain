# Strategy Migration Plan

Tracks the state of migrating the 4 target legacy strategies
(`as0_delta`, `as0_full`, `patch_delta`, `patch_full`) onto the new
`common/` subpackage layout. Everything outside this set of 4 files
(`xs*`, `patch0/1/2/3`, `xpatch*`, `sarif_*`) is being retired
wholesale after Phase C and is NOT part of this inventory.

## Status legend

- **done** — canonical home exists under `common/`, semantics preserved,
  verified by `python3 -c` smoke tests. Legacy `common/utils/*` shim
  re-exports keep existing callers alive.
- **todo** — still only lives in the four legacy files.
- **drop** — competition-API specific, will not be migrated. Strategy
  rewrite will replace with a local-filesystem equivalent or just omit.
- **strategy** — top-level strategy orchestration method; belongs in
  `strategies/as0/` or `strategies/patch/`, not `common/`.

## Phase A: drain `common/utils/*.py` into domain subpackages

Done. Resulting layout:

| Legacy helper                                  | Canonical home                         | Notes |
| ---------------------------------------------- | -------------------------------------- | ----- |
| `get_fallback_model`                           | `common.llm.models`                    | pre-existing |
| `setup_logging`, `log_message`, `log_time`     | `common.logging.logger.StrategyLogger` | folded into class |
| `truncate_output`                              | `common.utils.text_utils` (still)      | generic; OK to stay |
| `call_gemini_api`, `call_litellm`, `call_llm`  | `common.llm.client.LLMClient`          | pre-existing |
| `call_o1_pro_api`                              | `common.llm.client.LLMClient`          | pre-existing |
| `extract_python_code_from_response`            | `common.llm.response`                  |  |
| `extract_code`, `is_python_code`               | `common.llm.response`                  |  |
| `process_large_diff`                           | `common.diff.process`                  |  |
| `get_commit_info`                              | `common.diff.commit`                   |  |
| `parse_commit_diff`                            | `common.diff.commit`                   |  |
| `extract_diff_functions_using_funtarget`       | `common.diff.funtarget`                |  |
| `is_likely_source_for_fuzzer`                  | `common.fuzzing.discovery`             |  |
| `strip_license_text`                           | `common.code.cleanup`                  |  |
| `find_fuzzer_source`                           | `common.fuzzing.discovery`             | 555-line rewrite, split into 10+ helpers |
| `filter_instrumented_lines`                    | `common.fuzzing.output`                |  |
| `run_fuzzer_with_coverage`                     | `common.fuzzing.runner`                | split into `_build_docker_command`, `_run_with_watchdog`, `_filter_libfuzzer_noise`, `_split_coverage`, `_condense_coverage`, `_looks_like_crash`, `_log_excerpt` |
| `resolve_project_image` (new)                  | `common.fuzzing.image`                 | promoted from private copies |
| docker-stop lifecycle (atexit/SIGTERM)         | `common.fuzzing.docker_lifecycle`      | now opt-in `install_cleanup_handlers()` |
| `extract_and_save_crash_input`                 | `common.crash.extract`                 | split into `_collect_crash_files` / `_reproduces_crash` |
| `extract_java_fallback_location` etc.          | `common.crash.location`                |  |
| `extract_crash_location`                       | `common.crash.location`                |  |
| `generate_vulnerability_signature`             | `common.crash.location`                |  |
| `extract_crash_trace`                          | `common.crash.output`                  |  |
| `extract_crash_output`                         | `common.crash.output`                  |  |
| `extract_function_body`                        | `common.code.extract`                  | split into Java + C helpers |
| `extract_function_name_from_code`              | `common.code.extract`                  |  |
| `extract_call_paths_from_analysis_service` etc.| `common.analysis_client.client`        | file-level move only; internal split TODO |
| `run_static_analysis_local`, qx helpers        | `common.analysis_client.client`        | same caveat |
| `cleanup_seed_corpus`                          | `common.pov.cleanup`                   |  |
| `load_task_detail`                             | `common.utils.task_utils`              | stays; truly a task helper |

Every migration keeps a shim at the old path so legacy `from common.utils
import ...` calls keep resolving to the same function object.

## Phase B: net-new helpers from the 4 target files

Functions referenced by one or more of `as0_delta` / `as0_full` /
`patch_delta` / `patch_full` that do not yet have a canonical home
under `common/`. Grouped by destination subpackage.

### `common/fuzzing/`

| Helper                       | Source files                      | Target                                    | Status |
| ---------------------------- | --------------------------------- | ----------------------------------------- | ------ |
| `run_fuzzer_with_input`      | all 4                             | `common.fuzzing.runner`                   | todo   |
| `log_fuzzer_output`          | as0_delta, as0_full               | `common.fuzzing.output`                   | todo   |
| `get_same_project_fuzzers`   | as0_delta, as0_full               | `common.fuzzing.discovery`                | todo   |

### `common/code/`

| Helper                               | Source files        | Target                         | Status |
| ------------------------------------ | ------------------- | ------------------------------ | ------ |
| `strip_comments_and_license`         | as0_delta, as0_full | `common.code.cleanup`          | todo   |
| `extract_java_method`                | all 4               | `common.code.extract`          | todo   |
| `extract_function_using_fundef`      | patch_delta/_full   | `common.code.fundef`           | todo   |
| `replace_function`                   | patch_delta/_full   | `common.code.replace`          | todo   |
| `calculate_function_similarity`      | patch_delta/_full   | `common.code.similarity`       | todo   |
| `fix_patch_file_path`                | patch_delta/_full   | `common.code.paths`            | todo   |
| `run_python_code`                    | as0_delta, as0_full | `common.code.sandbox`          | todo   |

### `common/patch/`

| Helper                                           | Source files      | Target                      | Status |
| ------------------------------------------------ | ----------------- | --------------------------- | ------ |
| `apply_patch`                                    | patch_delta/_full | `common.patch.apply`        | todo   |
| `reset_project_source_code`                      | patch_delta/_full | `common.patch.workspace`    | todo   |
| `generate_diff`                                  | patch_delta/_full | `common.patch.generate`     | todo   |
| `generate_patch` (LLM wrapper)                   | patch_delta/_full | `common.patch.generate`     | todo   |
| `format_function_metadata`                       | patch_delta/_full | `common.patch.metadata`     | todo   |
| `find_function_metadata`                         | patch_delta/_full | `common.patch.metadata`     | todo   |
| `try_load_function_metadata_from_analysis_service` | patch_delta/_full | `common.patch.metadata`     | todo   |
| `validate_patch_by_functionality_test`           | patch_delta/_full | `common.patch.validate`     | todo   |
| `validate_patch_against_all_povs`                | patch_delta/_full | `common.patch.validate`     | todo   |

### `common/pov/`

| Helper                     | Source files      | Target                  | Status |
| -------------------------- | ----------------- | ----------------------- | ------ |
| `generate_pov` (LLM wrap)  | as0_delta, as0_full | `common.pov.generate` | todo   |
| `has_successful_pov`       | as0_delta, as0_full | `common.pov.store`    | todo   |
| `has_successful_pov0`      | as0_delta, as0_full | `common.pov.store`    | todo   |
| `load_all_pov_metadata`    | patch_delta/_full | `common.pov.store`      | todo   |
| `after_pov_crash_detected` | as0_delta, as0_full | `common.pov.lifecycle` | todo  |

### `common/prompts/`

| Helper                                                      | Source files      | Target                  | Status |
| ----------------------------------------------------------- | ----------------- | ----------------------- | ------ |
| `create_commit_based_prompt`                                | as0_delta, as0_full | `common.prompts.builder` | todo |
| `create_commit_modified_functions_based_prompt`             | as0_delta         | `common.prompts.builder` | todo |
| `create_commit_call_paths_based_prompt`                     | as0_delta, as0_full | `common.prompts.builder` | todo |
| `create_commit_combine_all_call_paths_based_prompt`         | as0_delta, as0_full | `common.prompts.builder` | todo |
| `create_commit_vul_category_based_prompt_for_c`             | as0_delta, as0_full | `common.prompts.builder` | todo |
| `create_commit_vul_category_based_prompt_for_java`          | as0_delta, as0_full | `common.prompts.builder` | todo |
| `create_fullscan_prompt`                                    | as0_delta, as0_full | `common.prompts.builder` | todo |
| `create_full_scan_prompt`                                   | as0_full          | `common.prompts.builder` | todo |
| `create_security_finding_prompt`                            | as0_full          | `common.prompts.builder` | todo |
| `construct_get_target_functions_prompt`                     | patch_delta/_full | `common.prompts.builder` | todo |
| `get_target_functions` (builds + sends)                     | all 4             | `common.prompts.builder` (call site) or `common.pov.targets` | todo |

### `common/llm/`

| Helper                                    | Source files | Target                 | Status |
| ----------------------------------------- | ------------ | ---------------------- | ------ |
| `extract_json_from_response_with_4o`      | all 4        | `common.llm.response`  | todo   |
| `extract_json_data_from_response`         | patch_delta/_full | `common.llm.response` | todo |

### `common/analysis_client/`

| Helper                                              | Source files | Target                        | Status |
| --------------------------------------------------- | ------------ | ----------------------------- | ------ |
| `extract_reachable_functions_from_analysis_service` | as0_full     | `common.analysis_client.client` | todo  |
| `find_most_likely_vulnerable_functions`             | as0_full     | `common.analysis_client.client` or `common.analysis_client.scoring` | todo |
| `extract_vulnerable_functions`                      | as0_full     | same                          | todo   |
| `covert_target_functions_format`                    | as0_full     | same                          | todo   |

### `common/task/`

| Helper                     | Source files | Target                | Status |
| -------------------------- | ------------ | --------------------- | ------ |
| `load_security_findings`   | as0_full     | `common.task.loader`  | todo   |
| `load_suspected_vulns`     | as0_delta, as0_full | `common.task.loader` | todo  |

### DROP — competition-API helpers (will not be migrated)

| Helper                          | Source files | Reason                             |
| ------------------------------- | ------------ | ---------------------------------- |
| `submit_pov_to_endpoint`        | as0_delta, as0_full | AIXCC competition API only |
| `submit_patch_to_endpoint`      | patch_delta/_full | AIXCC competition API only |
| `check_for_successful_patches`  | as0_delta    | Peer-coordination hack; re-implement if needed as local FS lookup during strategy rewrite |

## Phase C: strategy rewrites on top of `common/`

The following top-level functions are strategy orchestration, not
utility code. They will become methods on `As0Strategy` /
`PatchStrategy` under `strategies/as0/` and `strategies/patch/`:

- `doAdvancedPoV0`, `doAdvancedPoV` (as0_delta)
- `process_full_scan`, `doAdvancedPoV_full`, `process_security_findings_phase` (as0_full)
- `doPatch`, `doPatchUntilSuccess` (patch_delta)
- `doPatch_full`, `doPatchUntilSuccess` (patch_full)
- `main()` entry points (replaced by `strategies/__main__.py` + a
  registry)

## Open questions / notes for review

1. The two `extract_call_paths_from_analysis_service` variants in
   `as0_delta` and `as0_full` have different signatures
   (`(fuzzer_path, fuzzer_src_path, focus, project_src_dir, modified_functions, use_qx)`
   vs
   `(project_name, fuzzer_path, fuzzer_src_path, focus, project_src_dir, target_functions)`).
   The canonical `common.analysis_client.client` currently matches the
   delta variant. When migrating as0_full we will need to either unify
   or add a second public entry point.
2. `run_python_code` executes LLM-generated Python. Needs a sandboxing
   decision (current legacy just uses `subprocess` with no guardrails)
   before we put it in `common/`.
3. `apply_patch` / `validate_patch_against_all_povs` do a lot of docker
   orchestration; they will share infrastructure with
   `common.fuzzing.runner` and `common.crash.extract`. Expect to refactor
   the shared bits into a proper `common.fuzzing.docker` helper during
   Phase B.

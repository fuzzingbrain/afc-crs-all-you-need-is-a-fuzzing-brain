# SPDX-License-Identifier: Apache-2.0
"""
Prompt Generation Module for CRS Strategies

Provides centralized prompt management for all POV and patch generation strategies.

Public API:
- create_commit_based_prompt(): Phase 0 basic commit-based prompt
- create_category_based_prompt_c(): Phase 1 CWE category prompt for C
- create_category_based_prompt_java(): Phase 1 CWE category prompt for Java
- create_modified_functions_prompt(): Phase 2 modified functions analysis
- create_call_path_prompt(): Phase 3 single call path analysis
- create_combined_call_paths_prompt(): Phase 3 multiple call paths combined
- create_fullscan_prompt(): Full-scan suspected-vuln prompt
- create_security_finding_prompt(): Security-analyser finding prompt
- construct_get_target_functions_prompt(): Prompt body for vulnerable-function identification
- get_target_functions(): LLM-driven vulnerable-function identifier

Usage:
    from common.prompts import create_commit_based_prompt

    prompt = create_commit_based_prompt(
        fuzzer_code=code,
        commit_diff=diff,
        sanitizer="address",
        language="c"
    )
"""

from common.prompts.builder import (
    construct_get_target_functions_prompt,
    create_call_path_prompt,
    create_category_based_prompt_c,
    create_category_based_prompt_java,
    create_combined_call_paths_prompt,
    create_commit_based_prompt,
    create_fullscan_prompt,
    create_modified_functions_prompt,
    create_security_finding_prompt,
)
from common.prompts.targets import get_target_functions

__all__ = [
    "construct_get_target_functions_prompt",
    "create_call_path_prompt",
    "create_category_based_prompt_c",
    "create_category_based_prompt_java",
    "create_combined_call_paths_prompt",
    "create_commit_based_prompt",
    "create_fullscan_prompt",
    "create_modified_functions_prompt",
    "create_security_finding_prompt",
    "get_target_functions",
]

__version__ = "1.1.0"

# SPDX-License-Identifier: Apache-2.0
"""
Prompt Builder Functions

Builds complete prompts by combining templates with dynamic content.
All logic for variable substitution and conditional assembly is here.
"""
import os
from typing import Dict, List, Any, Optional

from common.prompts import templates


def create_commit_based_prompt(
    fuzzer_code: str,
    commit_diff: str,
    sanitizer: str,
    language: str
) -> str:
    """
    Create basic commit-based prompt for Phase 0

    Args:
        fuzzer_code: Source code of the fuzzer
        commit_diff: Git commit diff introducing the vulnerability
        sanitizer: Sanitizer type (address/memory/undefined)
        language: Programming language (c/java)

    Returns:
        Complete prompt string

    Raises:
        ValueError: If required parameters are empty
    """
    if not fuzzer_code or not commit_diff:
        raise ValueError("fuzzer_code and commit_diff cannot be empty")

    # Build base prompt
    base = templates.BASE_PROMPT.format(
        fuzzer_code=fuzzer_code,
        commit_diff=commit_diff
    )

    # Add language-specific section
    if language.startswith('c'):
        # Get sanitizer-specific guidance
        sanitizer_map = {
            "address": templates.SANITIZER_GUIDANCE_ADDRESS,
            "memory": templates.SANITIZER_GUIDANCE_MEMORY,
            "undefined": templates.SANITIZER_GUIDANCE_UNDEFINED
        }
        sanitizer_specific = sanitizer_map.get(
            sanitizer.lower(),
            templates.SANITIZER_GUIDANCE_DEFAULT
        )

        language_section = templates.C_LANGUAGE_SPECIFIC.format(
            sanitizer_specific=sanitizer_specific
        )
    else:
        language_section = templates.JAVA_LANGUAGE_SPECIFIC

    # Combine all parts
    return base + language_section + templates.PROMPT_ENDING


def create_category_based_prompt_c(
    fuzzer_code: str,
    commit_diff: str,
    sanitizer: str,
    category: str
) -> str:
    """
    Create CWE category-focused prompt for C/C++ (Phase 1)

    Args:
        fuzzer_code: Source code of the fuzzer
        commit_diff: Git commit diff
        sanitizer: Sanitizer type
        category: CWE category (e.g., "CWE-119")

    Returns:
        Category-specific prompt string
    """
    # Get category description
    category_desc = templates.CWE_DESCRIPTIONS_C.get(
        category,
        "Unknown vulnerability type"
    )

    # Build base prompt with category
    base = templates.CATEGORY_PROMPT_C_BASE.format(
        category_desc=category_desc,
        fuzzer_code=fuzzer_code,
        commit_diff=commit_diff
    )

    # Add sanitizer+category specific guidance
    # (Simplified version - full version would include detailed mappings from legacy_strategy/as0_delta.py)
    guidance = f"""
The target uses {sanitizer.capitalize()}Sanitizer to detect {category_desc}.

Focus on creating test cases that will trigger {category} errors.
Think about edge cases and boundary conditions specific to this vulnerability type.
"""

    return base + guidance + templates.PROMPT_ENDING


def create_category_based_prompt_java(
    fuzzer_code: str,
    commit_diff: str,
    sanitizer: str,
    category: str
) -> str:
    """
    Create CWE category-focused prompt for Java (Phase 1)

    Args:
        fuzzer_code: Source code of the fuzzer
        commit_diff: Git commit diff
        sanitizer: Sanitizer type
        category: CWE category (e.g., "CWE-22")

    Returns:
        Category-specific prompt string
    """
    # Get category description
    category_desc = templates.CWE_DESCRIPTIONS_JAVA.get(
        category,
        "Unknown vulnerability type"
    )

    # Build base prompt
    base = f"""You are a top software vulnerability detection expert, which helps to find vulnerabilities, in particular, {category_desc} in Java code.
The provided commit introduces a vulnerability. Your job is to find the correct input to trigger the vulnerability.

Please output a Python script that creates five blob files (name as xi.bin with i=1..5). Each blob file will be run by this fuzzer code:
{fuzzer_code}

# Commit Diff
{commit_diff}
"""

    # Add Java-specific Jazzer guidance
    guidance = f"""
The target uses Jazzer sanitizers to detect {category_desc}.

Focus on creating test cases specific to {category} vulnerabilities in Java.
Consider Java-specific attack vectors and input validation bypasses.
"""

    return base + guidance + templates.JAVA_LANGUAGE_SPECIFIC + templates.PROMPT_ENDING


def create_modified_functions_prompt(
    fuzzer_code: str,
    commit_diff: str,
    project_src_dir: str,
    modified_functions: Dict[str, Any],
    sanitizer: str,
    language: str,
    logger: Optional[Any] = None
) -> str:
    """
    Create prompt with detailed information about modified functions (Phase 2)

    Args:
        fuzzer_code: Source code of the fuzzer
        commit_diff: Git commit diff
        project_src_dir: Path to project source directory
        modified_functions: Dictionary mapping file paths to modified function data
        sanitizer: Sanitizer type
        language: Programming language
        logger: Optional logger instance

    Returns:
        Prompt with enriched function information
    """
    # Build modified files information section
    modified_files_info = "# Modified Files\n\n"

    for file_path, file_data in modified_functions.items():
        relative_path = file_path
        modified_files_info += f"## File: {relative_path}\n"

        # Try to read full source code
        added_full_source = False
        try:
            full_file_path = os.path.join(project_src_dir, relative_path)

            with open(full_file_path, 'r') as f:
                source_code = f.read()

            # Check if file is reasonable size (< 2000 lines)
            line_count = source_code.count('\n') + 1
            if line_count < 2000:
                modified_files_info += f"## Source Code:\n{source_code}\n\n"
                added_full_source = True
            elif logger:
                logger.log(f"File {full_file_path} too large: {line_count} lines")

        except Exception as e:
            if logger:
                logger.error(f"Error reading source code: {str(e)}")

        # If full source not added, show individual modified functions
        if not added_full_source:
            modified_files_info += "## Modified Functions:\n\n"

            for func in file_data.get("modified_functions", []):
                func_name = func.get("name", "unknown")
                start_line = func.get("start_line", "unknown")
                body = func.get("body", "")

                modified_files_info += f"### Function: {func_name} (Line {start_line})\n"
                modified_files_info += "```\n"
                modified_files_info += body + "\n"
                modified_files_info += "```\n\n"

    # Combine with commit diff
    enriched_diff = f"{commit_diff}\n\n{modified_files_info}"

    # Create final prompt using base function
    return create_commit_based_prompt(fuzzer_code, enriched_diff, sanitizer, language)


def create_call_path_prompt(
    fuzzer_code: str,
    commit_diff: str,
    project_src_dir: str,
    call_path: List[Dict[str, Any]],
    sanitizer: str,
    language: str
) -> str:
    """
    Create prompt with call path information (Phase 3)

    Args:
        fuzzer_code: Source code of the fuzzer
        commit_diff: Git commit diff
        project_src_dir: Path to project source directory
        call_path: List of function info dictionaries representing the call path
        sanitizer: Sanitizer type
        language: Programming language

    Returns:
        Prompt with call path visualization and details
    """
    call_path_info = "# Vulnerability Call Path\n\n"
    call_path_info += "The following call path leads to the vulnerability:\n\n"

    # Create visual call path diagram
    call_path_diagram = "## Call Sequence\n\n```\n"

    for i, node_data in enumerate(call_path):
        function_name = node_data.get('function', 'unknown')
        file_name = os.path.basename(node_data.get('file', 'unknown'))
        is_modified = node_data.get('is_modified', False)

        prefix = "→ " if i > 0 else ""
        highlight = "**" if is_modified else ""

        call_path_diagram += f"{prefix}{highlight}{function_name}(){highlight} ({file_name})\n"

        if i < len(call_path) - 1:
            call_path_diagram += "    |\n    ↓\n"

    call_path_diagram += "```\n\n"
    call_path_info += call_path_diagram

    # Add detailed function information
    call_path_info += "## Function Details\n\n"

    for i, node_data in enumerate(call_path):
        file_path = node_data.get('file', 'unknown')
        function_name = node_data.get('function', 'unknown')
        function_body = node_data.get('body', '')
        is_modified = node_data.get('is_modified', False)

        # Add modification status
        modification_status = " (**MODIFIED in commit**)" if is_modified else ""

        call_path_info += f"{i+1}. {function_name}(){modification_status}\n"
        call_path_info += f"- **File**: {file_path}\n"

        # Skip fuzzer entry points (already shown in fuzzer_code)
        if function_name in ["fuzzerTestOneInput", "LLVMFuzzerTestOneInput"]:
            call_path_info += "\n"
            continue

        # Show code for non-empty function bodies
        if function_body.strip():
            lines = function_body.strip().splitlines()
            # Truncate if too long
            if len(lines) > 100:
                function_body_text = "\n".join(lines[:100]) + "\n... (truncated for brevity)"
            else:
                function_body_text = "\n".join(lines)

            call_path_info += (
                f"- **Code**:\n```{language.lower()}\n"
                f"{function_body_text}\n```\n\n"
            )
        else:
            call_path_info += "- **Code**: (not available)\n\n"

    # Combine with commit diff
    enriched_diff = f"{commit_diff}\n\n{call_path_info}"

    # Create final prompt
    return create_commit_based_prompt(fuzzer_code, enriched_diff, sanitizer, language)


def create_combined_call_paths_prompt(
    fuzzer_code: str,
    commit_diff: str,
    project_src_dir: str,
    call_paths: List[List[Dict[str, Any]]],
    sanitizer: str,
    language: str
) -> str:
    """
    Create prompt combining multiple call paths (Phase 3 fallback)

    Args:
        fuzzer_code: Source code of the fuzzer
        commit_diff: Git commit diff
        project_src_dir: Path to project source directory
        call_paths: List of call paths (each is a list of function dictionaries)
        sanitizer: Sanitizer type
        language: Programming language

    Returns:
        Prompt with all call paths combined
    """
    all_paths_info = f"# Multiple Vulnerability Call Paths ({len(call_paths)} paths found)\n\n"
    all_paths_info += "The following call paths all lead to potential vulnerabilities:\n\n"

    # Show summary of all paths
    for idx, call_path in enumerate(call_paths, 1):
        all_paths_info += f"## Path {idx}:\n```\n"

        for i, node_data in enumerate(call_path):
            function_name = node_data.get('function', 'unknown')
            file_name = os.path.basename(node_data.get('file', 'unknown'))

            prefix = "→ " if i > 0 else ""
            all_paths_info += f"{prefix}{function_name}() ({file_name})\n"

        all_paths_info += "```\n\n"

    # Combine with commit diff
    enriched_diff = f"{commit_diff}\n\n{all_paths_info}"

    # Create final prompt
    return create_commit_based_prompt(fuzzer_code, enriched_diff, sanitizer, language)


def create_fullscan_prompt(fuzzer_code: str, suspected_vuln: Dict[str, Any]) -> str:
    """Create a full-scan prompt driven by a suspected-vulnerability record.

    Used by the full-scan POV phase to feed LLM with a hand-picked
    vulnerability candidate (file + snippet + description) rather
    than a commit diff.

    Args:
        fuzzer_code: Source of the fuzzer harness.
        suspected_vuln: Dictionary with ``filePath`` / ``snippet`` /
            ``llmRawMessage`` (description). Missing fields default to
            ``"Unknown"`` or empty string.

    Returns:
        A complete prompt ready to send to the LLM.
    """
    file_path = suspected_vuln.get("filePath", "Unknown")
    snippet = suspected_vuln.get("snippet", "")
    vuln_details = suspected_vuln.get("llmRawMessage", "")

    return f"""
You are a top software vulnerability detection expert, which helps to find vulnerabilities.
The code snippet below may contain a security vulnerability. Your job is to analyze the code and create an input that triggers the suspected vulnerability.

# Suspected Vulnerability Information
File: {file_path}
Potential vulnerability description: {vuln_details}

# Code Snippet
{snippet}


Please output a Python script that creates a x.bin file. Your blob file will be run by this fuzzer code:
{fuzzer_code}

Think through these steps:
1. Analyze the code for the vulnerability described
2. Identify how to reach and trigger the vulnerable code path
3. Understand the input processing in the harness
4. Generate inputs that will trigger the vulnerability

Limit the blob size to 2MiB max

Your output must be a Python script that creates a file named exactly "x.bin" with a detailed description of:
1. The vulnerability type
2. The target function/location
3. How your input triggers it
"""


def create_security_finding_prompt(
    fuzzer_code: str,
    finding: Dict[str, Any],
    sanitizer: str,
    language: str,
) -> str:
    """Create a POV prompt from a Claude-agent security-analyser finding.

    ``finding`` is expected to be a dict with the keys produced by the
    upstream security analyser: ``vulnerability_type``, ``location``,
    ``function``, ``description``, ``root_cause``, ``trigger_condition``,
    ``verification``, ``verified``, and optionally ``seed_input_path``.
    Missing fields default to sensible placeholders.
    """
    del sanitizer  # reserved; not currently used in the template
    vuln_type = finding.get("vulnerability_type", "unknown")
    location = finding.get("location", "unknown")
    function = finding.get("function", "")
    description = finding.get("description", "")
    root_cause = finding.get("root_cause", "")
    trigger_condition = finding.get("trigger_condition", "")
    verification = finding.get("verification", "")
    verified = finding.get("verified", False)
    seed_input_path = finding.get("seed_input_path", "")

    status = "VERIFIED" if verified else "POTENTIAL (high confidence from code analysis)"

    prompt = f"""You are a top software vulnerability expert. A security analysis has identified a {status} vulnerability.

## Vulnerability Details
- **Type**: {vuln_type}
- **Location**: {location}
- **Function**: {function}
- **Status**: {status}

## Description
{description}

## Root Cause Analysis
{root_cause}

## Trigger Condition
{trigger_condition}

## Previous Verification Attempt
{verification}
"""

    if seed_input_path and os.path.exists(seed_input_path):
        prompt += f"""
## Existing Seed Input
A seed input was created at: {seed_input_path}
You can use this as a starting point and refine it to trigger the vulnerability.
"""

    prompt += f"""
## Your Task
Create a Python script that generates a binary input file named "x.bin" that will trigger this vulnerability.

The input will be fed to this fuzzer harness:
```
{fuzzer_code}
```

## Strategy
1. Analyze the vulnerability details above - the root cause tells you exactly what pattern causes the bug
2. The trigger condition tells you what input characteristics are needed
3. Craft an input that:
   - Reaches the vulnerable function ({function})
   - Satisfies the trigger condition: {trigger_condition}
   - Causes the {vuln_type} to manifest

## Requirements
- Output ONLY a Python script that creates "x.bin"
- Maximum blob size: 2MiB
- Include comments explaining how your input triggers the vulnerability
"""

    if language.startswith("c"):
        prompt += """
## Language-Specific Notes (C/C++)
- Consider byte-level crafting for buffer overflows
- Use struct.pack for binary data
- Pay attention to null terminators, length fields, and alignment
"""
    else:
        prompt += """
## Language-Specific Notes (Java)
- Consider serialized objects if relevant
- Pay attention to class structure and field values
"""

    return prompt


def construct_get_target_functions_prompt(context_info: str, crash_log: str) -> str:
    """Build the 'identify vulnerable functions' prompt.

    Used by :func:`common.prompts.targets.get_target_functions` to ask
    the LLM which functions in the codebase correspond to the crash
    site. ``context_info`` is prior conversation with the detector
    (may be empty); ``crash_log`` is the sanitiser output.
    """
    prompt = """
Your task is to identify all potentially vulnerable functions from a code commit and a crash log.

Background:
- The commit introduces a vulnerability.
- The vulnerability is found by an expert, with a crash log.
"""

    if context_info and context_info.strip():
        prompt += f"""

CONTEXT INFORMATION (the conversation history with the vulnerability detection expert)
{context_info}"""

    prompt += f"""

CRASH LOG (this vulnerability has been found with a test):
{crash_log}

Based on the above information, please extract *all potentially* vulnerable functions in JSON format, e.g.,
{{
    "file_path1":"func_name1",
    "file_path2":"func_name2",
    ...
}}

ONLY return the JSON, no comments, and nothing else.
"""
    return prompt

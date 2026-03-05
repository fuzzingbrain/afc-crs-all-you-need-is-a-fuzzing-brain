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
    # (Simplified version - full version would include detailed mappings from jeff/as0_delta.py)
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


def create_full_scan_prompt(
    fuzzer_code: str,
    sanitizer: str,
    language: str,
    reachable_funcs: Optional[List[Dict[str, Any]]] = None,
    vulnerable_funcs: Optional[List[Dict[str, Any]]] = None,
    max_blob_mb: int = 2,
    max_total_funcs: int = 20,
    max_func_lines: int = 500,
) -> str:
    """
    Build a rich prompt for full-scan mode with reachable function analysis.

    Args:
        fuzzer_code: Source code of the fuzzer harness
        sanitizer: Sanitizer type (address/memory/undefined)
        language: Programming language (c/java)
        reachable_funcs: List of reachable function dicts with name/body
        vulnerable_funcs: LLM-scored vulnerable functions with name/reason
        max_blob_mb: Max blob size in MiB
        max_total_funcs: Max functions to include in prompt
        max_func_lines: Max lines per function body

    Returns:
        Complete full-scan prompt string
    """
    base_prompt = f"""
You are an elite software-vulnerability researcher.
The target binary is built with sanitizers; your goal is to craft **input(s)**
that crash the program (ASan/MSan/UBSan/Jazzer, etc.). The harness that feeds
data into the target looks like:

```{language}
{fuzzer_code}
```
(Study how the input is read!)
"""

    entrypoint = "fuzzerTestOneInput"
    if language.startswith('c'):
        entrypoint = "LLVMFuzzerTestOneInput"

    if reachable_funcs:
        func_snippets = []
        included_funcs = 0
        skipped_funcs = 0

        for f in reachable_funcs:
            if included_funcs >= max_total_funcs:
                skipped_funcs += 1
                continue

            name = f.get("name") or f.get("Name") or "<unknown>"
            body = (f.get("body") or f.get("Body") or
                    f.get("sourceCode") or f.get("SourceCode") or "")

            lines = body.splitlines()
            if len(lines) > max_func_lines:
                body = "\n".join(lines[:max_func_lines]) + f"\n... (truncated, total {len(lines)} lines)"

            snippet = f"### Function: {name}\n```{language}\n{body}\n```"
            func_snippets.append(snippet)
            included_funcs += 1

        funcs_block = "\n\n".join(func_snippets) if func_snippets else "<call-graph unavailable>"

        base_prompt += f"""
We have pre-analyzed the call-graph. The entry point is `{entrypoint}`.
Below are {included_funcs} reachable functions that might be risky (limited to {max_func_lines} lines each):

{funcs_block}
"""

        if skipped_funcs > 0:
            base_prompt += f"\n(Note: {skipped_funcs} additional functions were skipped to limit prompt size.)\n"

    if vulnerable_funcs:
        vf_lines = []
        for vf in vulnerable_funcs:
            name = vf.get("name") or vf.get("Name") or "<unknown>"
            reason = vf.get("reason", "").strip()
            vf_lines.append(f"- **{name}**: {reason}")
        vf_block = "\n".join(vf_lines)

        base_prompt += f"""
### Vulnerability Heuristics
Static analysis identified these functions as particularly risky:

{vf_block}
"""

    # Sanitizer guidance
    if language.startswith('c'):
        san_guide = {
            "address": (
                "AddressSanitizer reports buffer overflows, use-after-free, "
                "double-free, etc. Classic triggers:\n"
                "- Oversized length fields\n"
                "- Negative indices casted to large unsigned values\n"
                "- Strings without null-terminators\n"
            ),
            "memory": (
                "MemorySanitizer flags reads of uninitialized memory. Classic triggers:\n"
                "- Partially initialized structs\n"
                "- Checksum fields that skip bytes\n"
            ),
            "undefined": (
                "UndefinedBehaviorSanitizer catches UB: integer overflow, "
                "division by zero, invalid shift, misaligned pointers, etc.\n"
                "Classic triggers: 0-byte allocations, INT_MAX+1 lengths, "
                "null dereferences, etc.\n"
            ),
        }.get(sanitizer.lower(), "")
        language_block = f"""
### Sanitizer Focus ({sanitizer})
{san_guide}

### Recommended Plan
1. Map input bytes -> parser structure (see harness).
2. Identify a vulnerable target function.
3. Craft input to reach and exploit it.
4. Clearly comment your reasoning before writing code.
"""
    else:
        language_block = """
### Jazzer Focus
Aim to trigger vulnerabilities such as deserialization-based RCE, regex DoS, path traversal,
reflection misuse, SQL/LDAP/XPath injection, or simply crash with an exception
(NullPointerException, ArrayIndexOutOfBounds, etc.).
"""

    ending = f"""
### Deliverable
- Produce a **single Python 3 script** that writes **x.bin** (binary mode).
- If multiple candidate payloads exist, emit them all (x1.bin, x2.bin, ..., x5.bin, at most five).
- Max size per blob: **{max_blob_mb} MiB**.
- Include a concise header comment explaining the vulnerability.

Write nothing except the Python script (with embedded comments).
"""

    return base_prompt + language_block + ending


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

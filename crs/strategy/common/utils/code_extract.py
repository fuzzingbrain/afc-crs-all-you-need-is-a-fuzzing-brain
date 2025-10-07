"""
Code extraction utilities
"""
import re
import time
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from common.logging.logger import StrategyLogger
    from common.llm.client import LLMClient


def extract_code(text: str, logger: Optional['StrategyLogger'] = None) -> Optional[str]:
    """
    Extract Python code from markdown code blocks

    Args:
        text: The text containing markdown code blocks
        logger: Optional StrategyLogger for logging

    Returns:
        Extracted Python code or None if not found
    """
    pattern = r"```(?:python)?\s*([\s\S]*?)```"
    matches = re.findall(pattern, text)
    if matches:
        code = matches[0].strip()
        if logger:
            logger.debug(f"Extracted {len(code)} characters of code from markdown")
        return code
    return None


def is_python_code(text: str) -> bool:
    """
    Check if a code block is Python code (not C/Java/etc)

    This is used to identify the Python blob generation script from mixed responses
    that may contain code examples in other languages.

    Args:
        text: Code block to check

    Returns:
        True if this appears to be Python code
    """
    if not text or len(text.strip()) < 10:
        return False

    lines = text.strip().split('\n')

    # Count Python-specific indicators
    python_score = 0
    other_lang_score = 0

    # Python indicators
    python_patterns = [
        r'^\s*def\s+\w+\s*\(',           # Function definition
        r'^\s*class\s+\w+',              # Class definition
        r'^\s*import\s+\w+',             # Import statement
        r'^\s*from\s+\w+\s+import',      # From import
        r'if __name__\s*==',             # Main guard
        r'with\s+open\(',                # File operations
        r'\.write\(',                    # Write method
        r'\.encode\(',                   # Encode method
        r'#!/usr/bin/env python',        # Shebang
        r'^\s*@\w+',                     # Decorator
    ]

    # Other language indicators (actual code, not comments)
    other_lang_patterns = [
        r'^\s*#include\s*[<"]',          # C/C++ include
        r'^\s*void\s+\w+\s*\(',          # C function
        r'^\s*int\s+main\s*\(',          # C main
        r'^\s*public\s+class\s+\w+',     # Java class
        r'^\s*private\s+\w+\s+\w+\s*\(', # Java method
        r'^\s*package\s+\w+',            # Java/Go package
        r'^\s*struct\s+\w+\s*\{',        # C/Go struct
        r'^\s*typedef\s+',               # C typedef
    ]

    for line in lines:
        # Skip comment lines for other language detection
        if re.match(r'^\s*#', line):
            continue

        for pattern in python_patterns:
            if re.search(pattern, line):
                python_score += 1

        for pattern in other_lang_patterns:
            if re.search(pattern, line):
                other_lang_score += 1

    # Decision: must have Python indicators and no other language code
    return python_score > 0 and other_lang_score == 0


def extract_python_code_from_response(
    text: str,
    llm_client: 'LLMClient',
    max_retries: int = 2,
    timeout: int = 30,
    logger: Optional['StrategyLogger'] = None
) -> Optional[str]:
    """
    Extract Python code from LLM response, using LLM to re-extract if needed

    Strategy:
    1. Find all code blocks with explicit python markers (```python)
    2. Find all code blocks without language markers and validate as Python
    3. Find all code blocks and validate each one
    4. Fallback to LLM re-extraction if all fail

    Args:
        text: The text containing code to extract
        llm_client: LLM client for fallback extraction
        max_retries: Maximum number of retry attempts
        timeout: Timeout in seconds for each API call
        logger: Optional StrategyLogger for logging

    Returns:
        Extracted Python code or None if extraction failed
    """
    if logger:
        logger.log("Extracting Python code from response...")

    # Strategy 1: Look for explicitly marked Python code blocks
    python_pattern = r"```python\s+([\s\S]*?)```"
    python_matches = re.findall(python_pattern, text)

    if python_matches:
        # Take the LAST python block (most likely to be the final solution)
        candidate = python_matches[-1].strip()
        if candidate and is_python_code(candidate):
            if logger:
                logger.log(f"Extracted {len(candidate)} chars from explicit ```python block (last of {len(python_matches)})")
            return candidate
        if logger:
            logger.warning(f"Found {len(python_matches)} ```python blocks but validation failed")

    # Strategy 2: Look for all code blocks (with or without language marker)
    all_blocks_pattern = r"```(?:\w+)?\s*([\s\S]*?)```"
    all_matches = re.findall(all_blocks_pattern, text)

    if all_matches:
        if logger:
            logger.log(f"Found {len(all_matches)} total code blocks, validating each...")

        # Check each block, prioritize later blocks (more likely to be refined solutions)
        for idx in range(len(all_matches) - 1, -1, -1):
            candidate = all_matches[idx].strip()
            if candidate and is_python_code(candidate):
                if logger:
                    logger.log(f"Validated code block #{idx+1}/{len(all_matches)} as Python ({len(candidate)} chars)")
                return candidate

        if logger:
            logger.warning("None of the code blocks validated as Python code")

    # Strategy 3: Check if entire response is Python code (no markdown blocks)
    if is_python_code(text):
        if logger:
            logger.log("Entire response appears to be Python code, using directly")
        return text.strip()

    # Strategy 4: Fallback to LLM re-extraction
    if logger:
        logger.log("All direct extraction attempts failed, using LLM to re-extract...")

    prompt = (
        "Please extract ONLY the Python code from the following text. "
        "The text may contain explanations and code examples in other languages (C, Java, etc.). "
        "Find the Python script and return it wrapped in ```python ``` markdown blocks. "
        "No explanations, no comments outside the code.\n\n"
        f"Text to extract from:\n{text}"
    )
    messages = [{"role": "user", "content": prompt}]

    for attempt in range(max_retries + 1):
        try:
            if logger:
                logger.log(f"LLM re-extraction attempt {attempt+1}/{max_retries+1}")

            start_time = time.time()
            response, success = llm_client.call(messages)
            end_time = time.time()

            if logger:
                logger.log(f"LLM extraction completed in {end_time - start_time:.2f}s")

            if not success:
                if logger:
                    logger.warning(f"LLM call failed on attempt {attempt+1}")
                continue

            # Try to extract from LLM response using same strategies
            python_blocks = re.findall(r"```python\s+([\s\S]*?)```", response)
            if python_blocks:
                candidate = python_blocks[-1].strip()
                if candidate:
                    if logger:
                        logger.log(f"LLM re-extraction successful ({len(candidate)} chars)")
                    return candidate

            # Try any code blocks
            any_blocks = re.findall(r"```(?:\w+)?\s*([\s\S]*?)```", response)
            if any_blocks:
                for block in reversed(any_blocks):
                    candidate = block.strip()
                    if candidate and is_python_code(candidate):
                        if logger:
                            logger.log(f"LLM provided valid Python code ({len(candidate)} chars)")
                        return candidate

            # Direct check
            if is_python_code(response):
                if logger:
                    logger.log("LLM response is Python code, using directly")
                return response.strip()

            if logger:
                logger.warning(f"LLM re-extraction attempt {attempt+1} did not yield valid Python code")

        except Exception as e:
            if logger:
                logger.error(f"Error in LLM re-extraction attempt {attempt+1}: {e}")

    if logger:
        logger.error("Failed to extract Python code after all attempts")
    return None


def extract_function_name_from_code(code_block: str) -> Optional[str]:
    """
    Attempts to extract a function name from a code block

    Args:
        code_block: Source code block

    Returns:
        Function name if found, None otherwise
    """
    # Common patterns for function definitions in various languages
    patterns = [
        r'(?:static\s+)?(?:void|int|char|double|float|size_t|png_\w+)\s+(\w+)\s*\(',  # C/C++ style
        r'(?:static\s+)?(?:\w+)\s+(?:\*\s*)?(\w+)\s*\(',  # More general C/C++ pattern
        r'function\s+(\w+)\s*\(',  # JavaScript style
        r'def\s+(\w+)\s*\(',  # Python style
        # Java patterns
        r'(?:public|private|protected|static|final|native|synchronized|abstract|transient)?\s*(?:<.*>)?\s*(?:(?:\w+)(?:<.*>)?(?:\[\])?\s+)?(\w+)\s*\(',  # Java method
        r'(?:public|private|protected)?\s*(?:static)?\s*(?:final)?\s*(?:\w+)(?:<.*>)?\s+(\w+)\s*\(',  # Simplified Java method
    ]

    for pattern in patterns:
        match = re.search(pattern, code_block)
        if match:
            return match.group(1)

    return None


def extract_function_body(file_path: str, function_name: str) -> str:
    """
    Extract the full function body from a source file

    Supports both C/C++ and Java files. Uses brace matching to find
    complete function implementations.

    Args:
        file_path: Path to the source file
        function_name: Name of the function to extract

    Returns:
        Complete function body including declaration, or empty string if not found

    Raises:
        FileNotFoundError: If file_path does not exist
    """
    try:
        with open(file_path, 'r') as f:
            content = f.read()

        # For Java files
        if file_path.endswith('.java'):
            # Pattern: method signature + body with balanced braces
            pattern = (
                r'(?:public|private|protected|static|\s)+ +(?:[a-zA-Z0-9_<>]+) +' +
                re.escape(function_name) +
                r' *\([^)]*\) *(?:\{[^}]*\}|\{(?:\{[^}]*\}|[^{}])*\})'
            )
            match = re.search(pattern, content, re.DOTALL)
            if match:
                return match.group(0)

        # For C/C++ files
        elif file_path.endswith(('.c', '.cpp', '.h')):
            # Pattern for function declaration
            decl_pattern = (
                r'(?:(?:static|inline|extern)?\s+(?:[a-zA-Z0-9_]+\s+)*' +
                re.escape(function_name) +
                r'\s*\([^)]*\)\s*(?:\{|$))|(?:^' +
                re.escape(function_name) +
                r'\s*\([^)]*\)\s*(?:\{|$))'
            )
            decl_match = re.search(decl_pattern, content, re.MULTILINE)

            if decl_match:
                start_pos = decl_match.start()

                # Find the opening brace
                opening_brace_pos = content.find('{', start_pos)
                if opening_brace_pos == -1:
                    return ""  # Function declaration without implementation

                # Find matching closing brace using brace counting
                brace_count = 1
                pos = opening_brace_pos + 1

                while brace_count > 0 and pos < len(content):
                    if content[pos] == '{':
                        brace_count += 1
                    elif content[pos] == '}':
                        brace_count -= 1
                    pos += 1

                if brace_count == 0:
                    # Extract full function including declaration and body
                    return content[start_pos:pos]

    except FileNotFoundError:
        raise
    except Exception as e:
        # Log error but don't crash
        import logging
        logging.debug(f"Error extracting function body from {file_path}: {e}")

    return ""

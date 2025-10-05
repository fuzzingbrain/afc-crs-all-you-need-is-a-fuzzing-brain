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
    Check if the response contains Python code

    Args:
        text: Text to check

    Returns:
        True if text appears to be Python code
    """
    # Simple heuristic: check for common Python keywords
    python_keywords = ['def ', 'class ', 'import ', 'from ', 'if __name__']
    return any(keyword in text for keyword in python_keywords)


def extract_python_code_from_response(
    text: str,
    llm_client: 'LLMClient',
    max_retries: int = 2,
    timeout: int = 30,
    logger: Optional['StrategyLogger'] = None
) -> Optional[str]:
    """
    Extract Python code from LLM response, using LLM to re-extract if needed

    Args:
        text: The text containing code to extract
        llm_client: LLM client for fallback extraction
        max_retries: Maximum number of retry attempts
        timeout: Timeout in seconds for each API call
        logger: Optional StrategyLogger for logging

    Returns:
        Extracted Python code or None if extraction failed
    """
    # Quick path: try to extract directly
    quick_pattern = r"```(?:python)?\s*([\s\S]*?)```"
    m = re.search(quick_pattern, text)
    if m:
        candidate = m.group(1).strip()
        if candidate:
            if logger:
                logger.log(f"Quick-path extracted {len(candidate)} chars of code")
            return candidate

    # Fallback: use LLM to extract code
    if logger:
        logger.log("Quick extraction failed, using LLM to extract code...")

    prompt = (
        "Please extract the Python code from the following text to generate a correct exploit. "
        "Return with markdown code blocks ```python ```. No comment. No explanation.\n\n"
        f"Here is the text:\n{text}"
    )
    messages = [{"role": "user", "content": prompt}]

    for attempt in range(max_retries + 1):
        try:
            if logger:
                logger.log(f"Attempt {attempt+1}/{max_retries+1} to extract code with LLM")

            start_time = time.time()
            response, success = llm_client.call(messages)
            end_time = time.time()

            if logger:
                logger.log(f"LLM extraction call completed in {end_time - start_time:.2f} seconds")

            if not success:
                if logger:
                    logger.warning(f"LLM call failed on attempt {attempt+1}")
                continue

            # Extract code from markdown blocks
            pattern = r"```(?:python)?\s*([\s\S]*?)```"
            matches = re.findall(pattern, response)
            if matches:
                extracted_code = matches[0].strip()
                if extracted_code:
                    if logger:
                        logger.log(f"Successfully extracted {len(extracted_code)} characters of code")
                    return extracted_code
                if logger:
                    logger.warning("Extracted code block was empty")
            else:
                if logger:
                    logger.warning("No code blocks found in LLM response")

                # If no code blocks but response looks like code, return it directly
                if is_python_code(response):
                    if logger:
                        logger.log("Response appears to be Python code, returning directly")
                    return response.strip()

        except Exception as e:
            if logger:
                logger.error(f"Error extracting code on attempt {attempt+1}: {e}")

    if logger:
        logger.error("Failed to extract code after all attempts")
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

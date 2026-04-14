"""
Text processing utilities
"""
from typing import Optional, TYPE_CHECKING

# Backward-compatibility re-exports. These functions have moved to domain
# subpackages; new code should import from the canonical modules directly.
from common.code.cleanup import strip_license_text  # noqa: F401  moved to common.code.cleanup
from common.fuzzing.discovery import is_likely_source_for_fuzzer  # noqa: F401  moved to common.fuzzing.discovery
from common.fuzzing.output import filter_instrumented_lines  # noqa: F401  moved to common.fuzzing.output

if TYPE_CHECKING:
    from common.logging.logger import StrategyLogger


def truncate_output(output: str, max_lines: int = 200, logger: Optional['StrategyLogger'] = None) -> str:
    """
    Truncate output to show only the first and last parts if it's too long.

    Args:
        output: The output string to truncate
        max_lines: Maximum number of lines to show
        logger: Optional StrategyLogger for logging

    Returns:
        str: Truncated output
    """
    lines = output.split('\n')
    if len(lines) <= max_lines:
        return output

    # Show first half and last half
    first_part = lines[:max_lines//2]
    last_part = lines[-(max_lines//2):]

    if logger:
        logger.debug(f"Truncated output from {len(lines)} lines to {max_lines} lines")

    return '\n'.join(first_part) + '\n\n[...truncated...]\n\n' + '\n'.join(last_part)



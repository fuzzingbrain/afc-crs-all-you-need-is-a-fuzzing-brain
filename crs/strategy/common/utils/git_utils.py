"""
Git and diff processing utilities
"""
import os
import re
import subprocess
from typing import Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from common.logging.logger import StrategyLogger


def process_large_diff(diff_content: str, logger: Optional['StrategyLogger'] = None) -> str:
    """
    Process a large diff to extract the most relevant parts for vulnerability analysis

    Args:
        diff_content: The full diff content
        logger: Optional StrategyLogger for logging

    Returns:
        Processed diff content focusing on security-relevant changes
    """
    # Split the diff into individual file changes
    file_diffs = re.split(r'diff --git ', diff_content)

    # The first element is usually empty or contains the commit message
    if file_diffs and not file_diffs[0].strip().startswith('a/'):
        header = file_diffs[0]
        file_diffs = file_diffs[1:]
    else:
        header = ""

    # Add the 'diff --git' prefix back to each file diff except the header
    file_diffs = ["diff --git " + d if d.strip() else d for d in file_diffs]

    # Extract useful information about the diff
    total_files = len(file_diffs)
    if logger:
        logger.log(f"Diff contains changes to {total_files} files")

    # Focus only on C and Java files
    c_extensions = ['.c', '.h']
    java_extensions = ['.java']
    binary_indicators = ['Binary files', 'GIT binary patch']

    # Categorize files by language
    c_files = []
    java_files = []
    other_files = 0
    binary_files = 0

    for file_diff in file_diffs:
        if not file_diff.strip():
            continue

        # Skip binary files
        if any(indicator in file_diff for indicator in binary_indicators):
            binary_files += 1
            continue

        # Try to extract the filename
        match = re.search(r'a/([^\s]+)', file_diff)
        if not match:
            other_files += 1
            continue

        filename = match.group(1)
        ext = os.path.splitext(filename)[1].lower()

        # Categorize based on extension
        if ext in c_extensions:
            c_files.append((filename, file_diff))
        elif ext in java_extensions:
            java_files.append((filename, file_diff))
        else:
            other_files += 1

    if logger:
        logger.log(f"Categorized files: {len(c_files)} C files, {len(java_files)} Java files, "
                   f"{binary_files} binary files, {other_files} other files")

    # Security keywords specific to C and Java
    c_security_keywords = [
        'overflow', 'underflow', 'bounds', 'check', 'validate', 'sanitize', 'input',
        'malloc', 'free', 'alloc', 'realloc', 'memcpy', 'strcpy', 'strncpy', 'strlcpy',
        'buffer', 'size', 'length', 'null', 'nullptr', 'crash', 'assert',
        'error', 'vulnerability', 'exploit', 'security', 'unsafe', 'safe',
        'race', 'deadlock', 'lock', 'mutex', 'semaphore', 'atomic',
        'format', 'printf', 'sprintf', 'fprintf', 'snprintf', 'scanf', 'sscanf',
        'exec', 'system', 'popen', 'shell', 'command', 'injection',
        'crypt', 'encrypt', 'decrypt', 'hash', 'sign', 'verify',
        'random', 'prng', 'secret', 'key', 'token', 'permission',
        'privilege', 'sandbox', 'container', 'isolation',
        'sizeof', 'pointer', 'array', 'index', 'out-of-bounds',
        'integer', 'signed', 'unsigned', 'cast', 'conversion',
        'stack', 'heap', 'use-after-free', 'double-free'
    ]

    java_security_keywords = [
        'overflow', 'underflow', 'bounds', 'check', 'validate', 'sanitize', 'input',
        'buffer', 'size', 'length', 'null', 'crash', 'assert', 'exception',
        'error', 'vulnerability', 'exploit', 'security', 'unsafe', 'safe',
        'race', 'deadlock', 'lock', 'mutex', 'semaphore', 'atomic', 'concurrent',
        'format', 'printf', 'String.format', 'injection', 'sql', 'query',
        'auth', 'password', 'crypt', 'encrypt', 'decrypt', 'hash', 'sign', 'verify',
        'certificate', 'random', 'SecureRandom', 'secret', 'key', 'token', 'permission',
        'privilege', 'sandbox', 'isolation', 'escape',
        'ClassLoader', 'Reflection', 'serialization', 'deserialization',
        'XSS', 'CSRF', 'SSRF', 'XXE', 'RCE', 'JNDI', 'LDAP', 'JMX',
        'ArrayIndexOutOfBoundsException', 'NullPointerException'
    ]

    # Score C files
    scored_c_files = []
    for filename, file_diff in c_files:
        score = 0

        # Check for security keywords in the diff
        for keyword in c_security_keywords:
            score += file_diff.lower().count(keyword) * 2

        # Check for added/removed lines that might indicate security changes
        added_lines = len(re.findall(r'^\+(?!\+\+)', file_diff, re.MULTILINE))
        removed_lines = len(re.findall(r'^-(?!--)', file_diff, re.MULTILINE))
        score += (added_lines + removed_lines) // 5  # More changes = higher score

        # Bonus for certain high-risk C functions or patterns
        high_risk_c_patterns = [
            'memcpy', 'strcpy', 'strcat', 'sprintf', 'gets', 'malloc', 'free',
            'sizeof', '[', ']', '->', 'char *', 'void *', 'int *'
        ]
        for pattern in high_risk_c_patterns:
            score += file_diff.count(pattern) * 3

        scored_c_files.append((score, filename, file_diff))

    # Score Java files
    scored_java_files = []
    for filename, file_diff in java_files:
        score = 0

        # Check for security keywords in the diff
        for keyword in java_security_keywords:
            score += file_diff.lower().count(keyword) * 2

        # Check for added/removed lines that might indicate security changes
        added_lines = len(re.findall(r'^\+(?!\+\+)', file_diff, re.MULTILINE))
        removed_lines = len(re.findall(r'^-(?!--)', file_diff, re.MULTILINE))
        score += (added_lines + removed_lines) // 5  # More changes = higher score

        # Bonus for certain high-risk Java patterns
        high_risk_java_patterns = [
            'Runtime.exec', 'ProcessBuilder', 'System.load', 'URLClassLoader',
            'ObjectInputStream', 'readObject', 'Class.forName', 'reflection',
            'setAccessible', 'doPrivileged', 'native', 'JNI', 'array', 'index',
            'Exception', 'try', 'catch', 'finally', 'throw'
        ]
        for pattern in high_risk_java_patterns:
            score += file_diff.count(pattern) * 3

        scored_java_files.append((score, filename, file_diff))

    # Sort by score (highest first)
    scored_c_files.sort(reverse=True)
    scored_java_files.sort(reverse=True)

    # Build the processed diff
    processed_diff = header + "\n\n"
    processed_diff += f"# Processed diff summary: {total_files} files changed\n"

    # Determine which language to prioritize based on file counts and scores
    c_max_score = scored_c_files[0][0] if scored_c_files else 0
    java_max_score = scored_java_files[0][0] if scored_java_files else 0

    if len(c_files) > 0 and (len(java_files) == 0 or c_max_score >= java_max_score):
        # Prioritize C files
        processed_diff += f"# Showing most security-relevant changes from C files ({len(c_files)} total C files)\n\n"

        # Add the top N most relevant C files
        max_c_files = min(10, len(scored_c_files))
        for i, (score, filename, file_diff) in enumerate(scored_c_files[:max_c_files]):
            processed_diff += f"# C File {i+1}: {filename} (relevance score: {score})\n"
            processed_diff += file_diff + "\n\n"

        # Add some Java files if available and space permits
        if java_files and len(processed_diff) < 40000:
            max_java_files = min(3, len(scored_java_files))
            processed_diff += f"\n# Selected Java files ({max_java_files} of {len(java_files)})\n\n"
            for i, (score, filename, file_diff) in enumerate(scored_java_files[:max_java_files]):
                processed_diff += f"# Java File {i+1}: {filename} (relevance score: {score})\n"
                processed_diff += file_diff + "\n\n"
    else:
        # Prioritize Java files
        processed_diff += f"# Showing most security-relevant changes from Java files ({len(java_files)} total Java files)\n\n"

        # Add the top N most relevant Java files
        max_java_files = min(10, len(scored_java_files))
        for i, (score, filename, file_diff) in enumerate(scored_java_files[:max_java_files]):
            processed_diff += f"# Java File {i+1}: {filename} (relevance score: {score})\n"
            processed_diff += file_diff + "\n\n"

        # Add some C files if available and space permits
        if c_files and len(processed_diff) < 40000:
            max_c_files = min(3, len(scored_c_files))
            processed_diff += f"\n# Selected C files ({max_c_files} of {len(c_files)})\n\n"
            for i, (score, filename, file_diff) in enumerate(scored_c_files[:max_c_files]):
                processed_diff += f"# C File {i+1}: {filename} (relevance score: {score})\n"
                processed_diff += file_diff + "\n\n"

    if logger:
        logger.log(f"Processed diff size: {len(processed_diff)} bytes (original: {len(diff_content)} bytes)")

    return processed_diff


def get_commit_info(
    project_dir: str,
    language: str,
    logger: Optional['StrategyLogger'] = None
) -> Tuple[str, str]:
    """
    Get information about the commit that introduced the vulnerability

    Args:
        project_dir: Project directory path
        language: Programming language (c or java)
        logger: Optional StrategyLogger for logging

    Returns:
        Tuple of (commit_message, diff_content)
    """
    # Check if diff/ref.diff exists in the project directory
    diff_path = os.path.join(project_dir, "diff", "ref.diff")
    if os.path.exists(diff_path):
        try:
            with open(diff_path, "r") as f:
                diff_content = f.read()
            if logger:
                logger.log(f"Read diff from {diff_path}, len(diff_content): {len(diff_content)}")

            # If the diff is very large, process it to make it more manageable
            if len(diff_content) > 50000:  # More than 50KB
                if logger:
                    logger.log("Diff is large, processing to extract relevant parts...")
                processed_diff = process_large_diff(diff_content, logger)
                return "Processed commit from diff/ref.diff", processed_diff

            return "Commit from diff/ref.diff", diff_content
        except Exception as e:
            if logger:
                logger.error(f"Error reading diff file: {str(e)}")

    try:
        # Get the latest commit message and diff
        git_log = subprocess.check_output(
            ["git", "log", "-1", "--pretty=format:%h %s"],
            cwd=project_dir,
            text=True
        )

        git_diff = subprocess.check_output(
            ["git", "diff", "HEAD~1", "HEAD"],
            cwd=project_dir,
            text=True
        )

        if logger:
            logger.log(f"Latest commit: {git_log}")
        return git_log, git_diff
    except subprocess.CalledProcessError as e:
        if logger:
            logger.error(f"Error getting commit info: {str(e)}")
        return "", ""



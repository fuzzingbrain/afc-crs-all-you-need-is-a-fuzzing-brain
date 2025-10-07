"""
Git and diff processing utilities
"""
import os
import re
import json
import subprocess
from typing import Optional, Tuple, List, Dict, Any, TYPE_CHECKING

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


def extract_diff_functions_using_funtarget(
    project_src_dir: str,
    out_dir: str,
    logger: Optional['StrategyLogger'] = None
) -> Optional[List[Dict[str, Any]]]:
    """
    Extract functions modified in diff using funtarget tool

    Args:
        project_src_dir: Project source directory
        out_dir: Output directory for funtarget results
        logger: Optional StrategyLogger for logging

    Returns:
        List of function metadata dictionaries or None on failure
    """
    funtarget_output_file = os.path.join(out_dir, "funtarget_output.json")

    if os.path.exists(funtarget_output_file):
        if logger:
            logger.log(f"Found existing funtarget output: {funtarget_output_file}")
        try:
            with open(funtarget_output_file, "r") as f:
                data = json.load(f)
            return data
        except Exception as e:
            if logger:
                logger.warning(f"Failed to read funtarget output: {e}")

    if logger:
        logger.log(f"Running funtarget on {project_src_dir}")

    funtarget_path = os.path.expanduser("~/funtarget/funtarget")
    if not os.path.exists(funtarget_path):
        if logger:
            logger.warning(f"funtarget not found at {funtarget_path}, skipping diff function extraction")
        return None

    diff_path = os.path.join(project_src_dir, "..", "diff", "ref.diff")
    if not os.path.exists(diff_path):
        if logger:
            logger.warning(f"diff file not found at {diff_path}")
        return None

    try:
        cmd = [funtarget_path, diff_path, project_src_dir]
        if logger:
            logger.log(f"Running: {' '.join(cmd)}")

        result = subprocess.run(
            cmd,
            cwd=out_dir,
            capture_output=True,
            text=True,
            timeout=60
        )

        if result.returncode != 0:
            if logger:
                logger.warning(f"funtarget failed with return code {result.returncode}")
                if result.stderr:
                    logger.log(f"stderr: {result.stderr}")
            return None

        if result.stdout:
            try:
                data = json.loads(result.stdout)
                with open(funtarget_output_file, "w") as f:
                    json.dump(data, f, indent=2)
                if logger:
                    logger.log(f"Saved funtarget output to {funtarget_output_file}")
                return data
            except json.JSONDecodeError as e:
                if logger:
                    logger.warning(f"Failed to parse funtarget output as JSON: {e}")
                return None

        return None

    except subprocess.TimeoutExpired:
        if logger:
            logger.warning("funtarget timed out")
        return None
    except Exception as e:
        if logger:
            logger.error(f"Error running funtarget: {e}")
        return None


def parse_commit_diff(project_src_dir: str, commit_diff: str) -> Dict[str, Any]:
    """
    Parse a commit diff in unified diff format and extract modified functions

    Analyzes the diff to identify which functions were changed in each file,
    extracting both the function metadata and full function bodies.

    Args:
        project_src_dir: Path to the project source directory
        commit_diff: Commit diff in unified diff format

    Returns:
        Dictionary mapping file paths to modified function information:
        {
            "path/to/file.c": {
                "file_path": "path/to/file.c",
                "modified_functions": [
                    {
                        "name": "function_name",
                        "start_line": 123,
                        "body": "full function code..."
                    },
                    ...
                ]
            },
            ...
        }
    """
    from common.utils.code_extract import extract_function_body

    # Initialize result dictionary
    modified_functions = {}

    # Split the diff by file
    file_diffs = re.split(r'diff --git ', commit_diff)
    if file_diffs[0] == '':
        file_diffs = file_diffs[1:]
    else:
        file_diffs[0] = file_diffs[0].lstrip()

    for file_diff in file_diffs:
        # Skip empty diffs
        if not file_diff:
            continue

        # Extract file path
        file_path_match = re.search(r'a/(.*) b/', file_diff)
        if not file_path_match:
            continue

        file_path = file_path_match.group(1)

        # Skip test files or non-source files
        if '/test/' in file_path or not any(file_path.endswith(ext) for ext in ['.java', '.c', '.h']):
            continue

        # Check if the file exists in the project
        full_file_path = os.path.join(project_src_dir, file_path)
        if not os.path.exists(full_file_path):
            continue

        # Initialize entry for this file
        if file_path not in modified_functions:
            modified_functions[file_path] = {
                "file_path": file_path,
                "modified_functions": []
            }

        # Extract hunk headers and changed lines
        hunks = re.finditer(
            r'@@ -(\d+),(\d+) \+(\d+),(\d+) @@(.*?)(?=\n@@|\Z)',
            file_diff,
            re.DOTALL
        )

        for hunk in hunks:
            start_line = int(hunk.group(3))  # New file start line
            hunk_text = hunk.group(0)

            # Find function definitions in the hunk context
            if file_path.endswith('.java'):
                # For Java files
                function_matches = re.finditer(
                    r'(?:public|private|protected|static|\s) +(?:[a-zA-Z0-9_<>]+) +([a-zA-Z0-9_]+) *\([^)]*\) *(?:\{|throws|$)',
                    hunk_text
                )

                for match in function_matches:
                    function_name = match.group(1)

                    # Skip constructor definitions
                    if '.' in file_path:
                        class_name = file_path.split('/')[-1].split('.')[0]
                        if function_name == class_name:
                            continue

                    # Find the function's position in the hunk
                    function_pos = match.start()

                    # Count lines to get the function's start line
                    lines_before = hunk_text[:function_pos].count('\n')
                    function_start_line = start_line + lines_before

                    # Extract the function body
                    function_body = extract_function_body(full_file_path, function_name)

                    # Add to the list of modified functions (avoid duplicates)
                    existing_names = [f["name"] for f in modified_functions[file_path]["modified_functions"]]
                    if function_name not in existing_names:
                        modified_functions[file_path]["modified_functions"].append({
                            "name": function_name,
                            "start_line": function_start_line,
                            "body": function_body
                        })

            elif file_path.endswith(('.c', '.h')):
                # For C/C++ files
                # Match both standard C function definitions and function definitions with return type on separate line
                function_matches = re.finditer(
                    r'(?:(?:static|inline|extern)?\s+(?:[a-zA-Z0-9_]+\s+)*([a-zA-Z0-9_]+)\s*\([^)]*\)\s*(?:\{|$))|(?:^([a-zA-Z0-9_]+)\s*\([^)]*\)\s*(?:\{|$))',
                    hunk_text,
                    re.MULTILINE
                )

                for match in function_matches:
                    # Either group 1 or group 2 will have the function name
                    function_name = match.group(1) if match.group(1) else match.group(2)

                    # Skip if function name is None or a C keyword
                    if not function_name or function_name in ['if', 'while', 'for', 'switch', 'return']:
                        continue

                    # Find the function's position in the hunk
                    function_pos = match.start()

                    # Count lines to get the function's start line
                    lines_before = hunk_text[:function_pos].count('\n')
                    function_start_line = start_line + lines_before

                    # Extract the function body
                    function_body = extract_function_body(full_file_path, function_name)

                    # Add to the list of modified functions (avoid duplicates)
                    existing_names = [f["name"] for f in modified_functions[file_path]["modified_functions"]]
                    if function_name not in existing_names:
                        modified_functions[file_path]["modified_functions"].append({
                            "name": function_name,
                            "start_line": function_start_line,
                            "body": function_body
                        })

    return modified_functions

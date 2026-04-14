"""
Fuzzer-related utility functions
"""
import os
import re
import tarfile
from typing import Optional, List, TYPE_CHECKING

from common.fuzzing.discovery import is_likely_source_for_fuzzer
from .text_utils import strip_license_text

if TYPE_CHECKING:
    from common.logging.logger import StrategyLogger
    from common.llm.client import LLMClient


def _parse_build_scripts_for_fuzzer_source(
    build_script_contents: dict,
    fuzzer_name: str,
    project_src_dir: str,
    logger: Optional['StrategyLogger'] = None
) -> Optional[str]:
    """
    Parse build scripts (Makefile, build.sh, CMakeLists.txt) to identify the source file
    that is compiled into the fuzzer binary.

    Args:
        build_script_contents: Dict mapping script path to content
        fuzzer_name: Name of the fuzzer binary
        project_src_dir: Project source directory
        logger: Optional logger

    Returns:
        Path to the source file, or None if not found
    """
    for script_path, content in build_script_contents.items():
        script_name = os.path.basename(script_path)

        # Parse Makefile
        if script_name in ['Makefile', 'makefile', 'GNUmakefile'] or 'make' in script_path.lower():
            # Look for fuzzer target definition
            # Pattern: $(BUILD_DIR)/fuzzer_name: source_file.c
            # or: fuzzer_name.o: source_file.c
            # Handle multi-line targets with backslash continuations
            pattern1 = rf'{re.escape(fuzzer_name)}[^:]*:\s*\\?\s*([^\s]+\.(?:c|cc|cpp))'
            matches = re.finditer(pattern1, content, re.MULTILINE | re.DOTALL)
            for match in matches:
                source_file = match.group(1)
                if logger:
                    logger.log(f"Found source from Makefile pattern 1: {source_file}")
                return source_file

            # Also look for fuzzer_name on a line, followed by a source file on the next line
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if fuzzer_name in line and ':' in line:
                    # Check next few lines for source files
                    for j in range(i+1, min(i+5, len(lines))):
                        next_line = lines[j].strip()
                        if next_line and not next_line.startswith('#'):
                            # Check if line contains a source file
                            source_match = re.search(r'([^\s]+\.(?:c|cc|cpp))\s*$', next_line)
                            if source_match:
                                source_file = source_match.group(1)
                                if logger:
                                    logger.log(f"Found source from Makefile multi-line: {source_file}")
                                return source_file
                        # Stop at next target definition
                        if ':' in next_line and not next_line.startswith('\t'):
                            break

            # Look for compilation commands with fuzzer-specific flags
            # Pattern: -DFUZZER_TARGET ... -o fuzzer_name.o source_file.c
            pattern2 = rf'-D[A-Z_]*FUZZ[A-Z_]*.*?-o.*?{re.escape(fuzzer_name)}[^\s]*\s+([^\s]+\.(?:c|cc|cpp))'
            matches = re.finditer(pattern2, content, re.DOTALL)
            for match in matches:
                source_file = match.group(1)
                # Remove any leading paths from build variables
                if '$' in source_file:
                    continue
                if logger:
                    logger.log(f"Found source from Makefile pattern 2: {source_file}")
                return source_file

            # Look for lines with fuzzer name and a .c/.cc/.cpp file
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if fuzzer_name in line and ('.c' in line or '.cc' in line or '.cpp' in line):
                    # Extract potential source file
                    parts = re.findall(r'([^\s]+\.(?:c|cc|cpp))', line)
                    for part in parts:
                        if '$' not in part and part not in ['$NJS_CC', '$CC', '$CXX']:
                            if logger:
                                logger.log(f"Found source from Makefile line scan: {part}")
                            return part

        # Parse build.sh
        elif script_name == 'build.sh' or script_name.endswith('.sh'):
            # Look for compile commands
            # Pattern: $CXX ... -o $OUT/fuzzer_name source_file.cc
            pattern1 = rf'\$(?:CXX|CC).*?-o.*?{re.escape(fuzzer_name)}[^\s]*\s+([^\s]+\.(?:c|cc|cpp))'
            matches = re.finditer(pattern1, content)
            for match in matches:
                source_file = match.group(1)
                if '$' not in source_file:
                    if logger:
                        logger.log(f"Found source from build.sh pattern 1: {source_file}")
                    return source_file

            # Pattern: compile_fuzzer source_file.cc fuzzer_name
            pattern2 = rf'compile_(?:fuzzer|libfuzzer)[^\n]+([^\s]+\.(?:c|cc|cpp))[^\n]+{re.escape(fuzzer_name)}'
            matches = re.finditer(pattern2, content)
            for match in matches:
                source_file = match.group(1)
                if logger:
                    logger.log(f"Found source from build.sh pattern 2: {source_file}")
                return source_file

            # Reverse pattern: compile_fuzzer fuzzer_name source_file.cc
            pattern3 = rf'compile_(?:fuzzer|libfuzzer)[^\n]+{re.escape(fuzzer_name)}[^\n]+([^\s]+\.(?:c|cc|cpp))'
            matches = re.finditer(pattern3, content)
            for match in matches:
                source_file = match.group(1)
                if logger:
                    logger.log(f"Found source from build.sh pattern 3: {source_file}")
                return source_file

        # Parse CMakeLists.txt
        elif script_name == 'CMakeLists.txt':
            # Pattern: add_executable(fuzzer_name source_file.c)
            pattern1 = rf'add_executable\s*\(\s*{re.escape(fuzzer_name)}\s+([^\s)]+\.(?:c|cc|cpp))'
            matches = re.finditer(pattern1, content)
            for match in matches:
                source_file = match.group(1)
                if logger:
                    logger.log(f"Found source from CMakeLists pattern 1: {source_file}")
                return source_file

    return None


def find_fuzzer_source(
    fuzzer_path: str,
    project_name: str,
    project_src_dir: str,
    focus: str,
    language: str = 'c',
    test_nginx: bool = False,
    llm_client: Optional['LLMClient'] = None,
    logger: Optional['StrategyLogger'] = None
) -> str:
    """
    Find the source code of the fuzzer by analyzing build scripts and source files

    Args:
        fuzzer_path: Path to the fuzzer binary
        project_name: Name of the project
        project_src_dir: Project source directory
        focus: Focus directory name
        language: Programming language ('c', 'cpp', 'java', etc.)
        test_nginx: Whether this is NGINX testing
        llm_client: Optional LLM client for intelligent source identification
        logger: Optional logger for progress messages

    Returns:
        Source code of the fuzzer as a string
    """
    # Handle NGINX special case
    if test_nginx:
        fuzzer_path = "src/harnesses/pov_harness.cc"
        try:
            with open(fuzzer_path, 'r') as f:
                fuzzer_code = f.read()
            return fuzzer_code
        except Exception as e:
            if logger:
                logger.error(f"Error reading fuzzer code: {str(e)}")
            return ""

    fuzzer_name = os.path.basename(fuzzer_path)
    project_dir = fuzzer_path.split("/fuzz-tooling/build/out")[0] + "/"

    if logger:
        logger.log(f"Looking for source of {fuzzer_name} in {project_src_dir}")

    # FIRST: Search all source files for LLVMFuzzerTestOneInput
    # This is the most reliable method
    if logger:
        logger.log("Searching for files containing LLVMFuzzerTestOneInput...")

    extensions = ['.c', '.cc', '.cpp']
    if not language.startswith('c'):
        extensions = ['.java']

    for root, dirs, files in os.walk(project_src_dir):
        for file in files:
            if any(file.endswith(ext) for ext in extensions):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        if 'LLVMFuzzerTestOneInput' in content:
                            if logger:
                                logger.log(f"Found LLVMFuzzerTestOneInput in: {file_path}")
                            return strip_license_text(content)
                except Exception as e:
                    if logger:
                        logger.error(f"Error reading {file_path}: {str(e)}")

    # If not found, log and continue with other methods
    if logger:
        logger.log("LLVMFuzzerTestOneInput not found in any source file, trying other methods...")

    # Extract base name without _fuzzer suffix
    base_name = fuzzer_name
    if "_fuzzer" in base_name:
        base_name = base_name.replace("_fuzzer", "")

    # Collect build scripts
    build_script_paths = []
    build_script_contents = {}

    # Search in fuzz-tooling/projects/{project_name}
    project_path = os.path.join(project_dir, f"fuzz-tooling/projects/{project_name}")
    if os.path.exists(project_path):
        for root, dirs, files in os.walk(project_path):
            if "build.sh" in files:
                script_path = os.path.join(root, "build.sh")
                build_script_paths.append(script_path)
                try:
                    with open(script_path, 'r') as f:
                        build_script_contents[script_path] = f.read()
                except Exception as e:
                    if logger:
                        logger.error(f"Error reading build script {script_path}: {str(e)}")

    # Also search project source directory for Makefiles
    if os.path.exists(project_src_dir):
        for root, dirs, files in os.walk(project_src_dir):
            # Limit depth to avoid searching too deep
            depth = root[len(project_src_dir):].count(os.sep)
            if depth > 3:
                continue

            for filename in files:
                if filename in ['Makefile', 'makefile', 'GNUmakefile', 'CMakeLists.txt']:
                    script_path = os.path.join(root, filename)
                    build_script_paths.append(script_path)
                    try:
                        with open(script_path, 'r') as f:
                            content = f.read()
                            # Only include Makefiles that mention the fuzzer name
                            if fuzzer_name in content or 'fuzzer' in content.lower():
                                build_script_contents[script_path] = content
                                if logger:
                                    logger.log(f"Found relevant build script: {script_path}")
                    except Exception as e:
                        if logger:
                            logger.error(f"Error reading build script {script_path}: {str(e)}")

    # Also search in {focus} if not found
    if len(build_script_paths) == 0:
        focus_path = os.path.join(project_dir, focus)
        if os.path.exists(focus_path):
            for root, dirs, files in os.walk(focus_path):
                if "build.sh" in files:
                    script_path = os.path.join(root, "build.sh")
                    build_script_paths.append(script_path)
                    try:
                        with open(script_path, 'r') as f:
                            build_script_contents[script_path] = f.read()
                    except Exception as e:
                        if logger:
                            logger.error(f"Error reading build script {script_path}: {str(e)}")

    # Extract directories referenced in build scripts
    dirs_from_build_scripts = set()
    for script_path, content in build_script_contents.items():
        # Look for common directory patterns in build scripts
        dir_patterns = re.findall(r'(?:^|\s)([\w_]+/[\w_/]+\.(?:c|cc|cpp))', content, re.MULTILINE)
        for pattern in dir_patterns:
            dir_path = os.path.dirname(pattern)
            if dir_path:
                dirs_from_build_scripts.add(dir_path)

    if logger and dirs_from_build_scripts:
        logger.log(f"Found {len(dirs_from_build_scripts)} directories referenced in build scripts")

    # Collect potential source files
    source_files = {}
    extensions = ['.c', '.cc', '.cpp']
    if not language.startswith('c'):
        extensions = ['.java']

    # Look in directories containing build scripts
    for script_path in build_script_paths:
        script_dir = os.path.dirname(script_path)
        for root, dirs, files in os.walk(script_dir):
            for file in files:
                if any(file.endswith(ext) for ext in extensions):
                    file_path = os.path.join(root, file)
                    file_name = os.path.basename(file_path)
                    file_base = os.path.splitext(file_name)[0]

                    # If we find a likely match, return it immediately
                    if is_likely_source_for_fuzzer(file_base, fuzzer_name, base_name):
                        try:
                            with open(file_path, 'r') as f:
                                content = f.read()
                                if logger:
                                    logger.log(f"Found likely match for fuzzer source: {file_path}")
                                return strip_license_text(content)
                        except Exception as e:
                            if logger:
                                logger.error(f"Error reading likely match file {file_path}: {str(e)}")

                    try:
                        with open(file_path, 'r') as f:
                            content = f.read()
                            # Only include files that are not too large
                            if len(content) < 50000:  # Limit to ~50KB
                                source_files[file_path] = content
                    except Exception as e:
                        if logger:
                            logger.error(f"Error reading source file {file_path}: {str(e)}")

    # Also look in directories referenced in build scripts
    for dir_from_build in dirs_from_build_scripts:
        # Try both absolute and relative to project_src_dir
        for base_dir in [project_src_dir, os.path.dirname(project_src_dir)]:
            search_dir = os.path.join(base_dir, dir_from_build)
            if os.path.exists(search_dir) and os.path.isdir(search_dir):
                for file in os.listdir(search_dir):
                    if any(file.endswith(ext) for ext in extensions):
                        file_path = os.path.join(search_dir, file)
                        if file_path not in source_files:
                            try:
                                with open(file_path, 'r') as f:
                                    content = f.read()
                                    if len(content) < 50000:
                                        source_files[file_path] = content
                                        if logger:
                                            logger.log(f"Added source file from build-referenced dir: {file_path}")
                            except Exception as e:
                                if logger:
                                    logger.error(f"Error reading source file {file_path}: {str(e)}")

    # Look in pkgs/ directories and archives
    fuzz_dirs: List[str] = []
    pkgs_dir = os.path.join(project_path, "pkgs")
    if os.path.isdir(pkgs_dir):
        # 1) Already-unpacked fuzzer directories
        for entry in os.listdir(pkgs_dir):
            abs_entry = os.path.join(pkgs_dir, entry)
            if os.path.isdir(abs_entry) and "fuzzer" in entry.lower():
                fuzz_dirs.append(abs_entry)
                if logger:
                    logger.log(f"Added extracted pkg dir: {abs_entry}")

        # 2) *_fuzzer.tar.gz archives
        for entry in os.listdir(pkgs_dir):
            if entry.endswith((".tar.gz", ".tgz")) and "fuzzer" in entry.lower():
                archive_path = os.path.join(pkgs_dir, entry)
                try:
                    with tarfile.open(archive_path, "r:gz") as tar:
                        top_dirs = set(m.name.split("/")[0] for m in tar.getmembers())
                        tar.extractall(path=pkgs_dir)

                    for td in top_dirs:
                        extracted_dir = os.path.join(pkgs_dir, td)
                        if os.path.isdir(extracted_dir):
                            fuzz_dirs.append(extracted_dir)
                            if logger:
                                logger.log(f"Extracted {archive_path} into {extracted_dir}")
                        else:
                            if pkgs_dir not in fuzz_dirs:
                                fuzz_dirs.append(pkgs_dir)
                except Exception as exc:
                    if logger:
                        logger.error(f"Error extracting {archive_path}: {exc}")

    # Continue with original fuzz-directory discovery
    for script_path in build_script_paths:
        script_dir = os.path.dirname(script_path)
        fuzz_dir = os.path.join(script_dir, "fuzz")
        if os.path.exists(fuzz_dir):
            fuzz_dirs.append(fuzz_dir)

    # Look for any directory under focus path that contains "fuzz" in its name
    focus_path = os.path.join(project_dir, focus)
    if os.path.exists(focus_path):
        for root, dirs, files in os.walk(focus_path):
            # Skip very deep directories
            if root.count(os.sep) - focus_path.count(os.sep) > 5:
                continue

            # Add any directory with "fuzz" in its name
            for dir_name in dirs:
                if "fuzz" in dir_name.lower() and "CMakeFiles" not in root:
                    fuzz_dir = os.path.join(root, dir_name)
                    if fuzz_dir not in fuzz_dirs:
                        fuzz_dirs.append(fuzz_dir)
                        if logger:
                            logger.log(f"Found fuzzer directory: {fuzz_dir}")

    # Search more broadly if no fuzz directories found
    if len(fuzz_dirs) == 0:
        fuzzer_related_dirs = []
        for root, dirs, files in os.walk(project_src_dir):
            # Skip very deep directories
            if root.count(os.sep) - project_src_dir.count(os.sep) > 7:
                continue

            # Look for directories with fuzzer-related names
            for dir_name in dirs:
                lower_dir = dir_name.lower()
                if "fuzz" in lower_dir or "test" in lower_dir or "harness" in lower_dir:
                    fuzzer_dir = os.path.join(root, dir_name)
                    fuzzer_related_dirs.append(fuzzer_dir)

            # Look for directories containing fuzzer-related files
            has_fuzzer_files = False
            for file in files:
                lower_file = file.lower()
                if "fuzz" in lower_file or "_test" in lower_file or "test_" in lower_file:
                    has_fuzzer_files = True
                    break

            if has_fuzzer_files:
                fuzzer_related_dirs.append(root)

        # Add unique directories to fuzz_dirs list
        for dir_path in fuzzer_related_dirs:
            if dir_path not in fuzz_dirs:
                fuzz_dirs.append(dir_path)

    if logger:
        logger.log(f"Found {len(fuzz_dirs)} potential fuzzer-related directories")

    # Scan fuzz directories for source files
    for fuzz_dir in fuzz_dirs:
        for root, dirs, files in os.walk(fuzz_dir):
            for file in files:
                if any(file.endswith(ext) for ext in extensions):
                    file_path = os.path.join(root, file)
                    file_name = os.path.basename(file_path)
                    file_base = os.path.splitext(file_name)[0]

                    # If we find a likely match, return it immediately
                    if is_likely_source_for_fuzzer(file_base, fuzzer_name, base_name):
                        try:
                            with open(file_path, 'r') as f:
                                content = f.read()
                                if logger:
                                    logger.log(f"Found likely match for fuzzer source in fuzz directory: {file_path}")
                                return strip_license_text(content)
                        except Exception as e:
                            if logger:
                                logger.error(f"Error reading likely match file {file_path}: {str(e)}")

                    try:
                        with open(file_path, 'r') as f:
                            content = f.read()
                            if len(content) < 50000:  # Limit to ~50KB
                                source_files[file_path] = content
                    except Exception as e:
                        if logger:
                            logger.error(f"Error reading source file {file_path}: {str(e)}")

    if logger:
        logger.log(f"Collected {len(source_files)} potential source files")

    # First, try to find files containing LLVMFuzzerTestOneInput
    llvm_fuzzer_files = {}
    for file_path, content in source_files.items():
        if 'LLVMFuzzerTestOneInput' in content:
            llvm_fuzzer_files[file_path] = content
            if logger:
                logger.log(f"Found LLVMFuzzerTestOneInput in: {file_path}")

    # If we found exactly one file with LLVMFuzzerTestOneInput, return it
    if len(llvm_fuzzer_files) == 1:
        only_file_path = list(llvm_fuzzer_files.keys())[0]
        if logger:
            logger.log(f"Found single file with LLVMFuzzerTestOneInput: {only_file_path}")
        return strip_license_text(llvm_fuzzer_files[only_file_path])

    # Try to parse build scripts to find which source file is compiled as the fuzzer
    fuzzer_source_from_build = _parse_build_scripts_for_fuzzer_source(
        build_script_contents, fuzzer_name, project_src_dir, logger
    )
    if fuzzer_source_from_build:
        # Try multiple path resolutions
        possible_paths = [
            fuzzer_source_from_build,  # As-is
            os.path.join(project_src_dir, fuzzer_source_from_build),  # Relative to project_src_dir
        ]

        # Also try to find it in the repo if it's a simple filename
        if '/' not in fuzzer_source_from_build:
            # Search in common directories
            for common_dir in ['src', 'external', 'lib', 'fuzz', 'test']:
                possible_paths.append(os.path.join(project_src_dir, common_dir, fuzzer_source_from_build))

        for path in possible_paths:
            if os.path.exists(path):
                try:
                    with open(path, 'r') as f:
                        content = f.read()
                        # Verify it contains fuzzer code
                        if 'LLVMFuzzerTestOneInput' in content:
                            if logger:
                                logger.log(f"Found fuzzer source from build script: {path}")
                            return strip_license_text(content)
                        elif logger:
                            logger.warning(f"Build-identified file {path} doesn't contain LLVMFuzzerTestOneInput")
                except Exception as e:
                    if logger:
                        logger.error(f"Error reading build-identified source {path}: {str(e)}")

    # If only one source file found, return it directly
    if len(source_files) == 1:
        only_file_path = list(source_files.keys())[0]
        if logger:
            logger.log(f"Only one source file found, returning it: {only_file_path}")
        return strip_license_text(source_files[only_file_path])

    # If too many source files, filter to most likely candidates
    if len(source_files) > 20:
        filtered_source_files = {}

        # Prioritize files with names similar to the fuzzer
        for file_path, content in source_files.items():
            file_name = os.path.basename(file_path)
            if fuzzer_name in file_name or base_name in file_name:
                filtered_source_files[file_path] = content

        # If still too few, add files that mention fuzzer name in content
        if len(filtered_source_files) < 5:
            for file_path, content in source_files.items():
                if file_path not in filtered_source_files and (fuzzer_name in content or base_name in content):
                    filtered_source_files[file_path] = content
                    if len(filtered_source_files) >= 10:
                        break

        source_files = filtered_source_files
        if logger:
            logger.log(f"Filtered to {len(source_files)} most likely source files")

    # Use LLM to identify the fuzzer source if available
    if llm_client and len(source_files) > 1:
        # If we have multiple files with LLVMFuzzerTestOneInput, use LLM to pick the right one
        files_to_analyze = llvm_fuzzer_files if len(llvm_fuzzer_files) > 1 else source_files

        prompt = f"""I need to identify the source code file for a fuzzer named '{fuzzer_name}' (base name: '{base_name}').
Please analyze the following build scripts and source files to determine which file is most likely the fuzzer source.

The fuzzer binary is located at: {fuzzer_path}

BUILD SCRIPTS:
"""

        # Add build scripts to prompt (truncate if too long)
        for script_path, content in build_script_contents.items():
            truncated_content = content[:5000] + ('\n... (truncated)' if len(content) > 5000 else '')
            prompt += f"\n--- {script_path} ---\n{truncated_content}\n"

        prompt += "\nSOURCE FILES:\n"

        # Add source files to prompt with more context
        for file_path, content in files_to_analyze.items():
            lines = content.split('\n')
            # For files with LLVMFuzzerTestOneInput, show more context around it
            if 'LLVMFuzzerTestOneInput' in content:
                # Find the line with LLVMFuzzerTestOneInput
                fuzzer_line_idx = None
                for i, line in enumerate(lines):
                    if 'LLVMFuzzerTestOneInput' in line:
                        fuzzer_line_idx = i
                        break

                if fuzzer_line_idx is not None:
                    # Show 10 lines before and 30 lines after
                    start_idx = max(0, fuzzer_line_idx - 10)
                    end_idx = min(len(lines), fuzzer_line_idx + 30)
                    preview = '\n'.join(lines[start_idx:end_idx])
                    prompt += f"\n--- {file_path} ---\n{preview}\n"
                else:
                    preview = '\n'.join(lines[:50]) + ('\n... (file continues)' if len(lines) > 50 else '')
                    prompt += f"\n--- {file_path} ---\n{preview}\n"
            else:
                # For other files, show first 50 lines
                preview = '\n'.join(lines[:50]) + ('\n... (file continues)' if len(lines) > 50 else '')
                prompt += f"\n--- {file_path} ---\n{preview}\n"

        prompt += f"""
Based on the build scripts and source files above, which file is the source code for the fuzzer?
Look for:
1. Files containing LLVMFuzzerTestOneInput function
2. Files referenced in build scripts for compiling the fuzzer
3. Files with fuzzer-related compilation flags (like -DFUZZER_TARGET)

IMPORTANT: Return the SOURCE FILE path, NOT the build artifact path.
- Good: external/njs_shell.c, src/fuzzer.cc, fuzz/test_fuzzer.c
- Bad: /build/{fuzzer_name}, /out/{fuzzer_name}, build/{fuzzer_name}

The fuzzer BINARY is at: {fuzzer_path}
You need to find the SOURCE FILE that was compiled to create this binary.

Please respond with ONLY the source file path (e.g., external/shell.c or src/fuzzer.cc), nothing else.
"""

        # Call LLM to identify the fuzzer source
        messages = [{"role": "user", "content": prompt}]
        response, success = llm_client.call(messages, "gemini-2.5-flash")

        if success:
            response = response.strip()

            # Extract file path from response - try multiple patterns
            # Pattern 1: Full absolute path
            file_path_match = re.search(r'(/[^\s]+\.(?:c|cc|cpp|java))', response)
            if file_path_match:
                identified_path = file_path_match.group(1)
            else:
                # Pattern 2: Relative path or just filename
                file_path_match = re.search(r'([^\s]+\.(?:c|cc|cpp|java))', response)
                if file_path_match:
                    identified_path = file_path_match.group(1)
                else:
                    identified_path = None

            if identified_path:
                if logger:
                    logger.log(f"Model identified fuzzer source as: {identified_path}")

                # Validate: reject build artifact paths
                build_artifact_patterns = ['/build/', '/out/', 'build/' + fuzzer_name, 'out/' + fuzzer_name]
                is_build_artifact = any(pattern in identified_path for pattern in build_artifact_patterns)
                if is_build_artifact:
                    if logger:
                        logger.warning(f"Model returned build artifact path (not source): {identified_path}")
                    identified_path = None

            if identified_path:
                # Try to find this path in our source files (check basename match)
                identified_basename = os.path.basename(identified_path)
                for file_path, content in source_files.items():
                    if os.path.basename(file_path) == identified_basename:
                        if logger:
                            logger.log(f"Matched identified source to collected file: {file_path}")
                        return strip_license_text(content)

                # Check if identified path is in collected source files
                if identified_path in source_files:
                    return strip_license_text(source_files[identified_path])

                # Try to read file directly (absolute path)
                if os.path.exists(identified_path):
                    try:
                        with open(identified_path, 'r') as f:
                            content = f.read()
                            if logger:
                                logger.log("Successfully read identified fuzzer source")
                            return strip_license_text(content)
                    except Exception as e:
                        if logger:
                            logger.error(f"Error reading identified source: {str(e)}")

                # Try relative to project_src_dir
                relative_path = os.path.join(project_src_dir, identified_path)
                if os.path.exists(relative_path):
                    try:
                        with open(relative_path, 'r') as f:
                            content = f.read()
                            if logger:
                                logger.log(f"Successfully read identified fuzzer source (relative): {relative_path}")
                            return strip_license_text(content)
                    except Exception as e:
                        if logger:
                            logger.error(f"Error reading identified source: {str(e)}")

    # Fall back to name-based matching
    for file_path in source_files.keys():
        file_name = os.path.basename(file_path)
        if file_name == f"{fuzzer_name}.c" or file_name == f"{fuzzer_name}.cc" or file_name == f"{fuzzer_name}.cpp" or \
           file_name == f"{base_name}.c" or file_name == f"{base_name}.cc" or file_name == f"{base_name}.cpp" or \
           file_name == f"{fuzzer_name}.java" or file_name == f"{base_name}.java":
            if logger:
                logger.log(f"Falling back to likely fuzzer source: {file_path}")
            return strip_license_text(source_files[file_path])

    if logger:
        logger.warning("Could not identify fuzzer source")
    return "// Could not find the source code for the fuzzer"

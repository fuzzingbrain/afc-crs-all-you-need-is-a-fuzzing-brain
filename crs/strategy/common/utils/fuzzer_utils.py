"""
Fuzzer-related utility functions
"""
import os
import re
import tarfile
from typing import Optional, List, TYPE_CHECKING

from common.utils.text_utils import is_likely_source_for_fuzzer, strip_license_text

if TYPE_CHECKING:
    from common.logging.logger import StrategyLogger
    from common.llm.client import LLMClient


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
                if "fuzz" in dir_name.lower():
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
        prompt = f"""I need to identify the source code file for a fuzzer named '{fuzzer_name}' (base name: '{base_name}').
Please analyze the following build scripts and source files to determine which file is most likely the fuzzer source.

The fuzzer binary is located at: {fuzzer_path}

BUILD SCRIPTS:
"""

        # Add build scripts to prompt
        for script_path, content in build_script_contents.items():
            prompt += f"\n--- {script_path} ---\n{content}\n"

        prompt += "\nSOURCE FILES:\n"

        # Add source files to prompt
        for file_path, content in source_files.items():
            lines = content.split('\n')
            preview = '\n'.join(lines[:20]) + ('\n... (file continues)' if len(lines) > 20 else '')
            prompt += f"\n--- {file_path} ---\n{preview}\n"

        prompt += """
Based on the build scripts and source files, which file is most likely the source code for the fuzzer?
Please respond with just the full path to the file you believe is the fuzzer source code.
"""

        # Call LLM to identify the fuzzer source
        messages = [{"role": "user", "content": prompt}]
        response, success = llm_client.call(messages, "gemini-2.5-flash")

        if success:
            response = response.strip()

            # Extract file path from response
            file_path_match = re.search(r'(/[^\s]+)', response)
            if file_path_match:
                identified_path = file_path_match.group(1)
                if logger:
                    logger.log(f"Model identified fuzzer source as: {identified_path}")

                # Check if identified path is in collected source files
                if identified_path in source_files:
                    return strip_license_text(source_files[identified_path])

                # Try to read file directly
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

"""
Task and file utilities
"""
import os
import json
import shutil
import time
import glob
import select
import subprocess
from pathlib import Path
from typing import Optional, Tuple, List, TYPE_CHECKING

if TYPE_CHECKING:
    from common.logging.logger import StrategyLogger

# Constants
DETECT_TIMEOUT_CRASH_SENTINEL = "detect_timeout_crash"


def load_task_detail(fuzz_dir: str, logger: Optional['StrategyLogger'] = None) -> Optional[dict]:
    """
    Load TaskDetail from the task_detail.json file in the fuzzing directory

    Args:
        fuzz_dir: Path to the fuzzing directory
        logger: Optional StrategyLogger for logging

    Returns:
        The TaskDetail as a dictionary, or None if the file doesn't exist or can't be parsed
    """
    task_detail_path = os.path.join(fuzz_dir, "task_detail.json")

    if not os.path.exists(task_detail_path):
        if logger:
            logger.warning(f"Task detail file not found at {task_detail_path}")
        return None

    try:
        with open(task_detail_path, 'r') as f:
            task_detail = json.load(f)

        # Validate required fields
        required_fields = ["task_id", "type", "metadata", "deadline", "focus", "project_name"]
        for field in required_fields:
            if field not in task_detail:
                if logger:
                    logger.warning(f"Required field '{field}' missing from task_detail.json")

        if logger:
            logger.log(f"Successfully loaded task detail for project: {task_detail.get('project_name', 'unknown')}")
        return task_detail

    except json.JSONDecodeError as e:
        if logger:
            logger.error(f"Failed to parse task_detail.json: {str(e)}")
        return None
    except Exception as e:
        if logger:
            logger.error(f"Error loading task_detail.json: {str(e)}")
        return None


def cleanup_seed_corpus(dir_path: str, max_age_minutes: int = 10, logger: Optional['StrategyLogger'] = None):
    """
    Clean up old files in the seed corpus directory

    Args:
        dir_path: Directory path to clean
        max_age_minutes: Maximum age of files to keep in minutes
        logger: Optional StrategyLogger for logging
    """
    if not os.path.exists(dir_path):
        return

    current_time = time.time()
    max_age_seconds = max_age_minutes * 60

    try:
        for filename in os.listdir(dir_path):
            file_path = os.path.join(dir_path, filename)
            if os.path.isfile(file_path):
                file_age = current_time - os.path.getmtime(file_path)
                if file_age > max_age_seconds:
                    os.remove(file_path)
                    if logger:
                        logger.debug(f"Removed old seed file: {filename}")
    except Exception as e:
        if logger:
            logger.error(f"Error cleaning up seed corpus: {str(e)}")


def extract_and_save_crash_input(
    crash_dir: str,
    fuzzer_name: str,
    out_dir_x: str,
    project_name: str,
    sanitizer: str,
    project_dir: str,
    sanitizer_project_dir: str,
    logger: Optional['StrategyLogger'] = None
) -> Tuple[Optional[bytes], Optional[str]]:
    """
    Extract and save crash input from fuzzer output, finding the latest that actually triggers a crash

    Args:
        crash_dir: Directory containing crash files
        fuzzer_name: Name of the fuzzer executable
        out_dir_x: Output directory for this phase
        project_name: Name of the project
        sanitizer: Sanitizer type (address, memory, undefined)
        project_dir: Project directory path
        sanitizer_project_dir: Path to sanitizer-specific project directory
        logger: Optional StrategyLogger for logging

    Returns:
        Tuple of (crash_data: bytes, crash_file_path: str) or (None, None) if no valid crash found
    """

    def get_crash_files(pattern: str) -> List[str]:
        """Get all crash files matching the pattern, sorted by creation time (newest first)"""
        crash_files = glob.glob(pattern)
        crash_files.sort(key=os.path.getctime, reverse=True)
        return crash_files

    def test_crash_file(crash_file: str) -> Tuple[bool, str]:
        """Test if a crash file actually triggers a crash when run with the fuzzer"""
        if logger:
            logger.log(f"Testing crash file: {crash_file}")

        # Get just the "crashes/crash-xxx" part correctly
        if "crashes/" in crash_file:
            relative_path = "crashes/" + os.path.basename(crash_file)
        else:
            relative_path = os.path.basename(crash_file)

        # Find docker image
        docker_image = None

        # Check aixcc-afc/{project_name}
        try:
            result = subprocess.run(
                ["docker", "images", f"aixcc-afc/{project_name}", "--format", "{{.Repository}}:{{.Tag}}"],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0 and result.stdout.strip():
                docker_image = result.stdout.strip().split('\n')[0]
        except Exception as e:
            if logger:
                logger.warning(f"Failed to find docker image for aixcc-afc/{project_name}: {str(e)}")

        # If not found, check gcr.io/oss-fuzz/{project_name}
        if not docker_image:
            try:
                result = subprocess.run(
                    ["docker", "images", f"gcr.io/oss-fuzz/{project_name}", "--format", "{{.Repository}}:{{.Tag}}"],
                    capture_output=True, text=True, timeout=60
                )
                if result.returncode == 0 and result.stdout.strip():
                    docker_image = result.stdout.strip().split('\n')[0]
            except Exception as e:
                if logger:
                    logger.warning(f"Failed to find docker image for gcr.io/oss-fuzz/{project_name}: {str(e)}")

        if not docker_image:
            if logger:
                logger.error(f"Failed to find docker image for {project_name}")
            return False, ""

        if logger:
            logger.log(f"Found docker image for {project_name}: {docker_image}")

        docker_cmd = [
            "docker", "run", "--rm",
            "--platform", "linux/amd64",
            "-e", "FUZZING_ENGINE=libfuzzer",
            "-e", f"SANITIZER={sanitizer}",
            "-e", "ARCHITECTURE=x86_64",
            "-e", f"PROJECT_NAME={project_name}",
            "-v", f"{sanitizer_project_dir}:/src/{project_name}",
            "-v", f"{out_dir_x}:/out",
            "-v", f"{os.path.dirname(crash_file)}:/crashes",
            docker_image,
            f"/out/{fuzzer_name}",
            "-timeout=30",
            "-timeout_exitcode=99",
            f"/out/{relative_path}"
        ]

        try:
            if logger:
                logger.log(f"Running crash test: {' '.join(docker_cmd)}")
            result = subprocess.run(docker_cmd, capture_output=True, text=True, timeout=60)

            # Check if the output indicates a crash
            crash_indicators = [
                "==ERROR:",
                "WARNING: MemorySanitizer:",
                "SUMMARY: AddressSanitizer:",
                "Segmentation fault",
                "AddressSanitizer: heap-use-after-free",
                "AddressSanitizer: heap-buffer-overflow",
                "AddressSanitizer: SEGV",
                "UndefinedBehaviorSanitizer: undefined-behavior",
                "runtime error:",
                "AddressSanitizer:DEADLYSIGNAL",
                "Java Exception: com.code_intelligence.jazzer",
                "ERROR: HWAddressSanitizer:",
                "WARNING: ThreadSanitizer:",
                "libfuzzer exit=1"
            ]

            for indicator in crash_indicators:
                if indicator in result.stdout or indicator in result.stderr:
                    if logger:
                        logger.log(f"Crash confirmed for {crash_file}")
                    return True, result.stdout + result.stderr

            if logger:
                logger.log(f"No crash detected for {crash_file}")
            return False, ""

        except subprocess.TimeoutExpired:
            if logger:
                logger.warning(f"Timeout while testing {crash_file}")
            return False, ""
        except Exception as e:
            if logger:
                logger.error(f"Error testing crash file: {str(e)}")
            return False, ""

    # Step 1: Find all potential crash files
    crash_patterns = [os.path.join(crash_dir, "crash-*")]

    # Add timeout pattern only if DETECT_TIMEOUT_CRASH=1
    sentinel = Path(project_dir) / DETECT_TIMEOUT_CRASH_SENTINEL
    if os.environ.get("DETECT_TIMEOUT_CRASH") == "1" or sentinel.exists():
        crash_patterns.append(os.path.join(crash_dir, "timeout-*"))

    all_crash_files = []
    for pattern in crash_patterns:
        all_crash_files.extend(get_crash_files(pattern))

    if not all_crash_files:
        if logger:
            logger.log("No crash files found in any location")
        return None, None

    if logger:
        logger.log(f"Found {len(all_crash_files)} potential crash files")

    # Step 2: Test each crash file from newest to oldest
    for crash_file in all_crash_files:
        crashes, crash_output = test_crash_file(crash_file)

        if crashes:
            # Found a valid crash file
            try:
                with open(crash_file, 'rb') as f:
                    crash_data = f.read()
                    if crash_data:
                        if logger:
                            logger.log(f"Found valid crash data in: {crash_file}")
                        return crash_data, crash_file
            except Exception as e:
                if logger:
                    logger.error(f"Error reading crash file {crash_file}: {str(e)}")
                continue

    if logger:
        logger.log("No valid crash files found that trigger crashes")
    return None, None


def run_fuzzer_with_coverage(
    fuzzer_path: str,
    project_dir: str,
    focus: str,
    sanitizer: str,
    project_name: str,
    seed_corpus_dir: str,
    pov_phase: int,
    logger: Optional['StrategyLogger'] = None
) -> Tuple[bool, str, str, Optional[bytes]]:
    """
    Run the fuzzer with seed corpus and collect coverage information

    Args:
        fuzzer_path: Path to fuzzer executable
        project_dir: Project directory
        focus: Focus area (e.g., project component)
        sanitizer: Sanitizer type (address, memory, undefined)
        project_name: Name of the project
        seed_corpus_dir: Directory containing seed corpus files
        pov_phase: POV phase number (for output directory naming)
        logger: Optional StrategyLogger for logging

    Returns:
        Tuple of (crash_detected: bool, fuzzer_output: str, coverage_output: str, crash_input: bytes or None)
    """
    
    def _log_fuzzer_output(combined_output: str, max_line_length: int = 200):
        """Log fuzzer output (first and last 200 lines)"""
        lines = combined_output.splitlines()
        
        # Get first 200 lines and truncate each line if too long
        start_lines = []
        for line in lines[:200]:
            if len(line) > max_line_length:
                truncated = line[:max_line_length] + f" ... (truncated, full length: {len(line)})"
                start_lines.append(truncated)
            else:
                start_lines.append(line)
        
        # Get last 200 lines and truncate each line if too long
        end_lines = []
        if len(lines) > 200:
            for line in lines[-200:]:
                if len(line) > max_line_length:
                    truncated = line[:max_line_length] + f" ... (truncated, full length: {len(line)})"
                    end_lines.append(truncated)
                else:
                    end_lines.append(line)
        
        # Log the output
        start_output = '\n'.join(start_lines)
        end_output = '\n'.join(end_lines)

        if logger:
            logger.log(f"Fuzzer output START (first 200 lines):\n{start_output}")
            if len(lines) > 200:
                logger.log(f"\n... ({len(lines) - 400} lines skipped) ...\n")
            if end_lines:
                logger.log(f"Fuzzer output END (last 200 lines):\n{end_output}")

    try:
        if logger:
            logger.log(f"Running fuzzer {fuzzer_path} with {seed_corpus_dir}")
        
        # Get the directory containing the fuzzer
        fuzzer_name = os.path.basename(fuzzer_path)
        sanitizer_project_dir = os.path.join(project_dir, focus)
        out_dir = os.path.dirname(fuzzer_path)
        out_dir_x = os.path.join(out_dir, f"ap{pov_phase}")

        work_dir = os.path.join(project_dir, "fuzz-tooling", "build", "work", f"{project_name}-{sanitizer}")
        
        # Create a directory for crash inputs if it doesn't exist
        crash_dir = os.path.join(out_dir_x, "crashes")
        os.makedirs(crash_dir, exist_ok=True)
        
        corpus_container_path = "/corpus"
        
        # Set a shorter timeout for the fuzzer itself to ensure we get coverage output
        # Make this less than the subprocess timeout
        fuzzer_timeout = 55  # 55 seconds for the fuzzer
        subprocess_timeout = 60  # 60 seconds for the subprocess

        # Find docker image: try aixcc-afc first, then gcr.io/oss-fuzz
        docker_image = None

        # Check aixcc-afc/{project_name}
        try:
            result = subprocess.run(
                ["docker", "images", f"aixcc-afc/{project_name}", "--format", "{{.Repository}}:{{.Tag}}"],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0 and result.stdout.strip():
                docker_image = result.stdout.strip().split('\n')[0]
        except Exception as e:
            if logger:
                logger.warning(f"Failed to find docker image for aixcc-afc/{project_name}: {str(e)}")

        # If not found, check gcr.io/oss-fuzz/{project_name}
        if not docker_image:
            try:
                result = subprocess.run(
                    ["docker", "images", f"gcr.io/oss-fuzz/{project_name}", "--format", "{{.Repository}}:{{.Tag}}"],
                    capture_output=True, text=True, timeout=60
                )
                if result.returncode == 0 and result.stdout.strip():
                    docker_image = result.stdout.strip().split('\n')[0]
            except Exception as e:
                if logger:
                    logger.warning(f"Failed to find docker image for gcr.io/oss-fuzz/{project_name}: {str(e)}")

        if not docker_image:
            if logger:
                logger.error(f"Failed to find docker image for {project_name}")
            return False, "", "", None
        
        if logger:
            logger.log(f"Found docker image for {project_name}: {docker_image}")

        docker_cmd = [
            "docker", "run", "--rm",
            "--platform", "linux/amd64",
            "-e", "FUZZING_ENGINE=libfuzzer",
            "-e", f"SANITIZER={sanitizer}",
            "-e", "ARCHITECTURE=x86_64",
            "-e", f"PROJECT_NAME={project_name}",
            "-v", f"{sanitizer_project_dir}:/src/{project_name}",
            "-v", f"{out_dir_x}:/out",
            "-v", f"{work_dir}:/work",
            "-v", f"{seed_corpus_dir}:{corpus_container_path}",
            docker_image,
            f"/out/{fuzzer_name}",
            "-print_coverage=1",
            f"-max_total_time={fuzzer_timeout}",
            "-max_len=262144",
            "-verbosity=0",
            "-detect_leaks=0",
            "-artifact_prefix=/out/crashes/",
            corpus_container_path,
        ]

        if logger:
            logger.log(f"Running Docker command: {' '.join(docker_cmd)}")
        
        # Use a process with pipes to capture output in real-time
        process = subprocess.Popen(
            docker_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8",
            errors="backslashreplace",
            text=True,
            bufsize=1
        )
        
        stdout_data = []
        stderr_data = []
        
        start_time = time.time()
        timed_out = False
        
        # Read output until process completes or times out
        while process.poll() is None:
            # Check if we've exceeded our timeout
            if time.time() - start_time > subprocess_timeout:
                if logger:
                    logger.log("Subprocess timeout reached, terminating process")
                process.terminate()
                timed_out = True
                # Give it a moment to terminate gracefully
                time.sleep(10)
                if process.poll() is None:
                    process.kill()
                break
                
            # Check if there's data to read (with a small timeout)
            reads = [process.stdout, process.stderr]
            readable, _, _ = select.select(reads, [], [], 0.1)
            
            for stream in readable:
                line = stream.readline()
                if line.startswith("Error: in prepare") or "unknown option" in line:
                   continue  # skip parse errors
                if line:
                    if stream == process.stdout:
                        stdout_data.append(line)
                    else:
                        stderr_data.append(line)
        
        # Get any remaining output
        stdout, stderr = process.communicate()
        if stdout:
            stdout_data.append(stdout)
        if stderr:
            stderr_data.append(stderr)
            
        stdout_text = ''.join(stdout_data)
        stderr_text = ''.join(stderr_data)
        combined_output = stdout_text + "\n" + stderr_text
        
        # Filter out REDUCE lines from fuzzer output
        filtered_output_lines = []
        max_line_length = 200
        for line in combined_output.split('\n'):
            # Check if line starts with # followed by a number (fuzzer progress lines)
            if line.strip().startswith('#') and any(x in line for x in ["REDUCE cov:", "INITED cov:", "NEW    cov:"]):
                # Only keep NEW lines that contain NEW_FUNC (important function discoveries)
                if "NEW_FUNC" in line:
                    filtered_output_lines.append(line)
            elif len(line) > max_line_length:
                truncated = line[:max_line_length] + f" ... (truncated, full length: {len(line)})"
                filtered_output_lines.append(truncated)
            else:
                if not line.lstrip().startswith("WARNING:"):
                    filtered_output_lines.append(line)
        
        filtered_output = '\n'.join(filtered_output_lines)
        
        # Extract coverage information
        coverage_output = ""
        fuzzer_output = filtered_output

        _log_fuzzer_output(fuzzer_output)

        # Check if "COVERAGE:" is in the output
        if "COVERAGE:" in filtered_output:
            parts = filtered_output.split("COVERAGE:", 1)
            fuzzer_output = parts[0].strip()
            full_coverage = parts[1].strip()
            
            # Process coverage output to make it more concise
            coverage_lines = full_coverage.split('\n')
            condensed_coverage_lines = []
            
            # Keep track of covered and uncovered functions
            covered_funcs = []
            uncovered_funcs = []
            
            current_func = None
            seen_uncovered_pcs = set()  # Track unique uncovered PCs to avoid duplicates
            
            for line in coverage_lines:
                if line.startswith("COVERED_FUNC:") and "/src/" in line:
                    current_func = line
                    covered_funcs.append(line)
                    condensed_coverage_lines.append(line)
                elif line.startswith("UNCOVERED_FUNC:") and "/src/" in line:
                    uncovered_funcs.append(line)
                    # Don't add to condensed output yet
                elif line.startswith("  UNCOVERED_PC:"):
                    # Skip lines with line number 0
                    if ":0" in line or not line.startswith("  UNCOVERED_PC: /src/"):
                        continue
                    
                    # Only add unique uncovered PCs and limit to 3 per function
                    if (line not in seen_uncovered_pcs and 
                        current_func and 
                        sum(1 for l in condensed_coverage_lines if l.startswith("  UNCOVERED_PC:")) < 3):
                        seen_uncovered_pcs.add(line)
                        condensed_coverage_lines.append(line)

            # Add a summary of uncovered functions
            condensed_coverage_lines.append(f"\nUNCOVERED FUNCTIONS SUMMARY: {len(uncovered_funcs)} functions")
            # Add first 10 uncovered functions as examples
            for func in uncovered_funcs[:10]:
                condensed_coverage_lines.append(func)
            if len(uncovered_funcs) > 10:
                condensed_coverage_lines.append(f"... and {len(uncovered_funcs) - 10} more uncovered functions")
            
            coverage_output = "COVERAGE:\n" + '\n'.join(condensed_coverage_lines)
        
        # Check if the fuzzer crashed
        crash_detected = False
        crash_input = None
        
        if logger:
            logger.log(f"Fuzzer exited with returncode: {process.returncode}")
        
        if "runtime error:" in combined_output:
            timed_out = False

        if process.returncode == 77 and "Java Exception: java.lang.NoClassDefFoundError:" in combined_output:
            if logger:
                logger.log(f"Fuzzer exited with non-zero code {process.returncode}, but no crash indicators found")
        elif (process.returncode != 0 and not timed_out) or "ABORTING" in combined_output:
            # Check for actual crash indicators vs warnings
            if any(indicator in combined_output for indicator in [
                "ERROR: AddressSanitizer:",
                "ERROR: MemorySanitizer:",
                "WARNING: MemorySanitizer:",
                "ERROR: ThreadSanitizer:",
                "ERROR: UndefinedBehaviorSanitizer:",
                "SEGV on unknown address",
                "Segmentation fault",
                "runtime error:",
                "AddressSanitizer: heap-buffer-overflow",
                "AddressSanitizer: heap-use-after-free",
                "UndefinedBehaviorSanitizer: undefined-behavior",
                "AddressSanitizer:DEADLYSIGNAL",
                "Java Exception: com.code_intelligence.jazzer",
                "ERROR: HWAddressSanitizer:",
                "WARNING: ThreadSanitizer:",
                "libfuzzer exit=1"
            ]):
                if logger:
                    logger.log(f"Fuzzer crashed with exit code {process.returncode} - potential vulnerability triggered!")
                crash_detected = True
                
                # Extract and save the crash input
                crash_input, crash_input_filepath = extract_and_save_crash_input(
                    crash_dir, fuzzer_name, out_dir_x, project_name, 
                    sanitizer, project_dir, sanitizer_project_dir, logger
                )
            else:
                if logger:
                    logger.log(f"Fuzzer exited with non-zero code {process.returncode}, but no crash indicators found")
        elif timed_out:
            if logger:
                logger.log("Fuzzer execution timed out, but we captured available output")
            fuzzer_output = "Execution timed out, partial output:\n" + fuzzer_output
        else:
            if logger:
                logger.log("Fuzzer ran successfully without crashing")
        
        return crash_detected, fuzzer_output, coverage_output, crash_input
    
    except Exception as e:
        if logger:
            logger.error(f"Error running fuzzer: {str(e)}")
        return False, str(e), "", None

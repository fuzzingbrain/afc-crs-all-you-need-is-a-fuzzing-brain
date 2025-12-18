#!/usr/bin/env python3
"""
AS0 Delta Strategy - Advanced multi-phase POV generation

Multi-phase strategy with different prompt approaches:
- Phase 0: Basic commit-based (similar to XS0)
- Phase 1: Vulnerability category-based
- Phase 2: Modified functions-based
- Phase 3: Call path analysis-based
- Phase 4: Input sequence generation (TODO)
"""
import os
import sys
import uuid
import time
import shutil
import subprocess
import random
from typing import Dict, Any, Tuple, List, Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from core.pov_strategy import PoVStrategy
from common.config import StrategyConfig
from common.logging.logger import StrategyLogger
from common.llm.client import LLMClient
from common.llm.models import CLAUDE_MODEL_SONNET_45, OPENAI_MODEL_O3
from common.prompts import create_commit_based_prompt
from common.utils import (
    filter_instrumented_lines,
    truncate_output,
    extract_crash_output,
    generate_vulnerability_signature,
    cleanup_seed_corpus,
)
from code_analysis import CoverageAnalyzer


# Vulnerability categories for Phase 1
VUL_CATEGORIES_C = [
    "CWE-119",  # Buffer Overflow
    "CWE-416",  # Use After Free
    "CWE-476",  # NULL Pointer Dereference
    "CWE-190",  # Integer Overflow
    "CWE-122",  # Heap-based Buffer Overflow
    "CWE-787",  # Out-of-bounds Write
    "CWE-125",  # Out-of-bounds Read
    "CWE-134",  # Format String
    "CWE-369"   # Divide by Zero
]

VUL_CATEGORIES_JAVA = [
    "CWE-22",   # Path Traversal
    "CWE-77",   # Command Injection
    "CWE-78",   # OS Command Injection
    "CWE-601",  # Path Traversal (URL)
    "CWE-79",   # Cross-Site Scripting (XSS)
    "CWE-89",   # SQL Injection
    "CWE-200",  # Information Exposure
    "CWE-306",  # Missing Authentication
    "CWE-502",  # Deserialization
    "CWE-611",  # XXE Processing
    "CWE-776",  # Recursive Entity References
    "CWE-400",  # Resource Consumption
    "CWE-755",  # Exception Handling
    "CWE-347",  # Cryptographic Verification
    "CWE-918"   # Server-Side Request Forgery (SSRF)
]


class AS0DeltaStrategy(PoVStrategy):
    """
    AS0 Delta Strategy: Advanced multi-phase POV generation

    Generates 5 blob files (x1.bin - x5.bin) per iteration.
    Supports multiple phases with different prompt strategies.
    """

    # System prompt for LLM guidance
    SYSTEM_PROMPT = "You are a security expert specializing in vulnerability detection."

    def get_strategy_name(self) -> str:
        """Return strategy name for logging"""
        return "as0_delta"

    def create_initial_prompt(self, fuzzer_code: str, commit_diff: str) -> str:
        """
        Override parent method to use AS0-specific prompt (generates 5 blobs: x1.bin - x5.bin)

        Args:
            fuzzer_code: Source code of the fuzzer
            commit_diff: Commit diff introducing the vulnerability

        Returns:
            Initial prompt string for LLM
        """
        return create_commit_based_prompt(
            fuzzer_code=fuzzer_code,
            commit_diff=commit_diff,
            sanitizer=self.config.sanitizer,
            language=self.config.language
        )

    def execute_core_logic(self) -> bool:
        """
        Override to save fuzzer_code and commit_diff for Phase 1-3
        """
        self.logger.log("Starting POV generation...")

        # Find fuzzer source code
        self.fuzzer_code = self.find_fuzzer_source()
        if not self.fuzzer_code:
            self.logger.error("Failed to find fuzzer source code")
            return False

        # Get commit information
        from common.utils import get_commit_info
        commit_msg, self.commit_diff = get_commit_info(
            self.config.project_dir,
            self.config.language,
            logger=self.logger
        )

        # Create initial prompt (for Phase 0, Phase 1-3 will override)
        initial_msg = self.create_initial_prompt(self.fuzzer_code, self.commit_diff)

        # Execute POV generation loop
        success, metadata = self.do_pov(initial_msg)

        return success

    def do_pov(self, initial_msg: str) -> Tuple[bool, Dict[str, Any]]:
        """
        AS0 POV generation with multi-phase support

        Args:
            initial_msg: Initial prompt for LLM

        Returns:
            Tuple of (success: bool, metadata: dict)
        """
        pov_phase = self.config.pov_phase
        self.logger.log(f"POV_PHASE: {pov_phase} AS0 Delta Strategy")

        # Route to appropriate phase handler
        if pov_phase == 0:
            return self._do_pov_phase_0(initial_msg)
        elif pov_phase == 1:
            return self._do_pov_phase_1(initial_msg)
        elif pov_phase == 2:
            return self._do_pov_phase_2(initial_msg)
        elif pov_phase == 3:
            return self._do_pov_phase_3(initial_msg)
        elif pov_phase == 4:
            self.logger.log(f"POV_PHASE: {pov_phase} TODO: input sequence generation")
            return False, {}
        else:
            self.logger.error(f"POV_PHASE: {pov_phase} does not exist")
            return False, {}

    def _do_pov_phase_0(self, initial_msg: str, max_iterations: Optional[int] = None, models: Optional[List[str]] = None) -> Tuple[bool, Dict[str, Any]]:
        """
        Phase 0: Basic commit-based POV generation (similar to XS0)

        Args:
            initial_msg: Initial prompt for LLM
            max_iterations: Override max iterations (defaults to config value)
            models: Override models to try (defaults to config value)

        Returns:
            Tuple of (success: bool, metadata: dict)
        """
        pov_id = str(uuid.uuid4())[:8]

        if self.config.check_patch_success:
            self.logger.log("Will check for successful patches periodically")

        start_time = time.time()
        end_time = start_time + (self.config.fuzzing_timeout_minutes * 60)

        print(f"start_time: {start_time} end_time: {end_time} FUZZING_TIMEOUT_MINUTES: {self.config.fuzzing_timeout_minutes}")
        self.logger.log(f"POV generation timeout: {self.config.fuzzing_timeout_minutes} minutes")

        found_pov = False
        successful_pov_metadata = {}

        # Use provided values or fall back to config
        actual_max_iterations = max_iterations if max_iterations is not None else self.config.max_iterations
        actual_models = models if models is not None else self.config.models

        # Try with different models
        for model_name in actual_models:
            self.logger.log(f"Attempting POV generation with model: {model_name}")

            # Initialize messages with system prompt and user message
            messages = [
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": initial_msg}
            ]
            model_success_count = 0

            for iteration in range(1, actual_max_iterations + 1):
                current_time = time.time()
                if current_time > end_time:
                    self.logger.log(f"Timeout reached after {iteration-1} iterations with {model_name}")
                    break

                # Check for successful patches if enabled
                if self.config.check_patch_success:
                    if self.check_for_successful_patches():
                        self.logger.log("Successful patch detected, stopping POV generation")
                        return True, {}

                # Check if POV already exists
                if self.has_successful_pov():
                    self.logger.log("Successful POV already exists")
                    return True, {}

                self.logger.log(f"Iteration {iteration} with {model_name}")

                # Generate POV code using LLM
                code = self.generate_pov(messages, model_name)

                if not code:
                    self.logger.warning("No valid Python code generated, continuing to next iteration")
                    messages.append({"role": "user", "content": "No valid Python code generated, please try again"})
                    continue

                # Create unique directory for this iteration
                unique_id = str(uuid.uuid4())[:8]
                xbin_dir = os.path.join(self.config.project_dir, f"ap{self.config.pov_phase}", unique_id)
                os.makedirs(xbin_dir, exist_ok=True)
                self.logger.log(f"Created xbin_dir: {xbin_dir}")

                # Generate blob files (x1.bin - x5.bin)
                try:
                    blob_paths = self.generate_blobs(code, xbin_dir)
                except Exception as e:
                    self.logger.error(f"Failed to generate blobs: {str(e)}")
                    messages.append({
                        "role": "user",
                        "content": f"Python code failed with error: {str(e)}\n\nPlease try again."
                    })
                    continue

                if not blob_paths:
                    self.logger.warning("No blobs generated")
                    messages.append({
                        "role": "user",
                        "content": "Python code failed to create blob files, please try again."
                    })
                    continue

                # Test each blob file
                crash_found_in_blob = False
                for blob_num, blob_file in enumerate([f"x{i}.bin" for i in range(1, 6)], 1):
                    blob_path = os.path.join(xbin_dir, blob_file)
                    if not os.path.exists(blob_path):
                        self.logger.log(f"Blob file {blob_file} does not exist, skipping...")
                        continue

                    self.logger.log(f"Testing blob {blob_file}...")

                    # Run fuzzer with generated blob (DO NOT FILTER YET - needed for race condition check)
                    crash_detected, fuzzer_output = self.run_fuzzer([blob_path])

                    if not crash_detected:
                        # No crash - save to seed corpus
                        self.logger.log(f"Blob {blob_file} did not trigger a crash, trying next blob...")

                        seed_corpus_dir = os.path.join(
                            self.config.project_dir,
                            f"{self.config.fuzzer_name}_seed_corpus"
                        )
                        os.makedirs(seed_corpus_dir, exist_ok=True)
                        cleanup_seed_corpus(seed_corpus_dir, max_age_minutes=10, logger=self.logger)

                        unique_id = str(uuid.uuid4())[:8]
                        seed_file_path = os.path.join(
                            seed_corpus_dir,
                            f"seed_{model_name}_{iteration}_{unique_id}.bin"
                        )
                        shutil.copy(blob_path, seed_file_path)
                        self.logger.log(f"Saved test case to seed corpus: {seed_file_path}")
                        os.remove(blob_path)
                        continue
                    else:
                        # Crash detected! Set flag and break blob loop
                        found_pov = True
                        crash_found_in_blob = True
                        break  # Break from blob loop only

                # If no crash in any blob, run fuzzer with coverage
                if not found_pov:
                    self.logger.log("Trying libfuzzer print_coverage running for 60s")

                    # Run fuzzer with coverage using seed corpus
                    from common.utils import run_fuzzer_with_coverage

                    seed_corpus_dir = os.path.join(
                        self.config.project_dir,
                        f"{self.config.fuzzer_name}_seed_corpus"
                    )

                    found_pov, fuzzer_output, coverage_output, blob_data = run_fuzzer_with_coverage(
                        fuzzer_path=self.config.fuzzer_path,
                        project_dir=self.config.project_dir,
                        focus=self.config.focus,
                        sanitizer=self.config.sanitizer,
                        project_name=self.config.project_name,
                        seed_corpus_dir=seed_corpus_dir,
                        pov_phase=self.config.pov_phase,
                        logger=self.logger
                    )

                    # If coverage fuzzing found a crash with blob_data, save it
                    if blob_data:
                        unique_id = str(uuid.uuid4())
                        blob_filename = f"blob_{self.config.sanitizer}_{unique_id}.bin"
                        blob_path = os.path.join(xbin_dir, blob_filename)
                        with open(blob_path, 'wb') as f:
                            f.write(blob_data)
                        self.logger.log(f"Saved blob data to: {blob_path}")
                    else:
                        blob_path = None
                        found_pov = False

                # Race condition check (applies to both blob and coverage POVs)
                if found_pov and "NOTE: fuzzing was not performed" in fuzzer_output:
                    self.logger.log(f"Weird race condition! found_pov is True but fuzzer_output is: {fuzzer_output}")
                    found_pov = False

                # Process POV if found (from either blob or coverage fuzzing)
                if found_pov and blob_path:
                    crash_output = extract_crash_output(fuzzer_output)
                    vuln_signature = self.config.fuzzer_name + "-" + generate_vulnerability_signature(crash_output, self.config.sanitizer)

                    # Save POV metadata
                    pov_metadata = self.save_pov_artifacts(
                        pov_id, model_name, iteration,
                        code, blob_path, fuzzer_output, messages
                    )

                    # Submit POV
                    submission_result = self.submit_pov(pov_metadata)
                    if submission_result or True:  # For local test w/o submission endpoint
                        successful_pov_metadata = pov_metadata
                        self.logger.log(f"POV SUCCESS! Vulnerability triggered with {model_name} on iteration {iteration}")
                        break  # Break from iteration loop

                else:
                    # No POV found - filter output and provide feedback
                    fuzzer_output = filter_instrumented_lines(fuzzer_output)

                    if iteration == 1:
                        user_message = f"""
Fuzzer output:
{truncate_output(fuzzer_output, 500)}

Fuzzer coverage after running 60s with the blob files as seeds:
{truncate_output(coverage_output, 2000)}

The test cases did not trigger the vulnerability. Please analyze the fuzzer output and try again with an improved approach. Consider:
1. Different input formats or values
2. Edge cases that might trigger the vulnerability
3. Focusing on the specific functions modified in the commit
4. Pay attention to details
5. Think step by step
"""
                    else:
                        user_message = f"""
Fuzzer output:
{truncate_output(fuzzer_output, 200)}

The test cases did not trigger the vulnerability. Please analyze the fuzzer output and try again with a different approach.
"""

                    if iteration == actual_max_iterations - 1:
                        user_message += "\nThis is your last attempt. This task is very very important to me. If you generate a successful blob, I will tip you 2000 dollars."

                    # Add control flow feedback if enabled
                    if hasattr(self.config, 'use_control_flow') and self.config.use_control_flow:
                        # Get all generated blobs for coverage analysis
                        all_blobs = []
                        for i in range(1, 6):
                            test_blob = os.path.join(xbin_dir, f"x{i}.bin")
                            if os.path.exists(test_blob):
                                all_blobs.append(test_blob)
                        if all_blobs:
                            coverage_analyzer = CoverageAnalyzer(self.config, self.logger)
                            control_flow_feedback = coverage_analyzer.get_coverage_feedback(all_blobs[-1])
                            if control_flow_feedback:
                                user_message += control_flow_feedback

                    messages.append({"role": "user", "content": user_message})

            # If found POV with this model, break from model loop
            if found_pov:
                break

        # Final summary
        total_time = time.time() - start_time
        self.logger.log(f"AS0 Delta Phase 0 completed in {total_time:.2f} seconds")

        # Check if any successful POVs were found
        if os.path.exists(self.config.pov_success_dir):
            pov_files = [f for f in os.listdir(self.config.pov_success_dir) if f.startswith("pov_metadata_")]
            if pov_files:
                self.logger.log(f"Found {len(pov_files)} successful POVs")
                return True, successful_pov_metadata

        self.logger.log("No successful POVs found")
        return False, {}

    def _do_pov_phase_1(self, initial_msg: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Phase 1: Vulnerability category-based POV generation

        Tries different CWE categories with randomized order.
        Uses reduced iterations (3) compared to Phase 0.
        """
        self.logger.log("Phase 1: Vulnerability category-based approach")

        # Import prompt builders
        from common.prompts import (
            create_category_based_prompt_c,
            create_category_based_prompt_java
        )

        # Select categories based on language
        if self.config.language.startswith('c'):
            categories = VUL_CATEGORIES_C[:]
            prompt_builder = create_category_based_prompt_c
            self.logger.log(f"Using C vulnerability categories ({len(categories)} types)")
        else:
            categories = VUL_CATEGORIES_JAVA[:]
            prompt_builder = create_category_based_prompt_java
            self.logger.log(f"Using Java vulnerability categories ({len(categories)} types)")

        # Randomize order to avoid bias
        random.shuffle(categories)

        # Try each category
        for idx, category in enumerate(categories, 1):
            self.logger.log(f"[{idx}/{len(categories)}] Trying category: {category}")

            # Generate category-specific prompt using common.prompts
            category_prompt = prompt_builder(
                fuzzer_code=self.fuzzer_code,
                commit_diff=self.commit_diff,
                sanitizer=self.config.sanitizer,
                category=category
            )

            # Run Phase 0 logic with this category-specific prompt (with 3 iterations instead of 5)
            # Use specific models: [CLAUDE_MODEL, OPENAI_MODEL, OPENAI_MODEL_O3] from original
            # Both CLAUDE_MODEL and OPENAI_MODEL are set to CLAUDE_MODEL_SONNET_45 in original
            pov_success, pov_metadata = self._do_pov_phase_0(
                category_prompt,
                max_iterations=3,
                models=[CLAUDE_MODEL_SONNET_45, CLAUDE_MODEL_SONNET_45, OPENAI_MODEL_O3]
            )

            if pov_success:
                self.logger.log(f"SUCCESS! Category {category} found POV")
                return True, pov_metadata
            else:
                self.logger.log(f"Category {category} did not find POV, trying next...")

        self.logger.log(f"Phase 1 exhausted all {len(categories)} categories without success")
        return False, {}

    def _do_pov_phase_2(self, initial_msg: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Phase 2: Modified functions-based POV generation

        Analyzes functions modified in the vulnerability commit and includes
        their full implementations in the prompt.
        """
        self.logger.log("Phase 2: Modified functions-based approach")

        # Import utilities
        from common.utils import parse_commit_diff
        from common.prompts import create_modified_functions_prompt

        # Get project source directory
        project_src_dir = os.path.join(self.config.project_dir, f"{self.config.focus}-{self.config.sanitizer}")

        # Parse commit diff to extract modified functions
        modified_functions = parse_commit_diff(project_src_dir, self.commit_diff)
        self.logger.log(f"Found {len(modified_functions)} modified files with functions")

        # Generate modified-functions-based prompt
        phase2_prompt = create_modified_functions_prompt(
            fuzzer_code=self.fuzzer_code,
            commit_diff=self.commit_diff,
            project_src_dir=project_src_dir,
            modified_functions=modified_functions,
            sanitizer=self.config.sanitizer,
            language=self.config.language,
            logger=self.logger
        )

        # Run Phase 0 logic with modified-functions prompt
        pov_success, pov_metadata = self._do_pov_phase_0(phase2_prompt)

        return pov_success, pov_metadata

    def _do_pov_phase_3(self, initial_msg: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Phase 3: Call path analysis-based POV generation

        Uses static analysis to extract call paths from fuzzer to vulnerable
        functions, then generates POVs targeting specific paths.
        """
        self.logger.log("Phase 3: Call path analysis-based approach")

        # Import utilities
        from common.utils import parse_commit_diff, extract_call_paths_from_analysis_service
        from common.prompts import create_call_path_prompt, create_combined_call_paths_prompt

        # Get project source directory
        project_src_dir = os.path.join(self.config.project_dir, f"{self.config.focus}-{self.config.sanitizer}")

        # Parse commit diff to extract modified functions
        modified_functions = parse_commit_diff(project_src_dir, self.commit_diff)
        self.logger.log(f"Found {len(modified_functions)} modified files")

        # Determine use_qx based on language (Java uses extended query)
        use_qx = not self.config.language.startswith('c')

        # Get fuzzer source path (need to find it)
        fuzzer_src_path = self.find_fuzzer_source()  # Already have as self.fuzzer_code but need path
        # For now, skip fuzzer_src_path - this would require additional tracking
        # TODO: Track fuzzer_src_path in execute_core_logic()

        # Extract call paths from static analysis service
        self.logger.log(f"Querying static analysis service (use_qx={use_qx})...")
        call_paths = extract_call_paths_from_analysis_service(
            fuzzer_path=self.config.fuzzer_path,
            fuzzer_src_path="",  # TODO: Add fuzzer_src_path tracking
            focus=self.config.focus,
            project_src_dir=project_src_dir,
            modified_functions=modified_functions,
            use_qx=use_qx
        )

        # Fallback: If no paths found, always retry with use_qx=False (match original behavior)
        if len(call_paths) == 0:
            self.logger.log("No call paths found, retrying with use_qx=False...")
            call_paths = extract_call_paths_from_analysis_service(
                fuzzer_path=self.config.fuzzer_path,
                fuzzer_src_path="",
                focus=self.config.focus,
                project_src_dir=project_src_dir,
                modified_functions=modified_functions,
                use_qx=False
            )

        # Check if POV already exists (from other phases)
        if len(call_paths) == 0 and self.has_successful_pov():
            self.logger.log("No call paths found, but POV already exists from another phase")
            return True, {}

        if len(call_paths) == 0:
            self.logger.log("No call paths found, skipping Phase 3")
            return False, {}

        self.logger.log(f"Found {len(call_paths)} call paths to analyze")

        # Try each call path
        for idx, call_path in enumerate(call_paths, 1):
            self.logger.log(f"[{idx}/{len(call_paths)}] Trying call path with {len(call_path)} nodes")

            # Generate call-path-based prompt
            path_prompt = create_call_path_prompt(
                fuzzer_code=self.fuzzer_code,
                commit_diff=self.commit_diff,
                project_src_dir=project_src_dir,
                call_path=call_path,
                sanitizer=self.config.sanitizer,
                language=self.config.language
            )

            # Run Phase 0 logic with this call path
            pov_success, pov_metadata = self._do_pov_phase_0(path_prompt)

            if pov_success:
                self.logger.log(f"SUCCESS! Call path {idx} found POV")
                return True, pov_metadata

        # If no single path succeeded and we have multiple paths, combine them
        if len(call_paths) > 1:
            self.logger.log(f"Combining all {len(call_paths)} call paths for final attempt")

            # Generate combined prompt
            combined_prompt = create_combined_call_paths_prompt(
                fuzzer_code=self.fuzzer_code,
                commit_diff=self.commit_diff,
                project_src_dir=project_src_dir,
                call_paths=call_paths,
                sanitizer=self.config.sanitizer,
                language=self.config.language
            )

            pov_success, pov_metadata = self._do_pov_phase_0(combined_prompt)
            return pov_success, pov_metadata

        self.logger.log("Phase 3 exhausted all call paths without success")
        return False, {}

    def generate_blobs(self, code: str, xbin_dir: str) -> List[str]:
        """
        Override parent method to generate 5 blob files (x1.bin - x5.bin)

        AS0 strategy generates multiple blobs to diversify test cases.

        Args:
            code: Python code generated by LLM
            xbin_dir: Directory to store blob files

        Returns:
            List of blob file paths that were successfully created
        """
        # Save code to temp file
        code_file = os.path.join(xbin_dir, "generate_blob.py")
        with open(code_file, "w") as f:
            f.write(code)

        # Execute code
        try:
            result = subprocess.run(
                [sys.executable, code_file],
                cwd=xbin_dir,
                capture_output=True,
                text=True,
                timeout=30
            )

            # Log execution output
            if result.stdout:
                self.logger.log(f"Python code execution stdout: {result.stdout}")
            if result.stderr:
                self.logger.log(f"Python code execution stderr: {result.stderr}")

            if result.returncode != 0:
                raise RuntimeError(f"Code execution failed: {result.stderr}")

            # Check for x1.bin - x5.bin (AS0 generates 5 blobs)
            blob_paths = []
            for i in range(1, 6):
                blob_path = os.path.join(xbin_dir, f"x{i}.bin")
                if os.path.exists(blob_path):
                    blob_size = os.path.getsize(blob_path)
                    self.logger.log(f"x{i}.bin created successfully ({blob_size} bytes)")
                    blob_paths.append(blob_path)

            # If no x1-x5.bin, check for fallback x.bin (backward compatibility)
            if not blob_paths:
                blob_path = os.path.join(xbin_dir, "x.bin")
                if os.path.exists(blob_path):
                    blob_size = os.path.getsize(blob_path)
                    self.logger.log(f"x.bin created successfully ({blob_size} bytes)")
                    blob_paths.append(blob_path)

            # Must have at least one blob file
            if not blob_paths:
                raise RuntimeError("Code did not create any blob files (x1.bin - x5.bin or x.bin)")

            return blob_paths

        except subprocess.TimeoutExpired:
            raise RuntimeError("Code execution timed out")
        except Exception as e:
            raise RuntimeError(f"Code execution error: {str(e)}")

    def submit_pov(self, pov_metadata: Dict[str, Any]) -> bool:
        """
        Submit POV to endpoint (same as XS0 for now)
        """
        import base64
        import re
        import requests
        from common.utils import extract_crash_trace

        self.logger.log("Submitting POV to submission endpoint")

        # Get API credentials from environment
        api_key_id = os.environ.get("COMPETITION_API_KEY_ID")
        api_token = os.environ.get("COMPETITION_API_KEY_TOKEN")
        submission_endpoint = os.environ.get("SUBMISSION_ENDPOINT")
        task_id = os.environ.get("TASK_ID")

        if not submission_endpoint:
            self.logger.log("SUBMISSION_ENDPOINT not set, skipping submission")
            return False

        if not task_id:
            self.logger.log("TASK_ID not set, skipping submission")
            return False

        if not api_key_id or not api_token:
            api_key_id = os.environ.get("CRS_KEY_ID")
            api_token = os.environ.get("CRS_KEY_TOKEN")
            if not api_key_id or not api_token:
                self.logger.log("API credentials not set, skipping submission")
                return False

        # Read blob file
        blob_path = os.path.join(self.config.pov_success_dir, pov_metadata.get("blob_file", ""))
        if not os.path.exists(blob_path):
            self.logger.error(f"Blob file {blob_path} does not exist")
            return False

        with open(blob_path, "rb") as f:
            blob_data = f.read()

        # Read fuzzer output
        fuzzer_output_path = os.path.join(self.config.pov_success_dir, pov_metadata.get("fuzzer_output", ""))
        if not os.path.exists(fuzzer_output_path):
            self.logger.error(f"Fuzzer output file {fuzzer_output_path} does not exist")
            return False

        with open(fuzzer_output_path, "r") as f:
            fuzzer_output = f.read()

        # Extract crash trace
        crash_trace = ""

        # Check for UndefinedBehaviorSanitizer errors
        ubsan_match = re.search(r'(.*runtime error:.*)', fuzzer_output)
        if ubsan_match:
            ubsan_error = ubsan_match.group(1).strip()
            crash_trace = f"UndefinedBehaviorSanitizer Error: {ubsan_error}\n\n"

            # Extract stack trace
            stack_lines = re.findall(r'(#\d+.*)', fuzzer_output)
            if stack_lines:
                crash_trace += "Stack Trace:\n"
                for line in stack_lines:
                    crash_trace += f"{line}\n"

            # Extract summary
            summary_match = re.search(r'SUMMARY: UndefinedBehaviorSanitizer: (.*)', fuzzer_output)
            if summary_match:
                crash_trace += f"\nSummary: {summary_match.group(1)}\n"

        # Fall back to extract_crash_trace if no UBSan error
        if not crash_trace:
            crash_trace = extract_crash_trace(fuzzer_output)

        # Limit size
        if len(crash_trace) > 10000:
            crash_trace = crash_trace[:10000] + "... (truncated)"

        # Create submission payload
        submission = {
            "task_id": task_id,
            "architecture": "x86_64",
            "engine": "libfuzzer",
            "fuzzer_name": pov_metadata.get("fuzzer_name", ""),
            "sanitizer": pov_metadata.get("sanitizer", ""),
            "testcase": base64.b64encode(blob_data).decode('utf-8'),
            "signature": pov_metadata.get("pov_signature", ""),
        }

        # Add generated fuzzer source if available
        new_fuzzer_src_path = os.environ.get("NEW_FUZZER_SRC_PATH", "")
        if new_fuzzer_src_path:
            submission["fuzzer_file"] = new_fuzzer_src_path
            try:
                with open(new_fuzzer_src_path, "r", encoding="utf-8", errors="backslashreplace") as fp:
                    submission["fuzzer_source"] = fp.read()
            except Exception as e:
                self.logger.warning(f"Failed to read fuzzer source at {new_fuzzer_src_path}: {e}")

        # Add crash trace
        if crash_trace:
            submission["crash_trace"] = crash_trace

        # Add strategy information
        submission["strategy"] = "as0_delta"
        submission["strategy_version"] = "1.0"

        try:
            # Build URL
            url = f"{submission_endpoint}/v1/task/{task_id}/pov/"
            if new_fuzzer_src_path:
                url = f"{submission_endpoint}/v1/task/{task_id}/freeform/pov/"

            headers = {"Content-Type": "application/json"}
            auth = (api_key_id, api_token) if api_key_id and api_token else None

            # Send request
            response = requests.post(
                url,
                headers=headers,
                auth=auth,
                json=submission,
                timeout=60
            )

            # Check response
            if response.status_code in [200, 201]:
                self.logger.log(f"Successfully submitted POV: {response.status_code}")
                try:
                    response_data = response.json()
                    self.logger.log(f"Response: {response_data}")
                except:
                    self.logger.log(f"Raw response: {response.text}")
                return True
            else:
                self.logger.error(f"Submission failed with status {response.status_code}: {response.text}")
                return False

        except Exception as e:
            self.logger.error(f"Error submitting POV: {str(e)}")
            return False


def main():
    """
    Main entry point for AS0 Delta strategy (called by Go goroutines)
    """
    import argparse

    parser = argparse.ArgumentParser(description="AS0 Delta Strategy")
    parser.add_argument("fuzzer_path", help="Path to fuzzer executable")
    parser.add_argument("project_name", help="Project name")
    parser.add_argument("focus", help="Focus directory")
    parser.add_argument("language", help="Project language (e.g., c, java)")

    # Optional arguments
    parser.add_argument("--test-nginx", dest="test_nginx", type=lambda x: x.lower() == 'true',
                        default=False, help="Whether to test Nginx (true/false)")
    parser.add_argument("--do-patch", dest="do_patch", type=lambda x: x.lower() == 'true',
                        default=False, help="Whether to apply patches (true/false)")
    parser.add_argument("--do-patch-only", dest="do_patch_only", type=lambda x: x.lower() == 'true',
                        default=False, help="Whether to only run patching (true/false)")
    parser.add_argument("--full-scan", dest="full_scan", type=lambda x: x.lower() == 'true',
                        default=False, help="Whether full scan (default is delta-scan (true/false)")
    parser.add_argument("--check-patch-success", action="store_true",
                        help="Check for successful patches and exit early if found")
    parser.add_argument("--max-iterations", dest="max_iterations", type=int, default=5,
                        help="Maximum number of iterations")
    parser.add_argument("--fuzzing-timeout", dest="fuzzing_timeout", type=int, default=45,
                        help="Fuzzing timeout in minutes")
    parser.add_argument("--patching-timeout", dest="patching_timeout", type=int, default=30,
                        help="Patching timeout in minutes")
    parser.add_argument("--pov-metadata-dir", dest="pov_metadata_dir", type=str, default="successful_povs",
                        help="Directory to store POV metadata")
    parser.add_argument("--patch-workspace-dir", type=str, default="patch_workspace",
                        help="Directory for patch workspace")
    parser.add_argument("--model", type=str, default="",
                        help="Specific model to use (overrides default model list)")
    parser.add_argument("--cpv", type=str, default="cpv12",
                        help="CPV number to test (e.g., cpv3, cpv5, cpv9)")
    parser.add_argument("--log-dir", type=str, default="./logs",
                        help="Directory to store log files (default: ./logs)")
    parser.add_argument("--pov-phase", type=int, default=0,
                        help="POV generation phase (0-4, default: 0)")

    args = parser.parse_args()

    # Create config
    config = StrategyConfig(
        strategy_name="as0_delta",
        fuzzer_path=args.fuzzer_path,
        project_name=args.project_name,
        focus=args.focus,
        language=args.language,
        test_nginx=args.test_nginx,
        do_patch=args.do_patch,
        do_patch_only=args.do_patch_only,
        full_scan=args.full_scan,
        check_patch_success=args.check_patch_success,
        max_iterations=args.max_iterations,
        fuzzing_timeout_minutes=args.fuzzing_timeout,
        patching_timeout_minutes=args.patching_timeout,
        pov_metadata_dir=args.pov_metadata_dir,
        patch_workspace_dir=args.patch_workspace_dir,
        cpv=args.cpv,
        log_dir=args.log_dir,
        pov_phase=args.pov_phase,
        models=[args.model] if args.model else None,  # None uses default from config
    )

    # Create and run strategy
    strategy = AS0DeltaStrategy(config)
    success = strategy.run()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

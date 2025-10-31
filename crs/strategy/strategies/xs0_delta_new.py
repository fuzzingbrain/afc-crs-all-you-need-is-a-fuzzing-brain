#!/usr/bin/env python3
"""
XS0 Delta Strategy - LLM-guided test harness generation for vulnerability triggering

New OOP implementation based on PoVStrategy base class.
"""
import os
import sys
import uuid
import time
import shutil
from typing import Dict, Any, Tuple, List

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from core.pov_strategy import PoVStrategy
from common.config import StrategyConfig
from common.logging.logger import StrategyLogger
from common.llm.client import LLMClient
from common.utils import (
    filter_instrumented_lines,
    truncate_output,
    extract_crash_output,
    generate_vulnerability_signature,
    cleanup_seed_corpus,
)
from code_analysis import CoverageAnalyzer


class XS0DeltaStrategy(PoVStrategy):
    """
    XS0 Delta Strategy: Basic commit-based POV generation

    Generates 1 blob file (x.bin) per iteration and tests with fuzzer.
    Uses default implementations for most methods from PoVStrategy.
    """

    # System prompt for LLM guidance
    SYSTEM_PROMPT = """You are a world-leading top software vulnerability detection expert, which helps to find vulnerabilities.
Do not aplogize when you are wrong. Just keep optimizing the result directly and proceed the progress. Do not lie or guess when you are unsure about the answer.
If possible, show the information needed to make the response better apart from the answer given. """

    def get_strategy_name(self) -> str:
        """Return strategy name for logging"""
        return "xs0_delta"

    def do_pov(self, initial_msg: str) -> Tuple[bool, Dict[str, Any]]:
        """
        XS0 POV generation main loop

        Args:
            initial_msg: Initial prompt for LLM

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

        # Try with different models
        for model_name in self.config.models:
            self.logger.log(f"Attempting POV generation with model: {model_name}")

            # Initialize messages with system prompt and user message
            messages = [
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": initial_msg}
            ]
            model_success_count = 0

            for iteration in range(1, self.config.max_iterations + 1):
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
                    continue

                # Create unique directory for this iteration
                unique_id = str(uuid.uuid4())[:8]
                xbin_dir = os.path.join(self.config.project_dir, "xp0", unique_id)
                os.makedirs(xbin_dir, exist_ok=True)
                self.logger.log(f"Created xbin_dir: {xbin_dir}")

                # Generate blob file (uses default generate_blobs which creates x.bin)
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

                blob_path = blob_paths[0]  # XS0 only uses 1 blob

                # Run fuzzer with generated blob
                crash_detected, fuzzer_output = self.run_fuzzer(blob_paths)
                fuzzer_output = filter_instrumented_lines(fuzzer_output)

                if crash_detected:
                    found_pov = True
                    model_success_count += 1

                    # Save successful POV
                    pov_metadata = self.save_pov_artifacts(
                        pov_id, model_name, iteration,
                        code, blob_path, fuzzer_output, messages
                    )

                    # Submit POV
                    self.submit_pov(pov_metadata)

                    successful_pov_metadata = pov_metadata

                    # Continue searching for different POVs
                    user_message = """
Great job! You've successfully triggered the vulnerability.

Now, let's try to find a different way to trigger a different vulnerability in the code.
Can you create a different test case that might trigger the vulnerability through a different code path or with different input values?

Focus on:
1. Different input formats or values
2. Alternative code paths that might reach the vulnerable function
3. Edge cases that weren't covered by your previous solution
4. Other potential vulnerabilities in the code

Please provide a new Python script that creates a different x.bin file.
"""
                    messages.append({"role": "user", "content": user_message})

                    # If we found enough POVs with this model, move to next model
                    if model_success_count >= 1:
                        self.logger.log(f"Found {model_success_count} successful POVs with {model_name}, moving to next model")
                        break

                else:
                    # No crash - provide feedback and continue
                    self.logger.log("Fuzzer did not crash, enhancing context and continuing")

                    # Save to seed corpus
                    if os.path.exists(blob_path):
                        seed_corpus_dir = os.path.join(
                            self.config.project_dir,
                            f"{self.config.fuzzer_name}_seed_corpus"
                        )
                        os.makedirs(seed_corpus_dir, exist_ok=True)
                        cleanup_seed_corpus(seed_corpus_dir, max_age_minutes=10, logger=self.logger)

                        timestamp = int(time.time())
                        seed_file_path = os.path.join(
                            seed_corpus_dir,
                            f"seed_{model_name}_{iteration}_{timestamp}.bin"
                        )
                        shutil.copy(blob_path, seed_file_path)
                        self.logger.log(f"Saved test case to seed corpus: {seed_file_path}")

                    # Provide feedback for next iteration
                    if iteration == 1:
                        user_message = f"""
Fuzzer output:
{truncate_output(fuzzer_output, 200)}

The test case did not trigger the vulnerability. Please analyze the fuzzer output and try again with an improved approach. Consider:
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

The test case did not trigger the vulnerability. Please analyze the fuzzer output and try again with a different approach.
"""

                    if iteration == self.config.max_iterations - 1:
                        user_message += "\nThis is your last attempt. This task is very important. If you generate a successful blob, I will tip you 2000 dollars."

                    # Add control flow feedback if enabled
                    if hasattr(self.config, 'use_control_flow') and self.config.use_control_flow:
                        coverage_analyzer = CoverageAnalyzer(self.config, self.logger)
                        control_flow_feedback = coverage_analyzer.get_coverage_feedback(blob_path)
                        if control_flow_feedback:
                            user_message += control_flow_feedback

                    messages.append({"role": "user", "content": user_message})

                    # Clean up failed blob
                    if os.path.exists(blob_path):
                        os.remove(blob_path)

            # If found POV with this model, potentially stop
            if model_success_count >= 1:
                self.logger.log(f"Found {model_success_count} successful POVs! Breaking model loop.")
                break

        # Final summary
        total_time = time.time() - start_time
        self.logger.log(f"XS0 Delta strategy completed in {total_time:.2f} seconds")

        # Check if any successful POVs were found
        if os.path.exists(self.config.pov_success_dir):
            pov_files = [f for f in os.listdir(self.config.pov_success_dir) if f.startswith("pov_metadata_")]
            if pov_files:
                self.logger.log(f"Found {len(pov_files)} successful POVs")
                return True, successful_pov_metadata

        self.logger.log("No successful POVs found")
        return False, {}

    def submit_pov(self, pov_metadata: Dict[str, Any]) -> bool:
        """
        Submit POV to endpoint

        Args:
            pov_metadata: POV metadata to submit

        Returns:
            True if submission successful, False otherwise
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
        submission["strategy"] = "xs0_delta"
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
    Main entry point for XS0 Delta strategy (called by Go goroutines)
    """
    import argparse

    parser = argparse.ArgumentParser(description="XS0 Delta Strategy")
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

    args = parser.parse_args()

    # Create config
    config = StrategyConfig(
        strategy_name="xs0_delta",
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
        models=[args.model] if args.model else None,  # None uses default from config
    )

    # Create and run strategy
    strategy = XS0DeltaStrategy(config)
    success = strategy.run()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

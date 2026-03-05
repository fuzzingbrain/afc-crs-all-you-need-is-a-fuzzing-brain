#!/usr/bin/env python3
"""
Patch0 Delta Strategy - LLM-guided patch generation for delta scans

New OOP implementation based on PatchStrategy base class.
Replaces the old patch0_delta.py / patch_delta.py monolithic scripts.
"""
import os
import sys
import json
import time
import shutil
import uuid
import subprocess
import re
import base64
from typing import Dict, Any, Tuple, List, Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from core.patch_strategy import PatchStrategy, INITIAL_PATCH_TEMPLATE
from common.config import StrategyConfig
from common.utils import (
    get_commit_info,
    truncate_output,
    extract_crash_trace,
    extract_diff_functions_using_funtarget,
)


class Patch0DeltaStrategy(PatchStrategy):
    """
    Patch0 Delta Strategy: LLM-guided patch generation for delta scans.

    Workflow:
    1. Load POV metadata (crash info, blob)
    2. Use LLM to identify target functions to patch
    3. Locate function definitions in source
    4. Iteratively generate patches, apply, build, test
    5. Validate against all POVs
    6. Submit successful patch
    """

    SYSTEM_PROMPT = "You are a software vulnerability patching expert."

    def get_strategy_name(self) -> str:
        return "patch0_delta"

    def do_patch(self, pov_metadata: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Main patch generation loop for a single POV.

        Args:
            pov_metadata: POV metadata dict with blob_file, fuzzer_output, conversation

        Returns:
            Tuple of (success: bool, patch_id: str)
        """
        patch_id = str(uuid.uuid4())[:8]

        # Load POV context
        context_info, crash_log = self.load_pov_context(pov_metadata)

        # Get test blob path
        test_blob_file = os.path.join(
            self.config.pov_success_dir,
            pov_metadata.get("blob_file", "")
        )

        if not os.path.exists(test_blob_file):
            self.logger.error(f"Test blob not found: {test_blob_file}")
            return False, patch_id

        # Create patch workspace (copy source)
        project_src_dir_x = os.path.join(
            self.config.project_dir,
            f"{self.config.focus}-{self.config.sanitizer}"
        )

        if not os.path.exists(project_src_dir_x):
            self.logger.error(f"Source directory not found: {project_src_dir_x}")
            return False, patch_id

        project_src_dir = os.path.join(
            self.config.project_dir,
            f"{self.config.focus}_patch_{patch_id}"
        )
        shutil.copytree(project_src_dir_x, project_src_dir)
        self.logger.log(f"Created patch workspace: {project_src_dir}")

        try:
            return self._patch_loop(
                pov_metadata, context_info, crash_log,
                test_blob_file, project_src_dir, patch_id
            )
        finally:
            # Cleanup patch workspace
            if os.path.exists(project_src_dir):
                shutil.rmtree(project_src_dir, ignore_errors=True)

    def _patch_loop(
        self,
        pov_metadata: Dict[str, Any],
        context_info: str,
        crash_log: str,
        test_blob_file: str,
        project_src_dir: str,
        patch_id: str,
    ) -> Tuple[bool, str]:
        """Inner patch generation loop."""

        # Identify target functions using LLM
        target_functions = self._identify_target_functions(context_info, crash_log)

        # Find function metadata in source
        function_metadata = self._find_function_metadata(
            target_functions, project_src_dir
        )

        if not function_metadata:
            self.logger.warning("Could not find function metadata, patching may fail")

        # Format metadata for prompt
        functions_metadata_str = self._format_function_metadata(function_metadata, project_src_dir)

        # Get commit info for context
        commit_msg, commit_diff = get_commit_info(
            self.config.project_dir, self.config.language, logger=self.logger
        )

        # Build initial patch prompt
        initial_msg = INITIAL_PATCH_TEMPLATE.format(
            crash_log=crash_log,
            commit_diff=commit_diff,
            functions_metadata_str=functions_metadata_str
        )

        # Initialize git in patch workspace
        self._init_git(project_src_dir)

        # Patch iteration loop
        start_time = time.time()
        end_time = start_time + (self.config.patching_timeout_minutes * 60)

        messages = [
            {"role": "system", "content": self.SYSTEM_PROMPT},
            {"role": "user", "content": initial_msg}
        ]

        for iteration in range(1, self.config.max_iterations + 1):
            if time.time() > end_time:
                self.logger.log(f"Timeout after {iteration-1} iterations")
                break

            self.logger.log(f"Patch iteration {iteration} with {self.config.models[0]}")

            # Generate patch
            model_name = self.config.models[iteration % len(self.config.models) - 1]
            response, success = self.llm_client.call(messages, model_name)

            if not success or not response:
                self.logger.warning("LLM call failed")
                continue

            messages.append({"role": "assistant", "content": response})

            # Parse patch from response
            patch_code_dict = self._extract_patch_from_response(response)
            if not patch_code_dict:
                self.logger.warning("Could not extract patch from response")
                messages.append({"role": "user", "content": "Could not parse your response as JSON. Please return ONLY a valid JSON dict."})
                continue

            # Apply patch
            apply_success = self._apply_patch(patch_code_dict, function_metadata, project_src_dir)

            if not apply_success:
                self.logger.log("Patch application failed")
                self.reset_project_source_code(project_src_dir)
                messages.append({
                    "role": "user",
                    "content": "Patch application failed. Please try again with valid function replacements."
                })
                continue

            # Generate diff
            patch_diff = self.generate_diff(project_src_dir)

            # Test: run fuzzer with the POV blob
            crash_detected, fuzzer_output = self.run_fuzzer_with_input(test_blob_file, patch_id)

            if not crash_detected:
                # Patch blocks the crash!
                self.logger.log(f"PATCH SUCCESS on iteration {iteration}!")

                # Save patch artifacts
                os.makedirs(self.config.patch_success_dir, exist_ok=True)

                diff_path = os.path.join(
                    self.config.patch_success_dir,
                    f"patch_{model_name}_{time.strftime('%Y%m%d_%H%M%S')}.diff"
                )
                with open(diff_path, "w") as f:
                    f.write(patch_diff)

                # Submit patch
                pov_signature = pov_metadata.get("pov_signature", "")
                self.submit_patch(pov_signature, patch_diff)

                return True, patch_id
            else:
                # Still crashes - provide feedback
                self.logger.log("Patch does not fix the vulnerability")
                self.reset_project_source_code(project_src_dir)

                feedback = f"""
The patch was applied but the vulnerability still exists. Fuzzer output:
{truncate_output(fuzzer_output, 200)}

Please analyze the crash and provide a different fix.
Return ONLY a JSON dictionary with function names as keys and fixed code as values.
"""
                messages.append({"role": "user", "content": feedback})

        return False, patch_id

    def _identify_target_functions(
        self,
        context_info: str,
        crash_log: str,
    ) -> List[str]:
        """Use LLM to identify which functions need patching."""
        prompt = f"""Based on the vulnerability report and crash information below,
identify the function names that need to be patched.

## Context
{context_info}

## Crash Log
{truncate_output(crash_log, 500)}

Return a JSON list of function names that likely need patching.
Example: ["function_a", "function_b"]

Return ONLY the JSON list.
"""
        messages = [
            {"role": "system", "content": "You are an expert in code security vulnerabilities."},
            {"role": "user", "content": prompt}
        ]

        for model_name in self.config.models[:2]:
            response, success = self.llm_client.call(messages, model_name)
            if not success:
                continue

            # Parse function names from response
            try:
                # Strip markdown
                text = response.strip()
                m = re.search(r'```(?:json)?\s*([\s\S]*?)```', text)
                if m:
                    text = m.group(1).strip()

                parsed = json.loads(text)
                if isinstance(parsed, list) and parsed:
                    self.logger.log(f"Identified target functions: {parsed}")
                    return parsed
            except json.JSONDecodeError:
                pass

        self.logger.warning("Could not identify target functions")
        return []

    def _find_function_metadata(
        self,
        target_functions: List[str],
        project_src_dir: str,
    ) -> Dict[str, Dict[str, Any]]:
        """
        Find function definitions in the source code.
        Uses funtarget binary if available, otherwise falls back to grep.
        """
        metadata = {}

        for func_name in target_functions:
            # Try grep-based search
            try:
                result = subprocess.run(
                    ["grep", "-rn", f"\\b{func_name}\\b", project_src_dir,
                     "--include=*.c", "--include=*.cpp", "--include=*.h",
                     "--include=*.java", "--include=*.py"],
                    capture_output=True, text=True, timeout=30
                )
                if result.stdout:
                    first_match = result.stdout.strip().split('\n')[0]
                    parts = first_match.split(':', 2)
                    if len(parts) >= 3:
                        file_path = parts[0]
                        # Make relative to project_src_dir
                        if file_path.startswith(project_src_dir):
                            rel_path = os.path.relpath(file_path, project_src_dir)
                        else:
                            rel_path = file_path

                        # Read function content (simplified - reads surrounding lines)
                        try:
                            with open(file_path, 'r') as f:
                                content = f.read()
                            metadata[func_name] = {
                                "file_path": rel_path,
                                "content": content,
                                "start_line": int(parts[1]),
                            }
                        except Exception:
                            pass
            except Exception as e:
                self.logger.warning(f"Error searching for {func_name}: {e}")

        self.logger.log(f"Found metadata for {len(metadata)}/{len(target_functions)} functions")
        return metadata

    def _format_function_metadata(
        self,
        function_metadata: Dict[str, Dict[str, Any]],
        project_src_dir: str,
    ) -> str:
        """Format function metadata into a string for the patch prompt."""
        if not function_metadata:
            return "<no function metadata available>"

        parts = []
        for func_name, meta in function_metadata.items():
            content = meta.get("content", "")
            # Truncate very large files
            lines = content.split('\n')
            if len(lines) > 500:
                content = '\n'.join(lines[:500]) + f"\n... (truncated, total {len(lines)} lines)"

            parts.append(f"Function: {func_name} in file {meta.get('file_path', 'unknown')}\n"
                        f"Content:\n{content}\n")

        return "\n".join(parts)

    def _extract_patch_from_response(self, response: str) -> Optional[Dict[str, str]]:
        """Extract JSON dict of function_name -> fixed_code from LLM response."""
        text = response.strip()

        # Strip markdown code fences
        m = re.search(r'```(?:json)?\s*([\s\S]*?)```', text)
        if m:
            text = m.group(1).strip()

        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict) and parsed:
                return parsed
        except json.JSONDecodeError:
            pass

        # Try to find JSON object in the response
        try:
            start = text.index('{')
            end = text.rindex('}') + 1
            parsed = json.loads(text[start:end])
            if isinstance(parsed, dict):
                return parsed
        except (ValueError, json.JSONDecodeError):
            pass

        return None

    def _apply_patch(
        self,
        patch_code_dict: Dict[str, str],
        function_metadata: Dict[str, Dict[str, Any]],
        project_src_dir: str,
    ) -> bool:
        """Apply the patch by replacing function bodies in source files."""
        applied = False

        for func_name, new_code in patch_code_dict.items():
            meta = function_metadata.get(func_name)
            if not meta:
                self.logger.warning(f"No metadata for function {func_name}, skipping")
                continue

            file_path = os.path.join(project_src_dir, meta["file_path"])
            if not os.path.exists(file_path):
                self.logger.warning(f"File not found: {file_path}")
                continue

            try:
                with open(file_path, 'r') as f:
                    original = f.read()

                old_content = meta.get("content", "")
                if old_content and old_content in original:
                    new_file = original.replace(old_content, new_code, 1)
                    with open(file_path, 'w') as f:
                        f.write(new_file)
                    applied = True
                    self.logger.log(f"Applied patch to {func_name} in {meta['file_path']}")
                else:
                    self.logger.warning(f"Could not find original content for {func_name}")
            except Exception as e:
                self.logger.error(f"Error applying patch to {func_name}: {e}")

        return applied

    def _init_git(self, project_src_dir: str):
        """Initialize git repo in patch workspace for diff tracking."""
        if not os.path.exists(os.path.join(project_src_dir, ".git")):
            try:
                subprocess.run(["git", "init"], cwd=project_src_dir,
                             capture_output=True, text=True, timeout=30)
                subprocess.run(["git", "config", "user.email", "patch@crs.local"],
                             cwd=project_src_dir, capture_output=True, text=True, timeout=10)
                subprocess.run(["git", "config", "user.name", "CRS Patcher"],
                             cwd=project_src_dir, capture_output=True, text=True, timeout=10)
                subprocess.run(["git", "add", "-A"], cwd=project_src_dir,
                             capture_output=True, text=True, timeout=30)
                subprocess.run(["git", "commit", "-m", "baseline"],
                             cwd=project_src_dir, capture_output=True, text=True, timeout=30)
            except Exception as e:
                self.logger.warning(f"Git init failed: {e}")

    def submit_patch(self, pov_signature: str, patch_diff: str) -> bool:
        """Submit patch to competition API."""
        submission_endpoint = os.environ.get("SUBMISSION_ENDPOINT")
        task_id = os.environ.get("TASK_ID")

        if not submission_endpoint or not task_id:
            self.logger.log("SUBMISSION_ENDPOINT or TASK_ID not set, skipping submission")
            return False

        api_key_id = os.environ.get("COMPETITION_API_KEY_ID") or os.environ.get("CRS_KEY_ID")
        api_token = os.environ.get("COMPETITION_API_KEY_TOKEN") or os.environ.get("CRS_KEY_TOKEN")

        if not api_key_id or not api_token:
            self.logger.log("API credentials not set, skipping submission")
            return False

        import requests

        patch_base64 = base64.b64encode(patch_diff.encode('utf-8')).decode('utf-8')
        submission = {
            "pov_signature": pov_signature,
            "diff": patch_diff,
            "patch": patch_base64,
        }

        try:
            url = f"{submission_endpoint}/v1/task/{task_id}/patch/"
            response = requests.post(
                url,
                headers={"Content-Type": "application/json"},
                auth=(api_key_id, api_token),
                json=submission,
                timeout=60
            )

            if response.status_code in [200, 201]:
                self.logger.log(f"Patch submitted successfully: {response.status_code}")
                return True
            else:
                self.logger.error(f"Patch submission failed: {response.status_code}: {response.text}")
                return False

        except Exception as e:
            self.logger.error(f"Error submitting patch: {e}")
            return False


def main():
    """Main entry point for Patch0 Delta strategy."""
    import argparse

    parser = argparse.ArgumentParser(description="Patch0 Delta Strategy")
    parser.add_argument("fuzzer_path", help="Path to fuzzer executable")
    parser.add_argument("project_name", help="Project name")
    parser.add_argument("focus", help="Focus directory")
    parser.add_argument("language", help="Project language")

    parser.add_argument("--max-iterations", dest="max_iterations", type=int, default=5)
    parser.add_argument("--patching-timeout", dest="patching_timeout", type=int, default=30)
    parser.add_argument("--pov-metadata-dir", dest="pov_metadata_dir", type=str,
                        default="successful_povs")
    parser.add_argument("--patch-workspace-dir", type=str, default="patch_workspace")
    parser.add_argument("--model", type=str, default="")
    parser.add_argument("--log-dir", type=str, default="./logs")

    args = parser.parse_args()

    config = StrategyConfig(
        strategy_name="patch0_delta",
        fuzzer_path=args.fuzzer_path,
        project_name=args.project_name,
        focus=args.focus,
        language=args.language,
        do_patch=True,
        max_iterations=args.max_iterations,
        patching_timeout_minutes=args.patching_timeout,
        pov_metadata_dir=args.pov_metadata_dir,
        patch_workspace_dir=args.patch_workspace_dir,
        log_dir=args.log_dir,
        models=[args.model] if args.model else None,
    )

    strategy = Patch0DeltaStrategy(config)
    success = strategy.run()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

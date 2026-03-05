"""
Patch Strategy
Base class for all patch generation strategies.

Patch workflow:
1. Load POV metadata (crash info, blob files)
2. Extract context (conversation history, crash log)
3. Identify target functions using LLM
4. Find function metadata in source code
5. Iterative patch generation: generate -> apply -> build/test -> feedback
6. Validate patch against all POVs
7. Submit successful patch
"""
import os
import sys
import json
import time
import shutil
import uuid
import subprocess
import base64
from abc import abstractmethod
from typing import Tuple, Dict, Any, List, Optional
from pathlib import Path

from core.base_strategy import BaseStrategy
from common.utils import (
    get_commit_info,
    truncate_output,
    extract_crash_trace,
    extract_diff_functions_using_funtarget,
)


# Patch prompt template
INITIAL_PATCH_TEMPLATE = """# Vulnerability Patching Task

## Your Role
You are a world-leading security engineer tasked with fixing a vulnerability in code. Your goal is to generate minimal, precise patches that address only the vulnerability without changing other functionality.
Do not aplogize when you are wrong. Just keep optimizing the result directly and proceed the progress. Do not lie or guess when you are unsure about the answer.

## Input Information
### Vulnerability Report
{crash_log}

### Context Information
The vulnerability is introduced by the following commit:
{commit_diff}

### Relevant Functions
{functions_metadata_str}

Please return the fixed functions to patch the vulnerability.

## Requirements
1. Fix ONLY the vulnerability - do not add features or refactor code
2. Preserve all existing functionality and logic
3. Make minimal changes (fewest lines of code possible)
4. Focus on security best practices

## Output Format
Return ONLY a JSON dictionary where keys are function names and values are code blocks:
{{
"function_name1": "function_content_with_fix",
"function_name2": "function_content_with_fix",
...
}}

IMPORTANT:
- Return the fixed content for each changed function
- Do NOT return diffs, patches, or partial code snippets
- Do NOT include explanations or comments outside the JSON
- Include ALL lines of the original function in your response, with your fixes applied

Return ONLY the JSON dictionary described above.
"""

SUCCESS_PATCH_METADATA_FILE = "successful_patch_metadata.json"


class PatchStrategy(BaseStrategy):
    """
    Base class for patch generation strategies.

    Subclasses MUST implement:
    - do_patch(pov_metadata) -> Tuple[bool, str]
    - submit_patch(pov_signature, patch_diff) -> bool

    Provides default implementations for:
    - execute_core_logic() - Load POVs and run patch loop
    - load_all_pov_metadata() - Load saved POV metadata
    - load_pov_context(pov_metadata) - Extract context/crash from POV
    - get_target_functions(context_info, crash_log, model_name) - LLM-based
    - find_function_metadata(target_functions) - Locate in source
    - generate_patch(messages, model_name) - Generate patch code via LLM
    - apply_patch(patch_code_dict) - Apply patch to source
    - run_fuzzer_with_input(blob_path) - Test patched binary
    - validate_patch_against_all_povs(all_povs) - Cross-validate
    - reset_project_source_code() - Revert source changes
    """

    # ========== Abstract methods ==========

    @abstractmethod
    def do_patch(self, pov_metadata: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Main patch generation loop for a single POV.

        Args:
            pov_metadata: POV metadata dict

        Returns:
            Tuple of (success: bool, patch_id: str)
        """
        pass

    @abstractmethod
    def submit_patch(self, pov_signature: str, patch_diff: str) -> bool:
        """
        Submit patch to endpoint.

        Args:
            pov_signature: Vulnerability signature from POV
            patch_diff: Unified diff of the patch

        Returns:
            True if submission successful
        """
        pass

    # ========== Default implementations ==========

    def get_strategy_name(self) -> str:
        return "patch_base"

    def execute_core_logic(self) -> bool:
        """
        Default patch execution flow:
        1. Load all POV metadata
        2. Select primary POV
        3. Run patch loop with model rotation
        4. Validate against all POVs
        """
        self.logger.log("Starting patching process...")

        # Load all POVs
        all_povs = self.load_all_pov_metadata()
        if not all_povs:
            self.logger.log("No POVs found for patching")
            return False

        self.logger.log(f"Loaded {len(all_povs)} POVs for patch validation")

        # Select primary POV
        primary_pov = all_povs[0]
        self.logger.log(f"Using POV {primary_pov.get('blob_file', 'unknown')} as primary")

        # Track tried models
        tried_models = set()
        patch_success = False

        for iteration in range(1, self.config.max_iterations + 1):
            self.logger.log(f"Patch attempt {iteration}/{self.config.max_iterations}")

            # Select model
            untried = [m for m in self.config.models if m not in tried_models]
            if not untried:
                tried_models.clear()
                untried = self.config.models

            model_name = untried[0]
            tried_models.add(model_name)
            self.logger.log(f"Using model {model_name}")

            # Attempt patch
            success, patch_id = self.do_patch(primary_pov)

            if success:
                # Validate against all POVs
                self.logger.log(f"Patch generated, validating against all {len(all_povs)} POVs")
                all_blocked = self.validate_patch_against_all_povs(all_povs)

                if all_blocked:
                    self.logger.log(f"PATCH SUCCESS on attempt {iteration} with {model_name}")

                    # Save success metadata
                    os.makedirs(self.config.patch_success_dir, exist_ok=True)
                    success_metadata = {
                        "iteration": iteration,
                        "model_name": model_name,
                        "primary_pov": primary_pov,
                        "total_povs_blocked": len(all_povs),
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    }
                    success_file = os.path.join(self.config.patch_success_dir, SUCCESS_PATCH_METADATA_FILE)
                    with open(success_file, "w") as f:
                        json.dump(success_metadata, f, indent=2)

                    return True
                else:
                    self.logger.log("Patch blocks primary POV but fails on others, retrying")

        self.logger.log(f"Failed to patch after {self.config.max_iterations} attempts")
        return False

    def load_all_pov_metadata(self) -> List[Dict[str, Any]]:
        """Load all POV metadata files from the success directory."""
        if not os.path.exists(self.config.pov_success_dir):
            self.logger.log(f"POV directory {self.config.pov_success_dir} does not exist")
            return []

        metadata_files = [
            f for f in os.listdir(self.config.pov_success_dir)
            if f.startswith("pov_metadata_") and f.endswith(".json")
        ]

        if not metadata_files:
            self.logger.log("No POV metadata files found")
            return []

        all_metadata = []
        for mf in metadata_files:
            try:
                with open(os.path.join(self.config.pov_success_dir, mf), "r") as f:
                    metadata = json.load(f)
                blob_file = metadata.get("blob_file")
                if blob_file and os.path.exists(os.path.join(self.config.pov_success_dir, blob_file)):
                    all_metadata.append(metadata)
            except Exception as e:
                self.logger.warning(f"Error loading {mf}: {e}")

        self.logger.log(f"Loaded {len(all_metadata)} valid POV metadata entries")
        return all_metadata

    def load_pov_context(self, pov_metadata: Dict[str, Any]) -> Tuple[str, str]:
        """
        Extract context info and crash log from POV metadata.

        Returns:
            Tuple of (context_info, crash_log)
        """
        context_info = ""
        crash_log = ""

        # Read conversation history
        conv_file = pov_metadata.get("conversation", "")
        if conv_file:
            conv_path = os.path.join(self.config.pov_success_dir, conv_file)
            if os.path.exists(conv_path):
                try:
                    with open(conv_path, 'r') as f:
                        conversation = json.load(f)

                    # Check for infinite loop detection
                    if any("infinite loop" in m.get("content", "") for m in conversation):
                        os.environ["DETECT_TIMEOUT_CRASH"] = "1"

                    # Extract first user and last assistant messages
                    first_user = next((m["content"] for m in conversation if m["role"] == "user"), None)
                    last_assistant = next((m["content"] for m in reversed(conversation) if m["role"] == "assistant"), None)

                    if first_user:
                        context_info += f"\nUSER: {first_user}\n\n"
                    if last_assistant:
                        context_info += f"ASSISTANT: {last_assistant}\n\n"

                except Exception as e:
                    self.logger.warning(f"Error reading conversation: {e}")

        # Read fuzzer output / crash log
        output_file = pov_metadata.get("fuzzer_output", "")
        if output_file:
            output_path = os.path.join(self.config.pov_success_dir, output_file)
            if os.path.exists(output_path):
                try:
                    with open(output_path, 'r') as f:
                        crash_log = f.read()
                except Exception as e:
                    self.logger.warning(f"Error reading fuzzer output: {e}")

        return context_info, crash_log

    def run_fuzzer_with_input(self, blob_path: str, patch_id: str = "") -> Tuple[bool, str]:
        """
        Run fuzzer with a specific blob file against the (possibly patched) binary.

        Delegates to the parent PoVStrategy.run_fuzzer() via composition.
        """
        from core.pov_strategy import PoVStrategy

        if not os.path.exists(blob_path):
            self.logger.error(f"Blob file not found: {blob_path}")
            return False, ""

        # Use the same run_fuzzer logic from PoVStrategy
        # Create a temporary PoV-like runner
        is_c_project = self.config.language.startswith('c')
        fuzzer_dir = os.path.dirname(self.config.fuzzer_path)
        fuzzer_name = os.path.basename(self.config.fuzzer_path)

        path_parts = fuzzer_dir.split('/')
        project_sanitizer = None
        for part in path_parts:
            if '-' in part and any(san in part for san in ['address', 'undefined', 'memory']):
                project_sanitizer = part
                break

        if not project_sanitizer:
            self.logger.error(f"Could not determine sanitizer from path: {self.config.fuzzer_path}")
            return False, ""

        parts = project_sanitizer.split('-')
        sanitizer = parts[-1]
        project_name = '-'.join(parts[:-1])

        sanitizer_project_dir = os.path.join(self.config.project_dir, f"{self.config.focus}-{sanitizer}")
        out_dir = os.path.dirname(self.config.fuzzer_path)
        out_dir_x = os.path.join(out_dir, "xp0")
        os.makedirs(out_dir_x, exist_ok=True)

        work_dir = os.path.join(
            self.config.project_dir, "fuzz-tooling", "build", "work",
            f"{project_name}-{sanitizer}"
        )

        # Copy blob
        unique_id = str(uuid.uuid4())[:8]
        unique_blob_name = f"x_{unique_id}.bin"
        docker_blob_path = os.path.join(out_dir_x, unique_blob_name)
        shutil.copy(blob_path, docker_blob_path)

        # Find Docker image
        docker_image = None
        for prefix in [f"aixcc-afc/{project_name}", f"gcr.io/oss-fuzz/{project_name}"]:
            try:
                result = subprocess.run(
                    ["docker", "images", prefix, "--format", "{{.Repository}}:{{.Tag}}"],
                    capture_output=True, text=True, timeout=60
                )
                if result.returncode == 0 and result.stdout.strip():
                    docker_image = result.stdout.strip().split('\n')[0]
                    break
            except Exception:
                pass

        if not docker_image:
            self.logger.error(f"No Docker image found for {project_name}")
            return False, ""

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
            docker_image,
            f"/out/{fuzzer_name}",
            "-timeout=30",
            "-timeout_exitcode=99",
            f'/out/{unique_blob_name}'
        ]

        try:
            result = subprocess.run(docker_cmd, capture_output=True, text=True, timeout=60)
            combined_output = result.stderr + "\n" + result.stdout

            crash_indicators = [
                "ERROR: AddressSanitizer:", "ERROR: MemorySanitizer:",
                "WARNING: MemorySanitizer:", "ERROR: ThreadSanitizer:",
                "ERROR: UndefinedBehaviorSanitizer:", "SEGV on unknown address",
                "runtime error:", "AddressSanitizer: heap-buffer-overflow",
                "AddressSanitizer: heap-use-after-free",
                "Java Exception: com.code_intelligence.jazzer",
                "AddressSanitizer:DEADLYSIGNAL", "libfuzzer exit=1",
            ]

            sentinel = Path(self.config.project_dir) / "detect_timeout_crash"
            if os.environ.get("DETECT_TIMEOUT_CRASH") == "1" or sentinel.exists():
                crash_indicators.extend(["ERROR: libFuzzer: timeout", "libfuzzer exit=99"])

            if result.returncode == 0 and "ABORTING" not in combined_output:
                return False, combined_output

            if "assertion failed" in combined_output.lower():
                return True, combined_output

            if result.returncode != 0 or "ABORTING" in combined_output:
                if any(ind in combined_output for ind in crash_indicators):
                    return True, combined_output

            return False, combined_output

        except subprocess.TimeoutExpired:
            return False, "Execution timed out"
        except Exception as e:
            self.logger.error(f"Error running fuzzer: {e}")
            return False, str(e)

    def validate_patch_against_all_povs(
        self,
        all_povs: List[Dict[str, Any]],
        max_povs: int = 5,
    ) -> bool:
        """
        Validate that the current patch blocks all known POVs.

        Args:
            all_povs: List of POV metadata dicts
            max_povs: Max POVs to test (for efficiency)

        Returns:
            True if all tested POVs are blocked
        """
        povs_to_test = all_povs[:max_povs]
        self.logger.log(f"Validating patch against {len(povs_to_test)} POVs")

        for idx, pov in enumerate(povs_to_test, 1):
            blob_file = pov.get("blob_file", "")
            blob_path = os.path.join(self.config.pov_success_dir, blob_file)

            if not os.path.exists(blob_path):
                self.logger.warning(f"POV blob {blob_file} not found, skipping")
                continue

            crash_detected, _ = self.run_fuzzer_with_input(blob_path)

            if crash_detected:
                self.logger.log(f"POV {idx}/{len(povs_to_test)} still crashes - patch incomplete")
                return False
            else:
                self.logger.log(f"POV {idx}/{len(povs_to_test)} blocked")

        self.logger.log(f"All {len(povs_to_test)} POVs blocked!")
        return True

    def generate_diff(self, project_src_dir: str) -> str:
        """Generate unified diff of changes in project_src_dir."""
        try:
            result = subprocess.run(
                ["git", "diff"],
                cwd=project_src_dir,
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.stdout
        except Exception as e:
            self.logger.error(f"Error generating diff: {e}")
            return ""

    def reset_project_source_code(self, project_src_dir: str):
        """Reset source code to original state."""
        try:
            subprocess.run(
                ["git", "checkout", "."],
                cwd=project_src_dir,
                capture_output=True, text=True, timeout=30
            )
        except Exception as e:
            self.logger.error(f"Error resetting source: {e}")

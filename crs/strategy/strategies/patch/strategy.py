#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Patch strategy: LLM-guided vulnerability fix generation.

Loops until a generated patch:

1. Applies cleanly to the patch workspace.
2. Rebuilds the project image without errors.
3. Blocks every known POV blob on the rebuilt fuzzer.
4. Passes any ``test.sh`` functionality check shipped with the project.

The delta / full-scan split is a thin configuration toggle on a single
:class:`PatchStrategy` class — the patch flow is the same either way;
full-scan tasks just don't have a commit diff to feed into the initial
prompt.
"""
from __future__ import annotations

import os
import sys
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from dotenv import load_dotenv

load_dotenv()

from core.base_strategy import BaseStrategy
from common.crash.output import extract_crash_output
from common.diff.commit import get_commit_info
from common.fuzzing.discovery import find_fuzzer_source
from common.llm.models import CLAUDE_MODEL_SONNET_45, OPENAI_MODEL_O3
from common.patch.apply import apply_patch
from common.patch.generate import INITIAL_PATCH_TEMPLATE, generate_patch
from common.patch.metadata import find_function_metadata, format_function_metadata
from common.patch.validate import (
    validate_patch_against_all_povs,
    validate_patch_by_functionality_test,
)
from common.patch.workspace import ensure_patch_workspace_git, generate_diff, reset_project_source_code
from common.pov.store import load_all_pov_metadata
from common.prompts.targets import get_target_functions


class PatchStrategy(BaseStrategy):
    """LLM-guided patch strategy; handles delta and full scan uniformly."""

    # ------------------------------------------------------------------
    # Abstract-method implementations
    # ------------------------------------------------------------------

    def get_strategy_name(self) -> str:
        return "patch_full" if self.config.full_scan else "patch_delta"

    def execute_core_logic(self) -> bool:
        """Top-level entry: gather inputs, run the retry loop, return success."""
        self.logger.log("Starting patch strategy")

        fuzzer_code = find_fuzzer_source(
            fuzzer_path=self.config.fuzzer_path,
            project_name=self.config.project_name,
            project_src_dir=self.config.project_src_dir,
            focus=self.config.focus,
            language=self.config.language,
            test_nginx=self.config.test_nginx,
            llm_client=self.llm_client,
        )
        if not fuzzer_code:
            self.logger.error("Failed to find fuzzer source code")
            return False

        commit_diff = ""
        if not self.config.full_scan:
            _, commit_diff = get_commit_info(self.config.project_dir, self.config.language)

        all_povs = load_all_pov_metadata(self.config.pov_success_dir)
        if not all_povs:
            self.logger.warning("No POV metadata available; nothing to patch against")
            return False
        self.logger.log(f"Found {len(all_povs)} POVs for patch validation")

        # Target the first POV for initial prompt context; the patch is
        # re-validated against every POV below.
        primary_pov = all_povs[0]
        crash_log = extract_crash_output(self._read_fuzzer_output(primary_pov))

        target_functions = get_target_functions(
            self.llm_client,
            context_info="",
            crash_log=crash_log,
            language=self.config.language,
        ) or []
        self.logger.log(f"Identified {len(target_functions)} target functions")

        function_metadata = find_function_metadata(
            target_functions=target_functions,
            project_src_dir0=self.config.project_src_dir,
            project_src_dir=self.config.project_src_dir,
            project_name=self.config.project_name,
            focus=self.config.focus,
            language=self.config.language,
        )
        if not function_metadata:
            self.logger.warning("No function metadata resolved; aborting")
            return False

        functions_metadata_str = format_function_metadata(
            function_metadata, self.config.project_src_dir
        )

        initial_prompt = INITIAL_PATCH_TEMPLATE.format(
            crash_log=crash_log,
            commit_diff=commit_diff,
            functions_metadata_str=functions_metadata_str,
        )

        messages: List[Dict[str, Any]] = [
            {"role": "system", "content": "You are a world-class security engineer."},
            {"role": "user", "content": initial_prompt},
        ]

        return self._do_patch_until_success(
            messages,
            primary_pov,
            function_metadata,
            all_povs,
        )

    # ------------------------------------------------------------------
    # Patch retry loop
    # ------------------------------------------------------------------

    def _do_patch_until_success(
        self,
        messages: List[Dict[str, Any]],
        pov_metadata: Dict[str, Any],
        function_metadata: Dict[str, Any],
        all_povs: List[Dict[str, Any]],
    ) -> bool:
        """Run the patch retry loop against every configured model."""
        timeout_seconds = self.config.patching_timeout_minutes * 60
        start = time.time()

        models = self.config.models or [CLAUDE_MODEL_SONNET_45, OPENAI_MODEL_O3]

        ensure_patch_workspace_git(self.config.project_src_dir)

        for model_name in models:
            for iteration in range(1, self.config.max_iterations + 1):
                if time.time() - start > timeout_seconds:
                    self.logger.log("Patch strategy wall-clock timeout reached")
                    return False

                self.logger.log(f"Patch attempt {iteration} with {model_name}")
                patch_code_dict = generate_patch(self.llm_client, messages, model_name)
                if not patch_code_dict:
                    self.logger.warning("No patch extracted from model response")
                    continue

                patch_id = uuid.uuid4().hex[:8]
                build_ok, _, build_err = apply_patch(
                    patch_code_dict=patch_code_dict,
                    project_dir=self.config.project_dir,
                    project_src_dir=self.config.project_src_dir,
                    language=self.config.language,
                    pov_metadata=pov_metadata,
                    patch_id=patch_id,
                    function_metadata=function_metadata,
                    unharnessed=self.config.unharnessed,
                )
                if not build_ok:
                    self.logger.warning(f"Build failed: {build_err[:500]}")
                    messages.append(
                        {
                            "role": "user",
                            "content": (
                                "Build failed after applying your patch. "
                                f"Error: {build_err}\n\nPlease revise the patch."
                            ),
                        }
                    )
                    reset_project_source_code(self.config.project_src_dir)
                    continue

                patched_fuzzer_path = self._patched_fuzzer_path(pov_metadata, patch_id)
                blocked = validate_patch_against_all_povs(
                    fuzzer_path=patched_fuzzer_path,
                    project_dir=self.config.project_dir,
                    project_name=self.config.project_name,
                    focus=self.config.focus,
                    sanitizer=pov_metadata["sanitizer"],
                    all_povs=all_povs,
                    pov_success_dir=self.config.pov_success_dir,
                    language=self.config.language,
                    patch_id=patch_id,
                )
                if not blocked:
                    self.logger.warning("Patch does not block every POV")
                    messages.append(
                        {
                            "role": "user",
                            "content": "One or more POVs still crash after the patch. Please try again.",
                        }
                    )
                    reset_project_source_code(self.config.project_src_dir)
                    continue

                test_sh_path = os.path.join(self.config.project_dir, "test.sh")
                passed, test_output = validate_patch_by_functionality_test(
                    test_sh_path=test_sh_path,
                    project_src_dir=self.config.project_src_dir,
                    project_name=self.config.project_name,
                )
                if not passed:
                    self.logger.warning("Functionality test failed")
                    messages.append(
                        {
                            "role": "user",
                            "content": (
                                "Functionality test failed after the patch:\n"
                                f"{test_output[:1000]}\n\nPlease revise."
                            ),
                        }
                    )
                    reset_project_source_code(self.config.project_src_dir)
                    continue

                diff_text = generate_diff(
                    project_src_dir=self.config.project_src_dir,
                    focus=self.config.focus,
                    function_metadata=function_metadata,
                )
                self._save_patch_artifact(patch_id, model_name, diff_text)
                self.logger.success(f"Patch success on attempt {iteration} with {model_name}")
                return True

        self.logger.log("Patch strategy exhausted all model attempts without success")
        return False

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _read_fuzzer_output(self, pov_metadata: Dict[str, Any]) -> str:
        """Return the saved fuzzer output for a POV record, or empty on error."""
        fuzzer_output_file = pov_metadata.get("fuzzer_output")
        if not fuzzer_output_file:
            return ""
        path = os.path.join(self.config.pov_success_dir, fuzzer_output_file)
        try:
            with open(path, "r") as fh:
                return fh.read()
        except OSError as exc:
            self.logger.warning(f"Unable to read POV fuzzer output {path}: {exc}")
            return ""

    def _patched_fuzzer_path(self, pov_metadata: Dict[str, Any], patch_id: str) -> str:
        """Build the expected path to the patched fuzzer binary."""
        project_name = pov_metadata["project_name"]
        sanitizer = pov_metadata["sanitizer"]
        fuzzer_name = pov_metadata.get("fuzzer_name", self.config.fuzzer_name)
        return os.path.join(
            self.config.project_dir,
            "fuzz-tooling",
            "build",
            "out",
            f"{project_name}-{sanitizer}-{patch_id}",
            fuzzer_name,
        )

    def _save_patch_artifact(self, patch_id: str, model_name: str, diff_text: str) -> None:
        """Persist a successful patch diff to the patch success directory."""
        try:
            os.makedirs(self.config.patch_success_dir, exist_ok=True)
            path = os.path.join(
                self.config.patch_success_dir,
                f"patch_{patch_id}_{model_name}.diff",
            )
            with open(path, "w") as fh:
                fh.write(diff_text)
            self.logger.log(f"Saved successful patch diff to {path}")
        except OSError as exc:
            self.logger.warning(f"Failed to save patch artifact: {exc}")

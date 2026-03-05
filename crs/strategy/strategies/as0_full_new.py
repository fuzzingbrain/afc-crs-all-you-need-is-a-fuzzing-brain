#!/usr/bin/env python3
"""
AS0 Full Strategy - Advanced multi-phase POV generation for full scan

Full-scan variant of AS0. Instead of commit diffs, it:
1. Queries static analysis service for reachable functions
2. Uses LLM to score/rank vulnerable functions
3. Builds prompts from reachable function bodies
4. Supports multi-phase POV generation (same phases as delta variant)
"""
import os
import sys
import random
from typing import Dict, Any, Tuple, List, Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from strategies.as0_delta_new import AS0DeltaStrategy
from common.config import StrategyConfig
from common.llm.models import CLAUDE_MODEL_SONNET_45, OPENAI_MODEL_O3
from common.prompts import (
    create_commit_based_prompt,
    create_full_scan_prompt,
    create_category_based_prompt_c,
    create_category_based_prompt_java,
    create_call_path_prompt,
    create_combined_call_paths_prompt,
)
from common.utils import (
    extract_reachable_functions_from_analysis_service,
    extract_reachable_functions_from_analysis_service_for_c,
    find_most_likely_vulnerable_functions,
    extract_vulnerable_functions,
    convert_target_functions_format,
    extract_call_paths_from_analysis_service,
)
from strategies.as0_delta_new import VUL_CATEGORIES_C, VUL_CATEGORIES_JAVA


class AS0FullStrategy(AS0DeltaStrategy):
    """
    AS0 Full Strategy: Advanced multi-phase POV generation for full scan.

    Inherits from AS0DeltaStrategy and overrides:
    - execute_core_logic(): Uses reachable functions instead of commit diff
    - Phases 0/2/3: Use static analysis service for function discovery
    - Phase 1: Same vulnerability category approach (with empty commit_diff)
    """

    def get_strategy_name(self) -> str:
        return "as0_full"

    def execute_core_logic(self) -> bool:
        """
        Override: Full scan uses reachable functions from analysis service
        instead of commit diffs.
        """
        self.logger.log("Starting Full Scan POV generation...")

        # Find fuzzer source code
        self.fuzzer_code = self.find_fuzzer_source()
        if not self.fuzzer_code:
            self.logger.error("Failed to find fuzzer source code")
            return False

        # Full scan has no commit diff
        self.commit_diff = ""

        # Create initial prompt (will be overridden per phase)
        initial_msg = self._build_full_scan_initial_prompt()

        # Execute POV generation loop
        success, metadata = self.do_pov(initial_msg)
        return success

    def _get_reachable_functions(self) -> List[Dict[str, Any]]:
        """Query analysis service for reachable functions based on language."""
        fuzzer_src_path = ""  # Full scan doesn't track fuzzer source path
        project_src_dir = os.path.join(
            self.config.project_dir,
            f"{self.config.focus}-{self.config.sanitizer}"
        )

        if self.config.language.startswith('j'):
            return extract_reachable_functions_from_analysis_service(
                self.config.fuzzer_path, fuzzer_src_path,
                self.config.focus, project_src_dir, False
            )
        else:
            return extract_reachable_functions_from_analysis_service_for_c(
                self.config.fuzzer_path, fuzzer_src_path,
                self.config.focus, project_src_dir
            )

    def _score_and_filter_functions(
        self,
        all_reachable_funcs: List[Dict[str, Any]],
        model_name: Optional[str] = None,
        top_k_divisor: int = 10,
    ) -> Tuple[List[Dict[str, Any]], Optional[List[Dict[str, Any]]]]:
        """
        Score reachable functions using LLM and filter to top-k.

        Returns:
            Tuple of (filtered_reachable_funcs, vulnerable_functions_or_None)
        """
        vulnerable_functions = None
        reachable_funcs = all_reachable_funcs

        if len(all_reachable_funcs) > 10:
            if model_name is None:
                model_name = OPENAI_MODEL_O3 if self.config.language.startswith('j') else CLAUDE_MODEL_SONNET_45
            top_k = min(len(all_reachable_funcs) // top_k_divisor, 10)

            vulnerable_functions = find_most_likely_vulnerable_functions(
                all_reachable_funcs, self.config.language,
                self.llm_client, self.logger, top_k
            )
            reachable_funcs = extract_vulnerable_functions(
                reachable_funcs, vulnerable_functions
            )

        return reachable_funcs, vulnerable_functions

    def _build_full_scan_initial_prompt(self) -> str:
        """Build the initial prompt for full scan using reachable functions."""
        all_reachable_funcs = self._get_reachable_functions()
        self.logger.log(f"Found {len(all_reachable_funcs)} reachable functions")

        if all_reachable_funcs:
            reachable_funcs, vulnerable_functions = self._score_and_filter_functions(
                all_reachable_funcs
            )
            return create_full_scan_prompt(
                self.fuzzer_code, self.config.sanitizer,
                self.config.language, reachable_funcs, vulnerable_functions,
            )
        else:
            # Fallback to commit-based prompt (empty diff)
            return create_commit_based_prompt(
                self.fuzzer_code, self.commit_diff,
                self.config.sanitizer, self.config.language
            )

    def do_pov(self, initial_msg: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Override: Route to full-scan-aware phase handlers.
        """
        pov_phase = self.config.pov_phase
        self.logger.log(f"POV_PHASE: {pov_phase} AS0 Full Strategy")

        if pov_phase == 0:
            return self._do_full_phase_0(initial_msg)
        elif pov_phase == 1:
            return self._do_full_phase_1(initial_msg)
        elif pov_phase == 2:
            return self._do_full_phase_2(initial_msg)
        elif pov_phase == 3:
            return self._do_full_phase_3(initial_msg)
        else:
            self.logger.error(f"POV_PHASE: {pov_phase} does not exist")
            return False, {}

    def _do_full_phase_0(self, initial_msg: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Phase 0: Full scan with reachable function analysis.
        Java uses full-scan prompt; C falls back to commit-based.
        """
        self.logger.log("Phase 0: Full scan basic approach")

        if self.config.language.startswith('j'):
            # Java: use full scan prompt (already built in initial_msg)
            return self._do_pov_phase_0(initial_msg)
        else:
            # C: use commit-based prompt (original behavior)
            prompt = create_commit_based_prompt(
                self.fuzzer_code, self.commit_diff,
                self.config.sanitizer, self.config.language
            )
            return self._do_pov_phase_0(prompt)

    def _do_full_phase_1(self, initial_msg: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Phase 1: Vulnerability category-based (same as delta, with empty commit_diff).
        """
        self.logger.log("Phase 1: Vulnerability category-based approach (full scan)")

        if self.config.language.startswith('c'):
            categories = VUL_CATEGORIES_C[:]
            prompt_builder = create_category_based_prompt_c
        else:
            categories = VUL_CATEGORIES_JAVA[:]
            prompt_builder = create_category_based_prompt_java

        random.shuffle(categories)

        for idx, category in enumerate(categories, 1):
            self.logger.log(f"[{idx}/{len(categories)}] Trying category: {category}")

            category_prompt = prompt_builder(
                fuzzer_code=self.fuzzer_code,
                commit_diff=self.commit_diff,
                sanitizer=self.config.sanitizer,
                category=category
            )

            pov_success, pov_metadata = self._do_pov_phase_0(
                category_prompt,
                max_iterations=3,
                models=[CLAUDE_MODEL_SONNET_45, CLAUDE_MODEL_SONNET_45, OPENAI_MODEL_O3]
            )

            if pov_success:
                self.logger.log(f"SUCCESS! Category {category} found POV")
                return True, pov_metadata

        self.logger.log(f"Phase 1 exhausted all {len(categories)} categories")
        return False, {}

    def _do_full_phase_2(self, initial_msg: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Phase 2: Full scan with reachable function analysis + vulnerability scoring.
        Uses a different model than Phase 0 for diversity.
        """
        self.logger.log("Phase 2: Reachable functions with vulnerability scoring")

        all_reachable_funcs = self._get_reachable_functions()
        self.logger.log(f"Found {len(all_reachable_funcs)} reachable functions")

        if not all_reachable_funcs:
            self.logger.warning("No reachable functions found, skipping Phase 2")
            return False, {}

        # Use different model for scoring diversity
        scoring_model = OPENAI_MODEL_O3 if self.config.language.startswith('j') else CLAUDE_MODEL_SONNET_45
        reachable_funcs, vulnerable_functions = self._score_and_filter_functions(
            all_reachable_funcs, model_name=scoring_model
        )

        prompt = create_full_scan_prompt(
            self.fuzzer_code, self.config.sanitizer,
            self.config.language, reachable_funcs, vulnerable_functions,
        )

        return self._do_pov_phase_0(prompt)

    def _do_full_phase_3(self, initial_msg: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Phase 3: Call path analysis on reachable functions.
        Uses static analysis to find paths from fuzzer to vulnerable functions.
        """
        self.logger.log("Phase 3: Call path analysis (full scan)")

        all_reachable_funcs = self._get_reachable_functions()
        self.logger.log(f"Found {len(all_reachable_funcs)} reachable functions")

        if not all_reachable_funcs:
            self.logger.warning("No reachable functions found, skipping Phase 3")
            return False, {}

        # Score and filter
        scoring_model = OPENAI_MODEL_O3 if self.config.language.startswith('j') else CLAUDE_MODEL_SONNET_45
        reachable_funcs, vulnerable_functions = self._score_and_filter_functions(
            all_reachable_funcs, model_name=scoring_model, top_k_divisor=5
        )

        # Convert to target functions format for call path extraction
        target_functions = convert_target_functions_format(reachable_funcs)
        self.logger.log(f"Target functions for call path analysis: {len(target_functions)} files")

        project_src_dir = os.path.join(
            self.config.project_dir,
            f"{self.config.focus}-{self.config.sanitizer}"
        )
        fuzzer_src_path = ""

        # Query call paths
        use_qx = not self.config.language.startswith('c')
        call_paths = extract_call_paths_from_analysis_service(
            self.config.fuzzer_path, fuzzer_src_path,
            self.config.focus, project_src_dir,
            target_functions, use_qx
        )

        if len(call_paths) == 0:
            call_paths = extract_call_paths_from_analysis_service(
                self.config.fuzzer_path, fuzzer_src_path,
                self.config.focus, project_src_dir,
                target_functions, False
            )

        if len(call_paths) == 0:
            if self.has_successful_pov():
                self.logger.log("No call paths, but POV already exists")
                return True, {}
            self.logger.log("No call paths found, skipping Phase 3")
            return False, {}

        # Limit call paths
        MAX_CALL_PATHS = 10
        if len(call_paths) > MAX_CALL_PATHS:
            self.logger.log(f"Limiting {len(call_paths)} call paths to {MAX_CALL_PATHS}")
            call_paths = call_paths[:MAX_CALL_PATHS]

        self.logger.log(f"Found {len(call_paths)} call paths to analyze")

        # Try each call path
        for idx, call_path in enumerate(call_paths, 1):
            self.logger.log(f"[{idx}/{len(call_paths)}] Trying call path")

            path_prompt = create_call_path_prompt(
                fuzzer_code=self.fuzzer_code,
                commit_diff=self.commit_diff,
                project_src_dir=project_src_dir,
                call_path=call_path,
                sanitizer=self.config.sanitizer,
                language=self.config.language
            )

            pov_success, pov_metadata = self._do_pov_phase_0(path_prompt)
            if pov_success:
                self.logger.log(f"SUCCESS! Call path {idx} found POV")
                return True, pov_metadata

        # Combine all paths for final attempt
        if len(call_paths) > 1:
            self.logger.log(f"Combining all {len(call_paths)} call paths")
            combined_prompt = create_combined_call_paths_prompt(
                fuzzer_code=self.fuzzer_code,
                commit_diff=self.commit_diff,
                project_src_dir=project_src_dir,
                call_paths=call_paths,
                sanitizer=self.config.sanitizer,
                language=self.config.language
            )
            return self._do_pov_phase_0(combined_prompt)

        self.logger.log("Phase 3 exhausted all call paths")
        return False, {}

    def submit_pov(self, pov_metadata: Dict[str, Any]) -> bool:
        """Override strategy name in submission."""
        # Temporarily patch strategy name for submission
        pov_metadata_copy = dict(pov_metadata)
        result = super().submit_pov(pov_metadata_copy)
        return result


def main():
    """
    Main entry point for AS0 Full strategy
    """
    import argparse

    parser = argparse.ArgumentParser(description="AS0 Full Strategy")
    parser.add_argument("fuzzer_path", help="Path to fuzzer executable")
    parser.add_argument("project_name", help="Project name")
    parser.add_argument("focus", help="Focus directory")
    parser.add_argument("language", help="Project language (e.g., c, java)")

    parser.add_argument("--test-nginx", dest="test_nginx", type=lambda x: x.lower() == 'true',
                        default=False)
    parser.add_argument("--do-patch", dest="do_patch", type=lambda x: x.lower() == 'true',
                        default=False)
    parser.add_argument("--do-patch-only", dest="do_patch_only", type=lambda x: x.lower() == 'true',
                        default=False)
    parser.add_argument("--full-scan", dest="full_scan", type=lambda x: x.lower() == 'true',
                        default=True)
    parser.add_argument("--check-patch-success", action="store_true")
    parser.add_argument("--max-iterations", dest="max_iterations", type=int, default=5)
    parser.add_argument("--fuzzing-timeout", dest="fuzzing_timeout", type=int, default=30)
    parser.add_argument("--patching-timeout", dest="patching_timeout", type=int, default=30)
    parser.add_argument("--pov-metadata-dir", dest="pov_metadata_dir", type=str,
                        default="successful_povs")
    parser.add_argument("--patch-workspace-dir", type=str, default="patch_workspace")
    parser.add_argument("--model", type=str, default="")
    parser.add_argument("--cpv", type=str, default="cpv12")
    parser.add_argument("--log-dir", type=str, default="./logs")
    parser.add_argument("--pov-phase", type=int, default=0)

    args = parser.parse_args()

    config = StrategyConfig(
        strategy_name="as0_full",
        fuzzer_path=args.fuzzer_path,
        project_name=args.project_name,
        focus=args.focus,
        language=args.language,
        test_nginx=args.test_nginx,
        do_patch=args.do_patch,
        do_patch_only=args.do_patch_only,
        full_scan=True,
        check_patch_success=args.check_patch_success,
        max_iterations=args.max_iterations,
        fuzzing_timeout_minutes=args.fuzzing_timeout,
        patching_timeout_minutes=args.patching_timeout,
        pov_metadata_dir=args.pov_metadata_dir,
        patch_workspace_dir=args.patch_workspace_dir,
        cpv=args.cpv,
        log_dir=args.log_dir,
        pov_phase=args.pov_phase,
        models=[args.model] if args.model else None,
    )

    strategy = AS0FullStrategy(config)
    success = strategy.run()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

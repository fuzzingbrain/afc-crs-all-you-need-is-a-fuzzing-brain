"""
POV Delta Strategy

Strategy for delta-scan mode: analyzes changes in diff for vulnerabilities.

Workflow:
1. Check if diff changes are reachable from fuzzer
2. Analyze reachable code to find suspicious points
3. Verify suspicious points with AI Agent (parallel pipeline)
4. Generate POV for high-confidence points (parallel pipeline)
5. Save results
"""

import json
from datetime import datetime
from typing import Dict, Any, List, Optional

from .pov_base import POVBaseStrategy
from ...analysis.diff_parser import get_reachable_changes, get_all_changes, DiffReachabilityResult, FunctionChange
from ...core.models import SuspiciousPoint
from ...agents import SuspiciousPointAgent
from ...llms import CLAUDE_SONNET_4_5


class POVDeltaStrategy(POVBaseStrategy):
    """
    POV Strategy for Delta-scan mode.

    Focuses on analyzing changes in the diff that are reachable
    from the fuzzer entry point.
    """

    def __init__(self, executor, use_pipeline: bool = True):
        """
        Initialize POV Delta Strategy.

        Args:
            executor: WorkerExecutor instance
            use_pipeline: Whether to use parallel pipeline (default: True)
        """
        super().__init__(executor, use_pipeline)

        # Diff path for delta mode
        self.diff_path = executor.diff_path

        # Reachability result (populated after check)
        self._reachability_result: Optional[DiffReachabilityResult] = None

        # All changes (including static-unreachable) for new delta scan logic
        self._all_changes: List[FunctionChange] = []

        # Create the suspicious point agent for delta analysis
        # Note: Use higher max_iterations for finding SPs (not just verifying)
        agent_log_dir = self.log_dir / "agent" if self.log_dir else self.results_path
        self._agent = SuspiciousPointAgent(
            fuzzer=self.fuzzer,
            sanitizer=self.sanitizer,
            scan_mode="delta",  # Delta mode: skip reachability analysis in verify
            model=CLAUDE_SONNET_4_5,  # Force Sonnet for SP analysis
            verbose=True,
            task_id=self.task_id,
            worker_id=self.worker_id,
            log_dir=agent_log_dir,
            max_iterations=50,  # Need more iterations for finding SPs in delta mode
        )

    @property
    def strategy_name(self) -> str:
        return "POV Delta Strategy"

    @property
    def scan_mode(self) -> str:
        """Delta mode: skip reachability analysis in verify."""
        return "delta"

    def _pre_find_suspicious_points(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze diff changes before finding suspicious points.

        NEW LOGIC: Don't filter by reachability! Get ALL changes and let LLM analyze them.
        Static analysis may incorrectly mark function-pointer-called functions as unreachable.

        Args:
            result: Result dictionary to update

        Returns:
            Dict with 'skip': True only if no changes at all
        """
        import time

        self.log_info(f"[Step 1/5] Analyzing diff changes (ignoring reachability filter)...")
        step_start = time.time()

        # Get ALL changes (not just reachable ones)
        all_changes = self._get_all_diff_changes()
        self._all_changes = all_changes

        # Also get reachability result for reporting (but don't use it to filter)
        reachability = self._check_diff_reachability()

        # Report both reachable and unreachable
        result["reachable"] = reachability.reachable
        result["all_changes"] = [
            {
                "function": c.function_name,
                "file": c.file_path,
                "static_reachable": c.static_reachable,
                "distance": c.reachability_distance
            }
            for c in all_changes
        ]
        result["reachable_changes"] = [
            {"function": c.function_name, "file": c.file_path, "distance": c.reachability_distance}
            for c in reachability.reachable_changes
        ]
        result["unreachable_functions"] = reachability.unreachable_functions

        step_duration = time.time() - step_start
        result["phase_reachability"] = step_duration

        reachable_count = sum(1 for c in all_changes if c.static_reachable)
        unreachable_count = len(all_changes) - reachable_count
        self.log_info(f"[Step 1/5] Done in {step_duration:.1f}s - {len(all_changes)} changes ({reachable_count} reachable, {unreachable_count} static-unreachable)")

        # Only skip if NO changes at all (not based on reachability!)
        if not all_changes:
            self.log_info(f"No changes in diff, skipping")
            result["skip_reason"] = "no_changes"
            return {"skip": True}

        # Log the unreachable functions that will now be analyzed
        if unreachable_count > 0:
            unreachable_names = [c.function_name for c in all_changes if not c.static_reachable]
            self.log_info(f"[NEW] Will analyze {unreachable_count} static-unreachable functions: {unreachable_names}")
            self.log_info(f"[NEW] These may be reachable via function pointers - LLM will judge")

        return {"skip": False}

    def _find_suspicious_points(self) -> List[SuspiciousPoint]:
        """
        Find suspicious points in ALL changed functions (not just reachable).

        NEW LOGIC: Pass ALL changes to the agent, including static-unreachable ones.
        The agent will analyze all of them and create SPs. Reachability will be
        judged in the verify phase.

        Returns:
            List of SuspiciousPoint objects
        """
        self.log_info("Finding suspicious points in ALL changes (ignoring reachability filter)...")

        if not self._all_changes:
            self.log_warning("No changes found, cannot find suspicious points")
            return []

        # Prepare ALL changes for agent (including static-unreachable)
        all_changes = [
            {
                "function": c.function_name,
                "file": c.file_path,
                "static_reachable": c.static_reachable,
                "distance": c.reachability_distance,
            }
            for c in self._all_changes
        ]

        reachable_count = sum(1 for c in all_changes if c["static_reachable"])
        self.log_info(f"Passing {len(all_changes)} functions to agent ({reachable_count} reachable, {len(all_changes) - reachable_count} static-unreachable)")

        # Run the agent to find suspicious points
        try:
            response = self._agent.find_suspicious_points_sync(all_changes)
            self.log_debug(f"Agent response: {response[:500]}...")
        except Exception as e:
            self.log_error(f"Agent failed to find suspicious points: {e}")
            return []

        # Query database for suspicious points created by agent
        return self._get_suspicious_points_from_db()

    # =========================================================================
    # Diff Reachability
    # =========================================================================

    def _check_diff_reachability(self) -> DiffReachabilityResult:
        """
        Check if changes in diff are reachable from this fuzzer.

        Returns:
            DiffReachabilityResult with reachable changes
        """
        self.log_info(f"Checking diff reachability for fuzzer: {self.fuzzer}")

        # Check if diff file exists
        if not self.diff_path or not self.diff_path.exists():
            self.log_warning(f"Diff file not found: {self.diff_path}")
            return DiffReachabilityResult(reachable=False)

        # Read diff content
        try:
            diff_content = self.diff_path.read_text(encoding='utf-8', errors='replace')
        except Exception as e:
            self.log_error(f"Failed to read diff file: {e}")
            return DiffReachabilityResult(reachable=False)

        if not diff_content.strip():
            self.log_warning("Diff file is empty")
            return DiffReachabilityResult(reachable=False)

        self.log_debug(f"Read diff file: {len(diff_content)} bytes")

        # Check if Analysis Server is available
        analysis_client = self.get_analysis_client()
        if not analysis_client:
            self.log_error("Analysis Server not available, cannot check reachability")
            # Return optimistic result - assume reachable if we can't check
            return DiffReachabilityResult(reachable=True)

        # Analyze diff reachability
        result = get_reachable_changes(diff_content, self.fuzzer, analysis_client)
        self._reachability_result = result

        # Save report
        self._save_reachability_report(result)

        return result

    def _get_all_diff_changes(self) -> List[FunctionChange]:
        """
        Get ALL changed functions from diff (including static-unreachable).

        This is the new method that doesn't filter by reachability.
        Static reachability info is included but used for scoring, not filtering.

        Returns:
            List of FunctionChange objects
        """
        self.log_info(f"Getting all diff changes for fuzzer: {self.fuzzer}")

        # Check if diff file exists
        if not self.diff_path or not self.diff_path.exists():
            self.log_warning(f"Diff file not found: {self.diff_path}")
            return []

        # Read diff content
        try:
            diff_content = self.diff_path.read_text(encoding='utf-8', errors='replace')
        except Exception as e:
            self.log_error(f"Failed to read diff file: {e}")
            return []

        if not diff_content.strip():
            self.log_warning("Diff file is empty")
            return []

        self.log_debug(f"Read diff file: {len(diff_content)} bytes")

        # Check if Analysis Server is available
        analysis_client = self.get_analysis_client()
        if not analysis_client:
            self.log_error("Analysis Server not available")
            return []

        # Get ALL changes (not filtered by reachability)
        return get_all_changes(diff_content, self.fuzzer, analysis_client)

    def _save_reachability_report(self, result: DiffReachabilityResult) -> None:
        """Save diff reachability report to results directory."""
        report = {
            "timestamp": datetime.now().isoformat(),
            "task_id": self.task_id,
            "fuzzer": self.fuzzer,
            "sanitizer": self.sanitizer,
            "scan_mode": self.scan_mode,
            "diff_path": str(self.diff_path),
            "reachable": result.reachable,
            "summary": result.summary,
            "total_changed_functions": result.total_changed_functions,
            "changed_files": result.changed_files,
            "reachable_changes": [
                {
                    "function": c.function_name,
                    "file": c.file_path,
                    "function_file": c.function_file,
                    "lines": f"{c.line_start}-{c.line_end}",
                    "changed_lines": c.changed_lines,
                    "distance": c.reachability_distance,
                    "diff_content": c.diff_content,
                }
                for c in result.reachable_changes
            ],
            "unreachable_functions": result.unreachable_functions,
        }

        report_path = self.results_path / "diff_reachability_report.json"
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            self.log_info(f"Saved reachability report to: {report_path}")
        except Exception as e:
            self.log_error(f"Failed to save reachability report: {e}")

    # =========================================================================
    # Delta Seeds Generation
    # =========================================================================

    def _generate_delta_seeds(self, suspicious_points: List[SuspiciousPoint]) -> int:
        """
        Generate initial seeds for delta-scan mode.

        Creates seeds targeting the changed functions and identified suspicious points.
        Seeds are added to the Global Fuzzer's corpus.

        Args:
            suspicious_points: List of SPs created in the find phase

        Returns:
            Number of seeds generated
        """
        import asyncio

        # Check if FuzzerManager is available
        fuzzer_manager = getattr(self.executor, 'fuzzer_manager', None)
        if not fuzzer_manager:
            self.log_warning("FuzzerManager not available, skipping delta seeds generation")
            return 0

        # Prepare changed functions context
        changed_functions = [
            {
                "function": c.function_name,
                "file": c.file_path,
                "static_reachable": c.static_reachable,
                "distance": c.reachability_distance,
            }
            for c in self._all_changes
        ]

        if not changed_functions:
            self.log_warning("No changed functions, skipping delta seeds generation")
            return 0

        # Prepare suspicious points context
        sp_context = [
            {
                "function": sp.function_name,
                "vuln_type": sp.vuln_type,
                "description": sp.description,
            }
            for sp in suspicious_points
        ]

        # Get fuzzer source code
        fuzzer_source = ""
        analysis_client = self.get_analysis_client()
        if analysis_client:
            try:
                fuzzer_source = analysis_client.get_file_content(f"{self.fuzzer}.cc") or ""
                if not fuzzer_source:
                    fuzzer_source = analysis_client.get_file_content(f"{self.fuzzer}.cpp") or ""
                if not fuzzer_source:
                    fuzzer_source = analysis_client.get_file_content(f"{self.fuzzer}.c") or ""
            except Exception as e:
                self.log_warning(f"Failed to get fuzzer source: {e}")

        # Create SeedAgent
        from ...fuzzer import SeedAgent

        agent_log_dir = self.log_dir / "seed_agent" if self.log_dir else self.results_path
        seed_agent = SeedAgent(
            task_id=self.task_id,
            worker_id=self.worker_id,
            fuzzer=self.fuzzer,
            sanitizer=self.sanitizer,
            fuzzer_manager=fuzzer_manager,
            repos=self.repos,
            fuzzer_source=fuzzer_source,
            workspace_path=self.workspace_path,
            log_dir=agent_log_dir,
            max_iterations=15,  # Allow more iterations for delta seeds (with urgency forcing on last 2)
        )

        # Generate seeds (run async in sync context)
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        try:
            self.log_info(f"Generating delta seeds for {len(changed_functions)} changed functions...")

            result = loop.run_until_complete(
                seed_agent.generate_delta_seeds(
                    delta_id=self.task_id,
                    changed_functions=changed_functions,
                    suspicious_points=sp_context,
                )
            )

            seeds_generated = result.get("seeds_generated", 0)
            self.log_info(f"Delta seeds generation complete: {seeds_generated} seeds created")

            # Always start Global Fuzzer (even with 0 seeds, fuzzer can run with existing corpus)
            if not fuzzer_manager.global_fuzzer:
                self.log_info("Starting Global Fuzzer...")
                try:
                    loop.run_until_complete(fuzzer_manager.start_global_fuzzer())
                    self.log_info("Global Fuzzer started - running in background during SP analysis")
                except Exception as e:
                    self.log_warning(f"Failed to start Global Fuzzer: {e}")

            return seeds_generated

        except Exception as e:
            self.log_error(f"Delta seeds generation failed: {e}")
            return 0

    # =========================================================================
    # Properties
    # =========================================================================

    @property
    def reachable_changes(self) -> List:
        """Get the list of reachable changes (after running delta check)."""
        if self._reachability_result:
            return self._reachability_result.reachable_changes
        return []

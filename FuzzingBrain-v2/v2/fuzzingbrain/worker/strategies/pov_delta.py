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
from ...analysis.diff_parser import get_reachable_changes, DiffReachabilityResult
from ...core.models import SuspiciousPoint
from ...agents import SuspiciousPointAgent


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

        # Create the suspicious point agent for delta analysis
        # Note: Use higher max_iterations for finding SPs (not just verifying)
        agent_log_dir = self.log_dir / "agent" if self.log_dir else self.results_path
        self._agent = SuspiciousPointAgent(
            fuzzer=self.fuzzer,
            sanitizer=self.sanitizer,
            verbose=True,
            task_id=self.task_id,
            worker_id=self.worker_id,
            log_dir=agent_log_dir,
            max_iterations=50,  # Need more iterations for finding SPs in delta mode
        )

    @property
    def strategy_name(self) -> str:
        return "POV Delta Strategy"

    def _pre_find_suspicious_points(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check diff reachability before finding suspicious points.

        Args:
            result: Result dictionary to update

        Returns:
            Dict with 'skip': True if no reachable changes
        """
        import time

        self.log_info(f"[Step 1/5] Checking diff reachability...")
        step_start = time.time()

        reachability = self._check_diff_reachability()
        result["reachable"] = reachability.reachable
        result["reachable_changes"] = [
            {"function": c.function_name, "file": c.file_path, "distance": c.reachability_distance}
            for c in reachability.reachable_changes
        ]

        step_duration = time.time() - step_start
        result["phase_reachability"] = step_duration
        self.log_info(f"[Step 1/5] Done in {step_duration:.1f}s - {len(reachability.reachable_changes)} reachable changes")

        if not reachability.reachable:
            self.log_info(f"No reachable changes in diff, skipping")
            result["skip_reason"] = "no_reachable_changes"
            return {"skip": True}

        return {"skip": False}

    def _find_suspicious_points(self) -> List[SuspiciousPoint]:
        """
        Find suspicious points in reachable changed functions.

        Returns:
            List of SuspiciousPoint objects
        """
        self.log_info("Finding suspicious points in reachable changes...")

        if not self._reachability_result:
            self.log_warning("No reachability result, cannot find suspicious points")
            return []

        # Prepare reachable changes for agent
        reachable_changes = [
            {
                "function": c.function_name,
                "file": c.file_path,
                "distance": c.reachability_distance,
            }
            for c in self._reachability_result.reachable_changes
        ]

        # Run the agent to find suspicious points
        try:
            response = self._agent.find_suspicious_points_sync(reachable_changes)
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
    # Properties
    # =========================================================================

    @property
    def reachable_changes(self) -> List:
        """Get the list of reachable changes (after running delta check)."""
        if self._reachability_result:
            return self._reachability_result.reachable_changes
        return []

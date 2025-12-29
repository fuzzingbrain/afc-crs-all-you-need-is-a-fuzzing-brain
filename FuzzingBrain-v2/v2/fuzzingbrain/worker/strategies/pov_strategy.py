"""
POV Strategy

Finds vulnerabilities using AI-based suspicious point analysis.

Workflow (Delta-scan mode):
1. Check if diff changes are reachable from fuzzer
2. Analyze reachable code to find suspicious points
3. Verify suspicious points with AI Agent
4. Sort and prioritize suspicious points by score
5. Save results
"""

import json
from datetime import datetime
from typing import Dict, Any, List, Optional

from .base import BaseStrategy
from ...analysis.diff_parser import get_reachable_changes, DiffReachabilityResult
from ...core.models import SuspiciousPoint


class POVStrategy(BaseStrategy):
    """
    POV (Proof-of-Vulnerability) Strategy.

    Uses AI to analyze code and find vulnerabilities.
    """

    def __init__(self, executor):
        super().__init__(executor)

        # Diff path for delta mode
        self.diff_path = executor.diff_path

        # Reachability result (populated in delta mode)
        self._reachability_result: Optional[DiffReachabilityResult] = None

    def execute(self) -> Dict[str, Any]:
        """
        Execute POV strategy.

        Returns:
            Result dictionary with findings
        """
        self.log_info(f"Starting POV strategy for {self.fuzzer} (mode: {self.scan_mode})")

        result = {
            "strategy": "pov",
            "scan_mode": self.scan_mode,
            "reachable": True,
            "reachable_changes": [],
            "suspicious_points_found": 0,
            "suspicious_points_verified": 0,
            "confirmed_bugs": 0,
        }

        try:
            # Step 1: Delta mode - check diff reachability
            if self.scan_mode == "delta":
                reachability = self._check_diff_reachability()
                result["reachable"] = reachability.reachable
                result["reachable_changes"] = [
                    {"function": c.function_name, "file": c.file_path, "distance": c.reachability_distance}
                    for c in reachability.reachable_changes
                ]

                if not reachability.reachable:
                    self.log_info(f"No reachable changes in diff, skipping")
                    result["skip_reason"] = "no_reachable_changes"
                    return result

                self.log_info(f"Found {len(reachability.reachable_changes)} reachable changes")

            # Step 2: Find suspicious points
            suspicious_points = self._find_suspicious_points()
            result["suspicious_points_found"] = len(suspicious_points)

            if not suspicious_points:
                self.log_info("No suspicious points found")
                return result

            # Step 3: Verify suspicious points with AI Agent
            verified_points = self._verify_suspicious_points(suspicious_points)
            result["suspicious_points_verified"] = len(verified_points)

            # Step 4: Sort by score (higher score = more likely to be real bug)
            sorted_points = self._sort_by_priority(verified_points)

            # Count confirmed bugs (is_real == True)
            confirmed = [p for p in sorted_points if p.is_real]
            result["confirmed_bugs"] = len(confirmed)

            # Step 5: Save results
            self._save_results(sorted_points)

            self.log_info(f"Completed: {len(confirmed)} confirmed bugs out of {len(verified_points)} verified points")
            return result

        except Exception as e:
            self.log_error(f"Strategy failed: {e}")
            raise

    # =========================================================================
    # Step 1: Diff Reachability (Delta Mode)
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
    # Step 2: Find Suspicious Points
    # =========================================================================

    def _find_suspicious_points(self) -> List[SuspiciousPoint]:
        """
        Find suspicious points in code.

        For delta mode: Focus on reachable changed functions.
        For full mode: Analyze all reachable functions.

        Returns:
            List of SuspiciousPoint objects
        """
        self.log_info("Finding suspicious points...")

        suspicious_points = []

        if self.scan_mode == "delta" and self._reachability_result:
            # Delta mode: analyze reachable changes
            for change in self._reachability_result.reachable_changes:
                points = self._analyze_function_for_vulnerabilities(
                    function_name=change.function_name,
                    file_path=change.function_file,
                    diff_content=change.diff_content,
                )
                suspicious_points.extend(points)
        else:
            # Full mode: TODO - analyze all functions reachable from fuzzer
            self.log_warning("Full scan suspicious point analysis not yet implemented")

        self.log_info(f"Found {len(suspicious_points)} suspicious points")
        return suspicious_points

    def _analyze_function_for_vulnerabilities(
        self,
        function_name: str,
        file_path: str,
        diff_content: str = None,
    ) -> List[SuspiciousPoint]:
        """
        Analyze a function for potential vulnerabilities.

        Uses AI to identify suspicious code patterns.

        Args:
            function_name: Function to analyze
            file_path: File containing the function
            diff_content: Optional diff content for context

        Returns:
            List of SuspiciousPoint objects
        """
        # TODO: Implement AI-based vulnerability analysis
        # This should:
        # 1. Get function source code
        # 2. Send to LLM for analysis
        # 3. Parse LLM response into SuspiciousPoint objects

        self.log_debug(f"Analyzing function: {function_name} in {file_path}")

        # Placeholder - return empty list for now
        return []

    # =========================================================================
    # Step 3: Verify Suspicious Points
    # =========================================================================

    def _verify_suspicious_points(
        self, suspicious_points: List[SuspiciousPoint]
    ) -> List[SuspiciousPoint]:
        """
        Verify suspicious points with AI Agent.

        The agent performs deeper analysis to determine if each point
        is likely a real vulnerability.

        Args:
            suspicious_points: List of points to verify

        Returns:
            List of verified (likely real) suspicious points
        """
        self.log_info(f"Verifying {len(suspicious_points)} suspicious points...")

        verified = []

        for point in suspicious_points:
            # TODO: Implement AI verification
            # This should:
            # 1. Get more context (callers, callees, data flow)
            # 2. Ask AI to verify if the bug is real
            # 3. Mark point as verified or not

            # Placeholder - assume all are verified
            verified.append(point)

        self.log_info(f"Verified {len(verified)} suspicious points")
        return verified

    # =========================================================================
    # Step 4: Sort and Prioritize
    # =========================================================================

    def _sort_by_priority(
        self, suspicious_points: List[SuspiciousPoint]
    ) -> List[SuspiciousPoint]:
        """
        Sort suspicious points by priority.

        Sorting order:
        1. is_important (high priority bugs first)
        2. score (higher score = more likely to be real)

        Args:
            suspicious_points: List of points to sort

        Returns:
            Sorted list of suspicious points
        """
        return sorted(
            suspicious_points,
            key=lambda p: (p.is_important, p.score),
            reverse=True,
        )

    # =========================================================================
    # Step 5: Save Results
    # =========================================================================

    def _save_results(self, suspicious_points: List[SuspiciousPoint]) -> None:
        """
        Save suspicious points to database and results file.

        Args:
            suspicious_points: List of points to save
        """
        self.log_info(f"Saving {len(suspicious_points)} suspicious points...")

        # Save to database
        for point in suspicious_points:
            point.task_id = self.task_id
            try:
                self.repos.suspicious_points.save(point)
            except Exception as e:
                self.log_error(f"Failed to save suspicious point to DB: {e}")

        # Save summary to results file
        report = {
            "timestamp": datetime.now().isoformat(),
            "task_id": self.task_id,
            "fuzzer": self.fuzzer,
            "sanitizer": self.sanitizer,
            "scan_mode": self.scan_mode,
            "total_points": len(suspicious_points),
            "confirmed_bugs": len([p for p in suspicious_points if p.is_real]),
            "suspicious_points": [
                {
                    "id": p.suspicious_point_id,
                    "function": p.function_name,
                    "vuln_type": p.vuln_type,
                    "description": p.description,
                    "score": p.score,
                    "is_important": p.is_important,
                    "is_real": p.is_real,
                    "verification_notes": p.verification_notes,
                }
                for p in suspicious_points
            ],
        }

        report_path = self.results_path / "suspicious_points_report.json"
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            self.log_info(f"Saved results to: {report_path}")
        except Exception as e:
            self.log_error(f"Failed to save results: {e}")

    # =========================================================================
    # Properties
    # =========================================================================

    @property
    def reachable_changes(self) -> List:
        """Get the list of reachable changes (after running delta check)."""
        if self._reachability_result:
            return self._reachability_result.reachable_changes
        return []

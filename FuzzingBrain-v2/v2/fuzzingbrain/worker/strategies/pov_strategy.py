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
from ...agents import SuspiciousPointAgent
from ...tools.code_viewer import set_code_viewer_context
from ...tools.analyzer import set_analyzer_context


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

        # Set up tool contexts for MCP
        self._setup_tool_contexts()

        # Create the suspicious point agent
        self._agent = SuspiciousPointAgent(
            fuzzer=self.fuzzer,
            sanitizer=self.sanitizer,
            verbose=True,
        )

    def _setup_tool_contexts(self) -> None:
        """Set up contexts for MCP tools."""
        # Set code viewer context (workspace path, repo subdir, diff filename)
        set_code_viewer_context(
            workspace_path=str(self.workspace_path),
            repo_subdir="repo",
            diff_filename="diff/ref.diff",
        )

        # Set analyzer context (socket path)
        if self.executor.analysis_socket_path:
            set_analyzer_context(
                socket_path=self.executor.analysis_socket_path,
                client_id=f"agent_{self.fuzzer}_{self.sanitizer}",
            )

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
        Find suspicious points in code using AI Agent.

        For delta mode: Focus on reachable changed functions.
        For full mode: Analyze all reachable functions.

        Returns:
            List of SuspiciousPoint objects
        """
        self.log_info("Finding suspicious points with AI Agent...")

        if self.scan_mode == "delta" and self._reachability_result:
            # Delta mode: use agent to analyze reachable changes
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
                self.log_debug(f"Agent response: {response[:500]}...")  # Log first 500 chars
            except Exception as e:
                self.log_error(f"Agent failed to find suspicious points: {e}")
                return []

            # Query database for suspicious points created by agent
            suspicious_points = self._get_suspicious_points_from_db()

        else:
            # Full mode: TODO - analyze all functions reachable from fuzzer
            self.log_warning("Full scan suspicious point analysis not yet implemented")
            suspicious_points = []

        self.log_info(f"Found {len(suspicious_points)} suspicious points")
        return suspicious_points

    def _get_suspicious_points_from_db(self) -> List[SuspiciousPoint]:
        """
        Get suspicious points created by agent from database.

        Returns:
            List of SuspiciousPoint objects
        """
        try:
            # Query for unchecked points for this task
            points_data = self.repos.suspicious_points.find_unchecked(self.task_id)
            return [SuspiciousPoint.from_dict(p) for p in points_data]
        except Exception as e:
            self.log_error(f"Failed to get suspicious points from DB: {e}")
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
            List of verified suspicious points (all checked, some may be real)
        """
        self.log_info(f"Verifying {len(suspicious_points)} suspicious points with AI Agent...")

        verified = []

        for i, point in enumerate(suspicious_points):
            self.log_info(f"Verifying point {i+1}/{len(suspicious_points)}: {point.function_name}")

            # Convert SuspiciousPoint to dict for agent
            point_dict = point.to_dict()

            try:
                # Run agent to verify this point
                response = self._agent.verify_suspicious_point_sync(point_dict)
                self.log_debug(f"Verification response: {response[:300]}...")

                # Re-fetch the point from database (agent may have updated it)
                updated_point = self._get_suspicious_point_by_id(point.suspicious_point_id)
                if updated_point:
                    verified.append(updated_point)
                else:
                    # Point not found, use original
                    verified.append(point)

            except Exception as e:
                self.log_error(f"Failed to verify point {point.suspicious_point_id}: {e}")
                # Mark as checked but not verified due to error
                point.is_checked = True
                point.verification_notes = f"Verification failed: {e}"
                verified.append(point)

        self.log_info(f"Verified {len(verified)} suspicious points")
        return verified

    def _get_suspicious_point_by_id(self, sp_id: str) -> Optional[SuspiciousPoint]:
        """
        Get a suspicious point by ID from database.

        Args:
            sp_id: Suspicious point ID

        Returns:
            SuspiciousPoint or None
        """
        try:
            data = self.repos.suspicious_points.find_by_id(sp_id)
            if data:
                return SuspiciousPoint.from_dict(data)
        except Exception as e:
            self.log_error(f"Failed to get suspicious point {sp_id}: {e}")
        return None

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

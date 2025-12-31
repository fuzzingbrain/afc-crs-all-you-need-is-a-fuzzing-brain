"""
POV Strategy

Finds vulnerabilities using AI-based suspicious point analysis.

Workflow (Delta-scan mode):
1. Check if diff changes are reachable from fuzzer
2. Analyze reachable code to find suspicious points
3. Verify suspicious points with AI Agent (parallel pipeline)
4. Generate POV for high-confidence points (parallel pipeline)
5. Save results

Supports two modes:
- Sequential: Original step-by-step verification
- Pipeline: Parallel verification and POV generation using AgentPipeline
"""

import asyncio
import json
from datetime import datetime
from typing import Dict, Any, List, Optional

from .base import BaseStrategy
from ...analysis.diff_parser import get_reachable_changes, DiffReachabilityResult
from ...core.models import SuspiciousPoint, SPStatus
from ...agents import SuspiciousPointAgent
from ...tools.code_viewer import set_code_viewer_context
from ...tools.analyzer import set_analyzer_context


class POVStrategy(BaseStrategy):
    """
    POV (Proof-of-Vulnerability) Strategy.

    Uses AI to analyze code and find vulnerabilities.
    Supports parallel pipeline for verification and POV generation.
    """

    def __init__(self, executor, use_pipeline: bool = True):
        """
        Initialize POV Strategy.

        Args:
            executor: WorkerExecutor instance
            use_pipeline: Whether to use parallel pipeline (default: True)
        """
        super().__init__(executor)
        self.use_pipeline = use_pipeline

        # Diff path for delta mode
        self.diff_path = executor.diff_path

        # Reachability result (populated in delta mode)
        self._reachability_result: Optional[DiffReachabilityResult] = None

        # Set up tool contexts for MCP
        self._setup_tool_contexts()

        # Create the suspicious point agent with logging context
        # Agent logs go to main log directory under agent/ subdirectory
        agent_log_dir = self.log_dir / "agent" if self.log_dir else self.results_path
        self._agent = SuspiciousPointAgent(
            fuzzer=self.fuzzer,
            sanitizer=self.sanitizer,
            verbose=True,
            task_id=self.task_id,
            worker_id=self.worker_id,
            log_dir=agent_log_dir,
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
        import time
        start_time = time.time()

        self.log_info(f"========== POV Strategy Start ==========")
        self.log_info(f"Fuzzer: {self.fuzzer}, Mode: {self.scan_mode}")

        result = {
            "strategy": "pov",
            "scan_mode": self.scan_mode,
            "reachable": True,
            "reachable_changes": [],
            "suspicious_points_found": 0,
            "suspicious_points_verified": 0,
            "high_confidence_bugs": 0,
            # Phase timing (seconds)
            "phase_reachability": 0.0,
            "phase_find_sp": 0.0,
            "phase_verify_pov": 0.0,
            "phase_save": 0.0,
        }

        try:
            # Step 1: Delta mode - check diff reachability
            if self.scan_mode == "delta":
                self.log_info(f"[Step 1/4] Checking diff reachability...")
                step_start = time.time()
                reachability = self._check_diff_reachability()
                result["reachable"] = reachability.reachable
                result["reachable_changes"] = [
                    {"function": c.function_name, "file": c.file_path, "distance": c.reachability_distance}
                    for c in reachability.reachable_changes
                ]
                step_duration = time.time() - step_start
                result["phase_reachability"] = step_duration
                self.log_info(f"[Step 1/4] Done in {step_duration:.1f}s - {len(reachability.reachable_changes)} reachable changes")

                if not reachability.reachable:
                    self.log_info(f"No reachable changes in diff, skipping")
                    result["skip_reason"] = "no_reachable_changes"
                    return result

            # Step 2: Find suspicious points
            self.log_info(f"[Step 2/5] Finding suspicious points with AI Agent...")
            step_start = time.time()
            suspicious_points = self._find_suspicious_points()
            result["suspicious_points_found"] = len(suspicious_points)
            step_duration = time.time() - step_start
            result["phase_find_sp"] = step_duration
            self.log_info(f"[Step 2/5] Done in {step_duration:.1f}s - Found {len(suspicious_points)} suspicious points")

            if not suspicious_points:
                self.log_info("No suspicious points found")
                return result

            # Step 3 & 4: Verify and generate POV
            if self.use_pipeline:
                # Use parallel pipeline for verification and POV generation
                self.log_info(f"[Step 3-4/5] Running parallel pipeline for verification and POV generation...")
                step_start = time.time()
                pipeline_stats = self._run_pipeline()
                result["suspicious_points_verified"] = pipeline_stats.sp_verified
                result["pov_generated"] = pipeline_stats.pov_generated
                result["pipeline_stats"] = pipeline_stats.to_dict()
                step_duration = time.time() - step_start
                result["phase_verify_pov"] = step_duration
                self.log_info(f"[Step 3-4/5] Done in {step_duration:.1f}s")
                self.log_info(f"  Verified: {pipeline_stats.sp_verified} (real: {pipeline_stats.sp_verified_real}, fp: {pipeline_stats.sp_verified_fp})")
                self.log_info(f"  POV generated: {pipeline_stats.pov_generated}")
            else:
                # Sequential verification (original behavior)
                self.log_info(f"[Step 3/5] Verifying {len(suspicious_points)} suspicious points...")
                step_start = time.time()
                verified_points = self._verify_suspicious_points(suspicious_points)
                result["suspicious_points_verified"] = len(verified_points)
                step_duration = time.time() - step_start
                result["phase_verify_pov"] = step_duration
                self.log_info(f"[Step 3/5] Done in {step_duration:.1f}s - Verified {len(verified_points)} points")

            # Step 5: Sort and save results
            self.log_info(f"[Step 5/5] Sorting and saving results...")
            step_start = time.time()

            # Get latest points from DB
            all_points = self.repos.suspicious_points.find_by_task(self.task_id)
            sorted_points = self._sort_by_priority(all_points)

            # Count high-confidence bugs (is_important == True or score >= 0.9)
            high_conf = [p for p in sorted_points if p.is_important or p.score >= 0.9]
            result["high_confidence_bugs"] = len(high_conf)

            # Count POVs generated
            pov_points = [p for p in sorted_points if p.pov_id]
            result["pov_generated"] = result.get("pov_generated", len(pov_points))

            # Save results
            self._save_results(sorted_points)

            step_duration = time.time() - step_start
            result["phase_save"] = step_duration

            total_time = time.time() - start_time
            self.log_info(f"========== POV Strategy Complete ==========")
            self.log_info(f"Total time: {total_time:.1f}s")
            self.log_info(f"Results: {result['suspicious_points_found']} found, {result['suspicious_points_verified']} verified, {len(high_conf)} high-confidence, {result.get('pov_generated', 0)} POV generated")
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
            # Query all points for this task (agent may have already verified some)
            return self.repos.suspicious_points.find_by_task(self.task_id)
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
        import time

        verified = []
        total = len(suspicious_points)

        for i, point in enumerate(suspicious_points):
            point_start = time.time()
            self.log_info(f"  [{i+1}/{total}] Verifying: {point.function_name} ({point.vuln_type}, score={point.score:.2f})")

            # Convert SuspiciousPoint to dict for agent
            point_dict = point.to_dict()

            try:
                # Run agent to verify this point
                response = self._agent.verify_suspicious_point_sync(point_dict)

                # Re-fetch the point from database (agent may have updated it)
                updated_point = self._get_suspicious_point_by_id(point.suspicious_point_id)
                if updated_point:
                    verified.append(updated_point)
                    elapsed = time.time() - point_start
                    status = "HIGH" if updated_point.is_important or updated_point.score >= 0.9 else "verified"
                    self.log_info(f"  [{i+1}/{total}] Done in {elapsed:.1f}s - {status} (score={updated_point.score:.2f})")
                else:
                    # Point not found, use original
                    verified.append(point)
                    self.log_warning(f"  [{i+1}/{total}] Point not found in DB after verification")

            except Exception as e:
                self.log_error(f"  [{i+1}/{total}] Failed to verify: {e}")
                # Mark as checked but not verified due to error
                point.is_checked = True
                point.verification_notes = f"Verification failed: {e}"
                verified.append(point)

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
            # find_by_id already returns SuspiciousPoint, not dict
            return self.repos.suspicious_points.find_by_id(sp_id)
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
        Save suspicious points summary to results file.

        Note: Points are already saved/updated in DB by the agent via
        create_suspicious_point and update_suspicious_point tools.
        We only save the JSON report here.

        Args:
            suspicious_points: List of points to include in report
        """
        self.log_info(f"Saving {len(suspicious_points)} suspicious points report...")

        # Note: DO NOT call save() here - it would overwrite DB updates made by the agent
        # The agent already saves points via create_suspicious_point and updates via update_suspicious_point

        # Re-fetch all points from DB to get latest values (agent may have updated them)
        fresh_points = self.repos.suspicious_points.find_by_task(self.task_id)
        if not fresh_points:
            fresh_points = suspicious_points  # Fallback to in-memory if DB query fails

        # Save summary to results file
        report = {
            "timestamp": datetime.now().isoformat(),
            "task_id": self.task_id,
            "fuzzer": self.fuzzer,
            "sanitizer": self.sanitizer,
            "scan_mode": self.scan_mode,
            "total_points": len(fresh_points),
            "confirmed_bugs": len([p for p in fresh_points if p.is_real]),
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
                for p in fresh_points
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

    # =========================================================================
    # Pipeline Mode
    # =========================================================================

    def _run_pipeline(self):
        """
        Run parallel pipeline for verification and POV generation.

        Returns:
            PipelineStats with execution statistics
        """
        from ..pipeline import AgentPipeline, PipelineConfig, PipelineStats
        from ...tools.coverage import set_coverage_context, get_coverage_context

        # Ensure coverage context is fully set for trace_pov
        coverage_fuzzer_dir, _, _ = get_coverage_context()
        if coverage_fuzzer_dir:
            set_coverage_context(
                coverage_fuzzer_dir=coverage_fuzzer_dir,
                project_name=self.project_name,
                src_dir=self.workspace_path / "repo",
                docker_image=f"gcr.io/oss-fuzz/{self.project_name}",
                work_dir=self.results_path / "coverage_work",
            )

        # Configure pipeline
        config = PipelineConfig(
            num_verify_agents=2,   # 2 verification agents
            num_pov_agents=1,      # 1 POV generation agent
            pov_min_score=0.5,     # Minimum score to proceed to POV
            poll_interval=1.0,     # Poll every 1 second
            max_idle_cycles=10,    # Exit after 10 idle cycles
            max_iterations=200,    # Max POV agent iterations
            max_pov_attempts=40,   # Max POV generation attempts
            fuzzer_path=self.executor.fuzzer_binary_path,
            docker_image=f"gcr.io/oss-fuzz/{self.project_name}",
        )

        # Create pipeline
        pipeline = AgentPipeline(
            task_id=self.task_id,
            repos=self.repos,
            fuzzer=self.fuzzer,
            sanitizer=self.sanitizer,
            config=config,
            output_dir=self.povs_path,
            log_dir=self.log_dir / "agent" if self.log_dir else None,
            workspace_path=self.workspace_path,
        )

        # Run pipeline (asyncio)
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        try:
            stats = loop.run_until_complete(pipeline.run())
        except Exception as e:
            self.log_error(f"Pipeline failed: {e}")
            stats = PipelineStats()

        return stats

"""
POV Base Strategy

Base class for POV strategies with shared functionality.
"""

import asyncio
import json
from abc import abstractmethod
from datetime import datetime
from typing import Dict, Any, List, Optional

from .base import BaseStrategy
from ...core.models import SuspiciousPoint
from ...tools.code_viewer import set_code_viewer_context
from ...tools.analyzer import set_analyzer_context
from ...tools.suspicious_points import set_sp_context
from ...llms import CLAUDE_SONNET_4_5


class POVBaseStrategy(BaseStrategy):
    """
    Base class for POV (Proof-of-Vulnerability) strategies.

    Provides shared functionality for verification, POV generation,
    and result saving. Subclasses implement the suspicious point
    finding logic specific to their scan mode.
    """

    def __init__(self, executor, use_pipeline: bool = True):
        """
        Initialize POV Base Strategy.

        Args:
            executor: WorkerExecutor instance
            use_pipeline: Whether to use parallel pipeline (default: True)
        """
        super().__init__(executor)
        self.use_pipeline = use_pipeline

        # Set up tool contexts for MCP
        self._setup_tool_contexts()

    def _setup_tool_contexts(self) -> None:
        """Set up contexts for MCP tools."""
        # Set code viewer context (workspace path, repo subdir, diff filename)
        set_code_viewer_context(
            workspace_path=str(self.workspace_path),
            repo_subdir="repo",
            diff_filename="diff/ref.diff",
            project_name=self.project_name,
        )

        # Set analyzer context (socket path)
        if self.executor.analysis_socket_path:
            set_analyzer_context(
                socket_path=self.executor.analysis_socket_path,
                client_id=f"{self.fuzzer}_{self.sanitizer}",
            )

        # Set SP context (harness_name, sanitizer) for SP isolation
        # Each worker only processes SPs created with matching harness_name and sanitizer
        set_sp_context(
            harness_name=self.fuzzer,
            sanitizer=self.sanitizer,
        )

    @property
    @abstractmethod
    def strategy_name(self) -> str:
        """Get strategy name for logging."""
        pass

    @property
    def scan_mode(self) -> str:
        """Get scan mode for this strategy. Override in subclass.

        Returns:
            "delta" for delta-scan (skip reachability in verify)
            "full" for full-scan (full reachability analysis in verify)
        """
        return "full"  # Default to full-scan

    @property
    def agent_log_dir(self):
        """Get correct agent log directory path.

        Returns:
            Path to worker/{fuzzer}_{sanitizer}/agent/ directory
        """
        if self.log_dir:
            return self.log_dir / "worker" / f"{self.fuzzer}_{self.sanitizer}" / "agent"
        return self.results_path

    @abstractmethod
    def _find_suspicious_points(self) -> List[SuspiciousPoint]:
        """
        Find suspicious points in code.

        Returns:
            List of SuspiciousPoint objects
        """
        pass

    def _set_operation(self, operation: str) -> None:
        """Set current operation for evaluation tracking."""
        try:
            from ...eval import get_reporter

            reporter = get_reporter()
            reporter.set_operation(operation)
        except Exception:
            pass

    def execute(self) -> Dict[str, Any]:
        """
        Execute POV strategy.

        Returns:
            Result dictionary with findings
        """
        import time

        start_time = time.time()

        self.log_info(f"========== {self.strategy_name} Start ==========")
        self.log_info(f"Fuzzer: {self.fuzzer}, Mode: {self.scan_mode}")

        result = {
            "strategy": self.strategy_name,
            "scan_mode": self.scan_mode,
            "reachable": True,
            "reachable_changes": [],
            "suspicious_points_found": 0,
            "suspicious_points_verified": 0,
            "high_confidence_bugs": 0,
            "delta_seeds_generated": 0,
            # Phase timing (seconds)
            "phase_reachability": 0.0,
            "phase_find_sp": 0.0,
            "phase_delta_seeds": 0.0,
            "phase_verify": 0.0,
            "phase_pov": 0.0,
            "phase_save": 0.0,
        }

        try:
            # Step 1: Mode-specific pre-processing (e.g., delta reachability check)
            self._set_operation("reachability")
            pre_result = self._pre_find_suspicious_points(result)
            if pre_result.get("skip"):
                return result

            # Step 1.5: Generate delta seeds BEFORE finding SPs (delta-scan mode only)
            # This allows the fuzzer to start running while LLM finds SPs
            if self.scan_mode == "delta" and hasattr(self, "_generate_delta_seeds"):
                self._set_operation("delta_seeds")
                self.log_info(
                    "[Step 1.5/5] Generating delta seeds and starting fuzzer..."
                )
                step_start = time.time()
                try:
                    # Pass empty SPs list - we generate seeds based on changed functions only
                    seeds_count = self._generate_delta_seeds([])
                    result["delta_seeds_generated"] = seeds_count
                except Exception as e:
                    self.log_warning(f"Delta seeds generation failed: {e}")
                    result["delta_seeds_generated"] = 0
                    seeds_count = 0
                step_duration = time.time() - step_start
                result["phase_delta_seeds"] = step_duration
                self.log_info(
                    f"[Step 1.5/5] Done in {step_duration:.1f}s - Generated {seeds_count} seeds, fuzzer started"
                )

            # Step 2: Find suspicious points (fuzzer is already running in background)
            self._set_operation("find_sp")
            self.log_info("[Step 2/5] Finding suspicious points with AI Agent...")
            step_start = time.time()
            suspicious_points = self._find_suspicious_points()
            result["suspicious_points_found"] = len(suspicious_points)
            step_duration = time.time() - step_start
            result["phase_find_sp"] = step_duration
            self.log_info(
                f"[Step 2/5] Done in {step_duration:.1f}s - Found {len(suspicious_points)} suspicious points"
            )

            if not suspicious_points:
                self.log_info("No suspicious points found")
                return result

            # Step 3 & 4: Verify and generate POV
            if self.use_pipeline:
                # Use parallel pipeline for verification and POV generation
                self._set_operation("verify_pov_pipeline")
                self.log_info(
                    "[Step 3-4/5] Running parallel pipeline for verification and POV generation..."
                )
                step_start = time.time()
                pipeline_stats = self._run_pipeline()
                result["suspicious_points_verified"] = pipeline_stats.sp_verified
                result["pov_generated"] = pipeline_stats.pov_generated
                result["pipeline_stats"] = pipeline_stats.to_dict()
                step_duration = time.time() - step_start
                # Extract individual phase times from pipeline stats
                result["phase_verify"] = pipeline_stats.verify_time_total
                result["phase_pov"] = pipeline_stats.pov_time_total
                self.log_info(
                    f"[Step 3-4/5] Done in {step_duration:.1f}s (verify: {pipeline_stats.verify_time_total:.1f}s, pov: {pipeline_stats.pov_time_total:.1f}s)"
                )
                self.log_info(
                    f"  Verified: {pipeline_stats.sp_verified} (real: {pipeline_stats.sp_verified_real}, fp: {pipeline_stats.sp_verified_fp})"
                )
                self.log_info(f"  POV generated: {pipeline_stats.pov_generated}")
            else:
                # Sequential verification (original behavior)
                self._set_operation("verify")
                self.log_info(
                    f"[Step 3/5] Verifying {len(suspicious_points)} suspicious points..."
                )
                step_start = time.time()
                verified_points = self._verify_suspicious_points(suspicious_points)
                result["suspicious_points_verified"] = len(verified_points)
                step_duration = time.time() - step_start
                result["phase_verify"] = step_duration
                result["phase_pov"] = 0.0  # No POV in sequential mode
                self.log_info(
                    f"[Step 3/5] Done in {step_duration:.1f}s - Verified {len(verified_points)} points"
                )

            # Step 5: Sort and save results
            self._set_operation("save")
            self.log_info("[Step 5/5] Sorting and saving results...")
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
            self.log_info(f"========== {self.strategy_name} Complete ==========")
            self.log_info(f"Total time: {total_time:.1f}s")
            self.log_info(
                f"Results: {result['suspicious_points_found']} found, {result['suspicious_points_verified']} verified, {len(high_conf)} high-confidence, {result.get('pov_generated', 0)} POV generated"
            )
            return result

        except Exception as e:
            self.log_error(f"Strategy failed: {e}")
            raise

    def _pre_find_suspicious_points(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Mode-specific pre-processing before finding suspicious points.

        Override in subclasses for mode-specific logic (e.g., delta reachability check).

        Args:
            result: Result dictionary to update

        Returns:
            Dict with 'skip': True if should skip further processing
        """
        return {"skip": False}

    # =========================================================================
    # Verification
    # =========================================================================

    def _verify_suspicious_points(
        self, suspicious_points: List[SuspiciousPoint]
    ) -> List[SuspiciousPoint]:
        """
        Verify suspicious points with AI Agent.

        The agent performs deeper analysis to determine if each point
        is likely a real vulnerability.

        If a point is determined to be FP (False Positive), triggers
        SeedAgent to generate FP Seeds for the Global Fuzzer.

        Args:
            suspicious_points: List of points to verify

        Returns:
            List of verified suspicious points (all checked, some may be real)
        """
        import time

        # Lazy import to avoid circular dependency
        from ...agents import SuspiciousPointAgent

        # Create verification agent (reused for all points sequentially)
        agent_log_dir = self.agent_log_dir
        agent = SuspiciousPointAgent(
            fuzzer=self.fuzzer,
            sanitizer=self.sanitizer,
            scan_mode=self.scan_mode,  # Use strategy's scan_mode for verify prompt
            model=CLAUDE_SONNET_4_5,  # Force Sonnet for SP analysis
            verbose=True,
            task_id=self.task_id,
            worker_id=self.worker_id,
            log_dir=agent_log_dir,
            index=1,  # Single agent for sequential verification
        )

        verified = []
        fp_points = []  # Track FP points for seed generation
        total = len(suspicious_points)

        for i, point in enumerate(suspicious_points):
            point_start = time.time()
            self.log_info(
                f"  [{i + 1}/{total}] Verifying: {point.function_name} ({point.vuln_type}, score={point.score:.2f})"
            )

            # Convert SuspiciousPoint to dict for agent
            point_dict = point.to_dict()

            try:
                # Run agent to verify this point
                response = agent.verify_suspicious_point_sync(point_dict)

                # Re-fetch the point from database (agent may have updated it)
                updated_point = self._get_suspicious_point_by_id(
                    point.suspicious_point_id
                )
                if updated_point:
                    verified.append(updated_point)
                    elapsed = time.time() - point_start

                    # Check if this is FP (not important and score < 0.5)
                    is_fp = not updated_point.is_important and updated_point.score < 0.5

                    if is_fp:
                        status = "FP"
                        fp_points.append(updated_point)
                    elif updated_point.is_important or updated_point.score >= 0.9:
                        status = "HIGH"
                    else:
                        status = "verified"

                    self.log_info(
                        f"  [{i + 1}/{total}] Done in {elapsed:.1f}s - {status} (score={updated_point.score:.2f})"
                    )
                else:
                    # Point not found, use original
                    verified.append(point)
                    self.log_warning(
                        f"  [{i + 1}/{total}] Point not found in DB after verification"
                    )

            except Exception as e:
                self.log_error(f"  [{i + 1}/{total}] Failed to verify: {e}")
                # Mark as checked but not verified due to error
                point.is_checked = True
                point.verification_notes = f"Verification failed: {e}"
                verified.append(point)

        # Generate FP Seeds for false positive points (if FuzzerManager available)
        if fp_points:
            self._generate_fp_seeds(fp_points)

        return verified

    def _generate_fp_seeds(self, fp_points: List[SuspiciousPoint]) -> None:
        """
        Generate FP Seeds for false positive suspicious points.

        These seeds are added to the Global Fuzzer's corpus to help
        find similar vulnerabilities.

        Args:
            fp_points: List of false positive suspicious points
        """
        # Check if FuzzerManager is available
        fuzzer_manager = getattr(self.executor, "fuzzer_manager", None)
        if not fuzzer_manager:
            self.log_debug("FuzzerManager not available, skipping FP seed generation")
            return

        self.log_info(
            f"Generating FP Seeds for {len(fp_points)} false positive points..."
        )

        # Lazy import SeedAgent
        try:
            from ...fuzzer import SeedAgent
        except ImportError:
            self.log_warning("SeedAgent not available, skipping FP seed generation")
            return

        agent_log_dir = self.agent_log_dir

        for seed_index, point in enumerate(fp_points, start=1):
            try:
                # Create SeedAgent for this FP
                seed_agent = SeedAgent(
                    task_id=self.task_id,
                    worker_id=f"{self.worker_id}_fp_seed_{seed_index}",  # Unique per agent
                    fuzzer=self.fuzzer,
                    sanitizer=self.sanitizer,
                    fuzzer_manager=fuzzer_manager,
                    repos=self.repos,
                    log_dir=agent_log_dir,
                    max_iterations=3,  # Quick seed generation
                    index=seed_index,
                    target_name=point.function_name or "",
                )

                # Run seed generation (sync wrapper for async)
                result = asyncio.run(
                    seed_agent.generate_fp_seeds(
                        sp_id=point.suspicious_point_id,
                        function_name=point.function_name,
                        vuln_type=point.vuln_type,
                        description=point.description or "",
                    )
                )

                if result.get("success"):
                    self.log_info(
                        f"  Generated {result.get('seeds_generated', 0)} FP seeds "
                        f"for {point.function_name}"
                    )
                else:
                    self.log_warning(
                        f"  Failed to generate FP seeds for {point.function_name}"
                    )

            except Exception as e:
                self.log_warning(
                    f"  FP seed generation failed for {point.function_name}: {e}"
                )

    def _get_suspicious_point_by_id(self, sp_id: str) -> Optional[SuspiciousPoint]:
        """
        Get a suspicious point by ID from database.

        Args:
            sp_id: Suspicious point ID

        Returns:
            SuspiciousPoint or None
        """
        try:
            return self.repos.suspicious_points.find_by_id(sp_id)
        except Exception as e:
            self.log_error(f"Failed to get suspicious point {sp_id}: {e}")
        return None

    def _get_suspicious_points_from_db(self) -> List[SuspiciousPoint]:
        """
        Get suspicious points created by agent from database.

        Returns:
            List of SuspiciousPoint objects
        """
        try:
            return self.repos.suspicious_points.find_by_task(self.task_id)
        except Exception as e:
            self.log_error(f"Failed to get suspicious points from DB: {e}")
            return []

    # =========================================================================
    # Sorting and Saving
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
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            self.log_info(f"Saved results to: {report_path}")
        except Exception as e:
            self.log_error(f"Failed to save results: {e}")

    # =========================================================================
    # Pipeline Mode
    # =========================================================================

    def _get_fuzzer_code(self) -> str:
        """
        Get fuzzer source code for agent context.

        Tries multiple locations:
        1. fuzz-tooling/projects/{project_name}/{fuzzer}.cc
        2. fuzz-tooling/projects/{project_name}/{fuzzer}.c
        3. Analysis Server get_fuzzer_source API

        Returns:
            Fuzzer source code string, or empty string if not found.
        """
        # Common fuzzer source extensions
        extensions = [".cc", ".c", ".cpp"]

        # Try fuzz-tooling directory first
        fuzz_tooling_dir = (
            self.workspace_path / "fuzz-tooling" / "projects" / self.project_name
        )
        for ext in extensions:
            fuzzer_path = fuzz_tooling_dir / f"{self.fuzzer}{ext}"
            if fuzzer_path.exists():
                try:
                    return fuzzer_path.read_text()
                except Exception as e:
                    self.log_warning(
                        f"Failed to read fuzzer source from {fuzzer_path}: {e}"
                    )

        # Try Analysis Server API
        try:
            client = self.get_analysis_client()
            if client:
                result = client.get_fuzzer_source(self.fuzzer)
                if result and result.get("source"):
                    return result["source"]
        except Exception as e:
            self.log_warning(f"Failed to get fuzzer source from Analysis Server: {e}")

        return ""

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
            num_verify_agents=2,  # 2 verification agents
            num_pov_agents=5,  # 5 POV generation agents (parallel)
            pov_min_score=0.5,  # Minimum score to proceed to POV
            poll_interval=1.0,  # Poll every 1 second
            max_idle_cycles=10,  # Exit after 10 idle cycles
            max_iterations=200,  # Max POV agent iterations
            max_pov_attempts=40,  # Max POV generation attempts
            fuzzer_path=self.executor.fuzzer_binary_path,
            docker_image=f"gcr.io/oss-fuzz/{self.project_name}",
        )

        # Get fuzzer source code for agent context
        fuzzer_code = self._get_fuzzer_code()
        if fuzzer_code:
            self.log_info(f"Loaded fuzzer source code ({len(fuzzer_code)} chars)")
        else:
            self.log_warning("Could not load fuzzer source code")

        # Create pipeline
        pipeline = AgentPipeline(
            task_id=self.task_id,
            repos=self.repos,
            fuzzer=self.fuzzer,
            sanitizer=self.sanitizer,
            scan_mode=self.scan_mode,  # Pass scan_mode to pipeline
            config=config,
            output_dir=self.povs_path,
            log_dir=self.agent_log_dir,
            workspace_path=self.workspace_path,
            worker_id=self.worker_id,  # For SP Fuzzer lifecycle
            fuzzer_code=fuzzer_code,
        )

        # In delta mode, SP finding is already done (SPs come from diff analysis)
        # Signal pipeline so agents can exit when queue is empty
        pipeline._sp_finding_done = True

        # Run pipeline (asyncio)
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        # Start Global Fuzzer for Delta mode (no Direction Seeds, but FP Seeds need it)
        # In Fullscan mode, Global Fuzzer is started in _generate_direction_seeds_and_start_global_fuzzer
        fuzzer_manager = getattr(self.executor, "fuzzer_manager", None)
        if fuzzer_manager and not fuzzer_manager.global_fuzzer:
            self.log_info("Starting Global Fuzzer for FP Seeds collection...")
            try:
                loop.run_until_complete(fuzzer_manager.start_global_fuzzer())
            except Exception as e:
                self.log_warning(f"Failed to start Global Fuzzer: {e}")

        try:
            stats = loop.run_until_complete(pipeline.run())
        except Exception as e:
            self.log_error(f"Pipeline failed: {e}")
            stats = PipelineStats()

        return stats

# SPDX-License-Identifier: Apache-2.0
"""
PoC Base Strategy

Base class for PoC strategies with shared functionality.
"""

import asyncio
import json
from abc import abstractmethod
from datetime import datetime
from typing import Dict, Any, List, Optional

from .base import BaseStrategy
from ...core.concurrency import get_concurrency
from ...core.models import VulnerabilityHypothesis
from ...core.scoring import get_scoring
from ...tools.code_viewer import set_code_viewer_context
from ...tools.analyzer import set_analyzer_context
from ...tools.vulnerability_hypotheses import set_vh_context
from ...llms.routing import Role, model_for


class POCBaseStrategy(BaseStrategy):
    """
    Base class for PoC (Proof-of-Vulnerability) strategies.

    Provides shared functionality for verification, PoC generation,
    and result saving. Subclasses implement the vulnerability hypothesis
    finding logic specific to their scan mode.
    """

    def __init__(self, executor, use_pipeline: bool = True):
        """
        Initialize PoC Base Strategy.

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
        # Set code viewer context using main run workspace (shared repo/diff)
        set_code_viewer_context(
            workspace_path=str(self.executor.run_workspace_path),
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

        # Set VH context (harness_name, sanitizer) for VH isolation
        # Each worker only processes VHs created with matching harness_name and sanitizer
        set_vh_context(
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
    def _find_vulnerability_hypotheses(self) -> List[VulnerabilityHypothesis]:
        """
        Find vulnerability hypotheses in code.

        Returns:
            List of VulnerabilityHypothesis objects
        """
        pass

    def _set_operation(self, operation: str) -> None:
        """Set current operation for evaluation tracking."""
        pass

    def execute(self) -> Dict[str, Any]:
        """
        Execute PoC strategy.

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
            "vulnerability_hypotheses_found": 0,
            "vulnerability_hypotheses_verified": 0,
            "high_confidence_bugs": 0,
            "delta_seeds_generated": 0,
            # Phase timing (seconds)
            "phase_reachability": 0.0,
            "phase_find_vh": 0.0,
            "phase_delta_seeds": 0.0,
            "phase_verify": 0.0,
            "phase_poc": 0.0,
            "phase_save": 0.0,
        }

        try:
            # Step 1: Mode-specific pre-processing (e.g., delta reachability check)
            self._set_operation("reachability")
            pre_result = self._pre_find_vulnerability_hypotheses(result)
            if pre_result.get("skip"):
                return result

            # Step 1.5: Generate delta seeds BEFORE finding VHs (delta-scan mode only)
            # This allows the fuzzer to start running while LLM finds VHs
            if self.scan_mode == "delta" and hasattr(self, "_generate_delta_seeds"):
                self._set_operation("delta_seeds")
                self.log_info(
                    "[Step 1.5/5] Generating delta seeds and starting fuzzer..."
                )
                step_start = time.time()
                try:
                    # Pass empty VHs list - we generate seeds based on changed functions only
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

            # Step 2: Find vulnerability hypotheses (fuzzer is already running in background)
            self._set_operation("find_vh")
            self.log_info("[Step 2/5] Finding vulnerability hypotheses with AI Agent...")
            step_start = time.time()
            vulnerability_hypotheses = self._find_vulnerability_hypotheses()
            result["vulnerability_hypotheses_found"] = len(vulnerability_hypotheses)
            step_duration = time.time() - step_start
            result["phase_find_vh"] = step_duration
            self.log_info(
                f"[Step 2/5] Done in {step_duration:.1f}s - Found {len(vulnerability_hypotheses)} vulnerability hypotheses"
            )

            if not vulnerability_hypotheses:
                self.log_info("No vulnerability hypotheses found")
                return result

            # Step 3 & 4: Verify and generate PoC
            if self.use_pipeline:
                # Use parallel pipeline for verification and PoC generation
                self._set_operation("verify_poc_pipeline")
                self.log_info(
                    "[Step 3-4/5] Running parallel pipeline for verification and PoC generation..."
                )
                step_start = time.time()
                pipeline_stats = self._run_pipeline()
                result["vulnerability_hypotheses_verified"] = pipeline_stats.vh_verified
                result["poc_generated"] = pipeline_stats.poc_generated
                result["pipeline_stats"] = pipeline_stats.to_dict()
                step_duration = time.time() - step_start
                # Extract individual phase times from pipeline stats
                result["phase_verify"] = pipeline_stats.verify_time_total
                result["phase_poc"] = pipeline_stats.poc_time_total
                self.log_info(
                    f"[Step 3-4/5] Done in {step_duration:.1f}s (verify: {pipeline_stats.verify_time_total:.1f}s, poc: {pipeline_stats.poc_time_total:.1f}s)"
                )
                self.log_info(
                    f"  Verified: {pipeline_stats.vh_verified} (real: {pipeline_stats.vh_verified_real}, fp: {pipeline_stats.vh_verified_fp})"
                )
                self.log_info(f"  PoC generated: {pipeline_stats.poc_generated}")
            else:
                # Sequential verification (original behavior)
                self._set_operation("verify")
                self.log_info(
                    f"[Step 3/5] Verifying {len(vulnerability_hypotheses)} vulnerability hypotheses..."
                )
                step_start = time.time()
                verified_points = self._verify_vulnerability_hypotheses(vulnerability_hypotheses)
                result["vulnerability_hypotheses_verified"] = len(verified_points)
                step_duration = time.time() - step_start
                result["phase_verify"] = step_duration
                result["phase_poc"] = 0.0  # No PoC in sequential mode
                self.log_info(
                    f"[Step 3/5] Done in {step_duration:.1f}s - Verified {len(verified_points)} points"
                )

            # Step 5: Sort and save results
            self._set_operation("save")
            self.log_info("[Step 5/5] Sorting and saving results...")
            step_start = time.time()

            # Get latest points from DB
            all_points = self.repos.vulnerability_hypotheses.find_by_run(self.run_id)
            sorted_points = self._sort_by_priority(all_points)

            # Count high-confidence bugs. The bar is configured, not
            # written here: the prompt states it to the model too, and the
            # two have to be the same number.
            bar = get_scoring().high_confidence
            high_conf = [p for p in sorted_points if p.proceed]
            result["high_confidence_bugs"] = len(high_conf)

            # Count PoCs generated
            poc_points = [p for p in sorted_points if p.poc_id]
            result["poc_generated"] = result.get("poc_generated", len(poc_points))

            # Save results
            self._save_results(sorted_points)

            step_duration = time.time() - step_start
            result["phase_save"] = step_duration

            total_time = time.time() - start_time
            self.log_info(f"========== {self.strategy_name} Complete ==========")
            self.log_info(f"Total time: {total_time:.1f}s")
            self.log_info(
                f"Results: {result['vulnerability_hypotheses_found']} found, {result['vulnerability_hypotheses_verified']} verified, {len(high_conf)} high-confidence, {result.get('poc_generated', 0)} PoC generated"
            )
            return result

        except Exception as e:
            self.log_error(f"Strategy failed: {e}")
            raise

    def _pre_find_vulnerability_hypotheses(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Mode-specific pre-processing before finding vulnerability hypotheses.

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

    def _verify_vulnerability_hypotheses(
        self, vulnerability_hypotheses: List[VulnerabilityHypothesis]
    ) -> List[VulnerabilityHypothesis]:
        """
        Verify vulnerability hypotheses with AI Agent.

        The agent performs deeper analysis to determine if each point
        is likely a real vulnerability.

        If a point is determined to be FP (False Positive), triggers
        SeedAgent to generate FP Seeds for the Global Fuzzer.

        Args:
            vulnerability_hypotheses: List of points to verify

        Returns:
            List of verified vulnerability hypotheses (all checked, some may be real)
        """
        import time

        # Lazy import to avoid circular dependency
        from ...agents import VHVerifier

        # Create VH verifier (reused for all points sequentially)
        agent_log_dir = self.agent_log_dir
        verifier = VHVerifier(
            fuzzer=self.fuzzer,
            sanitizer=self.sanitizer,
            scan_mode=self.scan_mode,  # Use strategy's scan_mode for verify prompt
            model=model_for(Role.VERIFIER),
            verbose=True,
            run_id=self.run_id,
            worker_id=self.worker_id,
            log_dir=agent_log_dir,
            index=1,  # Single agent for sequential verification
        )

        verified = []
        fp_points = []  # Track FP points for seed generation
        total = len(vulnerability_hypotheses)

        for i, point in enumerate(vulnerability_hypotheses):
            point_start = time.time()
            self.log_info(
                f"  [{i + 1}/{total}] Verifying: {point.function_name} (score={point.score:.2f})"
            )

            # Convert VulnerabilityHypothesis to dict for agent
            point_dict = point.to_dict()

            try:
                # Run verifier to verify this point
                response = verifier.verify_sync(point_dict)

                # Re-fetch the point from database (agent may have updated it)
                updated_point = self._get_vulnerability_hypothesis_by_id(
                    point.vulnerability_hypothesis_id
                )
                if updated_point:
                    verified.append(updated_point)
                    elapsed = time.time() - point_start

                    # Not important and below the bar the prompt calls
                    # "worth testing": a false positive.
                    is_fp = not updated_point.proceed

                    if is_fp:
                        status = "FP"
                        fp_points.append(updated_point)
                    elif (
                        updated_point.proceed
                    ):
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
                point.is_checked_by_verifier = True
                point.verification_notes = f"Verification failed: {e}"
                verified.append(point)

        # Generate FP Seeds for false positive points (if FuzzerManager available)
        if fp_points:
            self._generate_fp_seeds(fp_points)

        return verified

    def _generate_fp_seeds(self, fp_points: List[VulnerabilityHypothesis]) -> None:
        """
        Generate FP Seeds for false positive vulnerability hypotheses.

        These seeds are added to the Global Fuzzer's corpus to help
        find similar vulnerabilities.

        Args:
            fp_points: List of false positive vulnerability hypotheses
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
                    model=model_for(Role.SEED),
                    run_id=self.run_id,
                    worker_id=self.worker_id,  # ObjectId for MongoDB linking
                    fuzzer=self.fuzzer,
                    sanitizer=self.sanitizer,
                    fuzzer_source=self.executor.harness_source(),  # full harness
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
                        vh_id=point.vulnerability_hypothesis_id,
                        function_name=point.function_name,
                        description=point.description or "",
                        important_controlflow=point.important_controlflow or "",
                        verification_notes=point.verification_notes or "",
                        evidence=point.evidence or "",
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

    def _get_vulnerability_hypothesis_by_id(self, vh_id: str) -> Optional[VulnerabilityHypothesis]:
        """
        Get a vulnerability hypothesis by ID from database.

        Args:
            vh_id: Vulnerability hypothesis ID

        Returns:
            VulnerabilityHypothesis or None
        """
        try:
            return self.repos.vulnerability_hypotheses.find_by_id(vh_id)
        except Exception as e:
            self.log_error(f"Failed to get vulnerability hypothesis {vh_id}: {e}")
        return None

    def _get_vulnerability_hypotheses_from_db(self) -> List[VulnerabilityHypothesis]:
        """
        Get vulnerability hypotheses created by agent from database.

        Returns:
            List of VulnerabilityHypothesis objects
        """
        try:
            return self.repos.vulnerability_hypotheses.find_by_run(self.run_id)
        except Exception as e:
            self.log_error(f"Failed to get vulnerability hypotheses from DB: {e}")
            return []

    # =========================================================================
    # Sorting and Saving
    # =========================================================================

    def _sort_by_priority(
        self, vulnerability_hypotheses: List[VulnerabilityHypothesis]
    ) -> List[VulnerabilityHypothesis]:
        """
        Sort vulnerability hypotheses by priority.

        Sorting order:
        1. proceed (recall-first pass first)
        2. priority (higher = processed earlier)

        Args:
            vulnerability_hypotheses: List of points to sort

        Returns:
            Sorted list of vulnerability hypotheses
        """
        return sorted(
            vulnerability_hypotheses,
            key=lambda p: (p.proceed, p.priority),
            reverse=True,
        )

    def _save_results(self, vulnerability_hypotheses: List[VulnerabilityHypothesis]) -> None:
        """
        Save vulnerability hypotheses summary to results file.

        Note: Points are already saved/updated in DB by the agent via
        create_vulnerability_hypothesis and update_vulnerability_hypothesis tools.
        We only save the JSON report here.

        Args:
            vulnerability_hypotheses: List of points to include in report
        """
        self.log_info(f"Saving {len(vulnerability_hypotheses)} vulnerability hypotheses report...")

        # Re-fetch all points from DB to get latest values (agent may have updated them)
        fresh_points = self.repos.vulnerability_hypotheses.find_by_run(self.run_id)
        if not fresh_points:
            fresh_points = vulnerability_hypotheses  # Fallback to in-memory if DB query fails

        # Save summary to results file
        report = {
            "timestamp": datetime.now().isoformat(),
            "run_id": self.run_id,
            "fuzzer": self.fuzzer,
            "sanitizer": self.sanitizer,
            "scan_mode": self.scan_mode,
            "total_points": len(fresh_points),
            "confirmed_bugs": len([p for p in fresh_points if p.is_crash_found]),
            "vulnerability_hypotheses": [
                {
                    "id": p.vulnerability_hypothesis_id,
                    "function": p.function_name,
                    "description": p.description,
                    "score": p.score,
                    "proceed": p.proceed,
                    "priority": p.priority,
                    "is_crash_found": p.is_crash_found,
                    "verification_notes": p.verification_notes,
                }
                for p in fresh_points
            ],
        }

        report_path = self.results_path / "vulnerability_hypotheses_report.json"
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

        # Try fuzz-tooling directory in main run workspace (shared, read-only)
        fuzz_tooling_dir = (
            self.executor.run_workspace_path
            / "fuzz-tooling"
            / "projects"
            / self.project_name
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
        Run parallel pipeline for verification and PoC generation.

        Returns:
            PipelineStats with execution statistics
        """
        from ..pipeline import AgentPipeline, PipelineConfig, PipelineStats
        from ...tools.coverage import set_coverage_context, get_coverage_context

        # Ensure coverage context is fully set for trace_poc
        coverage_fuzzer_dir, _, _ = get_coverage_context()
        if coverage_fuzzer_dir:
            set_coverage_context(
                coverage_fuzzer_dir=coverage_fuzzer_dir,
                project_name=self.project_name,
                src_dir=self.executor.run_workspace_path / "repo",
                docker_image=self.executor.docker_image,
                work_dir=self.results_path / "coverage_work",
            )

        # Verify-stage reach-probe context: the exact ASan ELF + fuzzer name so
        # the verifier can run candidate inputs under gdb-15 for dynamic evidence
        # (reach / crash / margin). Independent of the coverage build.
        from ...tools.coverage import set_reach_context
        set_reach_context(self.executor.fuzzer_binary_path, self.fuzzer, self.project_name, self.executor.docker_image)

        # Configure pipeline
        concurrency = get_concurrency()
        config = PipelineConfig(
            num_verify_agents=concurrency.verify_agents,
            num_poc_agents=concurrency.poc_agents,
            poc_min_score=0.5,  # Minimum score to proceed to PoC
            poll_interval=1.0,  # Poll every 1 second
            max_idle_cycles=10,  # Exit after 10 idle cycles
            max_iterations=100,  # Max PoC agent iterations
            max_poc_attempts=20,  # Max PoC generation attempts
            fuzzer_path=self.executor.fuzzer_binary_path,
            docker_image=self.executor.docker_image,
        )

        # Get fuzzer source code for agent context
        fuzzer_code = self._get_fuzzer_code()
        if fuzzer_code:
            self.log_info(f"Loaded fuzzer source code ({len(fuzzer_code)} chars)")
        else:
            self.log_warning("Could not load fuzzer source code")

        # Create pipeline
        pipeline = AgentPipeline(
            run_id=self.run_id,
            repos=self.repos,
            fuzzer=self.fuzzer,
            sanitizer=self.sanitizer,
            scan_mode=self.scan_mode,  # Pass scan_mode to pipeline
            config=config,
            output_dir=self.pocs_path,
            log_dir=self.agent_log_dir,
            workspace_path=self.executor.run_workspace_path,
            worker_id=self.worker_id,  # For VH Fuzzer lifecycle
            fuzzer_code=fuzzer_code,
            fuzzer_source=self.executor.harness_source(),  # full harness for verifier
        )

        # In delta mode, VH finding is already done (VHs come from diff analysis)
        # Signal pipeline so agents can exit when queue is empty
        pipeline._vh_finding_done = True

        # Run pipeline (asyncio)
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        # Start Global Fuzzer for Delta mode (no Logic group Seeds, but FP Seeds need it)
        # In Fullscan mode, Global Fuzzer is started in _generate_logic_group_seeds_and_start_global_fuzzer
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

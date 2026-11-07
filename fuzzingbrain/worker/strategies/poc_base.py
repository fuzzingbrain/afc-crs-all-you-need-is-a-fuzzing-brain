# SPDX-License-Identifier: Apache-2.0
"""
PoC Base Strategy

Base class for PoC strategies with shared functionality.
"""

import asyncio
import json
from abc import abstractmethod
from datetime import datetime
from typing import Dict, Any, List

from .base import BaseStrategy
from ...core.concurrency import get_concurrency
from ...db.store import get_store, vh_dict
from ...tools.code_viewer import set_code_viewer_context
from ...tools.analyzer import set_analyzer_context
from ...tools.vulnerability_hypotheses import set_vh_context


class POCBaseStrategy(BaseStrategy):
    """
    Base class for PoC (Proof-of-Vulnerability) strategies.

    Provides shared functionality for verification, PoC generation,
    and result saving. Subclasses implement the vulnerability hypothesis
    finding logic specific to their scan mode.
    """

    def __init__(self, executor):
        super().__init__(executor)

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

        # VHs belong to this worker (the scope); no logic group here.
        set_vh_context()

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
    def _find_vulnerability_hypotheses(self) -> List[Dict[str, Any]]:
        """Find vulnerability hypotheses; returns this worker's VHs (as dicts)."""
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

            # Step 3 & 4: verify and generate PoCs (parallel pipeline)
            self._set_operation("verify_poc_pipeline")
            self.log_info("[Step 3-4/5] Running the verify / PoC pipeline...")
            step_start = time.time()
            pipeline_stats = self._run_pipeline()
            result["vulnerability_hypotheses_verified"] = pipeline_stats.vh_verified
            result["poc_generated"] = pipeline_stats.poc_generated
            result["pipeline_stats"] = pipeline_stats.to_dict()
            result["phase_verify"] = pipeline_stats.verify_time_total
            result["phase_poc"] = pipeline_stats.poc_time_total
            self.log_info(
                f"[Step 3-4/5] Done in {time.time() - step_start:.1f}s "
                f"(verify: {pipeline_stats.verify_time_total:.1f}s, poc: {pipeline_stats.poc_time_total:.1f}s)"
            )
            self.log_info(
                f"  Verified: {pipeline_stats.vh_verified} (real: {pipeline_stats.vh_verified_real}, fp: {pipeline_stats.vh_verified_fp})"
            )
            self.log_info(f"  PoC generated: {pipeline_stats.poc_generated}")

            # Step 5: the report of this worker's VHs
            self._set_operation("save")
            step_start = time.time()
            vhs = self._worker_vhs()
            result["high_confidence_bugs"] = sum(
                1 for v in vhs if v["status"] in ("pending_poc", "generating_poc", "poc_generated", "poc_failed")
            )
            self._save_results(vhs)
            result["phase_save"] = time.time() - step_start

            self.log_info(f"========== {self.strategy_name} Complete ==========")
            self.log_info(f"Total time: {time.time() - start_time:.1f}s")
            self.log_info(
                f"Results: {result['vulnerability_hypotheses_found']} found, "
                f"{result['vulnerability_hypotheses_verified']} verified, "
                f"{result['high_confidence_bugs']} passed, {result.get('poc_generated', 0)} PoC generated"
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
    # This worker's VHs
    # =========================================================================

    def _worker_vhs(self) -> List[Dict[str, Any]]:
        try:
            return [vh_dict(v) for v in get_store().vhs(worker_id=self.worker_id)]
        except Exception as e:
            self.log_error(f"Failed to read this worker's VHs: {e}")
            return []

    def _save_results(self, vhs: List[Dict[str, Any]]) -> None:
        """results/vulnerability_hypotheses_report.json: a readable copy of the table."""
        report = {
            "timestamp": datetime.now().isoformat(),
            "run_id": self.run_id,
            "worker_id": self.worker_id,
            "fuzzer": self.fuzzer,
            "sanitizer": self.sanitizer,
            "scan_mode": self.scan_mode,
            "total_points": len(vhs),
            "vulnerability_hypotheses": [
                {
                    "id": v["id"],
                    "function": v["function_name"],
                    "file": v["function_file"],
                    "description": v["description"],
                    "finder_score": v["finder_score"],
                    "score": v["score"],
                    "status": v["status"],
                    "verifier_reproduced": v.get("verifier_reproduced"),
                    "verification_notes": v.get("verification_notes"),
                }
                for v in vhs
            ],
        }
        report_path = self.results_path / "vulnerability_hypotheses_report.json"
        try:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            self.log_info(f"Saved results to: {report_path}")
        except Exception as e:
            self.log_error(f"Failed to save results: {e}")

    # =========================================================================
    # Pipeline Mode
    # =========================================================================

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
            poll_interval=1.0,  # Poll every 1 second
            max_idle_cycles=10,  # Exit after 10 idle cycles
            max_iterations=100,  # Max PoC agent iterations
            max_poc_attempts=20,  # Max PoC generation attempts
            fuzzer_path=self.executor.fuzzer_binary_path,
            docker_image=self.executor.docker_image,
        )

        # The harness source, in full, for the agents
        fuzzer_code = self.executor.harness_source()
        if fuzzer_code:
            self.log_info(f"Loaded fuzzer source code ({len(fuzzer_code)} chars)")
        else:
            self.log_warning("Could not load fuzzer source code")

        # Create pipeline
        pipeline = AgentPipeline(
            run_id=self.run_id,
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

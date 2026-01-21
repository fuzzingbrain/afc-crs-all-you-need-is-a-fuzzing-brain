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
from ...agents import (
    SuspiciousPointAgent,
    DirectionPlanningAgent,
    FullscanSPAgent,
    FunctionAnalysisAgent,
    LargeFunctionAnalysisAgent,
)
from ...tools.code_viewer import set_code_viewer_context
from ...tools.directions import set_direction_context
from ...tools.analyzer import set_analyzer_context
from ...tools.suspicious_points import set_sp_context


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

        # SP Find v2: Locks for concurrent log writing (one per direction)
        self._direction_log_locks: Dict[str, asyncio.Lock] = {}

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
            project_name=self.project_name,
        )

        # Set analyzer context (socket path)
        if self.executor.analysis_socket_path:
            set_analyzer_context(
                socket_path=self.executor.analysis_socket_path,
                client_id=f"agent_{self.fuzzer}_{self.sanitizer}",
            )

        # Set SP context (harness_name, sanitizer) for SP isolation
        # Each worker only processes SPs created with matching harness_name and sanitizer
        set_sp_context(
            harness_name=self.fuzzer,
            sanitizer=self.sanitizer,
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
            "phase_verify": 0.0,
            "phase_pov": 0.0,
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
                # Extract individual phase times from pipeline stats
                result["phase_verify"] = pipeline_stats.verify_time_total
                result["phase_pov"] = pipeline_stats.pov_time_total
                self.log_info(f"[Step 3-4/5] Done in {step_duration:.1f}s (verify: {pipeline_stats.verify_time_total:.1f}s, pov: {pipeline_stats.pov_time_total:.1f}s)")
                self.log_info(f"  Verified: {pipeline_stats.sp_verified} (real: {pipeline_stats.sp_verified_real}, fp: {pipeline_stats.sp_verified_fp})")
                self.log_info(f"  POV generated: {pipeline_stats.pov_generated}")
            else:
                # Sequential verification (original behavior)
                self.log_info(f"[Step 3/5] Verifying {len(suspicious_points)} suspicious points...")
                step_start = time.time()
                verified_points = self._verify_suspicious_points(suspicious_points)
                result["suspicious_points_verified"] = len(verified_points)
                step_duration = time.time() - step_start
                result["phase_verify"] = step_duration
                result["phase_pov"] = 0.0  # No POV in sequential mode
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
            # Full mode: Two-phase analysis with Direction Planning + SP Find Agents
            suspicious_points = self._run_fullscan_analysis()

        self.log_info(f"Found {len(suspicious_points)} suspicious points")
        return suspicious_points

    def _run_fullscan_analysis(self) -> List[SuspiciousPoint]:
        """
        Run Full-scan analysis using SP Find v2 three-phase approach.

        Phase 0: Direction Planning - Create analysis directions
        Phase 1: Small Pool Analysis - Deep analysis of core_functions + entry_functions
        Phase 2: Big Pool Analysis - Analyze remaining reachable functions
        Phase 3: Free Exploration - Fallback using large agent with context compression

        Returns:
            List of SuspiciousPoint objects
        """
        import time

        # Set direction context for MCP tools
        set_direction_context(self.fuzzer)

        # Phase 0: Direction Planning
        self.log_info("=== SP Find v2 Phase 0: Direction Planning ===")
        phase0_start = time.time()

        # Get fuzzer source code for context
        fuzzer_code = self._get_fuzzer_source_code()
        reachable_count = self._get_reachable_function_count()

        self.log_info(f"Fuzzer: {self.fuzzer}, Reachable functions: {reachable_count}")

        # Create and run Direction Planning Agent
        agent_log_dir = self.log_dir / "agent" if self.log_dir else self.results_path
        planning_agent = DirectionPlanningAgent(
            fuzzer=self.fuzzer,
            sanitizer=self.sanitizer,
            task_id=self.task_id,
            worker_id=self.worker_id,
            log_dir=agent_log_dir,
            max_iterations=100,
        )

        try:
            result = planning_agent.plan_directions_sync(
                fuzzer_code=fuzzer_code,
                reachable_count=reachable_count,
            )
            self.log_info(f"Direction planning completed: {result.get('directions_created', 0)} directions created")
        except Exception as e:
            self.log_error(f"Direction planning failed: {e}")
            return []

        phase0_duration = time.time() - phase0_start
        self.log_info(f"Phase 0 completed in {phase0_duration:.1f}s")

        # Get directions from database
        directions = self.repos.directions.find_pending(self.task_id, self.fuzzer)
        if not directions:
            self.log_warning("No directions created, Full-scan cannot continue")
            return []

        # Phase 1: Small Pool Analysis (core_functions + entry_functions)
        self.log_info(f"=== SP Find v2 Phase 1: Small Pool Analysis ({len(directions)} directions) ===")
        phase1_start = time.time()

        asyncio.run(self._run_phase1_small_pool(
            directions=directions,
            agent_log_dir=agent_log_dir,
            fuzzer_source=fuzzer_code,
        ))

        phase1_duration = time.time() - phase1_start
        self.log_info(f"Phase 1 completed in {phase1_duration:.1f}s")

        # Phase 2: Big Pool Analysis (remaining reachable functions)
        self.log_info(f"=== SP Find v2 Phase 2: Big Pool Analysis ===")
        phase2_start = time.time()

        asyncio.run(self._run_phase2_big_pool(
            directions=directions,
            agent_log_dir=agent_log_dir,
            fuzzer_source=fuzzer_code,
        ))

        phase2_duration = time.time() - phase2_start
        self.log_info(f"Phase 2 completed in {phase2_duration:.1f}s")

        # Phase 3: Free Exploration (fallback)
        self.log_info(f"=== SP Find v2 Phase 3: Free Exploration ===")
        phase3_start = time.time()

        asyncio.run(self._run_phase3_free_exploration(
            directions=directions,
            fuzzer_code=fuzzer_code,
            agent_log_dir=agent_log_dir,
        ))

        phase3_duration = time.time() - phase3_start
        self.log_info(f"Phase 3 completed in {phase3_duration:.1f}s")

        # Log detailed coverage statistics (per documentation spec)
        self._log_coverage_report(directions)

        # Get all suspicious points created
        return self._get_suspicious_points_from_db()

    def _log_coverage_report(self, directions: List) -> None:
        """
        Log detailed coverage report per documentation spec.

        Reports:
        - Small pool coverage (core_functions + entry_functions)
        - Big pool coverage (all reachable functions)
        - Global coverage (across all directions)
        """
        direction_id = directions[0].direction_id if directions else ""

        # Collect small pool function names
        small_pool_names = set()
        for direction in directions:
            small_pool_names.update(direction.core_functions or [])
            small_pool_names.update(direction.entry_functions or [])

        # Get small pool stats
        small_pool_total = len(small_pool_names)
        small_pool_analyzed = 0
        if small_pool_names:
            small_pool_functions = self.repos.functions.find_all({
                "task_id": self.task_id,
                "name": {"$in": list(small_pool_names)},
                "analyzed_by_directions": {"$ne": []},
            })
            small_pool_analyzed = len([
                f for f in self.repos.functions.find_all({
                    "task_id": self.task_id,
                    "name": {"$in": list(small_pool_names)},
                })
                if f.analyzed_by_directions
            ])

        # Get global coverage stats
        global_coverage = self.repos.functions.get_analysis_coverage(
            self.task_id, self.fuzzer
        )

        # Get current direction coverage
        dir_coverage = self.repos.functions.get_unanalyzed_count(
            self.task_id, self.fuzzer, direction_id
        )

        # Get SP count
        sp_count = self.repos.suspicious_points.count({"task_id": self.task_id})
        high_conf_count = self.repos.suspicious_points.count({
            "task_id": self.task_id,
            "score": {"$gte": 0.7},
        })

        # Log report
        self.log_info("=" * 60)
        self.log_info("          SP Find v2 Coverage Report")
        self.log_info("=" * 60)
        self.log_info(f"  Fuzzer: {self.fuzzer}")
        self.log_info("-" * 60)
        self.log_info("  Small Pool Coverage:")
        self.log_info(f"    Total functions: {small_pool_total}")
        self.log_info(f"    Analyzed: {small_pool_analyzed}")
        if small_pool_total > 0:
            pct = small_pool_analyzed / small_pool_total * 100
            self.log_info(f"    Coverage: {pct:.1f}%")
        self.log_info("-" * 60)
        self.log_info("  Big Pool Coverage:")
        self.log_info(f"    Total functions: {global_coverage['total_functions']}")
        self.log_info(f"    Analyzed by this direction: {dir_coverage.get('analyzed_by_direction', 0)}")
        if global_coverage['total_functions'] > 0:
            pct = dir_coverage.get('analyzed_by_direction', 0) / global_coverage['total_functions'] * 100
            self.log_info(f"    Coverage: {pct:.1f}%")
        self.log_info("-" * 60)
        self.log_info("  Global Coverage (all directions):")
        self.log_info(f"    Total functions: {global_coverage['total_functions']}")
        self.log_info(f"    Analyzed by any direction: {global_coverage['analyzed_functions']}")
        self.log_info(f"    Coverage: {global_coverage['coverage_percent']:.1f}%")
        self.log_info("-" * 60)
        self.log_info("  SP Summary:")
        self.log_info(f"    Total SPs created: {sp_count}")
        self.log_info(f"    High confidence (>=0.7): {high_conf_count}")
        self.log_info("=" * 60)

    # =========================================================================
    # SP Find v2: Three-Phase Analysis
    # =========================================================================

    async def _run_phase1_small_pool(
        self,
        directions: List,
        agent_log_dir,
        num_parallel: int = 5,  # More parallelism for small agents
        fuzzer_source: str = "",
    ) -> None:
        """
        Phase 1: Small Pool Deep Analysis.

        Analyzes core_functions + entry_functions from each direction.
        Uses small agents (one per function) for token efficiency.

        Args:
            directions: List of Direction objects
            agent_log_dir: Log directory for agents
            num_parallel: Number of concurrent agents
            fuzzer_source: Pre-extracted fuzzer source code
        """
        # Collect all functions from small pool
        small_pool_functions = set()
        for direction in directions:
            small_pool_functions.update(direction.core_functions or [])
            small_pool_functions.update(direction.entry_functions or [])

        self.log_info(f"Phase 1: {len(small_pool_functions)} functions in small pool")

        # Get functions with priority ordering
        functions = self.repos.functions.get_functions_for_analysis(
            task_id=self.task_id,
            fuzzer_name=self.fuzzer,
            direction_id=directions[0].direction_id if directions else "",
            function_names=list(small_pool_functions),
            prioritize_unanalyzed=True,
        )

        if not functions:
            self.log_info("Phase 1: No functions to analyze in small pool")
            return

        self.log_info(f"Phase 1: Analyzing {len(functions)} functions")

        # Create a semaphore to limit concurrency
        semaphore = asyncio.Semaphore(num_parallel)

        async def analyze_function(func, index: int):
            """Analyze a single function with semaphore control."""
            async with semaphore:
                return await self._analyze_single_function(
                    func=func,
                    index=index,
                    total=len(functions),
                    agent_log_dir=agent_log_dir,
                    direction_id=directions[0].direction_id if directions else "",
                    fuzzer_source=fuzzer_source,
                )

        # Create tasks for all functions
        tasks = [analyze_function(func, i) for i, func in enumerate(functions)]

        # Run all tasks concurrently
        await asyncio.gather(*tasks, return_exceptions=True)

        self.log_info(f"Phase 1 completed: analyzed {len(functions)} functions")

    async def _run_phase2_big_pool(
        self,
        directions: List,
        agent_log_dir,
        num_parallel: int = 5,
        fuzzer_source: str = "",
    ) -> None:
        """
        Phase 2: Big Pool Analysis.

        Analyzes remaining reachable functions not in small pool.
        Uses small agents with priority ordering (unanalyzed first).

        Args:
            directions: List of Direction objects
            agent_log_dir: Log directory for agents
            num_parallel: Number of concurrent agents
            fuzzer_source: Pre-extracted fuzzer source code
        """
        # Get unanalyzed functions from big pool
        # Priority: not analyzed by any direction > not analyzed by this direction
        direction_id = directions[0].direction_id if directions else ""

        functions = self.repos.functions.get_functions_for_analysis(
            task_id=self.task_id,
            fuzzer_name=self.fuzzer,
            direction_id=direction_id,
            function_names=None,  # All reachable functions (big pool)
            prioritize_unanalyzed=True,
        )

        # Filter out already analyzed functions
        unanalyzed_count = self.repos.functions.get_unanalyzed_count(
            task_id=self.task_id,
            fuzzer_name=self.fuzzer,
            direction_id=direction_id,
        )

        self.log_info(f"Phase 2: {unanalyzed_count.get('unanalyzed_by_any', 0)} functions not analyzed by any direction")
        self.log_info(f"Phase 2: {unanalyzed_count.get('unanalyzed_by_direction', 0)} functions not analyzed by this direction")

        if not functions:
            self.log_info("Phase 2: No functions to analyze in big pool")
            return

        # Limit to unanalyzed functions for efficiency
        functions_to_analyze = [
            f for f in functions
            if not f.analyzed_by_directions or direction_id not in f.analyzed_by_directions
        ]

        if not functions_to_analyze:
            self.log_info("Phase 2: All functions already analyzed")
            return

        self.log_info(f"Phase 2: Analyzing {len(functions_to_analyze)} functions")

        # Create a semaphore to limit concurrency
        semaphore = asyncio.Semaphore(num_parallel)

        async def analyze_function(func, index: int):
            """Analyze a single function with semaphore control."""
            async with semaphore:
                return await self._analyze_single_function(
                    func=func,
                    index=index,
                    total=len(functions_to_analyze),
                    agent_log_dir=agent_log_dir,
                    direction_id=direction_id,
                    fuzzer_source=fuzzer_source,
                )

        # Create tasks for all functions
        tasks = [analyze_function(func, i) for i, func in enumerate(functions_to_analyze)]

        # Run all tasks concurrently
        await asyncio.gather(*tasks, return_exceptions=True)

        self.log_info(f"Phase 2 completed: analyzed {len(functions_to_analyze)} functions")

    async def _run_phase3_free_exploration(
        self,
        directions: List,
        fuzzer_code: str,
        agent_log_dir,
        num_parallel: int = 2,
    ) -> None:
        """
        Phase 3: Free Exploration (Fallback).

        Uses large agent with context compression to explore code freely.
        This is the original FullscanSPAgent behavior as a fallback.

        Args:
            directions: List of Direction objects
            fuzzer_code: Fuzzer source code for context
            agent_log_dir: Log directory for agents
            num_parallel: Number of concurrent agents
        """
        # Check if we have enough SPs already
        sp_count = self.repos.suspicious_points.count({"task_id": self.task_id})
        if sp_count >= 10:
            self.log_info(f"Phase 3: Skipping - already found {sp_count} SPs")
            return

        # Only run on high-risk directions
        high_risk_directions = [d for d in directions if d.risk_level == "high"]
        if not high_risk_directions:
            self.log_info("Phase 3: No high-risk directions for free exploration")
            return

        self.log_info(f"Phase 3: Running free exploration on {len(high_risk_directions)} high-risk directions")

        # Use original parallel SP find agents for exploration
        await self._run_parallel_sp_find_agents_legacy(
            directions=high_risk_directions,
            fuzzer_code=fuzzer_code,
            agent_log_dir=agent_log_dir,
            num_parallel=num_parallel,
        )

    async def _analyze_single_function(
        self,
        func,
        index: int,
        total: int,
        agent_log_dir,
        direction_id: str,
        fuzzer_source: str = "",
    ) -> dict:
        """
        Analyze a single function using FunctionAnalysisAgent.

        Args:
            func: Function object from database
            index: Function index
            total: Total number of functions
            agent_log_dir: Log directory
            direction_id: Direction ID for tracking
            fuzzer_source: Pre-extracted fuzzer source code

        Returns:
            Analysis result dict
        """
        import time
        func_start = time.time()

        self.log_debug(f"[{index+1}/{total}] Analyzing: {func.name}")

        # Get caller/callee names from call graph
        callers = self.repos.callgraph_nodes.find_callers(
            self.task_id, self.fuzzer, func.name
        )
        callees = self.repos.callgraph_nodes.find_callees(
            self.task_id, self.fuzzer, func.name
        )

        # Pre-extract top caller sources (limit to 3 to save context)
        caller_sources = {}
        for caller_name in callers[:3]:
            caller_func = self.repos.functions.get_by_name(self.task_id, caller_name)
            if caller_func and caller_func.content:
                caller_sources[caller_name] = caller_func.content

        # Determine if this is a large function
        func_lines = func.content.count('\n') + 1 if func.content else 0
        is_large = func_lines > LargeFunctionAnalysisAgent.LARGE_FUNCTION_THRESHOLD

        # Create appropriate agent
        if is_large:
            agent = LargeFunctionAnalysisAgent(
                function_name=func.name,
                function_source=func.content,
                function_file=func.file_path,
                function_lines=(func.start_line, func.end_line),
                callers=callers,
                callees=callees,
                fuzzer_source=fuzzer_source,
                caller_sources=caller_sources,
                fuzzer=self.fuzzer,
                sanitizer=self.sanitizer,
                direction_id=direction_id,
                task_id=self.task_id,
                worker_id=f"{self.worker_id}_func_{index}",
                log_dir=agent_log_dir,
                max_iterations=6,  # More iterations for large functions
            )
        else:
            agent = FunctionAnalysisAgent(
                function_name=func.name,
                function_source=func.content,
                function_file=func.file_path,
                function_lines=(func.start_line, func.end_line),
                callers=callers,
                callees=callees,
                fuzzer_source=fuzzer_source,
                caller_sources=caller_sources,
                fuzzer=self.fuzzer,
                sanitizer=self.sanitizer,
                direction_id=direction_id,
                task_id=self.task_id,
                worker_id=f"{self.worker_id}_func_{index}",
                log_dir=agent_log_dir,
                max_iterations=3,  # Reduced: key info provided upfront
            )

        try:
            # Run agent async
            result = await agent.analyze_async()

            # Mark function as analyzed
            self.repos.functions.mark_analyzed_by_direction(
                func.function_id, direction_id
            )

            func_duration = time.time() - func_start
            sp_status = "SP!" if result.get("sp_created") else "OK"
            self.log_debug(f"[{index+1}/{total}] Done: {func.name} in {func_duration:.1f}s - {sp_status}")

            # Write log block to direction log file
            await self._write_function_log(agent, direction_id, agent_log_dir)

            return result

        except Exception as e:
            self.log_error(f"[{index+1}/{total}] Failed: {func.name} - {e}")
            return {"success": False, "error": str(e)}

    async def _write_function_log(
        self,
        agent,
        direction_id: str,
        agent_log_dir,
    ) -> None:
        """
        Write function analysis log block to direction log file.

        Uses lock to prevent concurrent writes from corrupting the file.

        Args:
            agent: FunctionAnalysisAgent instance
            direction_id: Direction ID for log file naming
            agent_log_dir: Log directory
        """
        from pathlib import Path

        # Get or create lock for this direction
        if direction_id not in self._direction_log_locks:
            self._direction_log_locks[direction_id] = asyncio.Lock()

        lock = self._direction_log_locks[direction_id]

        # Get formatted log block from agent
        log_block = agent.get_log_block()

        # Determine log file path
        log_dir = Path(agent_log_dir) if agent_log_dir else self.results_path
        log_file = log_dir / f"{direction_id}-functioncheck.log"

        # Write with lock to prevent interleaving
        async with lock:
            try:
                with open(log_file, "a", encoding="utf-8") as f:
                    f.write(log_block)
            except Exception as e:
                self.log_error(f"Failed to write function log: {e}")

    async def _run_parallel_sp_find_agents_legacy(
        self,
        directions: List,
        fuzzer_code: str,
        agent_log_dir,
        num_parallel: int = 3,
    ) -> None:
        """
        Legacy: Run SP Find Agents in parallel using asyncio.
        Used for Phase 3 free exploration.

        Args:
            directions: List of Direction objects to analyze
            fuzzer_code: Fuzzer source code for context
            agent_log_dir: Log directory for agents
            num_parallel: Number of concurrent agents
        """
        # Create a semaphore to limit concurrency
        semaphore = asyncio.Semaphore(num_parallel)

        async def analyze_direction(direction, index: int):
            """Analyze a single direction with semaphore control."""
            async with semaphore:
                return await self._analyze_single_direction(
                    direction=direction,
                    index=index,
                    total=len(directions),
                    fuzzer_code=fuzzer_code,
                    agent_log_dir=agent_log_dir,
                )

        # Create tasks for all directions
        tasks = [
            analyze_direction(direction, i)
            for i, direction in enumerate(directions)
        ]

        # Run all tasks concurrently (limited by semaphore)
        self.log_info(f"Starting {len(directions)} direction analyses with {num_parallel} parallel agents")
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _analyze_single_direction(
        self,
        direction,
        index: int,
        total: int,
        fuzzer_code: str,
        agent_log_dir,
    ) -> dict:
        """
        Analyze a single direction (async wrapper for sync agent).

        Args:
            direction: Direction object
            index: Direction index
            total: Total number of directions
            fuzzer_code: Fuzzer source code
            agent_log_dir: Log directory

        Returns:
            Analysis result dict
        """
        import time
        direction_start = time.time()

        self.log_info(f"[{index+1}/{total}] Starting: {direction.name} ({direction.risk_level})")

        # Claim the direction
        claimed = self.repos.directions.claim(
            self.task_id,
            self.fuzzer,
            f"{self.worker_id}_sp_agent_{index}",
        )
        if not claimed:
            self.log_warning(f"[{index+1}/{total}] Could not claim: {direction.name}")
            return {"success": False, "error": "Could not claim direction"}

        # Create SP Find Agent
        sp_agent = FullscanSPAgent(
            fuzzer=self.fuzzer,
            sanitizer=self.sanitizer,
            direction_name=direction.name,
            direction_id=direction.direction_id,
            core_functions=direction.core_functions,
            entry_functions=direction.entry_functions,
            code_summary=direction.code_summary,
            fuzzer_code=fuzzer_code,
            task_id=self.task_id,
            worker_id=f"{self.worker_id}_agent_{index}",
            log_dir=agent_log_dir,
            max_iterations=100,
        )

        try:
            # Run agent async
            result = await sp_agent.analyze_direction_async()
            sp_count = result.get("sp_count", 0)
            functions_analyzed = result.get("functions_analyzed", 0)

            # Complete the direction
            self.repos.directions.complete(
                direction.direction_id,
                sp_count=sp_count,
                functions_analyzed=functions_analyzed,
            )

            direction_duration = time.time() - direction_start
            self.log_info(f"[{index+1}/{total}] Done: {direction.name} in {direction_duration:.1f}s - {sp_count} SPs")
            return result

        except Exception as e:
            self.log_error(f"[{index+1}/{total}] Failed: {direction.name} - {e}")
            self.repos.directions.release_claim(direction.direction_id)
            return {"success": False, "error": str(e)}

    def _get_fuzzer_source_code(self) -> str:
        """Get fuzzer source code for Full-scan context."""
        try:
            from ...analyzer import AnalysisClient

            if not self.executor.analysis_socket_path:
                return ""

            client = AnalysisClient(
                self.executor.analysis_socket_path,
                client_id=f"pov_strategy_{self.worker_id}",
            )

            # Try to get fuzzer entry point source
            source = client.get_function_source(self.fuzzer)
            if source:
                return source

            # Try common entry point names
            for entry in ["LLVMFuzzerTestOneInput", "main", "harness_main"]:
                source = client.get_function_source(entry)
                if source:
                    return source

            return ""
        except Exception as e:
            self.log_warning(f"Could not get fuzzer source code: {e}")
            return ""

    def _get_reachable_function_count(self) -> int:
        """Get count of functions reachable from fuzzer."""
        try:
            from ...analyzer import AnalysisClient

            if not self.executor.analysis_socket_path:
                return 0

            client = AnalysisClient(
                self.executor.analysis_socket_path,
                client_id=f"pov_strategy_{self.worker_id}",
            )

            functions = client.get_reachable_functions(self.fuzzer)
            return len(functions) if functions else 0
        except Exception as e:
            self.log_warning(f"Could not get reachable function count: {e}")
            return 0

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
        fuzz_tooling_dir = self.workspace_path / "fuzz-tooling" / "projects" / self.project_name
        for ext in extensions:
            fuzzer_path = fuzz_tooling_dir / f"{self.fuzzer}{ext}"
            if fuzzer_path.exists():
                try:
                    return fuzzer_path.read_text()
                except Exception as e:
                    self.log_warning(f"Failed to read fuzzer source from {fuzzer_path}: {e}")

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
            config=config,
            output_dir=self.povs_path,
            log_dir=self.log_dir / "agent" if self.log_dir else None,
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

        try:
            stats = loop.run_until_complete(pipeline.run())
        except Exception as e:
            self.log_error(f"Pipeline failed: {e}")
            stats = PipelineStats()

        return stats

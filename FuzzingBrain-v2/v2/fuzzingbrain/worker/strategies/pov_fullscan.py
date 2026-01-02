"""
POV Full-scan Strategy

Strategy for full-scan mode: analyzes all reachable functions for vulnerabilities.

Streaming Pipeline Architecture:
┌─────────────────────────────────────────────────────────────────┐
│                      Concurrent Execution                        │
├─────────────────┬─────────────────┬─────────────────────────────┤
│  SP Find Pool   │  Verify Pool    │  POV Pool                   │
│  (3 agents)     │  (2 agents)     │  (3 agents)                 │
│                 │                 │                             │
│  Poll directions│  Poll new SPs   │  Poll verified SPs          │
│  ↓              │  ↓              │  ↓                          │
│  Create SP ─────→ Verify ─────────→ Generate POV                │
└─────────────────┴─────────────────┴─────────────────────────────┘

All pools run concurrently - no waiting between stages!
"""

import asyncio
import time
from typing import Dict, Any, List

from .pov_base import POVBaseStrategy
from ...core.models import SuspiciousPoint
from ...agents import DirectionPlanningAgent, FullscanSPAgent
from ...tools.directions import set_direction_context
from ...tools.analyzer import set_analyzer_context


class POVFullscanStrategy(POVBaseStrategy):
    """
    POV Strategy for Full-scan mode with streaming pipeline.

    All agent pools run concurrently:
    1. Direction Planning Agent: Divides call graph into logical directions
    2. SP Find Pool: Analyze directions, create SPs
    3. Verify Pool: Verify SPs as they are created
    4. POV Pool: Generate POVs for verified SPs
    """

    def __init__(self, executor, use_pipeline: bool = True, num_parallel_agents: int = 5):
        """
        Initialize POV Full-scan Strategy.

        Args:
            executor: WorkerExecutor instance
            use_pipeline: Whether to use parallel pipeline (default: True)
            num_parallel_agents: Number of concurrent SP Find agents (default: 5)
        """
        super().__init__(executor, use_pipeline)
        self.num_parallel_agents = num_parallel_agents
        self._sp_finding_done = asyncio.Event()  # Signal when SP finding is complete

    @property
    def strategy_name(self) -> str:
        return "POV Fullscan Strategy (Streaming)"

    def execute(self) -> Dict[str, Any]:
        """
        Execute streaming pipeline - all pools run concurrently.

        Returns:
            Result dictionary with findings
        """
        start_time = time.time()

        self.log_info(f"========== {self.strategy_name} Start ==========")
        self.log_info(f"Fuzzer: {self.fuzzer}, Mode: {self.scan_mode}")

        result = {
            "strategy": self.strategy_name,
            "scan_mode": self.scan_mode,
            "reachable": True,
            "suspicious_points_found": 0,
            "suspicious_points_verified": 0,
            "high_confidence_bugs": 0,
            "pov_generated": 0,
        }

        try:
            # Phase 1: Direction Planning (must complete first)
            set_direction_context(self.fuzzer)
            directions = self._run_direction_planning()

            if not directions:
                self.log_warning("No directions created, cannot continue")
                return result

            # Phase 2: Run all pools concurrently (streaming)
            self.log_info(f"=== Starting Streaming Pipeline ({len(directions)} directions) ===")
            self.log_info(f"  SP Find Pool: {self.num_parallel_agents} agents")
            self.log_info(f"  Verify Pool: 5 agents")
            self.log_info(f"  POV Pool: 5 agents")

            pipeline_stats = asyncio.run(self._run_streaming_pipeline(directions))

            # Collect results
            all_points = self.repos.suspicious_points.find_by_task(self.task_id)
            result["suspicious_points_found"] = len(all_points)
            result["suspicious_points_verified"] = pipeline_stats.sp_verified
            result["pov_generated"] = pipeline_stats.pov_generated

            # Count high-confidence bugs
            high_conf = [p for p in all_points if p.is_important or p.score >= 0.9]
            result["high_confidence_bugs"] = len(high_conf)

            # Save results
            sorted_points = self._sort_by_priority(all_points)
            self._save_results(sorted_points)

            total_time = time.time() - start_time
            self.log_info(f"========== {self.strategy_name} Complete ==========")
            self.log_info(f"Total time: {total_time:.1f}s")
            self.log_info(f"Results: {result['suspicious_points_found']} found, "
                         f"{result['suspicious_points_verified']} verified, "
                         f"{result['pov_generated']} POV generated")

            return result

        except Exception as e:
            self.log_error(f"Strategy failed: {e}")
            raise

    def _run_direction_planning(self) -> List:
        """Run direction planning phase."""
        self.log_info("=== Phase 1: Direction Planning ===")
        phase1_start = time.time()

        fuzzer_code = self._get_fuzzer_source_code()
        reachable_count = self._get_reachable_function_count()

        self.log_info(f"Fuzzer: {self.fuzzer}, Reachable functions: {reachable_count}")

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
            self.log_info(f"Direction planning completed: {result.get('directions_created', 0)} directions")
        except Exception as e:
            self.log_error(f"Direction planning failed: {e}")
            return []

        phase1_duration = time.time() - phase1_start
        self.log_info(f"Phase 1 completed in {phase1_duration:.1f}s")

        return self.repos.directions.find_pending(self.task_id, self.fuzzer)

    async def _run_streaming_pipeline(self, directions: List):
        """
        Run all agent pools concurrently.

        Args:
            directions: List of Direction objects to analyze

        Returns:
            PipelineStats with execution statistics
        """
        from ..pipeline import AgentPipeline, PipelineConfig
        from ...tools.coverage import set_coverage_context, get_coverage_context

        # Setup coverage context
        coverage_fuzzer_dir, _, _ = get_coverage_context()
        if coverage_fuzzer_dir:
            set_coverage_context(
                coverage_fuzzer_dir=coverage_fuzzer_dir,
                project_name=self.project_name,
                src_dir=self.workspace_path / "repo",
                docker_image=f"gcr.io/oss-fuzz/{self.project_name}",
                work_dir=self.results_path / "coverage_work",
            )

        # Get fuzzer code for all agents (SP Find + Verify)
        fuzzer_code = self._get_fuzzer_source_code()
        agent_log_dir = self.log_dir / "agent" if self.log_dir else self.results_path

        # Configure pipeline
        config = PipelineConfig(
            num_verify_agents=5,
            num_pov_agents=5,
            pov_min_score=0.5,
            poll_interval=2.0,  # Poll every 2 seconds
            max_idle_cycles=30,  # Wait longer since SP finding takes time
            fuzzer_path=self.executor.fuzzer_binary_path,  # For POV verification
            docker_image=f"gcr.io/oss-fuzz/{self.project_name}",  # Docker image for fuzzer
        )

        # Create pipeline with fuzzer code for verify agents
        pipeline = AgentPipeline(
            task_id=self.task_id,
            repos=self.repos,
            fuzzer=self.fuzzer,
            sanitizer=self.sanitizer,
            config=config,
            output_dir=self.results_path / "povs",
            log_dir=self.log_dir / "agent" if self.log_dir else self.results_path,
            workspace_path=self.workspace_path,
            fuzzer_code=fuzzer_code,
            mcp_socket_path=self.executor.analysis_socket_path,
        )

        # Run all pools concurrently
        self.log_info("Starting concurrent execution of all pools...")

        # Create tasks for concurrent execution
        sp_task = asyncio.create_task(
            self._run_sp_finding_pool(directions, fuzzer_code, agent_log_dir),
            name="sp_finding_pool"
        )
        pipeline_task = asyncio.create_task(
            pipeline.run(),
            name="verify_pov_pipeline"
        )

        # Wait for SP finding to complete first
        await sp_task
        self._sp_finding_done.set()
        pipeline._sp_finding_done = True  # Signal pipeline that SP Finding is done
        self.log_info("SP Finding Pool completed, signaling pipeline...")

        # Wait for pipeline to finish processing all SPs (no timeout - let it drain completely)
        stats = await pipeline_task

        return stats

    async def _run_sp_finding_pool(
        self,
        directions: List,
        fuzzer_code: str,
        agent_log_dir,
    ) -> None:
        """
        Run SP Find Agents in parallel.

        Args:
            directions: List of Direction objects to analyze
            fuzzer_code: Fuzzer source code for context
            agent_log_dir: Log directory for agents
        """
        semaphore = asyncio.Semaphore(self.num_parallel_agents)

        async def analyze_direction(direction, index: int):
            async with semaphore:
                return await self._analyze_single_direction(
                    direction=direction,
                    index=index,
                    total=len(directions),
                    fuzzer_code=fuzzer_code,
                    agent_log_dir=agent_log_dir,
                )

        tasks = [analyze_direction(d, i) for i, d in enumerate(directions)]

        self.log_info(f"SP Finding Pool: {len(directions)} directions, {self.num_parallel_agents} concurrent agents")
        await asyncio.gather(*tasks, return_exceptions=True)
        self.log_info("SP Finding Pool: All directions processed")

    def _find_suspicious_points(self) -> List[SuspiciousPoint]:
        """
        Find suspicious points using two-phase analysis.

        Phase 1: Direction Planning - divide call graph into logical directions
        Phase 2: SP Find - analyze each direction in parallel

        Returns:
            List of SuspiciousPoint objects
        """
        # Set direction context for MCP tools
        set_direction_context(self.fuzzer)

        # Phase 1: Direction Planning
        self.log_info("=== Full-scan Phase 1: Direction Planning ===")
        phase1_start = time.time()

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

        phase1_duration = time.time() - phase1_start
        self.log_info(f"Phase 1 completed in {phase1_duration:.1f}s")

        # Get directions from database
        directions = self.repos.directions.find_pending(self.task_id, self.fuzzer)
        if not directions:
            self.log_warning("No directions created, Full-scan cannot continue")
            return []

        # Phase 2: SP Find Agents (parallel execution)
        self.log_info(f"=== Full-scan Phase 2: SP Find ({len(directions)} directions) ===")
        phase2_start = time.time()

        # Run SP Find Agents in parallel
        asyncio.run(self._run_parallel_sp_find_agents(
            directions=directions,
            fuzzer_code=fuzzer_code,
            agent_log_dir=agent_log_dir,
            num_parallel=self.num_parallel_agents,
        ))

        phase2_duration = time.time() - phase2_start
        self.log_info(f"Phase 2 completed in {phase2_duration:.1f}s")

        # Get all suspicious points created
        return self._get_suspicious_points_from_db()

    async def _run_parallel_sp_find_agents(
        self,
        directions: List,
        fuzzer_code: str,
        agent_log_dir,
        num_parallel: int = 3,
    ) -> None:
        """
        Run SP Find Agents in parallel using asyncio.

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
        # Set analyzer context for this task (ContextVar needs to be set per-task)
        if self.executor.analysis_socket_path:
            set_analyzer_context(
                self.executor.analysis_socket_path,
                client_id=f"{self.worker_id}_sp_agent_{index}"
            )

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

    # =========================================================================
    # Helper Methods
    # =========================================================================

    def _get_fuzzer_source_code(self) -> str:
        """Get fuzzer source code for Full-scan context."""
        try:
            from ...analyzer import AnalysisClient

            if not self.executor.analysis_socket_path:
                return ""

            client = AnalysisClient(
                self.executor.analysis_socket_path,
                client_id=f"fullscan_strategy_{self.worker_id}",
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
                client_id=f"fullscan_strategy_{self.worker_id}",
            )

            functions = client.get_reachable_functions(self.fuzzer)
            return len(functions) if functions else 0
        except Exception as e:
            self.log_warning(f"Could not get reachable function count: {e}")
            return 0

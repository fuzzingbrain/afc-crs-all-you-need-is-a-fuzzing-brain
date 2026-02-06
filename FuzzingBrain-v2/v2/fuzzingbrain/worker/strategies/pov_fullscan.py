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
from ...agents import (
    DirectionPlanningAgent,
    FullscanSPAgent,
    FunctionAnalysisAgent,
    LargeFunctionAnalysisAgent,
)
from ...llms.models import CLAUDE_OPUS_4_5, CLAUDE_SONNET_4_5
from ...tools.directions import set_direction_context
from ...tools.analyzer import set_analyzer_context
from ...tools.suspicious_points import set_sp_context
from ...fuzzer import SeedAgent


class POVFullscanStrategy(POVBaseStrategy):
    """
    POV Strategy for Full-scan mode with streaming pipeline.

    All agent pools run concurrently:
    1. Direction Planning Agent: Divides call graph into logical directions
    2. SP Find Pool: Analyze directions, create SPs
    3. Verify Pool: Verify SPs as they are created
    4. POV Pool: Generate POVs for verified SPs
    """

    def __init__(
        self,
        executor,
        use_pipeline: bool = True,
        num_parallel_agents: int = 5,
        use_v2: bool = True,
    ):
        """
        Initialize POV Full-scan Strategy.

        Args:
            executor: WorkerExecutor instance
            use_pipeline: Whether to use parallel pipeline (default: True)
            num_parallel_agents: Number of concurrent SP Find agents (default: 5)
            use_v2: Use SP Find v2 three-phase architecture (default: True)
        """
        super().__init__(executor, use_pipeline)
        self.num_parallel_agents = num_parallel_agents
        self.use_v2 = use_v2
        self._sp_finding_done = asyncio.Event()  # Signal when SP finding is complete
        self._direction_log_locks: Dict[str, asyncio.Lock] = {}  # For v2 log buffering

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
            # Run everything in a single event loop to avoid litellm client caching issues
            set_direction_context(self.fuzzer)
            pipeline_stats = asyncio.run(self._run_full_pipeline())

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
            self.log_info(
                f"Results: {result['suspicious_points_found']} found, "
                f"{result['suspicious_points_verified']} verified, "
                f"{result['pov_generated']} POV generated"
            )

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

        agent_log_dir = self.agent_log_dir
        planning_agent = DirectionPlanningAgent(
            fuzzer=self.fuzzer,
            sanitizer=self.sanitizer,
            model=CLAUDE_OPUS_4_5,  # Force Opus for direction planning
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
            self.log_info(
                f"Direction planning completed: {result.get('directions_created', 0)} directions"
            )
        except Exception as e:
            self.log_error(f"Direction planning failed: {e}")
            return []

        phase1_duration = time.time() - phase1_start
        self.log_info(f"Phase 1 completed in {phase1_duration:.1f}s")

        return self.repos.directions.find_pending(self.task_id, self.fuzzer)

    async def _run_direction_planning_async(self) -> List:
        """Run direction planning phase asynchronously."""
        self.log_info("=== Phase 1: Direction Planning ===")
        phase1_start = time.time()

        fuzzer_code = self._get_fuzzer_source_code()
        reachable_count = self._get_reachable_function_count()

        self.log_info(f"Fuzzer: {self.fuzzer}, Reachable functions: {reachable_count}")

        agent_log_dir = self.agent_log_dir
        planning_agent = DirectionPlanningAgent(
            fuzzer=self.fuzzer,
            sanitizer=self.sanitizer,
            model=CLAUDE_OPUS_4_5,  # Force Opus for direction planning
            task_id=self.task_id,
            worker_id=self.worker_id,
            log_dir=agent_log_dir,
            max_iterations=100,
        )

        try:
            result = await planning_agent.plan_directions_async(
                fuzzer_code=fuzzer_code,
                reachable_count=reachable_count,
            )
            self.log_info(
                f"Direction planning completed: {result.get('directions_created', 0)} directions"
            )
        except Exception as e:
            self.log_error(f"Direction planning failed: {e}")
            return []

        phase1_duration = time.time() - phase1_start
        self.log_info(f"Phase 1 completed in {phase1_duration:.1f}s")

        return self.repos.directions.find_pending(self.task_id, self.fuzzer)

    async def _run_full_pipeline(self):
        """
        Run the full pipeline in a single event loop.

        This includes:
        1. Direction Planning (async)
        2. Direction Seeds generation + Global Fuzzer startup
        3. SP Finding pipeline (v2 or streaming)

        Running everything in one event loop avoids litellm client caching issues
        where HTTP clients get bound to a closed event loop.
        """
        # Phase 1: Direction Planning
        directions = await self._run_direction_planning_async()

        if not directions:
            self.log_warning("No directions created, cannot continue")
            # Return empty stats
            from ..pipeline import PipelineStats

            return PipelineStats()

        # Phase 2+: SP Finding (Direction Seeds generation is done inside pipeline)
        if self.use_v2:
            # SP Find v2: Three-phase architecture (Small Pool -> Big Pool -> Free Exploration)
            self.log_info(
                f"=== SP Find v2: Three-Phase Architecture ({len(directions)} directions) ==="
            )
            return await self._run_v2_pipeline_with_fuzzer_init(directions)
        else:
            # Legacy: Streaming pipeline with FullscanSPAgent
            self.log_info(
                f"=== Starting Streaming Pipeline ({len(directions)} directions) ==="
            )
            self.log_info(f"  SP Find Pool: {self.num_parallel_agents} agents")
            self.log_info("  Verify Pool: 5 agents")
            self.log_info("  POV Pool: 5 agents")
            return await self._run_streaming_pipeline_with_fuzzer_init(directions)

    async def _run_streaming_pipeline_with_fuzzer_init(self, directions: List):
        """
        Wrapper that initializes fuzzer (Direction Seeds + Global Fuzzer)
        before running the streaming pipeline.

        This ensures all async operations run in the same event loop.
        """
        # Generate Direction Seeds and start Global Fuzzer first
        await self._generate_direction_seeds_and_start_global_fuzzer(directions)

        # Then run the streaming pipeline
        return await self._run_streaming_pipeline(directions)

    async def _run_v2_pipeline_with_fuzzer_init(self, directions: List):
        """
        Wrapper that initializes fuzzer (Direction Seeds + Global Fuzzer)
        before running the v2 pipeline.

        This ensures all async operations run in the same event loop.
        """
        # Generate Direction Seeds and start Global Fuzzer first
        await self._generate_direction_seeds_and_start_global_fuzzer(directions)

        # Then run the v2 pipeline
        return await self._run_v2_pipeline(directions)

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
        agent_log_dir = self.agent_log_dir

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
            scan_mode="full",  # Full-scan mode: use full reachability analysis
            config=config,
            output_dir=self.results_path / "povs",
            log_dir=self.agent_log_dir,
            workspace_path=self.workspace_path,
            fuzzer_code=fuzzer_code,
            mcp_socket_path=self.executor.analysis_socket_path,
            worker_id=self.worker_id,  # For SP Fuzzer lifecycle
        )

        # Run all pools concurrently
        self.log_info("Starting concurrent execution of all pools...")

        # Create tasks for concurrent execution
        sp_task = asyncio.create_task(
            self._run_sp_finding_pool(directions, fuzzer_code, agent_log_dir),
            name="sp_finding_pool",
        )
        pipeline_task = asyncio.create_task(pipeline.run(), name="verify_pov_pipeline")

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

        self.log_info(
            f"SP Finding Pool: {len(directions)} directions, {self.num_parallel_agents} concurrent agents"
        )
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
        agent_log_dir = self.agent_log_dir
        planning_agent = DirectionPlanningAgent(
            fuzzer=self.fuzzer,
            sanitizer=self.sanitizer,
            model=CLAUDE_OPUS_4_5,  # Force Opus for direction planning
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
            self.log_info(
                f"Direction planning completed: {result.get('directions_created', 0)} directions created"
            )
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
        self.log_info(
            f"=== Full-scan Phase 2: SP Find ({len(directions)} directions) ==="
        )
        phase2_start = time.time()

        # Run SP Find Agents in parallel
        asyncio.run(
            self._run_parallel_sp_find_agents(
                directions=directions,
                fuzzer_code=fuzzer_code,
                agent_log_dir=agent_log_dir,
                num_parallel=self.num_parallel_agents,
            )
        )

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
            analyze_direction(direction, i) for i, direction in enumerate(directions)
        ]

        # Run all tasks concurrently (limited by semaphore)
        self.log_info(
            f"Starting {len(directions)} direction analyses with {num_parallel} parallel agents"
        )
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
                client_id=f"SPG_{index}_{self.fuzzer}_{self.sanitizer}",
            )

        direction_start = time.time()

        self.log_info(
            f"[{index + 1}/{total}] Starting: {direction.name} ({direction.risk_level})"
        )

        # Claim the direction
        claimed = self.repos.directions.claim(
            self.task_id,
            self.fuzzer,
            f"SPG_{index}_{self.fuzzer}_{self.sanitizer}",
        )
        if not claimed:
            self.log_warning(f"[{index + 1}/{total}] Could not claim: {direction.name}")
            return {"success": False, "error": "Could not claim direction"}

        # Create SP Find Agent
        sp_agent = FullscanSPAgent(
            fuzzer=self.fuzzer,
            sanitizer=self.sanitizer,
            direction_name=direction.name,
            direction_id=direction.direction_id,
            risk_level=direction.risk_level,  # Pass risk level for min SP requirements
            core_functions=direction.core_functions,
            entry_functions=direction.entry_functions,
            code_summary=direction.code_summary,
            fuzzer_code=fuzzer_code,
            task_id=self.task_id,
            worker_id=f"SPG_{index}_{self.fuzzer}_{self.sanitizer}",
            log_dir=agent_log_dir,
            max_iterations=100,
            index=index + 1,  # 1-based index for log files
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
            self.log_info(
                f"[{index + 1}/{total}] Done: {direction.name} in {direction_duration:.1f}s - {sp_count} SPs"
            )
            return result

        except Exception as e:
            self.log_error(f"[{index + 1}/{total}] Failed: {direction.name} - {e}")
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

    # =========================================================================
    # SP Find v2: Three-Phase Architecture
    # =========================================================================

    async def _run_v2_pipeline(self, directions: List):
        """
        Run SP Find v2 three-phase pipeline with streaming verification.

        Phase 1: Small Pool - Deep analysis of core_functions + entry_functions
        Phase 2: Big Pool - Analyze remaining reachable functions
        Phase 3: Free Exploration - Fallback using large agent

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

        fuzzer_code = self._get_fuzzer_source_code()
        agent_log_dir = self.agent_log_dir

        # Configure pipeline for verification and POV
        config = PipelineConfig(
            num_verify_agents=5,
            num_pov_agents=5,
            pov_min_score=0.5,
            poll_interval=2.0,
            max_idle_cycles=30,
            fuzzer_path=self.executor.fuzzer_binary_path,
            docker_image=f"gcr.io/oss-fuzz/{self.project_name}",
        )

        pipeline = AgentPipeline(
            task_id=self.task_id,
            repos=self.repos,
            fuzzer=self.fuzzer,
            sanitizer=self.sanitizer,
            scan_mode="full",  # Full-scan mode: use full reachability analysis
            config=config,
            output_dir=self.results_path / "povs",
            log_dir=self.agent_log_dir,
            workspace_path=self.workspace_path,
            fuzzer_code=fuzzer_code,
            mcp_socket_path=self.executor.analysis_socket_path,
            worker_id=self.worker_id,  # For SP Fuzzer lifecycle
        )

        # Start pipeline in background
        pipeline_task = asyncio.create_task(pipeline.run(), name="verify_pov_pipeline")

        # Run three phases sequentially
        phase1_start = time.time()
        self.log_info("=== SP Find v2 Phase 1: Small Pool Analysis ===")
        await self._run_phase1_small_pool(directions, agent_log_dir)
        self.log_info(f"Phase 1 completed in {time.time() - phase1_start:.1f}s")

        phase2_start = time.time()
        self.log_info("=== SP Find v2 Phase 2: Big Pool Analysis ===")
        await self._run_phase2_big_pool(directions, agent_log_dir)
        self.log_info(f"Phase 2 completed in {time.time() - phase2_start:.1f}s")

        phase3_start = time.time()
        self.log_info("=== SP Find v2 Phase 3: Free Exploration ===")
        await self._run_phase3_free_exploration(directions, fuzzer_code, agent_log_dir)
        self.log_info(f"Phase 3 completed in {time.time() - phase3_start:.1f}s")

        # Log coverage report
        self._log_coverage_report(directions)

        # Signal pipeline that SP finding is complete
        self._sp_finding_done.set()
        pipeline._sp_finding_done = True
        self.log_info("SP Find v2 completed, waiting for pipeline to drain...")

        stats = await pipeline_task
        return stats

    async def _run_phase1_small_pool(
        self,
        directions: List,
        agent_log_dir,
        num_parallel: int = 5,
    ) -> None:
        """
        Phase 1: Small Pool Deep Analysis.

        Analyzes core_functions + entry_functions from each direction.
        Uses small agents (one per function) for token efficiency.
        """
        # Set direction_id in SP context for linking SPs to directions
        direction_id = directions[0].direction_id if directions else ""
        set_sp_context(self.fuzzer, self.sanitizer, direction_id)

        # Collect all functions from small pool
        small_pool_functions = set()
        for direction in directions:
            small_pool_functions.update(direction.core_functions or [])
            small_pool_functions.update(direction.entry_functions or [])

        self.log_info(f"Phase 1: {len(small_pool_functions)} functions in small pool")

        # Get function details from database
        functions = []
        for func_name in small_pool_functions:
            func = self.repos.functions.find_by_name(self.task_id, func_name)
            if func:
                functions.append(func)

        if not functions:
            self.log_info("Phase 1: No functions found in small pool")
            return

        self.log_info(f"Phase 1: Analyzing {len(functions)} functions")

        semaphore = asyncio.Semaphore(num_parallel)

        async def analyze_function(func, index: int):
            async with semaphore:
                return await self._analyze_single_function_v2(
                    func=func,
                    index=index,
                    total=len(functions),
                    agent_log_dir=agent_log_dir,
                    direction_id=directions[0].direction_id if directions else "",
                )

        tasks = [analyze_function(func, i) for i, func in enumerate(functions)]
        await asyncio.gather(*tasks, return_exceptions=True)

        self.log_info(f"Phase 1 completed: analyzed {len(functions)} functions")

    async def _run_phase2_big_pool(
        self,
        directions: List,
        agent_log_dir,
        num_parallel: int = 5,
    ) -> None:
        """
        Phase 2: Big Pool Analysis.

        Analyzes remaining reachable functions not in small pool.
        """
        direction_id = directions[0].direction_id if directions else ""

        # Set direction_id in SP context for linking SPs to directions
        set_sp_context(self.fuzzer, self.sanitizer, direction_id)

        # Get all reachable functions
        all_functions = self.repos.functions.find_by_task(self.task_id)

        # Collect small pool function names
        small_pool_names = set()
        for direction in directions:
            small_pool_names.update(direction.core_functions or [])
            small_pool_names.update(direction.entry_functions or [])

        # Filter to functions not in small pool and not already analyzed
        functions_to_analyze = [
            f
            for f in all_functions
            if f.name not in small_pool_names
            and (
                not f.analyzed_by_directions
                or direction_id not in f.analyzed_by_directions
            )
        ]

        self.log_info(
            f"Phase 2: {len(functions_to_analyze)} functions to analyze in big pool"
        )

        if not functions_to_analyze:
            self.log_info("Phase 2: No functions to analyze in big pool")
            return

        semaphore = asyncio.Semaphore(num_parallel)

        async def analyze_function(func, index: int):
            async with semaphore:
                return await self._analyze_single_function_v2(
                    func=func,
                    index=index,
                    total=len(functions_to_analyze),
                    agent_log_dir=agent_log_dir,
                    direction_id=direction_id,
                )

        tasks = [
            analyze_function(func, i) for i, func in enumerate(functions_to_analyze)
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

        self.log_info(
            f"Phase 2 completed: analyzed {len(functions_to_analyze)} functions"
        )

    async def _run_phase3_free_exploration(
        self,
        directions: List,
        fuzzer_code: str,
        agent_log_dir,
        num_parallel: int = 2,
    ) -> None:
        """
        Phase 3: Free Exploration (Fallback).

        Uses large agent with context compression for high-risk directions.
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

        self.log_info(
            f"Phase 3: Running free exploration on {len(high_risk_directions)} high-risk directions"
        )

        # Use legacy FullscanSPAgent for exploration
        semaphore = asyncio.Semaphore(num_parallel)

        async def explore_direction(direction, index: int):
            async with semaphore:
                return await self._analyze_single_direction(
                    direction=direction,
                    index=index,
                    total=len(high_risk_directions),
                    fuzzer_code=fuzzer_code,
                    agent_log_dir=agent_log_dir,
                )

        tasks = [explore_direction(d, i) for i, d in enumerate(high_risk_directions)]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _analyze_single_function_v2(
        self,
        func,
        index: int,
        total: int,
        agent_log_dir,
        direction_id: str,
    ) -> dict:
        """
        Analyze a single function using FunctionAnalysisAgent (v2 small agent).
        """
        func_start = time.time()

        self.log_debug(f"[{index + 1}/{total}] Analyzing: {func.name}")

        # Get caller/callee info
        callers = []
        callees = []
        try:
            callers = (
                self.repos.callgraph_nodes.find_callers(
                    self.task_id, self.fuzzer, func.name
                )
                or []
            )
            callees = (
                self.repos.callgraph_nodes.find_callees(
                    self.task_id, self.fuzzer, func.name
                )
                or []
            )
        except Exception:
            pass

        # Get function source - use DB content or fetch via tree-sitter fallback
        func_source = func.content or ""
        if not func_source and self.executor.analysis_socket_path:
            try:
                from ...analyzer import AnalysisClient

                client = AnalysisClient(
                    self.executor.analysis_socket_path,
                    client_id=f"fullscan_func_{self.worker_id}_{index}",
                )
                func_source = client.get_function_source(func.name) or ""
            except Exception:
                pass

        # Determine function size based on actual source
        func_lines = func_source.count("\n") + 1 if func_source else 0
        is_large = func_lines > LargeFunctionAnalysisAgent.LARGE_FUNCTION_THRESHOLD

        # Create appropriate agent
        if is_large:
            agent = LargeFunctionAnalysisAgent(
                function_name=func.name,
                function_source=func_source,  # Use fetched source
                function_file=func.file_path or "",
                function_lines=(func.start_line or 0, func.end_line or 0),
                callers=callers,
                callees=callees,
                fuzzer=self.fuzzer,
                sanitizer=self.sanitizer,
                model=CLAUDE_OPUS_4_5,  # Force Opus for large function analysis
                direction_id=direction_id,
                task_id=self.task_id,
                worker_id=f"Func_{index}_{self.fuzzer}_{self.sanitizer}",
                log_dir=agent_log_dir,
                index=index,  # For log file naming: SPG_{index}_{function_name}.log
            )
        else:
            agent = FunctionAnalysisAgent(
                function_name=func.name,
                function_source=func_source,  # Use fetched source
                function_file=func.file_path or "",
                function_lines=(func.start_line or 0, func.end_line or 0),
                callers=callers,
                callees=callees,
                fuzzer=self.fuzzer,
                sanitizer=self.sanitizer,
                model=CLAUDE_SONNET_4_5,  # Force Sonnet for function analysis
                direction_id=direction_id,
                task_id=self.task_id,
                worker_id=f"Func_{index}_{self.fuzzer}_{self.sanitizer}",
                log_dir=agent_log_dir,
                index=index,  # For log file naming: SPG_{index}_{function_name}.log
            )

        try:
            result = await agent.analyze_async()

            # Mark function as analyzed by this direction
            if hasattr(func, "function_id") and func.function_id:
                self.repos.functions.mark_analyzed_by_direction(
                    func.function_id, direction_id
                )

            func_duration = time.time() - func_start
            sp_status = "SP!" if result.get("sp_created") else "OK"
            self.log_debug(
                f"[{index + 1}/{total}] Done: {func.name} in {func_duration:.1f}s - {sp_status}"
            )

            # Note: Agent logs are now written directly to SPG_{index}_{function_name}.log
            # No need for separate combined log file

            return result

        except Exception as e:
            self.log_error(f"[{index + 1}/{total}] Failed: {func.name} - {e}")
            return {"success": False, "error": str(e)}

    def _log_coverage_report(self, directions: List) -> None:
        """
        Log detailed coverage statistics.
        """
        self.log_info("=== SP Find v2 Coverage Report ===")

        # Small pool stats
        small_pool_total = 0
        for direction in directions:
            small_pool_total += len(direction.core_functions or [])
            small_pool_total += len(direction.entry_functions or [])

        # Big pool stats
        all_functions = self.repos.functions.find_by_task(self.task_id)
        big_pool_total = len(all_functions) if all_functions else 0

        # Analyzed counts
        analyzed_count = sum(
            1
            for f in (all_functions or [])
            if f.analyzed_by_directions and len(f.analyzed_by_directions) > 0
        )

        self.log_info(f"  Small Pool: {small_pool_total} functions")
        self.log_info(f"  Big Pool: {big_pool_total} total reachable functions")
        self.log_info(f"  Analyzed: {analyzed_count} functions")
        self.log_info(
            f"  Coverage: {analyzed_count}/{big_pool_total} ({100 * analyzed_count / max(big_pool_total, 1):.1f}%)"
        )

    # =========================================================================
    # Fuzzer Worker Integration
    # =========================================================================

    async def _generate_direction_seeds_and_start_global_fuzzer(
        self,
        directions: List,
    ) -> None:
        """
        Generate Direction Seeds using SeedAgent and start Global Fuzzer.

        Called after Direction Planning completes.
        Flow: Direction Agent completes → SeedAgent generates initial seeds → Global Fuzzer starts

        Args:
            directions: List of Direction objects from Direction Planning
        """
        # Check if FuzzerManager is available
        fuzzer_manager = getattr(self.executor, "fuzzer_manager", None)
        if not fuzzer_manager:
            self.log_debug(
                "FuzzerManager not available, skipping Direction Seeds generation"
            )
            return

        self.log_info("=== Generating Direction Seeds ===")

        fuzzer_code = self._get_fuzzer_source_code()
        agent_log_dir = self.agent_log_dir

        # Generate seeds for each direction (high-risk first)
        sorted_directions = sorted(
            directions,
            key=lambda d: {"high": 0, "medium": 1, "low": 2}.get(d.risk_level, 3),
        )

        # Create tasks for parallel execution (top 5 directions)
        async def run_seed_agent(seed_index: int, direction) -> dict:
            """Run a single SeedAgent and return result."""
            try:
                seed_agent = SeedAgent(
                    task_id=self.task_id,
                    worker_id=f"{self.worker_id}_seed_{seed_index}",  # Unique per agent
                    fuzzer=self.fuzzer,
                    sanitizer=self.sanitizer,
                    model=CLAUDE_OPUS_4_5,  # Force Opus for seed generation
                    fuzzer_manager=fuzzer_manager,
                    repos=self.repos,
                    fuzzer_source=fuzzer_code,
                    log_dir=agent_log_dir,
                    max_iterations=20,
                    index=seed_index,
                    target_name=direction.name,
                )

                result = await seed_agent.generate_direction_seeds(
                    direction_id=direction.direction_id,
                    target_functions=direction.core_functions or [],
                    risk_level=direction.risk_level,
                    risk_reason=direction.risk_reason or "",
                )
                return {"direction": direction, "result": result}

            except Exception as e:
                self.log_warning(
                    f"  Failed to generate seeds for {direction.name}: {e}"
                )
                return {"direction": direction, "result": None, "error": str(e)}

        # Run all SeedAgents in parallel
        tasks = [
            run_seed_agent(idx, d)
            for idx, d in enumerate(sorted_directions[:5], start=1)
        ]
        results = await asyncio.gather(*tasks)

        # Collect results
        seeds_generated = 0
        for item in results:
            direction = item["direction"]
            result = item.get("result")
            if result and result.get("success"):
                count = result.get("seeds_generated", 0)
                seeds_generated += count
                self.log_info(
                    f"  Generated {count} seeds "
                    f"for direction: {direction.name} ({direction.risk_level})"
                )

        self.log_info(
            f"Direction Seeds generation complete: {seeds_generated} total seeds"
        )

        # Start Global Fuzzer with generated seeds
        if seeds_generated > 0:
            self.log_info("┌─────────────────────────────────────────┐")
            self.log_info("│  Starting Global Fuzzer...              │")
            self.log_info("└─────────────────────────────────────────┘")
            try:
                success = await fuzzer_manager.start_global_fuzzer()
                if not success:
                    self.log_warning("Failed to start Global Fuzzer")
            except Exception as e:
                self.log_warning(f"Error starting Global Fuzzer: {e}")
        else:
            self.log_info(
                "No Direction Seeds generated, skipping Global Fuzzer startup"
            )

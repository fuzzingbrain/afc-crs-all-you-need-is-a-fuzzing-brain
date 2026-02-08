"""
All-in-Agent Pipeline

Parallel pipeline for SP verification and POV generation.
Uses asyncio + MongoDB for concurrent agent execution with claim-based task distribution.

Architecture:
    ┌─────────────────────────────────────────────────────────────────────┐
    │   SP Verify Agent Pool       POV Generate Agent Pool                │
    │   ┌─────────────┐           ┌─────────────┐                        │
    │   │  Agent 1    │           │  Agent 1    │                        │
    │   │  Agent 2    │──Queue──>│  Agent 2    │                        │
    │   │  ...        │           │  ...        │                        │
    │   │  Agent y    │           │  Agent z    │                        │
    │   └─────────────┘           └─────────────┘                        │
    └─────────────────────────────────────────────────────────────────────┘
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from loguru import logger

from ..agents import SPVerifier, POVAgent
from ..core.models import SPStatus
from ..db import RepositoryManager
from ..tools.analyzer import set_analyzer_context
from ..fuzzer import FuzzerManager, get_fuzzer_manager
from ..llms import CLAUDE_SONNET_4_5


@dataclass
class PipelineConfig:
    """Configuration for the pipeline."""

    # Agent pool sizes
    num_verify_agents: int = 2  # Number of verification agents
    num_pov_agents: int = 1  # Number of POV generation agents

    # Thresholds
    pov_min_score: float = 0.5  # Minimum score to proceed to POV generation

    # Timeouts
    poll_interval: float = 1.0  # Seconds between polling for new tasks
    max_idle_cycles: int = 10  # Max cycles with no work before agent exits

    # POV Agent settings
    max_iterations: int = 200  # Max agent loop iterations
    max_pov_attempts: int = 40  # Max POV generation attempts

    # Fuzzer settings (for POV verification)
    fuzzer_path: Optional[Path] = None  # Path to fuzzer binary
    docker_image: Optional[str] = None  # Docker image for running fuzzer


@dataclass
class PipelineStats:
    """Statistics for pipeline execution."""

    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None

    # Counts
    sp_verified: int = 0
    sp_verified_real: int = 0
    sp_verified_fp: int = 0
    pov_generated: int = 0
    pov_failed: int = 0

    # Time tracking (cumulative seconds across all agents)
    verify_time_total: float = 0.0  # Total time spent on verification
    pov_time_total: float = 0.0  # Total time spent on POV generation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": (self.end_time - self.start_time).total_seconds()
            if self.end_time
            else None,
            "sp_verified": self.sp_verified,
            "sp_verified_real": self.sp_verified_real,
            "sp_verified_fp": self.sp_verified_fp,
            "pov_generated": self.pov_generated,
            "pov_failed": self.pov_failed,
            "verify_time_total": self.verify_time_total,
            "pov_time_total": self.pov_time_total,
        }


class AgentPipeline:
    """
    Parallel pipeline for SP verification and POV generation.

    Uses claim-based task distribution:
    - Agents atomically claim tasks from MongoDB
    - Priority queue: is_important > score
    - Automatic load balancing (fast agents do more work)
    """

    def __init__(
        self,
        task_id: str,
        repos: RepositoryManager,
        fuzzer: str = "",
        sanitizer: str = "address",
        scan_mode: str = "delta",  # "delta" or "full" - affects verify prompt
        config: PipelineConfig = None,
        output_dir: Path = None,
        log_dir: Path = None,
        workspace_path: Path = None,
        fuzzer_code: str = "",
        mcp_socket_path: str = None,
        worker_id: str = None,
    ):
        """
        Initialize the pipeline.

        Args:
            task_id: Task ID
            repos: Database repository manager
            fuzzer: Fuzzer name (for agent context)
            sanitizer: Sanitizer type
            config: Pipeline configuration
            output_dir: Directory for POV output
            log_dir: Directory for agent logs
            workspace_path: Path to workspace (for reading source code)
            fuzzer_code: Fuzzer source code (for verify agent context)
            mcp_socket_path: MCP socket path for analyzer context
            worker_id: Worker ID for FuzzerManager lookup
        """
        self.task_id = task_id
        self.repos = repos
        self.fuzzer = fuzzer
        self.sanitizer = sanitizer
        self.scan_mode = scan_mode
        self.config = config or PipelineConfig()
        self.output_dir = output_dir
        self.log_dir = log_dir
        self.workspace_path = workspace_path
        self.fuzzer_code = fuzzer_code
        self.mcp_socket_path = mcp_socket_path
        self.worker_id = worker_id

        # Statistics
        self.stats = PipelineStats()

        # Shutdown flag
        self._shutdown = False

        # Upstream completion flags (for streaming pipeline)
        self._sp_finding_done = False  # Set when SP Find pool completes
        self._verify_done = False  # Set when Verify pool completes

        # FuzzerManager for SP Fuzzer lifecycle
        self._fuzzer_manager: Optional[FuzzerManager] = None

    @property
    def fuzzer_manager(self) -> Optional[FuzzerManager]:
        """Get FuzzerManager (lazy lookup by worker_id)."""
        if self._fuzzer_manager is None and self.worker_id:
            self._fuzzer_manager = get_fuzzer_manager(self.worker_id)
        return self._fuzzer_manager

    async def run(self) -> PipelineStats:
        """
        Run the pipeline until all SPs are processed.

        Returns:
            Pipeline statistics
        """
        logger.info(f"[Pipeline] Starting pipeline for task {self.task_id}")
        logger.info(
            f"[Pipeline] Config: {self.config.num_verify_agents} verify agents, {self.config.num_pov_agents} POV agents"
        )

        self.stats = PipelineStats()

        try:
            # Create agent tasks
            tasks = []

            # Verification agents
            for i in range(self.config.num_verify_agents):
                agent_id = f"verify_{i + 1}"
                tasks.append(self._run_verify_agent(agent_id))

            # POV generation agents
            for i in range(self.config.num_pov_agents):
                agent_id = f"pov_{i + 1}"
                tasks.append(self._run_pov_agent(agent_id))

            # Run all agents concurrently
            await asyncio.gather(*tasks)

        except Exception as e:
            logger.exception(f"[Pipeline] Pipeline error: {e}")

        finally:
            self.stats.end_time = datetime.now()

        # Log final stats
        logger.info("[Pipeline] Pipeline completed")
        logger.info(f"[Pipeline] Stats: {self.stats.to_dict()}")

        return self.stats

    def shutdown(self):
        """Signal all agents to shutdown."""
        logger.info("[Pipeline] Shutdown requested")
        self._shutdown = True

    async def _run_verify_agent(self, agent_id: str):
        """
        Run a verification agent loop.

        Agent continuously:
        1. Claims a pending_verify SP
        2. Verifies it using SPVerifier
        3. Updates status (verified or pending_pov)
        4. Repeats until no more work

        Args:
            agent_id: Unique agent identifier
        """
        # Set analyzer context for this task (ContextVar needs to be set per-task)
        if self.mcp_socket_path:
            set_analyzer_context(self.mcp_socket_path, client_id=agent_id)
            logger.debug(
                f"[Pipeline:{agent_id}] Set analyzer context: {self.mcp_socket_path}"
            )

        logger.info(f"[Pipeline:{agent_id}] Verification agent started")
        idle_cycles = 0

        while not self._shutdown:
            # Try to claim a task (filter by fuzzer/sanitizer for worker isolation)
            sp = self.repos.suspicious_points.claim_for_verify(
                self.task_id,
                agent_id,
                harness_name=self.fuzzer,
                sanitizer=self.sanitizer,
            )

            if sp is None:
                # No work available - check if we should exit
                idle_cycles += 1

                # Only consider exiting if upstream (SP Finding) is done
                if self._sp_finding_done:
                    # Check if there are any remaining pending_verify SPs
                    pending_count = self.repos.suspicious_points.count_by_status(
                        self.task_id,
                        status="pending_verify",
                        harness_name=self.fuzzer,
                        sanitizer=self.sanitizer,
                    )
                    if pending_count == 0 and idle_cycles >= 5:
                        # SP Finding done + no pending work + waited a bit = exit
                        logger.info(
                            f"[Pipeline:{agent_id}] SP Finding done, no more work, exiting"
                        )
                        break

                # Log status periodically
                if idle_cycles % 30 == 0:
                    status = (
                        "waiting for SP Finding"
                        if not self._sp_finding_done
                        else "draining queue"
                    )
                    logger.debug(
                        f"[Pipeline:{agent_id}] Idle cycle {idle_cycles}, {status}"
                    )

                await asyncio.sleep(self.config.poll_interval)
                continue

            # Reset idle counter
            idle_cycles = 0

            # Process the SP with time tracking
            import time as time_module

            sp_start_time = time_module.time()
            claimed_sp_id = sp.suspicious_point_id
            try:
                logger.info(
                    f"[Pipeline:{agent_id}] Verifying SP {sp.suspicious_point_id}"
                )

                # Run verification agent
                # Extract index from agent_id (e.g., "verify_1" -> 1)
                agent_index = int(agent_id.split("_")[1]) if "_" in agent_id else 0
                verify_agent = SPVerifier(
                    # Note: mode removed - SPVerifier is always for verification
                    fuzzer=self.fuzzer,
                    sanitizer=self.sanitizer,
                    scan_mode=self.scan_mode,  # Use pipeline's scan_mode
                    model=CLAUDE_SONNET_4_5,  # Force Sonnet for SP analysis
                    task_id=self.task_id,
                    worker_id=self.worker_id,  # Use actual worker_id, not agent_id
                    log_dir=self.log_dir,
                    index=agent_index,
                    target_name=sp.function_name or "",
                )
                verify_agent.set_context(suspicious_point=sp.to_dict())

                # Run async with fuzzer code for context
                await verify_agent.run_async(
                    suspicious_point=sp.to_dict(),
                    fuzzer_code=self.fuzzer_code,
                )

                # Get updated SP from database (agent should have updated it via tools)
                updated_sp = self.repos.suspicious_points.find_by_id(
                    sp.suspicious_point_id
                )

                if updated_sp:
                    # Check if agent actually updated the SP
                    # If is_checked is still False, agent terminated abnormally
                    # In that case, default to letting it pass (is_important=True)
                    if not updated_sp.is_checked:
                        logger.warning(
                            f"[Pipeline:{agent_id}] Agent did not update SP {sp.suspicious_point_id}, "
                            f"defaulting to pass-through (is_important=True)"
                        )
                        # Default to pass-through when agent fails
                        is_important = True
                        is_real = False
                        score = updated_sp.score
                        notes = "Agent terminated without verdict - defaulting to pass-through"
                    else:
                        is_important = updated_sp.is_important
                        is_real = updated_sp.is_real
                        score = updated_sp.score
                        notes = updated_sp.verification_notes

                    # Determine if should proceed to POV
                    proceed_to_pov = score >= self.config.pov_min_score and is_important

                    # Complete verification
                    self.repos.suspicious_points.complete_verify(
                        sp.suspicious_point_id,
                        is_real=is_real,
                        score=score,
                        notes=notes,
                        is_important=is_important,
                        proceed_to_pov=proceed_to_pov,
                    )
                    claimed_sp_id = None  # Successfully processed

                    # Update stats
                    self.stats.sp_verified += 1
                    if is_real:
                        self.stats.sp_verified_real += 1
                    else:
                        self.stats.sp_verified_fp += 1

                    logger.info(
                        f"[Pipeline:{agent_id}] Verified SP {sp.suspicious_point_id}: "
                        f"score={score:.2f}, real={is_real}, "
                        f"proceed_to_pov={proceed_to_pov}"
                    )
                else:
                    # SP not found, release claim
                    self.repos.suspicious_points.release_claim(
                        sp.suspicious_point_id,
                        SPStatus.FAILED.value,
                    )
                    claimed_sp_id = None  # Handled

            except Exception as e:
                logger.exception(
                    f"[Pipeline:{agent_id}] Error verifying SP {sp.suspicious_point_id}: {e}"
                )
            finally:
                # Release claim if not successfully completed
                # Catches all exit paths including KeyboardInterrupt/CancelledError
                if claimed_sp_id:
                    try:
                        self.repos.suspicious_points.release_claim(
                            claimed_sp_id,
                            SPStatus.PENDING_VERIFY.value,
                        )
                    except Exception:
                        logger.warning(
                            f"[Pipeline:{agent_id}] Failed to release claim for {claimed_sp_id}"
                        )
                # Track verification time
                sp_duration = time_module.time() - sp_start_time
                self.stats.verify_time_total += sp_duration

        logger.info(f"[Pipeline:{agent_id}] Verification agent stopped")

    async def _run_pov_agent(self, agent_id: str):
        """
        Run a POV generation agent loop.

        Agent continuously:
        1. Claims a pending_pov SP
        2. Generates POV using POVAgent
        3. Updates status (pov_generated or failed)
        4. Repeats until no more work

        Args:
            agent_id: Unique agent identifier
        """
        # Set analyzer context for this task (ContextVar needs to be set per-task)
        if self.mcp_socket_path:
            set_analyzer_context(self.mcp_socket_path, client_id=agent_id)
            logger.debug(
                f"[Pipeline:{agent_id}] Set analyzer context: {self.mcp_socket_path}"
            )

        logger.info(f"[Pipeline:{agent_id}] POV generation agent started")
        idle_cycles = 0

        while not self._shutdown:
            # Try to claim a task (filter by fuzzer/sanitizer for worker isolation)
            sp = self.repos.suspicious_points.claim_for_pov(
                self.task_id,
                agent_id,
                min_score=self.config.pov_min_score,
                harness_name=self.fuzzer,
                sanitizer=self.sanitizer,
            )

            if sp is None:
                # No work available - check if we should exit
                idle_cycles += 1

                # Only consider exiting if upstream (SP Finding) is done
                # Once SP Finding is done, both verify and POV will drain their queues
                if self._sp_finding_done:
                    # Check if there are any remaining pending_pov or verifying SPs
                    pending_pov = self.repos.suspicious_points.count_by_status(
                        self.task_id,
                        status="pending_pov",
                        harness_name=self.fuzzer,
                        sanitizer=self.sanitizer,
                    )
                    # Also check if verify is still producing (pending_verify or verifying)
                    pending_verify = self.repos.suspicious_points.count_by_status(
                        self.task_id,
                        status="pending_verify",
                        harness_name=self.fuzzer,
                        sanitizer=self.sanitizer,
                    )
                    verifying = self.repos.suspicious_points.count_by_status(
                        self.task_id,
                        status="verifying",
                        harness_name=self.fuzzer,
                        sanitizer=self.sanitizer,
                    )

                    # Exit only when: SP Finding done + no pending_pov + no pending_verify + no verifying
                    if (
                        pending_pov == 0
                        and pending_verify == 0
                        and verifying == 0
                        and idle_cycles >= 5
                    ):
                        logger.info(
                            f"[Pipeline:{agent_id}] All upstream done, no more work, exiting"
                        )
                        break

                # Log status periodically
                if idle_cycles % 30 == 0:
                    status = (
                        "waiting for upstream"
                        if not self._sp_finding_done
                        else "draining queue"
                    )
                    logger.debug(
                        f"[Pipeline:{agent_id}] Idle cycle {idle_cycles}, {status}"
                    )

                await asyncio.sleep(self.config.poll_interval)
                continue

            # Reset idle counter
            idle_cycles = 0

            # Process the SP with time tracking
            import time as time_module

            sp_start_time = time_module.time()
            sp_fuzzer_started = False
            claimed_sp_id = sp.suspicious_point_id

            try:
                logger.info(
                    f"[Pipeline:{agent_id}] Generating POV for SP {sp.suspicious_point_id}"
                )

                # Start SP Fuzzer for this SP (starts when POV Agent begins processing SP)
                if self.fuzzer_manager:
                    try:
                        sp_fuzzer_started = await self.fuzzer_manager.start_sp_fuzzer(
                            sp.suspicious_point_id
                        )
                        if sp_fuzzer_started:
                            logger.debug(
                                f"[Pipeline:{agent_id}] Started SP Fuzzer for {sp.suspicious_point_id}"
                            )
                    except Exception as e:
                        logger.warning(
                            f"[Pipeline:{agent_id}] Failed to start SP Fuzzer: {e}"
                        )

                # Run POV agent with fuzzer code
                # Extract index from agent_id (e.g., "pov_1" -> 1)
                agent_index = int(agent_id.split("_")[1]) if "_" in agent_id else 0
                pov_agent = POVAgent(
                    fuzzer=self.fuzzer,
                    sanitizer=self.sanitizer,
                    model=CLAUDE_SONNET_4_5,  # Force Sonnet for POV generation
                    task_id=self.task_id,
                    worker_id=self.worker_id,  # Use actual worker_id, not agent_id
                    output_dir=self.output_dir,
                    log_dir=self.log_dir,
                    repos=self.repos,
                    max_iterations=self.config.max_iterations,
                    max_pov_attempts=self.config.max_pov_attempts,
                    fuzzer_path=self.config.fuzzer_path,
                    docker_image=self.config.docker_image,
                    workspace_path=self.workspace_path,
                    fuzzer_code=self.fuzzer_code,
                    fuzzer_manager=self.fuzzer_manager,  # For SP Fuzzer integration
                    index=agent_index,
                    target_name=sp.function_name or "",
                )

                result = await pov_agent.generate_pov_async(sp.to_dict())

                # Complete POV generation
                # On failure, pass harness_name/sanitizer so other contributors can retry
                self.repos.suspicious_points.complete_pov(
                    sp.suspicious_point_id,
                    pov_id=result.pov_id if result.success else None,
                    success=result.success,
                    harness_name=self.fuzzer,
                    sanitizer=self.sanitizer,
                )
                claimed_sp_id = None  # Successfully processed

                # Update stats
                if result.success:
                    self.stats.pov_generated += 1
                    logger.info(
                        f"[Pipeline:{agent_id}] Generated POV {result.pov_id} for SP {sp.suspicious_point_id}"
                    )
                else:
                    self.stats.pov_failed += 1
                    logger.warning(
                        f"[Pipeline:{agent_id}] Failed to generate POV for SP {sp.suspicious_point_id}"
                    )

            except Exception as e:
                logger.exception(
                    f"[Pipeline:{agent_id}] Error generating POV for SP {sp.suspicious_point_id}: {e}"
                )
                self.stats.pov_failed += 1
            finally:
                # Release claim if not successfully completed
                # Catches all exit paths including KeyboardInterrupt/CancelledError
                # Pass harness_name/sanitizer to also clean pov_attempted_by
                # so the same worker can retry after crash recovery
                if claimed_sp_id:
                    try:
                        self.repos.suspicious_points.release_claim(
                            claimed_sp_id,
                            SPStatus.PENDING_POV.value,
                            harness_name=self.fuzzer,
                            sanitizer=self.sanitizer,
                        )
                    except Exception:
                        logger.warning(
                            f"[Pipeline:{agent_id}] Failed to release claim for {claimed_sp_id}"
                        )

                # Stop SP Fuzzer (stops when POV succeeds or fails)
                if sp_fuzzer_started and self.fuzzer_manager:
                    try:
                        await self.fuzzer_manager.stop_sp_fuzzer(sp.suspicious_point_id)
                        logger.debug(
                            f"[Pipeline:{agent_id}] Stopped SP Fuzzer for {sp.suspicious_point_id}"
                        )
                    except Exception as e:
                        logger.warning(
                            f"[Pipeline:{agent_id}] Failed to stop SP Fuzzer: {e}"
                        )

                # Track POV generation time
                sp_duration = time_module.time() - sp_start_time
                self.stats.pov_time_total += sp_duration

        logger.info(f"[Pipeline:{agent_id}] POV generation agent stopped")


async def run_pipeline(
    task_id: str,
    repos: RepositoryManager,
    fuzzer: str = "",
    sanitizer: str = "address",
    scan_mode: str = "delta",  # "delta" or "full" - affects verify prompt
    num_verify_agents: int = 2,
    num_pov_agents: int = 1,
    pov_min_score: float = 0.5,
    output_dir: Path = None,
    log_dir: Path = None,
    fuzzer_path: Path = None,
    docker_image: str = None,
    max_iterations: int = 200,
    max_pov_attempts: int = 40,
    workspace_path: Path = None,
    fuzzer_code: str = "",
    sp_finding_done: bool = True,  # Default True for delta mode
    worker_id: str = None,
) -> PipelineStats:
    """
    Convenience function to run the pipeline.

    Args:
        task_id: Task ID
        repos: Database repository manager
        fuzzer: Fuzzer name
        sanitizer: Sanitizer type
        num_verify_agents: Number of verification agents
        num_pov_agents: Number of POV generation agents
        pov_min_score: Minimum score for POV generation
        output_dir: Directory for POV output
        log_dir: Directory for agent logs
        fuzzer_path: Path to fuzzer binary (for POV verification)
        docker_image: Docker image for running fuzzer
        max_iterations: Max POV agent iterations
        max_pov_attempts: Max POV generation attempts
        workspace_path: Path to workspace (for reading source code)
        fuzzer_code: Fuzzer source code (for verify agent context)
        sp_finding_done: Whether SP finding is already complete (True for delta mode)
        worker_id: Worker ID for FuzzerManager lookup

    Returns:
        Pipeline statistics
    """
    config = PipelineConfig(
        num_verify_agents=num_verify_agents,
        num_pov_agents=num_pov_agents,
        pov_min_score=pov_min_score,
        fuzzer_path=fuzzer_path,
        docker_image=docker_image,
        max_iterations=max_iterations,
        max_pov_attempts=max_pov_attempts,
    )

    pipeline = AgentPipeline(
        task_id=task_id,
        repos=repos,
        fuzzer=fuzzer,
        sanitizer=sanitizer,
        scan_mode=scan_mode,
        config=config,
        output_dir=output_dir,
        log_dir=log_dir,
        workspace_path=workspace_path,
        fuzzer_code=fuzzer_code,
        worker_id=worker_id,
    )

    # Set SP finding done flag so agents can exit when queue is empty
    pipeline._sp_finding_done = sp_finding_done

    return await pipeline.run()

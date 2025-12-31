"""
All-in-Agent Pipeline

Parallel pipeline for SP verification and POV generation.
Uses asyncio + MongoDB for concurrent agent execution with claim-based task distribution.

Architecture:
    ┌─────────────────────────────────────────────────────────────────────┐
    │   SP Verify Agent Pool       POV Generate Agent Pool                │
    │   ┌─────────────┐           ┌─────────────┐                        │
    │   │  Agent 1    │           │  Agent 1    │                        │
    │   │  Agent 2    │──队列───>│  Agent 2    │                        │
    │   │  ...        │           │  ...        │                        │
    │   │  Agent y    │           │  Agent z    │                        │
    │   └─────────────┘           └─────────────┘                        │
    └─────────────────────────────────────────────────────────────────────┘
"""

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from loguru import logger

from ..agents import SuspiciousPointAgent, POVAgent, POVResult
from ..core.models import SuspiciousPoint, SPStatus
from ..db import RepositoryManager


@dataclass
class PipelineConfig:
    """Configuration for the pipeline."""

    # Agent pool sizes
    num_verify_agents: int = 2  # Number of verification agents
    num_pov_agents: int = 1     # Number of POV generation agents

    # Thresholds
    pov_min_score: float = 0.5  # Minimum score to proceed to POV generation

    # Timeouts
    poll_interval: float = 1.0  # Seconds between polling for new tasks
    max_idle_cycles: int = 10   # Max cycles with no work before agent exits

    # POV Agent settings
    pov_sleep_seconds: float = 30.0  # Placeholder POV agent sleep time


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

    def to_dict(self) -> Dict[str, Any]:
        return {
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": (self.end_time - self.start_time).total_seconds() if self.end_time else None,
            "sp_verified": self.sp_verified,
            "sp_verified_real": self.sp_verified_real,
            "sp_verified_fp": self.sp_verified_fp,
            "pov_generated": self.pov_generated,
            "pov_failed": self.pov_failed,
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
        config: PipelineConfig = None,
        output_dir: Path = None,
        log_dir: Path = None,
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
        """
        self.task_id = task_id
        self.repos = repos
        self.fuzzer = fuzzer
        self.sanitizer = sanitizer
        self.config = config or PipelineConfig()
        self.output_dir = output_dir
        self.log_dir = log_dir

        # Statistics
        self.stats = PipelineStats()

        # Shutdown flag
        self._shutdown = False

    async def run(self) -> PipelineStats:
        """
        Run the pipeline until all SPs are processed.

        Returns:
            Pipeline statistics
        """
        logger.info(f"[Pipeline] Starting pipeline for task {self.task_id}")
        logger.info(f"[Pipeline] Config: {self.config.num_verify_agents} verify agents, {self.config.num_pov_agents} POV agents")

        self.stats = PipelineStats()

        try:
            # Create agent tasks
            tasks = []

            # Verification agents
            for i in range(self.config.num_verify_agents):
                agent_id = f"verify_{i+1}"
                tasks.append(self._run_verify_agent(agent_id))

            # POV generation agents
            for i in range(self.config.num_pov_agents):
                agent_id = f"pov_{i+1}"
                tasks.append(self._run_pov_agent(agent_id))

            # Run all agents concurrently
            await asyncio.gather(*tasks)

        except Exception as e:
            logger.exception(f"[Pipeline] Pipeline error: {e}")

        finally:
            self.stats.end_time = datetime.now()

        # Log final stats
        logger.info(f"[Pipeline] Pipeline completed")
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
        2. Verifies it using SuspiciousPointAgent
        3. Updates status (verified or pending_pov)
        4. Repeats until no more work

        Args:
            agent_id: Unique agent identifier
        """
        logger.info(f"[Pipeline:{agent_id}] Verification agent started")
        idle_cycles = 0

        while not self._shutdown:
            # Try to claim a task
            sp = self.repos.suspicious_points.claim_for_verify(
                self.task_id,
                agent_id,
            )

            if sp is None:
                # No work available
                idle_cycles += 1
                if idle_cycles >= self.config.max_idle_cycles:
                    # Check if pipeline is complete
                    if self.repos.suspicious_points.is_pipeline_complete(self.task_id):
                        logger.info(f"[Pipeline:{agent_id}] No more work, exiting")
                        break
                    # Otherwise keep waiting (new SPs might be added)
                    idle_cycles = self.config.max_idle_cycles // 2

                await asyncio.sleep(self.config.poll_interval)
                continue

            # Reset idle counter
            idle_cycles = 0

            # Process the SP
            try:
                logger.info(f"[Pipeline:{agent_id}] Verifying SP {sp.suspicious_point_id}")

                # Run verification agent
                verify_agent = SuspiciousPointAgent(
                    mode="verify",
                    fuzzer=self.fuzzer,
                    sanitizer=self.sanitizer,
                    task_id=self.task_id,
                    worker_id=agent_id,
                    log_dir=self.log_dir,
                )
                verify_agent.set_verify_context(sp.to_dict())

                # Run async
                await verify_agent.run_async(suspicious_point=sp.to_dict())

                # Get updated SP from database (agent should have updated it via tools)
                updated_sp = self.repos.suspicious_points.find_by_id(sp.suspicious_point_id)

                if updated_sp:
                    # Determine if should proceed to POV
                    proceed_to_pov = (
                        updated_sp.score >= self.config.pov_min_score and
                        updated_sp.is_important
                    )

                    # Complete verification
                    self.repos.suspicious_points.complete_verify(
                        sp.suspicious_point_id,
                        is_real=updated_sp.is_real,
                        score=updated_sp.score,
                        notes=updated_sp.verification_notes,
                        is_important=updated_sp.is_important,
                        proceed_to_pov=proceed_to_pov,
                    )

                    # Update stats
                    self.stats.sp_verified += 1
                    if updated_sp.is_real:
                        self.stats.sp_verified_real += 1
                    else:
                        self.stats.sp_verified_fp += 1

                    logger.info(
                        f"[Pipeline:{agent_id}] Verified SP {sp.suspicious_point_id}: "
                        f"score={updated_sp.score:.2f}, real={updated_sp.is_real}, "
                        f"proceed_to_pov={proceed_to_pov}"
                    )
                else:
                    # SP not found, release claim
                    self.repos.suspicious_points.release_claim(
                        sp.suspicious_point_id,
                        SPStatus.FAILED.value,
                    )

            except Exception as e:
                logger.exception(f"[Pipeline:{agent_id}] Error verifying SP {sp.suspicious_point_id}: {e}")
                # Release claim on error
                self.repos.suspicious_points.release_claim(
                    sp.suspicious_point_id,
                    SPStatus.PENDING_VERIFY.value,  # Revert to pending for retry
                )

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
        logger.info(f"[Pipeline:{agent_id}] POV generation agent started")
        idle_cycles = 0

        while not self._shutdown:
            # Try to claim a task
            sp = self.repos.suspicious_points.claim_for_pov(
                self.task_id,
                agent_id,
                min_score=self.config.pov_min_score,
            )

            if sp is None:
                # No work available
                idle_cycles += 1
                if idle_cycles >= self.config.max_idle_cycles:
                    # Check if pipeline is complete
                    if self.repos.suspicious_points.is_pipeline_complete(self.task_id):
                        logger.info(f"[Pipeline:{agent_id}] No more work, exiting")
                        break
                    # Otherwise keep waiting
                    idle_cycles = self.config.max_idle_cycles // 2

                await asyncio.sleep(self.config.poll_interval)
                continue

            # Reset idle counter
            idle_cycles = 0

            # Process the SP
            try:
                logger.info(f"[Pipeline:{agent_id}] Generating POV for SP {sp.suspicious_point_id}")

                # Run POV agent (placeholder)
                pov_agent = POVAgent(
                    fuzzer=self.fuzzer,
                    sanitizer=self.sanitizer,
                    task_id=self.task_id,
                    worker_id=agent_id,
                    output_dir=self.output_dir,
                    sleep_seconds=self.config.pov_sleep_seconds,
                )

                result = await pov_agent.generate_pov_async(sp.to_dict())

                # Complete POV generation
                self.repos.suspicious_points.complete_pov(
                    sp.suspicious_point_id,
                    pov_id=result.pov_id if result.success else None,
                    success=result.success,
                )

                # Update stats
                if result.success:
                    self.stats.pov_generated += 1
                    logger.info(f"[Pipeline:{agent_id}] Generated POV {result.pov_id} for SP {sp.suspicious_point_id}")
                else:
                    self.stats.pov_failed += 1
                    logger.warning(f"[Pipeline:{agent_id}] Failed to generate POV for SP {sp.suspicious_point_id}")

            except Exception as e:
                logger.exception(f"[Pipeline:{agent_id}] Error generating POV for SP {sp.suspicious_point_id}: {e}")
                # Release claim on error
                self.repos.suspicious_points.release_claim(
                    sp.suspicious_point_id,
                    SPStatus.PENDING_POV.value,  # Revert to pending for retry
                )
                self.stats.pov_failed += 1

        logger.info(f"[Pipeline:{agent_id}] POV generation agent stopped")


async def run_pipeline(
    task_id: str,
    repos: RepositoryManager,
    fuzzer: str = "",
    sanitizer: str = "address",
    num_verify_agents: int = 2,
    num_pov_agents: int = 1,
    pov_min_score: float = 0.5,
    output_dir: Path = None,
    log_dir: Path = None,
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

    Returns:
        Pipeline statistics
    """
    config = PipelineConfig(
        num_verify_agents=num_verify_agents,
        num_pov_agents=num_pov_agents,
        pov_min_score=pov_min_score,
    )

    pipeline = AgentPipeline(
        task_id=task_id,
        repos=repos,
        fuzzer=fuzzer,
        sanitizer=sanitizer,
        config=config,
        output_dir=output_dir,
        log_dir=log_dir,
    )

    return await pipeline.run()

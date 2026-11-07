# SPDX-License-Identifier: Apache-2.0
"""
All-in-Agent Pipeline

Parallel pipeline for VH verification and PoC generation.
Uses asyncio + MongoDB for concurrent agent execution with claim-based task distribution.

Architecture:
    ┌─────────────────────────────────────────────────────────────────────┐
    │   VH Verify Agent Pool       PoC Generate Agent Pool                │
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

from ..agents import VHVerifier, POCAgent
from ..core.models import VHStatus
from ..db import RepositoryManager
from ..tools.analyzer import set_analyzer_context
from ..fuzzer import FuzzerManager, get_fuzzer_manager
from ..llms.routing import Role, model_for


@dataclass
class PipelineConfig:
    """Configuration for the pipeline."""

    # Agent pool sizes
    num_verify_agents: int = 2  # Number of verification agents
    num_poc_agents: int = 1  # Number of PoC generation agents

    # Thresholds
    poc_min_score: float = 0.5  # Minimum score to proceed to PoC generation

    # Timeouts
    poll_interval: float = 1.0  # Seconds between polling for new tasks
    max_idle_cycles: int = 10  # Max cycles with no work before agent exits

    # PoC Agent settings
    max_iterations: int = 100  # Max agent loop iterations
    max_poc_attempts: int = 100  # Max PoC generation attempts

    # Fuzzer settings (for PoC verification)
    fuzzer_path: Optional[Path] = None  # Path to fuzzer binary
    docker_image: Optional[str] = None  # Docker image for running fuzzer


@dataclass
class PipelineStats:
    """Statistics for pipeline execution."""

    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None

    # Counts
    vh_verified: int = 0
    vh_verified_real: int = 0
    vh_verified_fp: int = 0
    poc_generated: int = 0
    poc_failed: int = 0

    # Time tracking (cumulative seconds across all agents)
    verify_time_total: float = 0.0  # Total time spent on verification
    poc_time_total: float = 0.0  # Total time spent on PoC generation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": (self.end_time - self.start_time).total_seconds()
            if self.end_time
            else None,
            "vh_verified": self.vh_verified,
            "vh_verified_real": self.vh_verified_real,
            "vh_verified_fp": self.vh_verified_fp,
            "poc_generated": self.poc_generated,
            "poc_failed": self.poc_failed,
            "verify_time_total": self.verify_time_total,
            "poc_time_total": self.poc_time_total,
        }


class AgentPipeline:
    """
    Parallel pipeline for VH verification and PoC generation.

    Uses claim-based task distribution:
    - Agents atomically claim tasks from MongoDB
    - Priority queue: proceed then priority
    - Automatic load balancing (fast agents do more work)
    """

    def __init__(
        self,
        run_id: str,
        repos: RepositoryManager,
        fuzzer: str = "",
        sanitizer: str = "address",
        scan_mode: str = "delta",  # "delta" or "full" - affects verify prompt
        config: PipelineConfig = None,
        output_dir: Path = None,
        log_dir: Path = None,
        workspace_path: Path = None,
        fuzzer_code: str = "",
        fuzzer_source: str = "",
        mcp_socket_path: str = None,
        worker_id: str = None,
    ):
        """
        Initialize the pipeline.

        Args:
            run_id: Run ID
            repos: Database repository manager
            fuzzer: Fuzzer name (for agent context)
            sanitizer: Sanitizer type
            config: Pipeline configuration
            output_dir: Directory for PoC output
            log_dir: Directory for agent logs
            workspace_path: Path to workspace (for reading source code)
            fuzzer_code: Fuzzer source code (for verify agent context)
            mcp_socket_path: MCP socket path for analyzer context
            worker_id: Worker ID for FuzzerManager lookup
        """
        self.run_id = run_id
        self.repos = repos
        self.fuzzer = fuzzer
        self.sanitizer = sanitizer
        self.scan_mode = scan_mode
        self.config = config or PipelineConfig()
        self.output_dir = output_dir
        self.log_dir = log_dir
        self.workspace_path = workspace_path
        self.fuzzer_code = fuzzer_code
        # Full harness blob for the verifier's system prompt (cached per worker).
        self.fuzzer_source = fuzzer_source
        self.mcp_socket_path = mcp_socket_path
        self.worker_id = worker_id

        # Statistics
        self.stats = PipelineStats()

        # Shutdown flag
        self._shutdown = False

        # Upstream completion flags (for streaming pipeline)
        self._vh_finding_done = False  # Set when VH Find pool completes
        self._verify_done = False  # Set when Verify pool completes

        # FuzzerManager for VH Fuzzer lifecycle
        self._fuzzer_manager: Optional[FuzzerManager] = None

    @property
    def fuzzer_manager(self) -> Optional[FuzzerManager]:
        """Get FuzzerManager (lazy lookup by worker_id)."""
        if self._fuzzer_manager is None and self.worker_id:
            self._fuzzer_manager = get_fuzzer_manager(self.worker_id)
        return self._fuzzer_manager

    async def run(self) -> PipelineStats:
        """
        Run the pipeline until all VHs are processed.

        Returns:
            Pipeline statistics
        """
        logger.info(f"[Pipeline] Starting pipeline for run {self.run_id}")
        logger.info(
            f"[Pipeline] Config: {self.config.num_verify_agents} verify agents, {self.config.num_poc_agents} PoC agents"
        )

        self.stats = PipelineStats()

        try:
            # Create agent tasks
            tasks = []

            # Verification agents
            for i in range(self.config.num_verify_agents):
                agent_id = f"verify_{i + 1}"
                tasks.append(self._run_verify_agent(agent_id))

            # PoC generation agents
            for i in range(self.config.num_poc_agents):
                agent_id = f"poc_{i + 1}"
                tasks.append(self._run_poc_agent(agent_id))

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
        1. Claims a pending_verify VH
        2. Verifies it using VHVerifier
        3. Updates status (verified or pending_poc)
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
            vh = self.repos.vulnerability_hypotheses.claim_for_verify(
                self.run_id,
                agent_id,
                harness_name=self.fuzzer,
                sanitizer=self.sanitizer,
            )

            if vh is None:
                # No work available.
                #
                # DO NOT exit on an empty queue. The run's real end is owned by
                # the dispatcher, which revokes the workers on PoC target / budget
                # limit / the per-task celery timeout. The old early-exit (VH
                # finding done + queue drained) cut guided work short: the finder
                # does a single full scan and the verifier drains it in seconds,
                # so on tasks the first scan misses (e.g. freetype tt_size_reset)
                # the whole agent phase died in ~4 min and only blind global
                # fuzzing ran for the remaining ~86 min. Stay alive until the
                # clock or the budget ends the run, so late VHs -- e.g. ones
                # raised from fuzzer-found crashes -- still get verified/attempted.
                idle_cycles += 1

                # Log status periodically
                if idle_cycles % 30 == 0:
                    status = (
                        "waiting for VH Finding"
                        if not self._vh_finding_done
                        else "idle, staying alive until timeout/budget"
                    )
                    logger.debug(
                        f"[Pipeline:{agent_id}] Idle cycle {idle_cycles}, {status}"
                    )

                await asyncio.sleep(self.config.poll_interval)
                continue

            # Reset idle counter
            idle_cycles = 0

            # Process the VH with time tracking
            import time as time_module

            vh_start_time = time_module.time()
            claimed_vh_id = vh.vulnerability_hypothesis_id
            try:
                logger.info(
                    f"[Pipeline:{agent_id}] Verifying VH {vh.vulnerability_hypothesis_id}"
                )

                # Run verification agent
                # Extract index from agent_id (e.g., "verify_1" -> 1)
                agent_index = int(agent_id.split("_")[1]) if "_" in agent_id else 0
                verify_agent = VHVerifier(
                    # Note: mode removed - VHVerifier is always for verification
                    fuzzer=self.fuzzer,
                    sanitizer=self.sanitizer,
                    scan_mode=self.scan_mode,  # Use pipeline's scan_mode
                    model=model_for(Role.VERIFIER),
                    run_id=self.run_id,
                    worker_id=self.worker_id,  # Use actual worker_id, not agent_id
                    log_dir=self.log_dir,
                    index=agent_index,
                    target_name=vh.function_name or "",
                    fuzzer_source=self.fuzzer_source,
                )
                verify_agent.set_context(vulnerability_hypothesis=vh.to_dict())

                # Run async with fuzzer code for context
                await verify_agent.run_async(
                    vulnerability_hypothesis=vh.to_dict(),
                    fuzzer_code=self.fuzzer_code,
                )

                # Get updated VH from database (agent should have updated it via tools)
                updated_vh = self.repos.vulnerability_hypotheses.find_by_id(
                    vh.vulnerability_hypothesis_id
                )

                if updated_vh:
                    # Check if agent actually updated the VH
                    # If is_checked_by_verifier is still False, agent terminated abnormally
                    # In that case, default to letting it pass (proceed=True)
                    if not updated_vh.is_checked_by_verifier:
                        logger.warning(
                            f"[Pipeline:{agent_id}] Agent did not update VH {vh.vulnerability_hypothesis_id}, "
                            f"defaulting to pass-through (proceed=True)"
                        )
                        # Recall-first: default to pass-through when the agent fails
                        proceed = True
                        priority = updated_vh.priority
                        evidence = updated_vh.evidence
                        is_crash_found = False
                        score = updated_vh.score
                        notes = "Agent terminated without verdict - defaulting to pass-through"
                    else:
                        proceed = updated_vh.proceed
                        priority = updated_vh.priority
                        evidence = updated_vh.evidence
                        is_crash_found = updated_vh.is_crash_found
                        score = updated_vh.score
                        notes = updated_vh.verification_notes

                    # Recall-first gate: proceed unless strongly disconfirmed.
                    # (a crash always proceeds; the score threshold is gone)
                    proceed_to_poc = bool(proceed) or bool(is_crash_found)

                    # Complete verification
                    self.repos.vulnerability_hypotheses.complete_verify(
                        vh.vulnerability_hypothesis_id,
                        is_crash_found=is_crash_found,
                        score=score,
                        notes=notes,
                        proceed=proceed,
                        priority=priority,
                        evidence=evidence,
                        proceed_to_poc=proceed_to_poc,
                    )
                    claimed_vh_id = None  # Successfully processed

                    # Update stats
                    self.stats.vh_verified += 1
                    if is_crash_found:
                        self.stats.vh_verified_real += 1
                    else:
                        self.stats.vh_verified_fp += 1

                    logger.info(
                        f"[Pipeline:{agent_id}] Verified VH {vh.vulnerability_hypothesis_id}: "
                        f"priority={priority:.2f}, real={is_crash_found}, "
                        f"proceed={proceed}, proceed_to_poc={proceed_to_poc}"
                    )
                else:
                    # VH not found, release claim
                    self.repos.vulnerability_hypotheses.release_claim(
                        vh.vulnerability_hypothesis_id,
                        VHStatus.FAILED.value,
                    )
                    claimed_vh_id = None  # Handled

            except Exception as e:
                logger.exception(
                    f"[Pipeline:{agent_id}] Error verifying VH {vh.vulnerability_hypothesis_id}: {e}"
                )
            finally:
                # Release claim if not successfully completed
                # Catches all exit paths including KeyboardInterrupt/CancelledError
                if claimed_vh_id:
                    try:
                        self.repos.vulnerability_hypotheses.release_claim(
                            claimed_vh_id,
                            VHStatus.PENDING_VERIFY.value,
                        )
                    except Exception:
                        logger.warning(
                            f"[Pipeline:{agent_id}] Failed to release claim for {claimed_vh_id}"
                        )
                # Track verification time
                vh_duration = time_module.time() - vh_start_time
                self.stats.verify_time_total += vh_duration

        logger.info(f"[Pipeline:{agent_id}] Verification agent stopped")

    async def _run_poc_agent(self, agent_id: str):
        """
        Run a PoC generation agent loop.

        Agent continuously:
        1. Claims a pending_poc VH
        2. Generates PoC using POCAgent
        3. Updates status (poc_generated or failed)
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

        logger.info(f"[Pipeline:{agent_id}] PoC generation agent started")
        idle_cycles = 0

        while not self._shutdown:
            # Try to claim a task (filter by fuzzer/sanitizer for worker isolation)
            vh = self.repos.vulnerability_hypotheses.claim_for_poc(
                self.run_id,
                agent_id,
                min_score=self.config.poc_min_score,
                harness_name=self.fuzzer,
                sanitizer=self.sanitizer,
            )

            if vh is None:
                # No work available. Do NOT exit on an empty queue -- see the
                # matching note in _run_verify_agent. The PoC worker stays alive
                # until the dispatcher revokes it (PoC target / budget / per-task
                # timeout), so a pending_poc raised later (from continued
                # verification or a fuzzer-found crash) is still attempted instead
                # of the whole agent phase dying the moment the first scan drains.
                idle_cycles += 1

                # Log status periodically
                if idle_cycles % 30 == 0:
                    status = (
                        "waiting for upstream"
                        if not self._vh_finding_done
                        else "idle, staying alive until timeout/budget"
                    )
                    logger.debug(
                        f"[Pipeline:{agent_id}] Idle cycle {idle_cycles}, {status}"
                    )

                await asyncio.sleep(self.config.poll_interval)
                continue

            # Reset idle counter
            idle_cycles = 0

            # Process the VH with time tracking
            import time as time_module

            vh_start_time = time_module.time()
            vh_fuzzer_started = False
            claimed_vh_id = vh.vulnerability_hypothesis_id

            try:
                logger.info(
                    f"[Pipeline:{agent_id}] Generating PoC for VH {vh.vulnerability_hypothesis_id}"
                )

                # Start VH Fuzzer for this VH (starts when PoC Agent begins processing VH)
                if self.fuzzer_manager:
                    try:
                        vh_fuzzer_started = await self.fuzzer_manager.start_vh_fuzzer(
                            vh.vulnerability_hypothesis_id
                        )
                        if vh_fuzzer_started:
                            logger.debug(
                                f"[Pipeline:{agent_id}] Started VH Fuzzer for {vh.vulnerability_hypothesis_id}"
                            )
                    except Exception as e:
                        logger.warning(
                            f"[Pipeline:{agent_id}] Failed to start VH Fuzzer: {e}"
                        )

                # Run PoC agent with fuzzer code
                # Extract index from agent_id (e.g., "poc_1" -> 1)
                agent_index = int(agent_id.split("_")[1]) if "_" in agent_id else 0
                poc_agent = POCAgent(
                    fuzzer=self.fuzzer,
                    sanitizer=self.sanitizer,
                    model=model_for(Role.POC),
                    run_id=self.run_id,
                    worker_id=self.worker_id,  # Use actual worker_id, not agent_id
                    output_dir=self.output_dir,
                    log_dir=self.log_dir,
                    repos=self.repos,
                    max_iterations=self.config.max_iterations,
                    max_poc_attempts=self.config.max_poc_attempts,
                    fuzzer_path=self.config.fuzzer_path,
                    docker_image=self.config.docker_image,
                    workspace_path=self.workspace_path,
                    fuzzer_code=self.fuzzer_code,
                    fuzzer_source=self.fuzzer_source,  # full multi-file harness (cached)
                    fuzzer_manager=self.fuzzer_manager,  # For VH Fuzzer integration
                    index=agent_index,
                    target_name=vh.function_name or "",
                )

                result = await poc_agent.generate_poc_async(vh.to_dict())

                # Complete PoC generation
                # On failure, pass harness_name/sanitizer so other contributors can retry
                self.repos.vulnerability_hypotheses.complete_poc(
                    vh.vulnerability_hypothesis_id,
                    poc_id=result.poc_id if result.success else None,
                    success=result.success,
                    harness_name=self.fuzzer,
                    sanitizer=self.sanitizer,
                )
                claimed_vh_id = None  # Successfully processed

                # Update stats
                if result.success:
                    self.stats.poc_generated += 1
                    logger.info(
                        f"[Pipeline:{agent_id}] Generated PoC {result.poc_id} for VH {vh.vulnerability_hypothesis_id}"
                    )
                else:
                    self.stats.poc_failed += 1
                    logger.warning(
                        f"[Pipeline:{agent_id}] Failed to generate PoC for VH {vh.vulnerability_hypothesis_id}"
                    )

            except Exception as e:
                logger.exception(
                    f"[Pipeline:{agent_id}] Error generating PoC for VH {vh.vulnerability_hypothesis_id}: {e}"
                )
                self.stats.poc_failed += 1
            finally:
                # Release claim if not successfully completed
                # Catches all exit paths including KeyboardInterrupt/CancelledError
                # Pass harness_name/sanitizer to also clean poc_attempted_by
                # so the same worker can retry after crash recovery
                if claimed_vh_id:
                    try:
                        self.repos.vulnerability_hypotheses.release_claim(
                            claimed_vh_id,
                            VHStatus.PENDING_POC.value,
                            harness_name=self.fuzzer,
                            sanitizer=self.sanitizer,
                        )
                    except Exception:
                        logger.warning(
                            f"[Pipeline:{agent_id}] Failed to release claim for {claimed_vh_id}"
                        )

                # Stop VH Fuzzer (stops when PoC succeeds or fails)
                if vh_fuzzer_started and self.fuzzer_manager:
                    try:
                        await self.fuzzer_manager.stop_vh_fuzzer(vh.vulnerability_hypothesis_id)
                        logger.debug(
                            f"[Pipeline:{agent_id}] Stopped VH Fuzzer for {vh.vulnerability_hypothesis_id}"
                        )
                    except Exception as e:
                        logger.warning(
                            f"[Pipeline:{agent_id}] Failed to stop VH Fuzzer: {e}"
                        )

                # Track PoC generation time
                vh_duration = time_module.time() - vh_start_time
                self.stats.poc_time_total += vh_duration

        logger.info(f"[Pipeline:{agent_id}] PoC generation agent stopped")


async def run_pipeline(
    run_id: str,
    repos: RepositoryManager,
    fuzzer: str = "",
    sanitizer: str = "address",
    scan_mode: str = "delta",  # "delta" or "full" - affects verify prompt
    num_verify_agents: int = 2,
    num_poc_agents: int = 1,
    poc_min_score: float = 0.5,
    output_dir: Path = None,
    log_dir: Path = None,
    fuzzer_path: Path = None,
    docker_image: str = None,
    max_iterations: int = 200,
    max_poc_attempts: int = 100,
    workspace_path: Path = None,
    fuzzer_code: str = "",
    fuzzer_source: str = "",
    vh_finding_done: bool = True,  # Default True for delta mode
    worker_id: str = None,
) -> PipelineStats:
    """
    Convenience function to run the pipeline.

    Args:
        run_id: Run ID
        repos: Database repository manager
        fuzzer: Fuzzer name
        sanitizer: Sanitizer type
        num_verify_agents: Number of verification agents
        num_poc_agents: Number of PoC generation agents
        poc_min_score: Minimum score for PoC generation
        output_dir: Directory for PoC output
        log_dir: Directory for agent logs
        fuzzer_path: Path to fuzzer binary (for PoC verification)
        docker_image: Docker image for running fuzzer
        max_iterations: Max PoC agent iterations
        max_poc_attempts: Max PoC generation attempts
        workspace_path: Path to workspace (for reading source code)
        fuzzer_code: Fuzzer source code (for verify agent context)
        vh_finding_done: Whether VH finding is already complete (True for delta mode)
        worker_id: Worker ID for FuzzerManager lookup

    Returns:
        Pipeline statistics
    """
    config = PipelineConfig(
        num_verify_agents=num_verify_agents,
        num_poc_agents=num_poc_agents,
        poc_min_score=poc_min_score,
        fuzzer_path=fuzzer_path,
        docker_image=docker_image,
        max_iterations=max_iterations,
        max_poc_attempts=max_poc_attempts,
    )

    pipeline = AgentPipeline(
        run_id=run_id,
        repos=repos,
        fuzzer=fuzzer,
        sanitizer=sanitizer,
        scan_mode=scan_mode,
        config=config,
        output_dir=output_dir,
        log_dir=log_dir,
        workspace_path=workspace_path,
        fuzzer_code=fuzzer_code,
        fuzzer_source=fuzzer_source,
        worker_id=worker_id,
    )

    # Set VH finding done flag so agents can exit when queue is empty
    pipeline._vh_finding_done = vh_finding_done

    return await pipeline.run()

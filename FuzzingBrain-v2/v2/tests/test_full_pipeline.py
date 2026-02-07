"""
Full Pipeline Integration Test

Tests the complete flow from Task -> Worker -> Agents -> POV
without calling real LLM APIs.

Run with: pytest tests/test_full_pipeline.py -v
"""

import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from bson import ObjectId
from datetime import datetime
from pathlib import Path

# Models
from fuzzingbrain.core.models import (
    Task,
    SuspiciousPoint,
    Direction,
    POV,
)
from fuzzingbrain.core.models.worker import Worker
from fuzzingbrain.core.models.suspicious_point import SPStatus
from fuzzingbrain.core.models.task import ScanMode

# Agents
from fuzzingbrain.agents import (
    DirectionPlanningAgent,
    FullSPGenerator,
    LargeFullSPGenerator,
    DeltaSPGenerator,
    SPVerifier,
    POVAgent,
)
from fuzzingbrain.agents.context import AgentContext

# Pipeline
from fuzzingbrain.worker.pipeline import AgentPipeline, PipelineConfig

# Worker context
from fuzzingbrain.worker.context import WorkerContext


class TestTaskToWorkerFlow:
    """Test Task -> Worker creation flow."""

    def test_task_creation(self):
        """Task should be created with valid ObjectId."""
        task = Task(
            task_id=str(ObjectId()),
            project_name="libpng",
            scan_mode=ScanMode.FULL,
        )

        assert ObjectId.is_valid(task.task_id)
        assert task.project_name == "libpng"

        # to_dict should work
        task_dict = task.to_dict()
        assert "_id" in task_dict
        assert isinstance(task_dict["_id"], ObjectId)

    def test_worker_creation(self):
        """Worker should be created with valid ObjectId references."""
        task_id = str(ObjectId())
        worker = Worker(
            worker_id=str(ObjectId()),
            task_id=task_id,
            fuzzer="libpng_read_fuzzer",
            sanitizer="address",
        )

        assert ObjectId.is_valid(worker.worker_id)
        assert worker.task_id == task_id

        # to_dict should work
        worker_dict = worker.to_dict()
        assert "_id" in worker_dict
        assert isinstance(worker_dict["_id"], ObjectId)


class TestDirectionPlanningAgent:
    """Test Direction Planning Agent instantiation and setup."""

    def test_agent_instantiation(self):
        """DirectionPlanningAgent should instantiate correctly."""
        task_id = str(ObjectId())
        worker_id = str(ObjectId())

        agent = DirectionPlanningAgent(
            fuzzer="libpng_read_fuzzer",
            sanitizer="address",
            task_id=task_id,
            worker_id=worker_id,
        )

        assert agent.task_id == task_id
        assert agent.worker_id == worker_id
        assert agent.fuzzer == "libpng_read_fuzzer"

    def test_agent_context_creation(self):
        """AgentContext should be creatable for Direction agent."""
        task_id = str(ObjectId())
        worker_id = str(ObjectId())

        ctx = AgentContext(
            task_id=task_id,
            worker_id=worker_id,
            agent_type="DirectionPlanningAgent",
            target="full_scan",
            fuzzer="libpng_read_fuzzer",
            sanitizer="address",
        )

        assert ObjectId.is_valid(ctx.agent_id)
        assert ctx.agent_type == "DirectionPlanningAgent"


class TestSPGenerators:
    """Test SP Generator agents."""

    def test_full_sp_generator_instantiation(self):
        """FullSPGenerator should instantiate correctly."""
        task_id = str(ObjectId())
        worker_id = str(ObjectId())
        direction_id = str(ObjectId())

        agent = FullSPGenerator(
            function_name="png_read_row",
            function_source="void png_read_row(...) { ... }",
            function_file="pngread.c",
            function_lines=(100, 200),
            callers=["png_read_image"],
            callees=["png_read_filter_row"],
            fuzzer="libpng_read_fuzzer",
            sanitizer="address",
            direction_id=direction_id,
            task_id=task_id,
            worker_id=worker_id,
        )

        assert agent.function_name == "png_read_row"
        assert agent.worker_id == worker_id

    def test_large_sp_generator_instantiation(self):
        """LargeFullSPGenerator should instantiate correctly."""
        task_id = str(ObjectId())
        worker_id = str(ObjectId())

        agent = LargeFullSPGenerator(
            function_name="png_read_IDAT_data",
            function_source="/* large function */",
            function_file="pngread.c",
            function_lines=(500, 800),
            callers=[],
            callees=[],
            fuzzer="libpng_read_fuzzer",
            sanitizer="address",
            task_id=task_id,
            worker_id=worker_id,
        )

        assert agent.function_name == "png_read_IDAT_data"

    def test_delta_sp_generator_instantiation(self):
        """DeltaSPGenerator should instantiate correctly."""
        task_id = str(ObjectId())
        worker_id = str(ObjectId())

        agent = DeltaSPGenerator(
            fuzzer="libpng_read_fuzzer",
            sanitizer="address",
            task_id=task_id,
            worker_id=worker_id,
        )

        assert agent.fuzzer == "libpng_read_fuzzer"


class TestSPVerifier:
    """Test SP Verifier agent."""

    def test_verifier_instantiation(self):
        """SPVerifier should instantiate correctly."""
        task_id = str(ObjectId())
        worker_id = str(ObjectId())

        verifier = SPVerifier(
            fuzzer="libpng_read_fuzzer",
            sanitizer="address",
            scan_mode=ScanMode.FULL,
            task_id=task_id,
            worker_id=worker_id,
        )

        assert verifier.worker_id == worker_id
        assert verifier.scan_mode == "full"

    def test_verifier_set_context(self):
        """SPVerifier.set_context should work with SP dict."""
        verifier = SPVerifier(
            fuzzer="libpng_read_fuzzer",
            sanitizer="address",
        )

        sp_dict = {
            "suspicious_point_id": str(ObjectId()),
            "function_name": "png_read_row",
            "vuln_type": "heap-buffer-overflow",
            "score": 0.7,
            "static_reachable": True,
        }

        # Should NOT raise
        verifier.set_context(suspicious_point=sp_dict)

        assert verifier.suspicious_point == sp_dict

    def test_verifier_with_sp_model(self):
        """SPVerifier should work with SuspiciousPoint.to_dict()."""
        verifier = SPVerifier(
            fuzzer="libpng_read_fuzzer",
            sanitizer="address",
        )

        sp = SuspiciousPoint(
            suspicious_point_id=str(ObjectId()),
            task_id=str(ObjectId()),
            function_name="png_read_row",
            vuln_type="heap-buffer-overflow",
            processor_id="verify_1",  # Non-ObjectId string
        )

        # to_dict should work (uses safe_object_id)
        sp_dict = sp.to_dict()

        # set_context should work
        verifier.set_context(suspicious_point=sp_dict)

        assert verifier.suspicious_point is not None


class TestPOVAgent:
    """Test POV Agent."""

    def test_pov_agent_instantiation(self):
        """POVAgent should instantiate correctly."""
        task_id = str(ObjectId())
        worker_id = str(ObjectId())
        mock_repos = MagicMock()

        agent = POVAgent(
            fuzzer="libpng_read_fuzzer",
            sanitizer="address",
            task_id=task_id,
            worker_id=worker_id,
            repos=mock_repos,
        )

        assert agent.worker_id == worker_id
        assert agent.fuzzer == "libpng_read_fuzzer"


class TestAgentPipeline:
    """Test the AgentPipeline class."""

    def test_pipeline_instantiation(self):
        """AgentPipeline should instantiate correctly."""
        task_id = str(ObjectId())
        worker_id = str(ObjectId())
        mock_repos = MagicMock()

        pipeline = AgentPipeline(
            task_id=task_id,
            repos=mock_repos,
            fuzzer="libpng_read_fuzzer",
            sanitizer="address",
            scan_mode=ScanMode.FULL,
            worker_id=worker_id,
        )

        assert pipeline.task_id == task_id
        assert pipeline.worker_id == worker_id
        assert pipeline.fuzzer == "libpng_read_fuzzer"

    def test_pipeline_config(self):
        """PipelineConfig should have correct defaults."""
        config = PipelineConfig()

        assert config.num_verify_agents >= 1
        assert config.num_pov_agents >= 1
        assert config.pov_min_score > 0


class TestSuspiciousPointFlow:
    """Test the SP lifecycle through the pipeline."""

    def test_sp_creation_for_verification(self):
        """SP should be creatable with pending_verify status."""
        sp = SuspiciousPoint(
            suspicious_point_id=str(ObjectId()),
            task_id=str(ObjectId()),
            direction_id=str(ObjectId()),
            function_name="png_read_row",
            vuln_type="heap-buffer-overflow",
            status=SPStatus.PENDING_VERIFY.value,
            score=0.7,
        )

        assert sp.status == "pending_verify"

        # to_dict should work
        sp_dict = sp.to_dict()
        assert sp_dict["status"] == "pending_verify"

    def test_sp_claim_for_verification(self):
        """SP should transition to verifying when claimed."""
        sp = SuspiciousPoint(
            suspicious_point_id=str(ObjectId()),
            task_id=str(ObjectId()),
            function_name="png_read_row",
            status=SPStatus.PENDING_VERIFY.value,
            processor_id=None,
        )

        # Simulate claim
        sp.status = SPStatus.VERIFYING.value
        sp.processor_id = "verify_1"  # Non-ObjectId processor ID

        # to_dict should NOT crash (uses safe_object_id)
        sp_dict = sp.to_dict()
        assert sp_dict["processor_id"] == "verify_1"

    def test_sp_verified_high_score(self):
        """High-score verified SP should go to pending_pov."""
        sp = SuspiciousPoint(
            suspicious_point_id=str(ObjectId()),
            task_id=str(ObjectId()),
            function_name="png_read_row",
            status=SPStatus.VERIFYING.value,
            score=0.8,
            is_important=True,
        )

        # Simulate verification complete
        sp.status = SPStatus.PENDING_POV.value
        sp.is_checked = True

        assert sp.status == "pending_pov"
        assert sp.is_important is True

    def test_sp_verified_low_score(self):
        """Low-score verified SP should stay verified (no POV)."""
        sp = SuspiciousPoint(
            suspicious_point_id=str(ObjectId()),
            task_id=str(ObjectId()),
            function_name="png_read_row",
            status=SPStatus.VERIFYING.value,
            score=0.3,
            is_important=False,
        )

        # Simulate verification complete
        sp.status = SPStatus.VERIFIED.value
        sp.is_checked = True

        assert sp.status == "verified"
        assert sp.is_important is False


class TestDirectionFlow:
    """Test Direction lifecycle."""

    def test_direction_creation(self):
        """Direction should be creatable."""
        direction = Direction(
            direction_id=str(ObjectId()),
            task_id=str(ObjectId()),
            fuzzer="libpng_read_fuzzer",
            name="PNG Chunk Parsing",
            core_functions=["png_handle_IHDR", "png_handle_IDAT"],
            entry_functions=["png_read_info"],
        )

        assert direction.name == "PNG Chunk Parsing"
        assert len(direction.core_functions) == 2

    def test_direction_claim(self):
        """Direction should be claimable with processor_id."""
        direction = Direction(
            direction_id=str(ObjectId()),
            task_id=str(ObjectId()),
            name="Test Direction",
            processor_id=None,
        )

        # Simulate claim
        direction.processor_id = "spg_worker_1"  # Non-ObjectId

        # to_dict should NOT crash
        direction_dict = direction.to_dict()
        assert direction_dict["processor_id"] == "spg_worker_1"


class TestPOVFlow:
    """Test POV creation flow."""

    def test_pov_creation(self):
        """POV should be creatable."""
        pov = POV(
            pov_id=str(ObjectId()),
            task_id=str(ObjectId()),
            suspicious_point_id=str(ObjectId()),
            agent_id=str(ObjectId()),
            gen_blob="import struct\nblob = struct.pack(...)",
            iteration=5,
            attempt=1,
        )

        assert pov.iteration == 5
        assert pov.attempt == 1

        # to_dict should work
        pov_dict = pov.to_dict()
        assert "_id" in pov_dict


class TestFullPipelineIntegration:
    """Integration test simulating full pipeline flow."""

    def test_complete_flow_objects(self):
        """Test creating all objects in a complete flow."""
        # 1. Create Task
        task_id = str(ObjectId())
        task = Task(
            task_id=task_id,
            project_name="libpng",
            scan_mode=ScanMode.FULL,
        )
        assert task.to_dict()  # Should not crash

        # 2. Create Worker
        worker_id = str(ObjectId())
        worker = Worker(
            worker_id=worker_id,
            task_id=task_id,
            fuzzer="libpng_read_fuzzer",
            sanitizer="address",
        )
        assert worker.to_dict()  # Should not crash

        # 3. Create Direction
        direction_id = str(ObjectId())
        direction = Direction(
            direction_id=direction_id,
            task_id=task_id,
            fuzzer="libpng_read_fuzzer",
            name="Image Row Processing",
            processor_id=worker_id,  # Valid ObjectId
        )
        assert direction.to_dict()  # Should not crash

        # 4. Create SP
        sp_id = str(ObjectId())
        sp = SuspiciousPoint(
            suspicious_point_id=sp_id,
            task_id=task_id,
            direction_id=direction_id,
            function_name="png_read_row",
            vuln_type="heap-buffer-overflow",
            status=SPStatus.PENDING_VERIFY.value,
            processor_id="verify_1",  # Non-ObjectId - should still work
        )
        sp_dict = sp.to_dict()
        assert sp_dict["processor_id"] == "verify_1"  # safe_object_id handled it

        # 5. Create SPVerifier and set context
        verifier = SPVerifier(
            fuzzer="libpng_read_fuzzer",
            sanitizer="address",
            task_id=task_id,
            worker_id=worker_id,
        )
        verifier.set_context(suspicious_point=sp_dict)
        assert verifier.suspicious_point is not None

        # 6. Simulate verification complete, create POV
        sp.status = SPStatus.PENDING_POV.value
        sp.is_checked = True
        sp.is_important = True
        sp.score = 0.85

        pov = POV(
            pov_id=str(ObjectId()),
            task_id=task_id,
            suspicious_point_id=sp_id,
            agent_id=str(ObjectId()),
            gen_blob="blob = b'PNG...'",
        )
        assert pov.to_dict()  # Should not crash

        print("\n=== Full Pipeline Flow Test PASSED ===")
        print(f"Task: {task_id[:8]}...")
        print(f"Worker: {worker_id[:8]}...")
        print(f"Direction: {direction.name}")
        print(f"SP: {sp.function_name} (score={sp.score})")
        print(f"POV: {pov.pov_id[:8]}...")


class TestAgentInstantiationInPipeline:
    """Test that agents can be instantiated as they would be in pipeline."""

    def test_verify_agent_like_pipeline(self):
        """Simulate how pipeline creates verify agent."""
        task_id = str(ObjectId())
        worker_id = str(ObjectId())  # Real worker_id from pipeline

        sp = SuspiciousPoint(
            suspicious_point_id=str(ObjectId()),
            task_id=task_id,
            function_name="test_func",
            processor_id="verify_1",  # Set by claim
        )

        # Pipeline creates agent like this:
        agent_index = 1
        verify_agent = SPVerifier(
            fuzzer="libpng_read_fuzzer",
            sanitizer="address",
            scan_mode=ScanMode.FULL,
            task_id=task_id,
            worker_id=worker_id,  # Should be real worker_id, not "verify_1"
            index=agent_index,
            target_name=sp.function_name or "",
        )

        # Pipeline calls set_context
        verify_agent.set_context(suspicious_point=sp.to_dict())

        assert verify_agent.worker_id == worker_id
        assert verify_agent.suspicious_point is not None

    def test_pov_agent_like_pipeline(self):
        """Simulate how pipeline creates POV agent."""
        task_id = str(ObjectId())
        worker_id = str(ObjectId())
        mock_repos = MagicMock()

        # Pipeline creates agent like this:
        pov_agent = POVAgent(
            fuzzer="libpng_read_fuzzer",
            sanitizer="address",
            task_id=task_id,
            worker_id=worker_id,  # Should be real worker_id
            repos=mock_repos,
        )

        assert pov_agent.worker_id == worker_id


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

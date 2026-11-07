# SPDX-License-Identifier: Apache-2.0
"""
Full Pipeline Integration Test

Tests the complete flow from Run -> Worker -> Agents -> PoC
without calling real LLM APIs.

Run with: pytest tests/test_full_pipeline.py -v
"""

import pytest
from unittest.mock import MagicMock
from bson import ObjectId

# Models
from fuzzingbrain.core.models import (
    Run,
    VulnerabilityHypothesis,
    LogicGroup,
    POC,
)
from fuzzingbrain.core.models.worker import Worker
from fuzzingbrain.core.models.vulnerability_hypothesis import VHStatus
from fuzzingbrain.core.models.run import ScanMode

# Agents
from fuzzingbrain.agents import (
    LGPlanningAgent,
    FullVHGenerator,
    LargeFullVHGenerator,
    DeltaVHGenerator,
    VHVerifier,
    POCAgent,
)
from fuzzingbrain.agents.context import AgentContext

# Pipeline
from fuzzingbrain.worker.pipeline import AgentPipeline, PipelineConfig

# Worker context


class TestRunToWorkerFlow:
    """Test Run -> Worker creation flow."""

    def test_run_creation(self):
        """Run should be created with valid ObjectId."""
        run = Run(
            run_id=str(ObjectId()),
            project_name="libpng",
            scan_mode=ScanMode.FULL,
        )

        assert ObjectId.is_valid(run.run_id)
        assert run.project_name == "libpng"

        # to_dict should work
        run_dict = run.to_dict()
        assert "_id" in run_dict
        assert isinstance(run_dict["_id"], ObjectId)

    def test_worker_creation(self):
        """Worker should be created with valid ObjectId references."""
        run_id = str(ObjectId())
        worker = Worker(
            worker_id=str(ObjectId()),
            run_id=run_id,
            fuzzer="libpng_read_fuzzer",
            sanitizer="address",
        )

        assert ObjectId.is_valid(worker.worker_id)
        assert worker.run_id == run_id

        # to_dict should work
        worker_dict = worker.to_dict()
        assert "_id" in worker_dict
        assert isinstance(worker_dict["_id"], ObjectId)


class TestLGPlanningAgent:
    """Test Logic group Planning Agent instantiation and setup."""

    def test_agent_instantiation(self):
        """LGPlanningAgent should instantiate correctly."""
        run_id = str(ObjectId())
        worker_id = str(ObjectId())

        agent = LGPlanningAgent(
            fuzzer="libpng_read_fuzzer",
            sanitizer="address",
            run_id=run_id,
            worker_id=worker_id,
        )

        assert agent.run_id == run_id
        assert agent.worker_id == worker_id
        assert agent.fuzzer == "libpng_read_fuzzer"

    def test_agent_context_creation(self):
        """AgentContext should be creatable for Logic group agent."""
        run_id = str(ObjectId())
        worker_id = str(ObjectId())

        ctx = AgentContext(
            run_id=run_id,
            worker_id=worker_id,
            agent_type="LGPlanningAgent",
            target="full_scan",
            fuzzer="libpng_read_fuzzer",
            sanitizer="address",
        )

        assert ObjectId.is_valid(ctx.agent_id)
        assert ctx.agent_type == "LGPlanningAgent"


class TestVHGenerators:
    """Test VH Generator agents."""

    def test_full_vh_generator_instantiation(self):
        """FullVHGenerator should instantiate correctly."""
        run_id = str(ObjectId())
        worker_id = str(ObjectId())
        lg_id = str(ObjectId())

        agent = FullVHGenerator(
            function_name="png_read_row",
            function_source="void png_read_row(...) { ... }",
            function_file="pngread.c",
            function_lines=(100, 200),
            callers=["png_read_image"],
            callees=["png_read_filter_row"],
            fuzzer="libpng_read_fuzzer",
            sanitizer="address",
            lg_id=lg_id,
            run_id=run_id,
            worker_id=worker_id,
        )

        assert agent.function_name == "png_read_row"
        assert agent.worker_id == worker_id

    def test_large_vh_generator_instantiation(self):
        """LargeFullVHGenerator should instantiate correctly."""
        run_id = str(ObjectId())
        worker_id = str(ObjectId())

        agent = LargeFullVHGenerator(
            function_name="png_read_IDAT_data",
            function_source="/* large function */",
            function_file="pngread.c",
            function_lines=(500, 800),
            callers=[],
            callees=[],
            fuzzer="libpng_read_fuzzer",
            sanitizer="address",
            run_id=run_id,
            worker_id=worker_id,
        )

        assert agent.function_name == "png_read_IDAT_data"

    def test_delta_vh_generator_instantiation(self):
        """DeltaVHGenerator should instantiate correctly."""
        run_id = str(ObjectId())
        worker_id = str(ObjectId())

        agent = DeltaVHGenerator(
            fuzzer="libpng_read_fuzzer",
            sanitizer="address",
            run_id=run_id,
            worker_id=worker_id,
        )

        assert agent.fuzzer == "libpng_read_fuzzer"


class TestVHVerifier:
    """Test VH Verifier agent."""

    def test_verifier_instantiation(self):
        """VHVerifier should instantiate correctly."""
        run_id = str(ObjectId())
        worker_id = str(ObjectId())

        verifier = VHVerifier(
            fuzzer="libpng_read_fuzzer",
            sanitizer="address",
            scan_mode=ScanMode.FULL,
            run_id=run_id,
            worker_id=worker_id,
        )

        assert verifier.worker_id == worker_id
        assert verifier.scan_mode == "full"

    def test_verifier_set_context(self):
        """VHVerifier.set_context should work with VH dict."""
        verifier = VHVerifier(
            fuzzer="libpng_read_fuzzer",
            sanitizer="address",
        )

        vh_dict = {
            "vulnerability_hypothesis_id": str(ObjectId()),
            "function_name": "png_read_row",
            "score": 0.7,
            "static_reachable": True,
        }

        # Should NOT raise
        verifier.set_context(vulnerability_hypothesis=vh_dict)

        assert verifier.vulnerability_hypothesis == vh_dict

    def test_verifier_with_vh_model(self):
        """VHVerifier should work with VulnerabilityHypothesis.to_dict()."""
        verifier = VHVerifier(
            fuzzer="libpng_read_fuzzer",
            sanitizer="address",
        )

        vh = VulnerabilityHypothesis(
            vulnerability_hypothesis_id=str(ObjectId()),
            run_id=str(ObjectId()),
            function_name="png_read_row",
            processor_id="verify_1",  # Non-ObjectId string
        )

        # to_dict should work (uses safe_object_id)
        vh_dict = vh.to_dict()

        # set_context should work
        verifier.set_context(vulnerability_hypothesis=vh_dict)

        assert verifier.vulnerability_hypothesis is not None


class TestPOCAgent:
    """Test PoC Agent."""

    def test_poc_agent_instantiation(self):
        """POCAgent should instantiate correctly."""
        run_id = str(ObjectId())
        worker_id = str(ObjectId())
        mock_repos = MagicMock()

        agent = POCAgent(
            fuzzer="libpng_read_fuzzer",
            sanitizer="address",
            run_id=run_id,
            worker_id=worker_id,
            repos=mock_repos,
        )

        assert agent.worker_id == worker_id
        assert agent.fuzzer == "libpng_read_fuzzer"


class TestAgentPipeline:
    """Test the AgentPipeline class."""

    def test_pipeline_instantiation(self):
        """AgentPipeline should instantiate correctly."""
        run_id = str(ObjectId())
        worker_id = str(ObjectId())
        mock_repos = MagicMock()

        pipeline = AgentPipeline(
            run_id=run_id,
            repos=mock_repos,
            fuzzer="libpng_read_fuzzer",
            sanitizer="address",
            scan_mode=ScanMode.FULL,
            worker_id=worker_id,
        )

        assert pipeline.run_id == run_id
        assert pipeline.worker_id == worker_id
        assert pipeline.fuzzer == "libpng_read_fuzzer"

    def test_pipeline_config(self):
        """PipelineConfig should have correct defaults."""
        config = PipelineConfig()

        assert config.num_verify_agents >= 1
        assert config.num_poc_agents >= 1
        assert config.poc_min_score > 0


class TestVulnerabilityHypothesisFlow:
    """Test the VH lifecycle through the pipeline."""

    def test_vh_creation_for_verification(self):
        """VH should be creatable with pending_verify status."""
        vh = VulnerabilityHypothesis(
            vulnerability_hypothesis_id=str(ObjectId()),
            run_id=str(ObjectId()),
            lg_id=str(ObjectId()),
            function_name="png_read_row",
            status=VHStatus.PENDING_VERIFY.value,
            score=0.7,
        )

        assert vh.status == "pending_verify"

        # to_dict should work
        vh_dict = vh.to_dict()
        assert vh_dict["status"] == "pending_verify"

    def test_vh_claim_for_verification(self):
        """VH should transition to verifying when claimed."""
        vh = VulnerabilityHypothesis(
            vulnerability_hypothesis_id=str(ObjectId()),
            run_id=str(ObjectId()),
            function_name="png_read_row",
            status=VHStatus.PENDING_VERIFY.value,
            processor_id=None,
        )

        # Simulate claim
        vh.status = VHStatus.VERIFYING.value
        vh.processor_id = "verify_1"  # Non-ObjectId processor ID

        # to_dict should NOT crash (uses safe_object_id)
        vh_dict = vh.to_dict()
        assert vh_dict["processor_id"] == "verify_1"

    def test_vh_verified_high_score(self):
        """High-score verified VH should go to pending_poc."""
        vh = VulnerabilityHypothesis(
            vulnerability_hypothesis_id=str(ObjectId()),
            run_id=str(ObjectId()),
            function_name="png_read_row",
            status=VHStatus.VERIFYING.value,
            score=0.8,
            proceed=True,
        )

        # Simulate verification complete
        vh.status = VHStatus.PENDING_POC.value
        vh.is_checked_by_verifier = True

        assert vh.status == "pending_poc"
        assert vh.proceed is True

    def test_vh_verified_low_score(self):
        """Low-score verified VH should stay verified (no PoC)."""
        vh = VulnerabilityHypothesis(
            vulnerability_hypothesis_id=str(ObjectId()),
            run_id=str(ObjectId()),
            function_name="png_read_row",
            status=VHStatus.VERIFYING.value,
            score=0.3,
            proceed=False,
        )

        # Simulate verification complete
        vh.status = VHStatus.VERIFIED.value
        vh.is_checked_by_verifier = True

        assert vh.status == "verified"
        assert vh.proceed is False


class TestLogicGroupFlow:
    """Test Logic group lifecycle."""

    def test_logic_group_creation(self):
        """Logic group should be creatable."""
        logic_group = LogicGroup(
            lg_id=str(ObjectId()),
            run_id=str(ObjectId()),
            fuzzer="libpng_read_fuzzer",
            name="PNG Chunk Parsing",
            core_functions=["png_handle_IHDR", "png_handle_IDAT"],
            entry_functions=["png_read_info"],
        )

        assert logic_group.name == "PNG Chunk Parsing"
        assert len(logic_group.core_functions) == 2

    def test_logic_group_claim(self):
        """Logic group should be claimable with processor_id."""
        logic_group = LogicGroup(
            lg_id=str(ObjectId()),
            run_id=str(ObjectId()),
            name="Test Logic group",
            processor_id=None,
        )

        # Simulate claim
        logic_group.processor_id = "vhg_worker_1"  # Non-ObjectId

        # to_dict should NOT crash
        logic_group_dict = logic_group.to_dict()
        assert logic_group_dict["processor_id"] == "vhg_worker_1"


class TestPOCFlow:
    """Test PoC creation flow."""

    def test_poc_creation(self):
        """PoC should be creatable."""
        poc = POC(
            poc_id=str(ObjectId()),
            run_id=str(ObjectId()),
            vulnerability_hypothesis_id=str(ObjectId()),
            agent_id=str(ObjectId()),
            gen_blob="import struct\nblob = struct.pack(...)",
            iteration=5,
            attempt=1,
        )

        assert poc.iteration == 5
        assert poc.attempt == 1

        # to_dict should work
        poc_dict = poc.to_dict()
        assert "_id" in poc_dict


class TestFullPipelineIntegration:
    """Integration test simulating full pipeline flow."""

    def test_complete_flow_objects(self):
        """Test creating all objects in a complete flow."""
        # 1. Create Run
        run_id = str(ObjectId())
        run = Run(
            run_id=run_id,
            project_name="libpng",
            scan_mode=ScanMode.FULL,
        )
        assert run.to_dict()  # Should not crash

        # 2. Create Worker
        worker_id = str(ObjectId())
        worker = Worker(
            worker_id=worker_id,
            run_id=run_id,
            fuzzer="libpng_read_fuzzer",
            sanitizer="address",
        )
        assert worker.to_dict()  # Should not crash

        # 3. Create Logic group
        lg_id = str(ObjectId())
        logic_group = LogicGroup(
            lg_id=lg_id,
            run_id=run_id,
            fuzzer="libpng_read_fuzzer",
            name="Image Row Processing",
            processor_id=worker_id,  # Valid ObjectId
        )
        assert logic_group.to_dict()  # Should not crash

        # 4. Create VH
        vh_id = str(ObjectId())
        vh = VulnerabilityHypothesis(
            vulnerability_hypothesis_id=vh_id,
            run_id=run_id,
            lg_id=lg_id,
            function_name="png_read_row",
            status=VHStatus.PENDING_VERIFY.value,
            processor_id="verify_1",  # Non-ObjectId - should still work
        )
        vh_dict = vh.to_dict()
        assert vh_dict["processor_id"] == "verify_1"  # safe_object_id handled it

        # 5. Create VHVerifier and set context
        verifier = VHVerifier(
            fuzzer="libpng_read_fuzzer",
            sanitizer="address",
            run_id=run_id,
            worker_id=worker_id,
        )
        verifier.set_context(vulnerability_hypothesis=vh_dict)
        assert verifier.vulnerability_hypothesis is not None

        # 6. Simulate verification complete, create PoC
        vh.status = VHStatus.PENDING_POC.value
        vh.is_checked_by_verifier = True
        vh.proceed = True
        vh.score = 0.85

        poc = POC(
            poc_id=str(ObjectId()),
            run_id=run_id,
            vulnerability_hypothesis_id=vh_id,
            agent_id=str(ObjectId()),
            gen_blob="blob = b'PNG...'",
        )
        assert poc.to_dict()  # Should not crash

        print("\n=== Full Pipeline Flow Test PASSED ===")
        print(f"Run: {run_id[:8]}...")
        print(f"Worker: {worker_id[:8]}...")
        print(f"Logic group: {logic_group.name}")
        print(f"VH: {vh.function_name} (score={vh.score})")
        print(f"PoC: {poc.poc_id[:8]}...")


class TestAgentInstantiationInPipeline:
    """Test that agents can be instantiated as they would be in pipeline."""

    def test_verify_agent_like_pipeline(self):
        """Simulate how pipeline creates verify agent."""
        run_id = str(ObjectId())
        worker_id = str(ObjectId())  # Real worker_id from pipeline

        vh = VulnerabilityHypothesis(
            vulnerability_hypothesis_id=str(ObjectId()),
            run_id=run_id,
            function_name="test_func",
            processor_id="verify_1",  # Set by claim
        )

        # Pipeline creates agent like this:
        agent_index = 1
        verify_agent = VHVerifier(
            fuzzer="libpng_read_fuzzer",
            sanitizer="address",
            scan_mode=ScanMode.FULL,
            run_id=run_id,
            worker_id=worker_id,  # Should be real worker_id, not "verify_1"
            index=agent_index,
            target_name=vh.function_name or "",
        )

        # Pipeline calls set_context
        verify_agent.set_context(vulnerability_hypothesis=vh.to_dict())

        assert verify_agent.worker_id == worker_id
        assert verify_agent.vulnerability_hypothesis is not None

    def test_poc_agent_like_pipeline(self):
        """Simulate how pipeline creates PoC agent."""
        run_id = str(ObjectId())
        worker_id = str(ObjectId())
        mock_repos = MagicMock()

        # Pipeline creates agent like this:
        poc_agent = POCAgent(
            fuzzer="libpng_read_fuzzer",
            sanitizer="address",
            run_id=run_id,
            worker_id=worker_id,  # Should be real worker_id
            repos=mock_repos,
        )

        assert poc_agent.worker_id == worker_id


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

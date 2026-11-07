# SPDX-License-Identifier: Apache-2.0
"""
Unit tests for FuzzingBrain pipeline and agents.

Tests agent instantiation, context creation, and ObjectId handling.
Run with: pytest tests/test_pipeline.py -v
"""

import pytest
from unittest.mock import MagicMock
from bson import ObjectId

from fuzzingbrain.agents import VHVerifier, POCAgent
from fuzzingbrain.agents.context import AgentContext
from fuzzingbrain.core.models import VulnerabilityHypothesis


class TestAgentContext:
    """Tests for AgentContext."""

    def test_context_creation_with_valid_ids(self):
        """Context should be created with valid ObjectIds."""
        run_id = str(ObjectId())
        worker_id = str(ObjectId())

        ctx = AgentContext(
            run_id=run_id,
            worker_id=worker_id,
            agent_type="VHVerifier",
        )

        assert ctx.run_id == run_id
        assert ctx.worker_id == worker_id
        assert ctx.agent_type == "VHVerifier"
        # agent_id should be auto-generated ObjectId
        assert ObjectId.is_valid(ctx.agent_id)

    def test_context_to_dict(self):
        """to_dict should produce valid dictionary."""
        ctx = AgentContext(
            run_id=str(ObjectId()),
            worker_id=str(ObjectId()),
            agent_type="VHVerifier",
        )

        result = ctx.to_dict()
        assert "agent_id" in result
        assert "run_id" in result
        assert "worker_id" in result
        assert "agent_type" in result


class TestVHVerifier:
    """Tests for VHVerifier agent."""

    def test_instantiation_with_valid_worker_id(self):
        """VHVerifier should accept valid ObjectId worker_id."""
        worker_id = str(ObjectId())
        run_id = str(ObjectId())

        verifier = VHVerifier(
            fuzzer="test_fuzzer",
            sanitizer="address",
            run_id=run_id,
            worker_id=worker_id,
        )

        assert verifier.worker_id == worker_id
        assert verifier.run_id == run_id

    def test_set_context_method_exists(self):
        """VHVerifier should have set_context method (not set_verify_context)."""
        verifier = VHVerifier(
            fuzzer="test_fuzzer",
            sanitizer="address",
        )

        # Should have set_context, not set_verify_context
        assert hasattr(verifier, "set_context")
        assert not hasattr(verifier, "set_verify_context")

    def test_set_context_with_vulnerability_hypothesis(self):
        """set_context should accept vulnerability_hypothesis dict."""
        verifier = VHVerifier(
            fuzzer="test_fuzzer",
            sanitizer="address",
        )

        vh_dict = {
            "vulnerability_hypothesis_id": str(ObjectId()),
            "function_name": "test_func",
        }

        # Should not raise
        verifier.set_context(vulnerability_hypothesis=vh_dict)
        assert verifier.vulnerability_hypothesis == vh_dict


class TestPOCAgent:
    """Tests for POCAgent."""

    def test_instantiation_with_valid_worker_id(self):
        """POCAgent should accept valid ObjectId worker_id."""
        worker_id = str(ObjectId())
        run_id = str(ObjectId())

        # Mock repos to avoid database dependency
        mock_repos = MagicMock()

        agent = POCAgent(
            fuzzer="test_fuzzer",
            sanitizer="address",
            run_id=run_id,
            worker_id=worker_id,
            repos=mock_repos,
        )

        assert agent.worker_id == worker_id
        assert agent.run_id == run_id


class TestVulnerabilityHypothesisToDict:
    """Tests for VulnerabilityHypothesis.to_dict with various processor_id values."""

    def test_with_objectid_processor(self):
        """Should handle valid ObjectId processor_id."""
        vh = VulnerabilityHypothesis(
            vulnerability_hypothesis_id=str(ObjectId()),
            run_id=str(ObjectId()),
            function_name="test_func",
            processor_id=str(ObjectId()),
        )

        # Should not raise
        result = vh.to_dict()
        assert isinstance(result["processor_id"], ObjectId)

    def test_with_string_processor(self):
        """Should handle non-ObjectId processor_id like 'verify_1'."""
        vh = VulnerabilityHypothesis(
            vulnerability_hypothesis_id=str(ObjectId()),
            run_id=str(ObjectId()),
            function_name="test_func",
            processor_id="verify_1",
        )

        # Should not raise - safe_object_id handles it
        result = vh.to_dict()
        assert result["processor_id"] == "verify_1"

    def test_with_none_processor(self):
        """Should handle None processor_id."""
        vh = VulnerabilityHypothesis(
            vulnerability_hypothesis_id=str(ObjectId()),
            run_id=str(ObjectId()),
            function_name="test_func",
            processor_id=None,
        )

        result = vh.to_dict()
        assert result["processor_id"] is None


class TestAgentImports:
    """Tests for agent imports - ensure deprecated aliases are removed."""

    def test_no_deprecated_aliases(self):
        """Deprecated agent aliases should not be importable."""
        from fuzzingbrain import agents

        # These should NOT exist
        assert not hasattr(agents, "FunctionAnalysisAgent")
        assert not hasattr(agents, "LargeFunctionAnalysisAgent")
        assert not hasattr(agents, "VulnerabilityHypothesisAgent")

        # These SHOULD exist
        assert hasattr(agents, "FullVHGenerator")
        assert hasattr(agents, "LargeFullVHGenerator")
        assert hasattr(agents, "DeltaVHGenerator")
        assert hasattr(agents, "VHVerifier")
        assert hasattr(agents, "POCAgent")
        assert hasattr(agents, "LGPlanningAgent")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

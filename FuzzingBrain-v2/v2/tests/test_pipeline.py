"""
Unit tests for FuzzingBrain pipeline and agents.

Tests agent instantiation, context creation, and ObjectId handling.
Run with: pytest tests/test_pipeline.py -v
"""

import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from bson import ObjectId
from pathlib import Path

from fuzzingbrain.agents import SPVerifier, POVAgent
from fuzzingbrain.agents.context import AgentContext
from fuzzingbrain.core.models import SuspiciousPoint


class TestAgentContext:
    """Tests for AgentContext."""

    def test_context_creation_with_valid_ids(self):
        """Context should be created with valid ObjectIds."""
        task_id = str(ObjectId())
        worker_id = str(ObjectId())

        ctx = AgentContext(
            task_id=task_id,
            worker_id=worker_id,
            agent_type="SPVerifier",
        )

        assert ctx.task_id == task_id
        assert ctx.worker_id == worker_id
        assert ctx.agent_type == "SPVerifier"
        # agent_id should be auto-generated ObjectId
        assert ObjectId.is_valid(ctx.agent_id)

    def test_context_to_dict(self):
        """to_dict should produce valid dictionary."""
        ctx = AgentContext(
            task_id=str(ObjectId()),
            worker_id=str(ObjectId()),
            agent_type="SPVerifier",
        )

        result = ctx.to_dict()
        assert "agent_id" in result
        assert "task_id" in result
        assert "worker_id" in result
        assert "agent_type" in result


class TestSPVerifier:
    """Tests for SPVerifier agent."""

    def test_instantiation_with_valid_worker_id(self):
        """SPVerifier should accept valid ObjectId worker_id."""
        worker_id = str(ObjectId())
        task_id = str(ObjectId())

        verifier = SPVerifier(
            fuzzer="test_fuzzer",
            sanitizer="address",
            task_id=task_id,
            worker_id=worker_id,
        )

        assert verifier.worker_id == worker_id
        assert verifier.task_id == task_id

    def test_set_context_method_exists(self):
        """SPVerifier should have set_context method (not set_verify_context)."""
        verifier = SPVerifier(
            fuzzer="test_fuzzer",
            sanitizer="address",
        )

        # Should have set_context, not set_verify_context
        assert hasattr(verifier, "set_context")
        assert not hasattr(verifier, "set_verify_context")

    def test_set_context_with_suspicious_point(self):
        """set_context should accept suspicious_point dict."""
        verifier = SPVerifier(
            fuzzer="test_fuzzer",
            sanitizer="address",
        )

        sp_dict = {
            "suspicious_point_id": str(ObjectId()),
            "function_name": "test_func",
            "vuln_type": "buffer_overflow",
        }

        # Should not raise
        verifier.set_context(suspicious_point=sp_dict)
        assert verifier.suspicious_point == sp_dict


class TestPOVAgent:
    """Tests for POVAgent."""

    def test_instantiation_with_valid_worker_id(self):
        """POVAgent should accept valid ObjectId worker_id."""
        worker_id = str(ObjectId())
        task_id = str(ObjectId())

        # Mock repos to avoid database dependency
        mock_repos = MagicMock()

        agent = POVAgent(
            fuzzer="test_fuzzer",
            sanitizer="address",
            task_id=task_id,
            worker_id=worker_id,
            repos=mock_repos,
        )

        assert agent.worker_id == worker_id
        assert agent.task_id == task_id


class TestSuspiciousPointToDict:
    """Tests for SuspiciousPoint.to_dict with various processor_id values."""

    def test_with_objectid_processor(self):
        """Should handle valid ObjectId processor_id."""
        sp = SuspiciousPoint(
            suspicious_point_id=str(ObjectId()),
            task_id=str(ObjectId()),
            function_name="test_func",
            processor_id=str(ObjectId()),
        )

        # Should not raise
        result = sp.to_dict()
        assert isinstance(result["processor_id"], ObjectId)

    def test_with_string_processor(self):
        """Should handle non-ObjectId processor_id like 'verify_1'."""
        sp = SuspiciousPoint(
            suspicious_point_id=str(ObjectId()),
            task_id=str(ObjectId()),
            function_name="test_func",
            processor_id="verify_1",
        )

        # Should not raise - safe_object_id handles it
        result = sp.to_dict()
        assert result["processor_id"] == "verify_1"

    def test_with_none_processor(self):
        """Should handle None processor_id."""
        sp = SuspiciousPoint(
            suspicious_point_id=str(ObjectId()),
            task_id=str(ObjectId()),
            function_name="test_func",
            processor_id=None,
        )

        result = sp.to_dict()
        assert result["processor_id"] is None


class TestAgentImports:
    """Tests for agent imports - ensure deprecated aliases are removed."""

    def test_no_deprecated_aliases(self):
        """Deprecated agent aliases should not be importable."""
        from fuzzingbrain import agents

        # These should NOT exist
        assert not hasattr(agents, "FunctionAnalysisAgent")
        assert not hasattr(agents, "LargeFunctionAnalysisAgent")
        assert not hasattr(agents, "SuspiciousPointAgent")

        # These SHOULD exist
        assert hasattr(agents, "FullSPGenerator")
        assert hasattr(agents, "LargeFullSPGenerator")
        assert hasattr(agents, "DeltaSPGenerator")
        assert hasattr(agents, "SPVerifier")
        assert hasattr(agents, "POVAgent")
        assert hasattr(agents, "DirectionPlanningAgent")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

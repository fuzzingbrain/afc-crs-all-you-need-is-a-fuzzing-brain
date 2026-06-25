"""
Unit tests for FuzzingBrain models.

Tests ObjectId handling, to_dict/from_dict conversions, and safe_object_id.
Run with: pytest tests/test_models.py -v
"""

import pytest
from bson import ObjectId
from datetime import datetime

from fuzzingbrain.core.utils import safe_object_id
from fuzzingbrain.core.models import (
    SuspiciousPoint,
    Direction,
    Task,
    Fuzzer,
    POV,
    Patch,
    LLMCall,
    Function,
    CallGraphNode,
)
from fuzzingbrain.core.models.worker import Worker


class TestSafeObjectId:
    """Tests for safe_object_id utility function."""

    def test_valid_objectid_string(self):
        """Valid 24-char hex string should return ObjectId."""
        oid_str = "507f1f77bcf86cd799439011"
        result = safe_object_id(oid_str)
        assert isinstance(result, ObjectId)
        assert str(result) == oid_str

    def test_invalid_objectid_string(self):
        """Invalid string should return as-is (not raise)."""
        invalid = "verify_1"
        result = safe_object_id(invalid)
        assert result == "verify_1"
        assert isinstance(result, str)

    def test_custom_agent_id(self):
        """Custom agent IDs like 'Func_0_fuzzer_address' should return as-is."""
        custom_id = "Func_0_libpng_read_fuzzer_address"
        result = safe_object_id(custom_id)
        assert result == custom_id
        assert isinstance(result, str)

    def test_objectid_object(self):
        """ObjectId object should be returned as-is."""
        oid = ObjectId()
        result = safe_object_id(str(oid))
        assert isinstance(result, ObjectId)

    def test_empty_string(self):
        """Empty string should return None (falsy value)."""
        result = safe_object_id("")
        assert result is None  # safe_object_id returns None for falsy input


class TestSuspiciousPointModel:
    """Tests for SuspiciousPoint model."""

    def test_to_dict_with_valid_objectids(self):
        """to_dict should work with valid ObjectIds."""
        sp = SuspiciousPoint(
            suspicious_point_id=str(ObjectId()),
            task_id=str(ObjectId()),
            direction_id=str(ObjectId()),
            function_name="test_func",
            processor_id=str(ObjectId()),  # Valid ObjectId
        )
        result = sp.to_dict()
        assert "_id" in result
        assert isinstance(result["_id"], ObjectId)
        assert isinstance(result["processor_id"], ObjectId)

    def test_to_dict_with_custom_processor_id(self):
        """to_dict should handle non-ObjectId processor_id (e.g., 'verify_1')."""
        sp = SuspiciousPoint(
            suspicious_point_id=str(ObjectId()),
            task_id=str(ObjectId()),
            function_name="test_func",
            processor_id="verify_1",  # NOT a valid ObjectId
        )
        # Should NOT raise - safe_object_id handles it
        result = sp.to_dict()
        assert result["processor_id"] == "verify_1"

    def test_from_dict_round_trip(self):
        """from_dict should correctly parse to_dict output."""
        original = SuspiciousPoint(
            suspicious_point_id=str(ObjectId()),
            task_id=str(ObjectId()),
            function_name="test_func",
            vuln_type="buffer_overflow",
            score=0.8,
        )
        dict_form = original.to_dict()
        restored = SuspiciousPoint.from_dict(dict_form)
        assert restored.function_name == original.function_name
        assert restored.vuln_type == original.vuln_type
        assert restored.score == original.score


class TestDirectionModel:
    """Tests for Direction model."""

    def test_to_dict_with_valid_objectids(self):
        """to_dict should work with valid ObjectIds."""
        direction = Direction(
            direction_id=str(ObjectId()),
            task_id=str(ObjectId()),
            name="Test Direction",
            processor_id=str(ObjectId()),
        )
        result = direction.to_dict()
        assert "_id" in result
        assert isinstance(result["processor_id"], ObjectId)

    def test_to_dict_with_custom_processor_id(self):
        """to_dict should handle non-ObjectId processor_id."""
        direction = Direction(
            direction_id=str(ObjectId()),
            task_id=str(ObjectId()),
            name="Test Direction",
            processor_id="spg_agent_1",  # NOT a valid ObjectId
        )
        result = direction.to_dict()
        assert result["processor_id"] == "spg_agent_1"

    def test_from_dict_round_trip(self):
        """from_dict should correctly parse to_dict output."""
        original = Direction(
            direction_id=str(ObjectId()),
            task_id=str(ObjectId()),
            name="Test Direction",
            risk_reason="Test risk reason",
        )
        dict_form = original.to_dict()
        restored = Direction.from_dict(dict_form)
        assert restored.name == original.name
        assert restored.risk_reason == original.risk_reason


class TestWorkerModel:
    """Tests for Worker model."""

    def test_to_dict_basic(self):
        """to_dict should produce valid MongoDB document."""
        worker = Worker(
            worker_id=str(ObjectId()),
            task_id=str(ObjectId()),
            fuzzer="test_fuzzer",
            sanitizer="address",
        )
        result = worker.to_dict()
        assert "_id" in result
        assert isinstance(result["_id"], ObjectId)
        assert result["fuzzer"] == "test_fuzzer"


class TestTaskModel:
    """Tests for Task model."""

    def test_to_dict_basic(self):
        """to_dict should produce valid MongoDB document."""
        task = Task(
            task_id=str(ObjectId()),
            project_name="test_project",
        )
        result = task.to_dict()
        assert "_id" in result
        assert isinstance(result["_id"], ObjectId)


class TestFuzzerModel:
    """Tests for Fuzzer model."""

    def test_to_dict_with_uuid_fuzzer_id(self):
        """Fuzzer with UUID-style ID should use safe_object_id."""
        fuzzer = Fuzzer(
            fuzzer_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",  # UUID format
            task_id=str(ObjectId()),
            fuzzer_name="test_fuzzer",
        )
        result = fuzzer.to_dict()
        # Should not raise, _id should be string (not ObjectId) for UUID
        assert "_id" in result


class TestCallGraphNodeModel:
    """Tests for CallGraphNode model."""

    def test_to_dict_with_fuzzer_name_as_id(self):
        """CallGraphNode with fuzzer name as fuzzer_id should work."""
        node = CallGraphNode(
            task_id=str(ObjectId()),
            fuzzer_id="libpng_read_fuzzer",  # Fuzzer name, not ObjectId
            fuzzer_name="libpng_read_fuzzer",
            function_name="test_func",
        )
        result = node.to_dict()
        # safe_object_id should handle fuzzer name
        assert result["fuzzer_id"] == "libpng_read_fuzzer"


class TestPOVModel:
    """Tests for POV model."""

    def test_to_dict_basic(self):
        """to_dict should produce valid MongoDB document."""
        pov = POV(
            pov_id=str(ObjectId()),
            task_id=str(ObjectId()),
            suspicious_point_id=str(ObjectId()),
            gen_blob="test code",  # Correct field name
        )
        result = pov.to_dict()
        assert "_id" in result
        assert isinstance(result["_id"], ObjectId)


class TestLLMCallModel:
    """Tests for LLMCall model."""

    def test_to_dict_basic(self):
        """to_dict should produce valid MongoDB document."""
        call = LLMCall(
            call_id=str(ObjectId()),
            agent_id=str(ObjectId()),
            worker_id=str(ObjectId()),
            task_id=str(ObjectId()),
            model="claude-3-sonnet",
            input_tokens=100,
            output_tokens=50,
            cost=0.01,
        )
        result = call.to_dict()
        assert "_id" in result
        assert isinstance(result["_id"], ObjectId)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

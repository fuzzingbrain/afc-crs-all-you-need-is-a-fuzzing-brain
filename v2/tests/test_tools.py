"""
Unit tests for MCP Tools.

Tests all tool functions and their parameter validation.
Mocks the AnalysisClient to avoid real database calls.

Run with: pytest tests/test_tools.py -v
"""

import pytest
from unittest.mock import MagicMock, patch
from bson import ObjectId

# Tool implementations
from fuzzingbrain.tools.suspicious_points import (
    create_suspicious_point_impl,
    update_suspicious_point_impl,
    list_suspicious_points_impl,
    set_sp_context,
    get_sp_context,
)


class TestUpdateSuspiciousPointParameters:
    """Test update_suspicious_point accepts all required parameters."""

    def test_function_signature_has_reachability_params(self):
        """update_suspicious_point_impl must accept reachability_* parameters."""
        import inspect
        sig = inspect.signature(update_suspicious_point_impl)
        params = list(sig.parameters.keys())

        # Must have these parameters
        assert "suspicious_point_id" in params
        assert "score" in params
        assert "is_checked" in params
        assert "is_real" in params
        assert "is_important" in params
        assert "verification_notes" in params
        assert "pov_guidance" in params
        # NEW - these caused the validation error
        assert "reachability_status" in params, "Missing reachability_status parameter!"
        assert "reachability_multiplier" in params, "Missing reachability_multiplier parameter!"
        assert "reachability_reason" in params, "Missing reachability_reason parameter!"

    @patch("fuzzingbrain.tools.suspicious_points._get_client")
    @patch("fuzzingbrain.tools.suspicious_points._ensure_client")
    def test_update_with_reachability_params(self, mock_ensure, mock_get_client):
        """update_suspicious_point should pass reachability params to client."""
        mock_ensure.return_value = None
        mock_client = MagicMock()
        mock_client.update_suspicious_point.return_value = {"updated": True}
        mock_get_client.return_value = mock_client

        # Set SP context
        set_sp_context("test_fuzzer", "address", "dir123", "agent123")

        # Call with reachability parameters
        result = update_suspicious_point_impl(
            suspicious_point_id="sp123",
            score=0.8,
            is_checked=True,
            is_important=True,
            pov_guidance="Trigger via oversized input to function pointer path",
            reachability_status="pointer_call",
            reachability_multiplier=0.95,
            reachability_reason="Reachable via function pointer",
        )

        # Verify client was called with reachability params
        mock_client.update_suspicious_point.assert_called_once()
        call_kwargs = mock_client.update_suspicious_point.call_args[1]
        assert call_kwargs["reachability_status"] == "pointer_call"
        assert call_kwargs["reachability_multiplier"] == 0.95
        assert call_kwargs["reachability_reason"] == "Reachable via function pointer"


class TestCreateSuspiciousPointParameters:
    """Test create_suspicious_point accepts all required parameters."""

    def test_function_signature(self):
        """create_suspicious_point_impl must have correct parameters."""
        import inspect
        sig = inspect.signature(create_suspicious_point_impl)
        params = list(sig.parameters.keys())

        assert "function_name" in params
        assert "vuln_type" in params
        assert "description" in params
        assert "score" in params
        assert "important_controlflow" in params

    @patch("fuzzingbrain.tools.suspicious_points._get_client")
    @patch("fuzzingbrain.tools.suspicious_points._ensure_client")
    def test_create_sp_basic(self, mock_ensure, mock_get_client):
        """create_suspicious_point should work with basic params."""
        mock_ensure.return_value = None
        mock_client = MagicMock()
        mock_client.create_suspicious_point.return_value = {
            "id": str(ObjectId()),
            "merged": False,
        }
        mock_get_client.return_value = mock_client

        # Set SP context
        set_sp_context("test_fuzzer", "address", "dir123", "agent123")

        result = create_suspicious_point_impl(
            function_name="png_read_row",
            vuln_type="heap-buffer-overflow",
            description="Buffer overflow in row processing",
            score=0.7,
        )

        assert result["success"] is True
        mock_client.create_suspicious_point.assert_called_once()


class TestMCPFactoryToolSignatures:
    """Test that MCP factory tools have correct signatures."""

    def test_update_suspicious_point_mcp_signature(self):
        """MCP update_suspicious_point tool must have reachability params."""
        # Import the mcp_factory module
        from fuzzingbrain.tools import mcp_factory

        # Check that the module can be imported without errors
        # The actual function is created dynamically, but we can check
        # that the impl function has the right signature
        import inspect
        sig = inspect.signature(update_suspicious_point_impl)
        params = list(sig.parameters.keys())

        assert "reachability_status" in params
        assert "reachability_multiplier" in params
        assert "reachability_reason" in params


class TestAnalyzerClientSignatures:
    """Test that AnalyzerClient methods have correct signatures."""

    def test_update_suspicious_point_client_signature(self):
        """AnalyzerClient.update_suspicious_point must have reachability params."""
        from fuzzingbrain.analyzer.client import AnalysisClient
        import inspect

        sig = inspect.signature(AnalysisClient.update_suspicious_point)
        params = list(sig.parameters.keys())

        assert "reachability_status" in params, "Client missing reachability_status!"
        assert "reachability_multiplier" in params, "Client missing reachability_multiplier!"
        assert "reachability_reason" in params, "Client missing reachability_reason!"


class TestAnalyzerServerHandlers:
    """Test that AnalyzerServer handles all parameters."""

    def test_update_suspicious_point_server_handles_reachability(self):
        """Server._update_suspicious_point must handle reachability params."""
        # Read the server code and check it handles the params
        import inspect
        from fuzzingbrain.analyzer.server import AnalysisServer

        # Get the source code of _update_suspicious_point
        source = inspect.getsource(AnalysisServer._update_suspicious_point)

        # Check that reachability params are handled
        assert "reachability_status" in source, "Server doesn't handle reachability_status!"
        assert "reachability_multiplier" in source, "Server doesn't handle reachability_multiplier!"
        assert "reachability_reason" in source, "Server doesn't handle reachability_reason!"


class TestSPContextFunctions:
    """Test SP context management."""

    def test_set_and_get_context(self):
        """set_sp_context and get_sp_context should work."""
        set_sp_context(
            harness_name="test_fuzzer",
            sanitizer="address",
            direction_id="dir123",
            agent_id="agent456",
        )

        harness, san, dir_id, agent_id = get_sp_context()
        assert harness == "test_fuzzer"
        assert san == "address"
        assert dir_id == "dir123"
        assert agent_id == "agent456"


class TestToolErrorHandling:
    """Test tool error handling."""

    def test_update_without_client_returns_error(self):
        """update_suspicious_point should return error if no client."""
        # Don't set up client - should fail gracefully
        with patch("fuzzingbrain.tools.suspicious_points._ensure_client") as mock:
            mock.return_value = {"success": False, "error": "No client"}
            result = update_suspicious_point_impl(
                suspicious_point_id="sp123",
                score=0.5,
            )
            assert result["success"] is False

    def test_create_without_client_returns_error(self):
        """create_suspicious_point should return error if no client."""
        with patch("fuzzingbrain.tools.suspicious_points._ensure_client") as mock:
            mock.return_value = {"success": False, "error": "No client"}
            result = create_suspicious_point_impl(
                function_name="test",
                vuln_type="overflow",
                description="test",
            )
            assert result["success"] is False


class TestDirectionTools:
    """Test direction-related tools."""

    def test_direction_tool_imports(self):
        """Direction tools should be importable."""
        from fuzzingbrain.tools.directions import (
            create_direction_impl,
            list_directions_impl,
            set_direction_context,
            get_direction_context,
        )
        # Just verify they're callable
        assert callable(create_direction_impl)
        assert callable(list_directions_impl)
        assert callable(set_direction_context)
        assert callable(get_direction_context)


class TestAnalyzerTools:
    """Test analyzer tools."""

    def test_analyzer_tool_imports(self):
        """Analyzer tools should be importable."""
        from fuzzingbrain.tools.analyzer import (
            set_analyzer_context,
            _get_client,
            _ensure_client,
        )
        assert callable(set_analyzer_context)
        assert callable(_get_client)
        assert callable(_ensure_client)


class TestPOVTools:
    """Test POV-related tools."""

    def test_pov_tool_function_signatures(self):
        """POV tools should have correct signatures."""
        from fuzzingbrain.tools.pov import (
            create_pov_impl,
            verify_pov_impl,
        )
        import inspect

        # Check create_pov_impl
        sig = inspect.signature(create_pov_impl)
        params = list(sig.parameters.keys())
        assert "generator_code" in params

        # Check verify_pov_impl
        sig = inspect.signature(verify_pov_impl)
        params = list(sig.parameters.keys())
        assert "pov_id" in params


class TestCodeViewerTools:
    """Test code viewer tools."""

    def test_code_viewer_imports(self):
        """Code viewer tools should be importable."""
        from fuzzingbrain.tools.code_viewer import (
            set_code_viewer_context,
            get_file_content_impl,
            search_code_impl,
        )
        assert callable(set_code_viewer_context)
        assert callable(get_file_content_impl)
        assert callable(search_code_impl)


class TestAllToolsHaveImpl:
    """Ensure all MCP tools have corresponding impl functions."""

    def test_suspicious_point_tools_have_impl(self):
        """All SP tools should have _impl functions."""
        from fuzzingbrain.tools import suspicious_points

        assert hasattr(suspicious_points, "create_suspicious_point_impl")
        assert hasattr(suspicious_points, "update_suspicious_point_impl")
        assert hasattr(suspicious_points, "list_suspicious_points_impl")

    def test_direction_tools_have_impl(self):
        """All direction tools should have _impl functions."""
        from fuzzingbrain.tools import directions

        assert hasattr(directions, "create_direction_impl")
        assert hasattr(directions, "list_directions_impl")

    def test_pov_tools_have_impl(self):
        """All POV tools should have _impl functions."""
        from fuzzingbrain.tools import pov

        assert hasattr(pov, "create_pov_impl")
        assert hasattr(pov, "verify_pov_impl")


class TestSeedTools:
    """Test seed-related tools."""

    def test_seed_tool_imports(self):
        """Seed tools should be importable."""
        from fuzzingbrain.fuzzer.seed_tools import (
            set_seed_context,
            get_seed_context,
            clear_seed_context,
            create_seed_impl,
        )
        assert callable(set_seed_context)
        assert callable(get_seed_context)
        assert callable(clear_seed_context)
        assert callable(create_seed_impl)

    def test_seed_context_with_worker_id(self):
        """Seed context should be retrievable by worker_id."""
        from fuzzingbrain.fuzzer.seed_tools import (
            set_seed_context,
            get_seed_context,
            clear_seed_context,
        )

        # Set context with a specific worker_id
        test_worker_id = "test_worker_12345"
        set_seed_context(
            task_id="task_001",
            worker_id=test_worker_id,
            direction_id="dir_001",
            fuzzer_manager=None,
            fuzzer="test_fuzzer",
            sanitizer="address",
        )

        # Retrieve context by worker_id
        ctx = get_seed_context(test_worker_id)
        assert ctx is not None
        assert ctx["task_id"] == "task_001"
        assert ctx["worker_id"] == test_worker_id
        assert ctx["direction_id"] == "dir_001"
        assert ctx["fuzzer"] == "test_fuzzer"

        # Clean up
        clear_seed_context(test_worker_id)
        ctx = get_seed_context(test_worker_id)
        assert ctx == {}

    def test_create_seed_impl_with_explicit_worker_id(self):
        """create_seed_impl should work with explicit worker_id parameter."""
        from fuzzingbrain.fuzzer.seed_tools import (
            set_seed_context,
            create_seed_impl,
            clear_seed_context,
        )

        # This simulates what happens in the MCP tool - the worker_id is bound in closure
        test_worker_id = "mcp_bound_worker_id"
        set_seed_context(
            task_id="task_002",
            worker_id=test_worker_id,
            direction_id="dir_002",
            fuzzer_manager=None,
            fuzzer="test_fuzzer",
            sanitizer="address",
        )

        # Call impl with explicit worker_id (like MCP tool does)
        generator_code = '''
def generate(seed_num: int) -> bytes:
    return b"test_" + str(seed_num).encode()
'''
        result = create_seed_impl(
            generator_code=generator_code,
            num_seeds=3,
            seed_type="direction",
            worker_id=test_worker_id,
        )

        # Should succeed (though seeds won't be saved without fuzzer_manager)
        assert result["success"] is True
        assert result["seeds_generated"] == 3

        # Clean up
        clear_seed_context(test_worker_id)

    def test_create_seed_fails_without_context(self):
        """create_seed_impl should fail if context not set for worker_id."""
        from fuzzingbrain.fuzzer.seed_tools import (
            create_seed_impl,
            clear_seed_context,
        )

        # Use a worker_id that has no context set
        nonexistent_worker_id = "nonexistent_worker_xyz"
        clear_seed_context(nonexistent_worker_id)  # Ensure it's cleared

        generator_code = 'def generate(seed_num): return b"test"'
        result = create_seed_impl(
            generator_code=generator_code,
            num_seeds=1,
            seed_type="direction",
            worker_id=nonexistent_worker_id,
        )

        # Should fail with "context not set" error
        assert result["success"] is False
        assert "context not set" in result["error"].lower()

    def test_mcp_factory_registers_seed_tools_with_worker_id(self):
        """MCP factory should register seed tools with worker_id bound in closure."""
        from fuzzingbrain.tools.mcp_factory import create_isolated_mcp_server
        from fastmcp import FastMCP

        # Create MCP server with seed tools enabled
        test_worker_id = "test_mcp_worker_id"
        mcp = create_isolated_mcp_server(
            agent_id="test_agent",
            worker_id=test_worker_id,
            include_seed_tools=True,
        )

        # Verify it's a FastMCP instance
        assert isinstance(mcp, FastMCP)

        # The tools are registered - we can verify by checking the tool is present
        # (FastMCP internal structure, but we can at least verify no exception)


class TestSeedAgentContextFlow:
    """Test that SeedAgent correctly sets up context for MCP tools."""

    def test_configure_context_sets_seed_context(self):
        """_configure_context should set seed context with ctx.agent_id."""
        from unittest.mock import MagicMock, patch

        # Mock AgentContext with a specific agent_id
        mock_ctx = MagicMock()
        mock_ctx.agent_id = "mock_agent_id_12345"

        # Create a minimal SeedAgent and test _configure_context
        with patch("fuzzingbrain.fuzzer.seed_agent.set_seed_context") as mock_set_ctx:
            from fuzzingbrain.fuzzer.seed_agent import SeedAgent

            agent = SeedAgent(
                task_id="task_001",
                worker_id="worker_001",
                fuzzer="test_fuzzer",
                sanitizer="address",
                fuzzer_manager=None,
                repos=None,
            )

            # Set up direction_id before configure
            agent.direction_id = "test_direction_id"

            # Call _configure_context
            agent._configure_context(mock_ctx)

            # Verify set_seed_context was called with ctx.agent_id
            mock_set_ctx.assert_called_once()
            call_kwargs = mock_set_ctx.call_args[1]
            assert call_kwargs["worker_id"] == "mock_agent_id_12345"
            assert call_kwargs["direction_id"] == "test_direction_id"

            # Verify agent stores the agent_id for cleanup
            assert agent._seed_agent_id == "mock_agent_id_12345"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

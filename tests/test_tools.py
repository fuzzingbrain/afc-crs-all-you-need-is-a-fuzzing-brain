# SPDX-License-Identifier: Apache-2.0
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
from fuzzingbrain.tools.vulnerability_hypotheses import (
    create_vulnerability_hypothesis_impl,
    update_vulnerability_hypothesis_impl,
    set_vh_context,
    get_vh_context,
)


class TestUpdateVulnerabilityHypothesisParameters:
    """Test update_vulnerability_hypothesis accepts all required parameters."""

    def test_function_signature_has_reachability_params(self):
        """update_vulnerability_hypothesis_impl must accept reachability_* parameters."""
        import inspect

        sig = inspect.signature(update_vulnerability_hypothesis_impl)
        params = list(sig.parameters.keys())

        # Must have these parameters
        assert "vulnerability_hypothesis_id" in params
        assert "score" in params
        assert "is_checked_by_verifier" in params
        assert "is_crash_found" in params
        assert "pattern" in params
        assert "verification_notes" in params
        assert "poc_guidance" in params
        # NEW - these caused the validation error
        assert "reachability_status" in params, "Missing reachability_status parameter!"
        assert "reachability_multiplier" in params, (
            "Missing reachability_multiplier parameter!"
        )
        assert "reachability_reason" in params, "Missing reachability_reason parameter!"

    @patch("fuzzingbrain.tools.vulnerability_hypotheses._get_client")
    @patch("fuzzingbrain.tools.vulnerability_hypotheses._ensure_client")
    def test_update_with_reachability_params(self, mock_ensure, mock_get_client):
        """update_vulnerability_hypothesis should pass reachability params to client."""
        mock_ensure.return_value = None
        mock_client = MagicMock()
        mock_client.update_vulnerability_hypothesis.return_value = {"updated": True}
        mock_get_client.return_value = mock_client

        # Set VH context
        set_vh_context("test_fuzzer", "address", "dir123", "agent123")

        # Call with reachability parameters
        result = update_vulnerability_hypothesis_impl(
            vulnerability_hypothesis_id="sp123",
            score=0.8,
            is_checked_by_verifier=True,
            pattern="confirmed",
            poc_guidance="Trigger via oversized input to function pointer path",
            reachability_status="pointer_call",
            reachability_multiplier=0.95,
            reachability_reason="Reachable via function pointer",
        )

        # Verify client was called with reachability params
        mock_client.update_vulnerability_hypothesis.assert_called_once()
        call_kwargs = mock_client.update_vulnerability_hypothesis.call_args[1]
        assert call_kwargs["reachability_status"] == "pointer_call"
        assert call_kwargs["reachability_multiplier"] == 0.95
        assert call_kwargs["reachability_reason"] == "Reachable via function pointer"


class TestCreateVulnerabilityHypothesisParameters:
    """Test create_vulnerability_hypothesis accepts all required parameters."""

    def test_function_signature(self):
        """create_vulnerability_hypothesis_impl must have correct parameters."""
        import inspect

        sig = inspect.signature(create_vulnerability_hypothesis_impl)
        params = list(sig.parameters.keys())

        assert "function_name" in params
        assert "description" in params
        assert "score" in params
        assert "important_controlflow" in params

    @patch("fuzzingbrain.tools.vulnerability_hypotheses._get_client")
    @patch("fuzzingbrain.tools.vulnerability_hypotheses._ensure_client")
    def test_create_vh_basic(self, mock_ensure, mock_get_client):
        """create_vulnerability_hypothesis should work with basic params."""
        mock_ensure.return_value = None
        mock_client = MagicMock()
        mock_client.create_vulnerability_hypothesis.return_value = {
            "id": str(ObjectId()),
            "merged": False,
        }
        mock_get_client.return_value = mock_client

        # Set VH context
        set_vh_context("test_fuzzer", "address", "dir123", "agent123")

        result = create_vulnerability_hypothesis_impl(
            function_name="png_read_row",
            description="Buffer overflow in row processing",
            score=0.7,
        )

        assert result["success"] is True
        mock_client.create_vulnerability_hypothesis.assert_called_once()


class TestMCPFactoryToolSignatures:
    """Test that MCP factory tools have correct signatures."""

    def test_update_vulnerability_hypothesis_mcp_signature(self):
        """MCP update_vulnerability_hypothesis tool must have reachability params."""
        # Import the mcp_factory module

        # Check that the module can be imported without errors
        # The actual function is created dynamically, but we can check
        # that the impl function has the right signature
        import inspect

        sig = inspect.signature(update_vulnerability_hypothesis_impl)
        params = list(sig.parameters.keys())

        assert "reachability_status" in params
        assert "reachability_multiplier" in params
        assert "reachability_reason" in params


class TestAnalyzerClientSignatures:
    """Test that AnalyzerClient methods have correct signatures."""

    def test_update_vulnerability_hypothesis_client_signature(self):
        """AnalyzerClient.update_vulnerability_hypothesis must have reachability params."""
        from fuzzingbrain.analyzer.client import AnalysisClient
        import inspect

        sig = inspect.signature(AnalysisClient.update_vulnerability_hypothesis)
        params = list(sig.parameters.keys())

        assert "reachability_status" in params, "Client missing reachability_status!"
        assert "reachability_multiplier" in params, (
            "Client missing reachability_multiplier!"
        )
        assert "reachability_reason" in params, "Client missing reachability_reason!"


class TestAnalyzerServerHandlers:
    """Test that AnalyzerServer handles all parameters."""

    def test_update_vulnerability_hypothesis_server_handles_reachability(self):
        """Server._update_vulnerability_hypothesis must handle reachability params."""
        # Read the server code and check it handles the params
        import inspect
        from fuzzingbrain.analyzer.server import AnalysisServer

        # Get the source code of _update_vulnerability_hypothesis
        source = inspect.getsource(AnalysisServer._update_vulnerability_hypothesis)

        # Check that reachability params are handled
        assert "reachability_status" in source, (
            "Server doesn't handle reachability_status!"
        )
        assert "reachability_multiplier" in source, (
            "Server doesn't handle reachability_multiplier!"
        )
        assert "reachability_reason" in source, (
            "Server doesn't handle reachability_reason!"
        )


class TestVHContextFunctions:
    """Test VH context management."""

    def test_set_and_get_context(self):
        """set_vh_context and get_vh_context should work."""
        set_vh_context(
            harness_name="test_fuzzer",
            sanitizer="address",
            lg_id="dir123",
            agent_id="agent456",
        )

        harness, san, dir_id, agent_id = get_vh_context()
        assert harness == "test_fuzzer"
        assert san == "address"
        assert dir_id == "dir123"
        assert agent_id == "agent456"


class TestToolErrorHandling:
    """Test tool error handling."""

    def test_update_without_client_returns_error(self):
        """update_vulnerability_hypothesis should return error if no client."""
        # Don't set up client - should fail gracefully
        with patch("fuzzingbrain.tools.vulnerability_hypotheses._ensure_client") as mock:
            mock.return_value = {"success": False, "error": "No client"}
            result = update_vulnerability_hypothesis_impl(
                vulnerability_hypothesis_id="sp123",
                score=0.5,
            )
            assert result["success"] is False

    def test_create_without_client_returns_error(self):
        """create_vulnerability_hypothesis should return error if no client."""
        with patch("fuzzingbrain.tools.vulnerability_hypotheses._ensure_client") as mock:
            mock.return_value = {"success": False, "error": "No client"}
            result = create_vulnerability_hypothesis_impl(
                function_name="test",
                description="test",
            )
            assert result["success"] is False


class TestLogicGroupTools:
    """Test logic group-related tools."""

    def test_logic_group_tool_imports(self):
        """Logic group tools should be importable."""
        from fuzzingbrain.tools.logic_groups import (
            create_logic_group_impl,
            list_logic_groups_impl,
            set_logic_group_context,
            get_logic_group_context,
        )

        # Just verify they're callable
        assert callable(create_logic_group_impl)
        assert callable(list_logic_groups_impl)
        assert callable(set_logic_group_context)
        assert callable(get_logic_group_context)


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


class TestPOCTools:
    """Test PoC-related tools."""

    def test_poc_tool_function_signatures(self):
        """PoC tools should have correct signatures."""
        from fuzzingbrain.tools.poc import (
            create_poc_impl,
            verify_poc_impl,
        )
        import inspect

        # Check create_poc_impl
        sig = inspect.signature(create_poc_impl)
        params = list(sig.parameters.keys())
        assert "generator_code" in params

        # Check verify_poc_impl
        sig = inspect.signature(verify_poc_impl)
        params = list(sig.parameters.keys())
        assert "poc_id" in params


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

    def test_vulnerability_hypothesis_tools_have_impl(self):
        """All VH tools should have _impl functions."""
        from fuzzingbrain.tools import vulnerability_hypotheses

        assert hasattr(vulnerability_hypotheses, "create_vulnerability_hypothesis_impl")
        assert hasattr(vulnerability_hypotheses, "update_vulnerability_hypothesis_impl")
        assert hasattr(vulnerability_hypotheses, "list_vulnerability_hypotheses_impl")

    def test_logic_group_tools_have_impl(self):
        """All logic group tools should have _impl functions."""
        from fuzzingbrain.tools import logic_groups

        assert hasattr(logic_groups, "create_logic_group_impl")
        assert hasattr(logic_groups, "list_logic_groups_impl")

    def test_poc_tools_have_impl(self):
        """All PoC tools should have _impl functions."""
        from fuzzingbrain.tools import poc

        assert hasattr(poc, "create_poc_impl")
        assert hasattr(poc, "verify_poc_impl")


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
            run_id="run_001",
            worker_id=test_worker_id,
            lg_id="dir_001",
            fuzzer_manager=None,
            fuzzer="test_fuzzer",
            sanitizer="address",
        )

        # Retrieve context by worker_id
        ctx = get_seed_context(test_worker_id)
        assert ctx is not None
        assert ctx["run_id"] == "run_001"
        assert ctx["worker_id"] == test_worker_id
        assert ctx["lg_id"] == "dir_001"
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
            run_id="run_002",
            worker_id=test_worker_id,
            lg_id="dir_002",
            fuzzer_manager=None,
            fuzzer="test_fuzzer",
            sanitizer="address",
        )

        # Call impl with explicit worker_id (like MCP tool does)
        generator_code = """
def generate(seed_num: int) -> bytes:
    return b"test_" + str(seed_num).encode()
"""
        result = create_seed_impl(
            generator_code=generator_code,
            num_seeds=3,
            seed_type="logic_group",
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
            seed_type="logic_group",
            worker_id=nonexistent_worker_id,
        )

        # The message must say the setup is at fault and retrying is pointless,
        # without naming set_seed_context -- not a tool the agent has.
        assert result["success"] is False
        assert "not initialised" in result["error"]
        assert "set_seed_context" not in result["error"]

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
                run_id="run_001",
                worker_id="worker_001",
                fuzzer="test_fuzzer",
                sanitizer="address",
                fuzzer_manager=None,
                repos=None,
            )

            # Set up lg_id before configure
            agent.lg_id = "test_lg_id"

            # Call _configure_context
            agent._configure_context(mock_ctx)

            # Verify set_seed_context was called with ctx.agent_id
            mock_set_ctx.assert_called_once()
            call_kwargs = mock_set_ctx.call_args[1]
            assert call_kwargs["worker_id"] == "mock_agent_id_12345"
            assert call_kwargs["lg_id"] == "test_lg_id"

            # Verify agent stores the agent_id for cleanup
            assert agent._seed_agent_id == "mock_agent_id_12345"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

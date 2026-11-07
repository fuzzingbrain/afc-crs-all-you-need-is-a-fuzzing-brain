# SPDX-License-Identifier: Apache-2.0
"""
Unit tests for MCP Tools.

Signatures and the checks that need no database; tests/test_worker_flow_pg.py
covers the VH and logic group tools against PostgreSQL.

Run with: pytest tests/test_tools.py -v
"""

import pytest
from unittest.mock import MagicMock, patch

# Tool implementations
from fuzzingbrain.tools.vulnerability_hypotheses import (
    create_vulnerability_hypothesis_impl,
    update_vulnerability_hypothesis_impl,
    set_vh_context,
    get_vh_context,
)


class TestVHToolSignatures:
    def test_mcp_create_requires_sink_code(self):
        import inspect

        from fuzzingbrain.tools import mcp_factory

        src = inspect.getsource(mcp_factory._register_vh_create_tools)
        assert "        sink_code: str,\n" in src

    def test_context_round_trip(self):
        set_vh_context(lg_id="lg1", agent_id="a1")
        assert get_vh_context() == ("lg1", "a1")
        set_vh_context()
        assert get_vh_context() == (None, "a1")


class TestToolsOutsideAWorker:
    """A VH tool called with no worker scope says so, not a database error."""

    @pytest.fixture(autouse=True)
    def _no_scope(self):
        from fuzzingbrain.worker import scope

        scope.set_scope(None)

    def test_create(self):
        r = create_vulnerability_hypothesis_impl("f", "d", sink_code="x;")
        assert r["success"] is False and "worker" in r["error"]

    def test_update(self):
        r = update_vulnerability_hypothesis_impl(vulnerability_hypothesis_id="abc", score=0.5)
        assert r["success"] is False

    def test_logic_group_tools(self):
        from fuzzingbrain.tools.logic_groups import create_logic_group_impl, list_logic_groups_impl

        assert list_logic_groups_impl()["success"] is False
        r = create_logic_group_impl(name="n", risk_level="high", core_functions=["f"],
                                    entry_functions=["g"], risk_reason="r")
        assert r["success"] is False


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

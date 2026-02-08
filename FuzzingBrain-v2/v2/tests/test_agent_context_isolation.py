"""
Agent Context Isolation Tests

Tests that agent context (harness_name, sanitizer, direction_id, agent_id, fuzzer)
flows correctly through tool function calls to the AnalysisClient.

Architecture:
- Pipeline sets ContextVars (SP context, direction context, analyzer context)
- Agent calls tool impl function (e.g. create_suspicious_point_impl)
- Impl reads ContextVars via get_sp_context() / get_direction_context()
- Impl passes values to AnalysisClient methods

Real business risks tested:
- SPG creates SP but wrong direction_id reaches the server
- SPV updates SP but SPG's agent_id leaks into the update
- Parallel agents' tool calls cross-contaminate context
- Direction planner's fuzzer leaks into SP generator's tool calls
"""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from fuzzingbrain.tools.suspicious_points import (
    set_sp_context,
    set_sp_agent_id,
    create_suspicious_point_impl,
    update_suspicious_point_impl,
)
from fuzzingbrain.tools.directions import (
    set_direction_context,
    create_direction_impl,
)
from fuzzingbrain.tools.analyzer import (
    _client_cache,
    _client_cache_lock,
)


@pytest.fixture(autouse=True)
def clean_client_cache():
    """Clean _client_cache before and after each test."""
    with _client_cache_lock:
        _client_cache.clear()
    yield
    with _client_cache_lock:
        _client_cache.clear()


def _mock_client():
    """Create a mock AnalysisClient that records all method calls."""
    client = MagicMock()
    client.create_suspicious_point.return_value = {
        "id": "sp_mock_12345678",
        "created": True,
        "merged": False,
    }
    client.update_suspicious_point.return_value = {
        "updated": True,
    }
    client.create_direction.return_value = {
        "id": "dir_mock_12345678",
        "created": True,
    }
    return client


class TestSPCreateContextFlow:
    """
    SPG agent calls create_suspicious_point_impl().
    Verify that AnalysisClient.create_suspicious_point() receives
    the correct harness_name, sanitizer, direction_id, agent_id from context.

    Real scenario: pipeline sets SP context for each direction,
    SPG agent creates SPs, each SP must be tagged correctly.
    """

    @patch("fuzzingbrain.tools.suspicious_points._get_client")
    @patch("fuzzingbrain.tools.suspicious_points._ensure_client", return_value=None)
    def test_create_sp_carries_full_context(self, _ensure, mock_get_client):
        """
        SPG agent for Direction "chunk_handlers" creates an SP.
        The AnalysisClient must receive all 4 context values.
        """
        client = _mock_client()
        mock_get_client.return_value = client

        set_sp_context(
            harness_name="fuzz_png",
            sanitizer="address",
            direction_id="dir_chunk_handlers",
            agent_id="agent_spg_001",
        )

        result = create_suspicious_point_impl(
            function_name="png_read_chunk",
            vuln_type="buffer-overflow",
            description="Unbounded memcpy from chunk data",
            score=0.8,
        )

        assert result["success"] is True
        kw = client.create_suspicious_point.call_args[1]
        assert kw["harness_name"] == "fuzz_png"
        assert kw["sanitizer"] == "address"
        assert kw["direction_id"] == "dir_chunk_handlers"
        assert kw["agent_id"] == "agent_spg_001"
        assert kw["function_name"] == "png_read_chunk"
        assert kw["vuln_type"] == "buffer-overflow"

    def test_phase1_parallel_spg_agents_share_direction_context(self):
        """
        pov_fullscan Phase 1: set_sp_context() once for a direction,
        then 3 SPG mini-agents analyze functions concurrently via asyncio.gather.
        All 3 SPs must carry the same direction_id.

        Real code: pov_fullscan.py:402-440
          set_sp_context(fuzzer, sanitizer, direction_id)
          tasks = [analyze_function(func, i) for i, func in enumerate(functions)]
          await asyncio.gather(*tasks)
        """
        captured = {}

        async def _run():
            # Phase 1 sets context once for the direction (pov_fullscan.py:404)
            set_sp_context(
                harness_name="fuzz_png",
                sanitizer="address",
                direction_id="dir_chunk_handlers",
                agent_id="phase1_spg",
            )

            events = [asyncio.Event() for _ in range(3)]

            async def spg_mini_agent(func_name, my_idx):
                # Wait for all agents to be ready
                events[my_idx].set()
                for e in events:
                    await e.wait()

                mock_client = _mock_client()
                with patch(
                    "fuzzingbrain.tools.suspicious_points._get_client",
                    return_value=mock_client,
                ), patch(
                    "fuzzingbrain.tools.suspicious_points._ensure_client",
                    return_value=None,
                ):
                    create_suspicious_point_impl(
                        function_name=func_name,
                        vuln_type="buffer-overflow",
                        description=f"Bug in {func_name}",
                    )
                    captured[func_name] = (
                        mock_client.create_suspicious_point.call_args[1]
                    )

            await asyncio.gather(
                spg_mini_agent("png_read_chunk", 0),
                spg_mini_agent("png_handle_IDAT", 1),
                spg_mini_agent("png_read_PLTE", 2),
            )

        asyncio.run(_run())

        # All 3 SPs must carry the same direction set once at Phase 1 start
        for func_name in ["png_read_chunk", "png_handle_IDAT", "png_read_PLTE"]:
            assert captured[func_name]["direction_id"] == "dir_chunk_handlers", (
                f"{func_name}'s SP tagged to '{captured[func_name]['direction_id']}' "
                f"— should be 'dir_chunk_handlers'"
            )
            assert captured[func_name]["harness_name"] == "fuzz_png"


class TestSPUpdateContextFlow:
    """
    SPV agent calls update_suspicious_point_impl().
    Verify that AnalysisClient.update_suspicious_point() receives
    the SPV's agent_id (not SPG's).

    Real scenario: SPG creates SP with agent_id="spg_001",
    then SPV verifies it with agent_id="spv_001".
    The update must carry "spv_001" so we know WHO verified the SP.
    """

    @patch("fuzzingbrain.tools.suspicious_points._get_client")
    @patch("fuzzingbrain.tools.suspicious_points._ensure_client", return_value=None)
    def test_update_sp_carries_verifier_agent_id(self, _ensure, mock_get_client):
        """
        SPV verifies an SP as real and important.
        The AnalysisClient must receive the SPV's agent_id.
        """
        client = _mock_client()
        mock_get_client.return_value = client

        set_sp_context(
            harness_name="fuzz_png",
            sanitizer="address",
            direction_id="dir_chunk",
            agent_id="agent_spv_001",
        )

        result = update_suspicious_point_impl(
            suspicious_point_id="sp_abc12345",
            is_checked=True,
            is_real=True,
            is_important=True,
            verification_notes="Confirmed: no bounds check before memcpy",
            pov_guidance="Send chunk with length > 4096",
        )

        assert result["success"] is True
        kw = client.update_suspicious_point.call_args[1]
        assert kw["agent_id"] == "agent_spv_001"
        assert kw["sp_id"] == "sp_abc12345"
        assert kw["is_checked"] is True
        assert kw["is_real"] is True

    @patch("fuzzingbrain.tools.suspicious_points._get_client")
    @patch("fuzzingbrain.tools.suspicious_points._ensure_client", return_value=None)
    def test_sequential_spg_then_spv_agent_id_switches(self, _ensure, mock_get_client):
        """
        SPG creates SP → SPV updates SP. Both in same asyncio Task (sequential).
        Pipeline calls set_sp_agent_id() between them.

        The create must carry SPG's agent_id.
        The update must carry SPV's agent_id — not SPG's.

        This is the real pattern in pipeline._run_verify_agent().
        """
        client = _mock_client()
        mock_get_client.return_value = client

        # --- Phase 1: SPG agent creates SP ---
        set_sp_context(
            harness_name="fuzz_png",
            sanitizer="address",
            direction_id="dir_chunk",
            agent_id="agent_spg_001",
        )
        create_suspicious_point_impl(
            function_name="parse_chunk",
            vuln_type="buffer-overflow",
            description="memcpy without bounds check",
        )

        create_kw = client.create_suspicious_point.call_args[1]
        assert create_kw["agent_id"] == "agent_spg_001"

        # --- Phase 2: SPV takes over (same Task, sequential) ---
        # Pipeline calls set_sp_agent_id() in BaseAgent.run_async()
        set_sp_agent_id("agent_spv_001")

        update_suspicious_point_impl(
            suspicious_point_id="sp_abc12345",
            is_checked=True,
            is_real=False,
            verification_notes="False positive: length validated in caller",
        )

        update_kw = client.update_suspicious_point.call_args[1]
        assert update_kw["agent_id"] == "agent_spv_001", (
            f"SPV update carried agent_id='{update_kw['agent_id']}' — "
            f"leaked from SPG (expected 'agent_spv_001')"
        )


class TestDirectionContextFlow:
    """
    Direction planner calls create_direction_impl().
    Verify that AnalysisClient.create_direction() receives
    the correct fuzzer from direction context.

    Real scenario: pipeline sets direction_context("fuzz_png") before
    running the direction planner. Planner creates directions,
    each tagged with the fuzzer it analyzes.
    """

    @patch("fuzzingbrain.tools.directions._get_client")
    @patch("fuzzingbrain.tools.directions._ensure_client", return_value=None)
    def test_create_direction_carries_fuzzer_context(self, _ensure, mock_get_client):
        """
        Direction planner creates a "chunk_handlers" direction.
        The AnalysisClient must receive fuzzer="fuzz_png" from context.
        """
        client = _mock_client()
        mock_get_client.return_value = client

        set_direction_context("fuzz_png")

        result = create_direction_impl(
            name="chunk_handlers",
            risk_level="high",
            risk_reason="Direct parsing of untrusted PNG chunk data",
            core_functions=["png_read_chunk", "png_handle_IDAT"],
        )

        assert result["success"] is True
        kw = client.create_direction.call_args[1]
        assert kw["fuzzer"] == "fuzz_png"
        assert kw["name"] == "chunk_handlers"
        assert kw["risk_level"] == "high"

    @patch("fuzzingbrain.tools.directions._get_client")
    @patch("fuzzingbrain.tools.directions._ensure_client", return_value=None)
    def test_planner_creates_multiple_directions_same_fuzzer(self, _ensure, mock_get_client):
        """
        Direction planner creates 3 directions in one session.
        All must carry the same fuzzer="fuzz_png" from context.

        Real scenario: planner analyzes call graph, creates directions:
        "chunk_handlers" (high), "color_management" (medium), "text_metadata" (low).
        All belong to the same fuzzer.
        """
        client = _mock_client()
        mock_get_client.return_value = client

        set_direction_context("fuzz_png")

        directions = [
            ("chunk_handlers", "high", "Direct parsing of untrusted chunk data"),
            ("color_management", "medium", "ICC profile processing with complex math"),
            ("text_metadata", "low", "Text field parsing, mostly safe string ops"),
        ]

        for name, risk, reason in directions:
            create_direction_impl(
                name=name,
                risk_level=risk,
                risk_reason=reason,
                core_functions=[f"{name}_func_1", f"{name}_func_2"],
            )

        # All 3 calls must have carried fuzzer="fuzz_png"
        assert client.create_direction.call_count == 3
        for call in client.create_direction.call_args_list:
            kw = call[1]
            assert kw["fuzzer"] == "fuzz_png", (
                f"Direction '{kw['name']}' got fuzzer='{kw['fuzzer']}' — "
                f"expected 'fuzz_png' from context"
            )


class TestParallelAgentToolCalls:
    """
    Parallel agents in asyncio.gather() call tool functions concurrently.
    Each agent's tool calls must carry its own context, not the other's.

    Real scenario: _run_verify_agent("verify_1") || _run_verify_agent("verify_2")
    verify_1 processes SPs for "dir_chunk", verify_2 for "dir_icc".
    If context leaks, SPs get tagged to the wrong direction in the database.
    """

    def test_parallel_create_sp_carries_correct_direction(self):
        """
        Two verify agents run concurrently, each creates an SP.
        verify_1's SP must have direction_id="dir_chunk".
        verify_2's SP must have direction_id="dir_icc".

        Cross-contamination here = SPs tagged to wrong direction = wrong analysis.
        """
        captured = {}

        async def _run():
            event_1 = asyncio.Event()
            event_2 = asyncio.Event()

            async def verify_agent(name, direction_id, my_event, other_event):
                set_sp_context(
                    harness_name="fuzz_png",
                    sanitizer="address",
                    direction_id=direction_id,
                    agent_id=name,
                )
                my_event.set()
                await other_event.wait()

                # Both contexts are set — now call tool function
                mock_client = _mock_client()
                with patch(
                    "fuzzingbrain.tools.suspicious_points._get_client",
                    return_value=mock_client,
                ), patch(
                    "fuzzingbrain.tools.suspicious_points._ensure_client",
                    return_value=None,
                ):
                    create_suspicious_point_impl(
                        function_name=f"func_{name}",
                        vuln_type="buffer-overflow",
                        description="test",
                    )
                    captured[name] = mock_client.create_suspicious_point.call_args[1]

            await asyncio.gather(
                verify_agent("verify_1", "dir_chunk", event_1, event_2),
                verify_agent("verify_2", "dir_icc", event_2, event_1),
            )

        asyncio.run(_run())

        assert captured["verify_1"]["direction_id"] == "dir_chunk", (
            f"verify_1's SP tagged to '{captured['verify_1']['direction_id']}' — "
            f"leaked from verify_2"
        )
        assert captured["verify_1"]["agent_id"] == "verify_1"

        assert captured["verify_2"]["direction_id"] == "dir_icc", (
            f"verify_2's SP tagged to '{captured['verify_2']['direction_id']}' — "
            f"leaked from verify_1"
        )
        assert captured["verify_2"]["agent_id"] == "verify_2"

    def test_sp_find_and_verify_pipeline_concurrent(self):
        """
        SP Find (Phase 1/2) creates SPs while verify pipeline updates SPs.
        Both run as concurrent asyncio Tasks (pov_fullscan.py:361-387):
          pipeline_task = asyncio.create_task(pipeline.run())
          await _run_phase1_small_pool(...)   # creates SPs
          await _run_phase2_big_pool(...)     # creates more SPs

        SP Find's create_sp must carry agent_id="phase1_spg".
        Verify's update_sp must carry agent_id="verify_1".
        Neither should see the other's context.
        """
        captured = {}

        async def _run():
            event_1 = asyncio.Event()
            event_2 = asyncio.Event()

            async def sp_find_phase(my_event, other_event):
                # SP Find sets its own context (pov_fullscan.py:404)
                set_sp_context(
                    harness_name="fuzz_png",
                    sanitizer="address",
                    direction_id="dir_chunk",
                    agent_id="phase1_spg",
                )
                my_event.set()
                await other_event.wait()

                mock_client = _mock_client()
                with patch(
                    "fuzzingbrain.tools.suspicious_points._get_client",
                    return_value=mock_client,
                ), patch(
                    "fuzzingbrain.tools.suspicious_points._ensure_client",
                    return_value=None,
                ):
                    create_suspicious_point_impl(
                        function_name="png_read_chunk",
                        vuln_type="buffer-overflow",
                        description="New SP from Phase 1",
                    )
                    captured["sp_find"] = (
                        mock_client.create_suspicious_point.call_args[1]
                    )

            async def verify_pipeline(my_event, other_event):
                # Verify agent sets its own context (pipeline.py:231)
                set_sp_context(
                    harness_name="fuzz_png",
                    sanitizer="address",
                    direction_id="dir_icc",
                    agent_id="verify_1",
                )
                my_event.set()
                await other_event.wait()

                mock_client = _mock_client()
                with patch(
                    "fuzzingbrain.tools.suspicious_points._get_client",
                    return_value=mock_client,
                ), patch(
                    "fuzzingbrain.tools.suspicious_points._ensure_client",
                    return_value=None,
                ):
                    update_suspicious_point_impl(
                        suspicious_point_id="sp_earlier_001",
                        is_checked=True,
                        is_real=True,
                        is_important=True,
                        verification_notes="Confirmed from earlier SP",
                        pov_guidance="Craft ICC profile",
                    )
                    captured["verify"] = (
                        mock_client.update_suspicious_point.call_args[1]
                    )

            await asyncio.gather(
                sp_find_phase(event_1, event_2),
                verify_pipeline(event_2, event_1),
            )

        asyncio.run(_run())

        # SP Find created SP with its own context
        assert captured["sp_find"]["agent_id"] == "phase1_spg"
        assert captured["sp_find"]["direction_id"] == "dir_chunk"
        # Verify pipeline updated SP with its own context
        assert captured["verify"]["agent_id"] == "verify_1"
        assert captured["verify"]["sp_id"] == "sp_earlier_001"


class TestContextLeakBetweenPipelinePhases:
    """
    Pipeline runs phases sequentially in the same asyncio Task:
    1. SPG for Direction-1 → creates SPs
    2. SPG for Direction-2 → creates SPs

    Risk: Direction-2's SPG forgets full context reset,
    its SPs get tagged to Direction-1's direction_id.
    """

    @patch("fuzzingbrain.tools.suspicious_points._get_client")
    @patch("fuzzingbrain.tools.suspicious_points._ensure_client", return_value=None)
    def test_set_sp_agent_id_must_not_leak_direction(self, _ensure, mock_get_client):
        """
        Invariant: set_sp_agent_id() clears direction_id to prevent leak.

        Fix: set_sp_agent_id() now clears direction_id. Combined with
        Layer A guard in create_suspicious_point_impl (rejects if no
        direction_id), this provides two-layer protection against
        non-SP-Finding agents accidentally creating SPs.
        """
        client = _mock_client()
        mock_get_client.return_value = client

        # --- Direction-1 SPG ---
        set_sp_context(
            harness_name="fuzz_png",
            sanitizer="address",
            direction_id="dir_chunk",
            agent_id="spg_dir1",
        )
        result1 = create_suspicious_point_impl(
            function_name="parse_chunk",
            vuln_type="buffer-overflow",
            description="test",
        )
        assert result1["success"] is True
        kw_dir1 = client.create_suspicious_point.call_args[1]
        assert kw_dir1["direction_id"] == "dir_chunk"

        # --- Direction-2 SPG — only updates agent_id ---
        set_sp_agent_id("spg_dir2")

        # Layer 1: set_sp_agent_id clears direction_id
        from fuzzingbrain.tools.suspicious_points import get_sp_context
        _, _, direction_id, agent_id = get_sp_context()
        assert direction_id is None or direction_id == "", \
            "Direction leak: set_sp_agent_id must clear direction_id"
        assert agent_id == "spg_dir2"

        # Layer 2: create_suspicious_point_impl rejects without direction_id
        result2 = create_suspicious_point_impl(
            function_name="parse_icc",
            vuln_type="out-of-bounds-read",
            description="test",
        )
        assert result2["success"] is False, \
            "SP creation must be blocked without direction_id"
        assert "direction_id" in result2["error"]

        # Server was only called once (Direction-1), not twice
        assert client.create_suspicious_point.call_count == 1

    @patch("fuzzingbrain.tools.suspicious_points._get_client")
    @patch("fuzzingbrain.tools.suspicious_points._ensure_client", return_value=None)
    def test_set_sp_context_resets_direction_correctly(self, _ensure, mock_get_client):
        """
        Using full set_sp_context() between directions correctly
        resets direction_id — no leak.
        """
        client = _mock_client()
        mock_get_client.return_value = client

        # --- Direction-1 ---
        set_sp_context(
            harness_name="fuzz_png",
            sanitizer="address",
            direction_id="dir_chunk",
            agent_id="spg_dir1",
        )
        create_suspicious_point_impl(
            function_name="parse_chunk",
            vuln_type="buffer-overflow",
            description="test",
        )

        # --- Direction-2 with full context reset ---
        set_sp_context(
            harness_name="fuzz_png",
            sanitizer="address",
            direction_id="dir_icc",
            agent_id="spg_dir2",
        )
        create_suspicious_point_impl(
            function_name="parse_icc",
            vuln_type="out-of-bounds-read",
            description="test",
        )
        kw_fixed = client.create_suspicious_point.call_args[1]
        assert kw_fixed["direction_id"] == "dir_icc"

    def test_parallel_verify_and_pov_update_isolated(self):
        """
        Verifier and POV agent run concurrently, both call update_sp_impl.
        Verifier updates SP-1 with agent_id="verify_1".
        POV agent updates SP-2 with agent_id="pov_1".

        Cross-contamination = wrong agent_id in verified_by field.
        """
        captured = {}

        async def _run():
            event_1 = asyncio.Event()
            event_2 = asyncio.Event()

            async def verifier(my_event, other_event):
                set_sp_context(
                    harness_name="fuzz_png",
                    sanitizer="address",
                    direction_id="dir_chunk",
                    agent_id="verify_1",
                )
                my_event.set()
                await other_event.wait()

                mock_client = _mock_client()
                with patch(
                    "fuzzingbrain.tools.suspicious_points._get_client",
                    return_value=mock_client,
                ), patch(
                    "fuzzingbrain.tools.suspicious_points._ensure_client",
                    return_value=None,
                ):
                    update_suspicious_point_impl(
                        suspicious_point_id="sp_001",
                        is_checked=True,
                        is_real=True,
                        is_important=True,
                        verification_notes="Confirmed buffer overflow",
                        pov_guidance="Oversize chunk length",
                    )
                    captured["verifier"] = (
                        mock_client.update_suspicious_point.call_args[1]
                    )

            async def pov_agent(my_event, other_event):
                set_sp_context(
                    harness_name="fuzz_png",
                    sanitizer="address",
                    direction_id="dir_icc",
                    agent_id="pov_1",
                )
                my_event.set()
                await other_event.wait()

                mock_client = _mock_client()
                with patch(
                    "fuzzingbrain.tools.suspicious_points._get_client",
                    return_value=mock_client,
                ), patch(
                    "fuzzingbrain.tools.suspicious_points._ensure_client",
                    return_value=None,
                ):
                    update_suspicious_point_impl(
                        suspicious_point_id="sp_002",
                        is_checked=True,
                        is_real=True,
                        is_important=True,
                        verification_notes="Also confirmed",
                        pov_guidance="Crafted ICC profile",
                    )
                    captured["pov"] = (
                        mock_client.update_suspicious_point.call_args[1]
                    )

            await asyncio.gather(
                verifier(event_1, event_2),
                pov_agent(event_2, event_1),
            )

        asyncio.run(_run())

        assert captured["verifier"]["agent_id"] == "verify_1"
        assert captured["verifier"]["sp_id"] == "sp_001"
        assert captured["pov"]["agent_id"] == "pov_1"
        assert captured["pov"]["sp_id"] == "sp_002"

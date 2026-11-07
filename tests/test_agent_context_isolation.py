# SPDX-License-Identifier: Apache-2.0
"""
Agent Context Isolation Tests

Tests that agent context (harness_name, sanitizer, lg_id, agent_id, fuzzer)
flows correctly through tool function calls to the AnalysisClient.

Architecture:
- Pipeline sets ContextVars (VH context, logic group context, analyzer context)
- Agent calls tool impl function (e.g. create_vulnerability_hypothesis_impl)
- Impl reads ContextVars via get_vh_context() / get_logic_group_context()
- Impl passes values to AnalysisClient methods

Real business risks tested:
- VHG creates VH but wrong lg_id reaches the server
- VHV updates VH but VHG's agent_id leaks into the update
- Parallel agents' tool calls cross-contaminate context
- Logic group planner's fuzzer leaks into VH generator's tool calls
"""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from fuzzingbrain.tools.vulnerability_hypotheses import (
    set_vh_context,
    set_vh_agent_id,
    create_vulnerability_hypothesis_impl,
    update_vulnerability_hypothesis_impl,
)
from fuzzingbrain.tools.logic_groups import (
    set_logic_group_context,
    create_logic_group_impl,
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
    client.create_vulnerability_hypothesis.return_value = {
        "id": "vh_mock_12345678",
        "created": True,
        "merged": False,
    }
    client.update_vulnerability_hypothesis.return_value = {
        "updated": True,
    }
    client.create_logic_group.return_value = {
        "id": "dir_mock_12345678",
        "created": True,
    }
    return client


class TestVHCreateContextFlow:
    """
    VHG agent calls create_vulnerability_hypothesis_impl().
    Verify that AnalysisClient.create_vulnerability_hypothesis() receives
    the correct harness_name, sanitizer, lg_id, agent_id from context.

    Real scenario: pipeline sets VH context for each logic group,
    VHG agent creates VHs, each VH must be tagged correctly.
    """

    @patch("fuzzingbrain.tools.vulnerability_hypotheses._get_client")
    @patch("fuzzingbrain.tools.vulnerability_hypotheses._ensure_client", return_value=None)
    def test_create_vh_carries_full_context(self, _ensure, mock_get_client):
        """
        VHG agent for Logic group "chunk_handlers" creates a VH.
        The AnalysisClient must receive all 4 context values.
        """
        client = _mock_client()
        mock_get_client.return_value = client

        set_vh_context(
            harness_name="fuzz_png",
            sanitizer="address",
            lg_id="dir_chunk_handlers",
            agent_id="agent_vhg_001",
        )

        result = create_vulnerability_hypothesis_impl(
            function_name="png_read_chunk",
            description="Unbounded memcpy from chunk data",
            score=0.8,
        )

        assert result["success"] is True
        kw = client.create_vulnerability_hypothesis.call_args[1]
        assert kw["harness_name"] == "fuzz_png"
        assert kw["sanitizer"] == "address"
        assert kw["lg_id"] == "dir_chunk_handlers"
        assert kw["agent_id"] == "agent_vhg_001"
        assert kw["function_name"] == "png_read_chunk"

    def test_phase1_parallel_vhg_agents_share_logic_group_context(self):
        """
        poc_fullscan Phase 1: set_vh_context() once for a logic group,
        then 3 VHG mini-agents analyze functions concurrently via asyncio.gather.
        All 3 VHs must carry the same lg_id.

        Real code: poc_fullscan.py:402-440
          set_vh_context(fuzzer, sanitizer, lg_id)
          tasks = [analyze_function(func, i) for i, func in enumerate(functions)]
          await asyncio.gather(*tasks)
        """
        captured = {}

        async def _run():
            # Phase 1 sets context once for the logic group (poc_fullscan.py:404)
            set_vh_context(
                harness_name="fuzz_png",
                sanitizer="address",
                lg_id="dir_chunk_handlers",
                agent_id="phase1_vhg",
            )

            events = [asyncio.Event() for _ in range(3)]

            async def vhg_mini_agent(func_name, my_idx):
                # Wait for all agents to be ready
                events[my_idx].set()
                for e in events:
                    await e.wait()

                mock_client = _mock_client()
                with (
                    patch(
                        "fuzzingbrain.tools.vulnerability_hypotheses._get_client",
                        return_value=mock_client,
                    ),
                    patch(
                        "fuzzingbrain.tools.vulnerability_hypotheses._ensure_client",
                        return_value=None,
                    ),
                ):
                    create_vulnerability_hypothesis_impl(
                        function_name=func_name,
                        description=f"Bug in {func_name}",
                    )
                    captured[func_name] = mock_client.create_vulnerability_hypothesis.call_args[
                        1
                    ]

            await asyncio.gather(
                vhg_mini_agent("png_read_chunk", 0),
                vhg_mini_agent("png_handle_IDAT", 1),
                vhg_mini_agent("png_read_PLTE", 2),
            )

        asyncio.run(_run())

        # All 3 VHs must carry the same logic group set once at Phase 1 start
        for func_name in ["png_read_chunk", "png_handle_IDAT", "png_read_PLTE"]:
            assert captured[func_name]["lg_id"] == "dir_chunk_handlers", (
                f"{func_name}'s VH tagged to '{captured[func_name]['lg_id']}' "
                f"— should be 'dir_chunk_handlers'"
            )
            assert captured[func_name]["harness_name"] == "fuzz_png"


class TestVHUpdateContextFlow:
    """
    VHV agent calls update_vulnerability_hypothesis_impl().
    Verify that AnalysisClient.update_vulnerability_hypothesis() receives
    the VHV's agent_id (not VHG's).

    Real scenario: VHG creates VH with agent_id="vhg_001",
    then VHV verifies it with agent_id="vhv_001".
    The update must carry "vhv_001" so we know WHO verified the VH.
    """

    @patch("fuzzingbrain.tools.vulnerability_hypotheses._get_client")
    @patch("fuzzingbrain.tools.vulnerability_hypotheses._ensure_client", return_value=None)
    def test_update_vh_carries_verifier_agent_id(self, _ensure, mock_get_client):
        """
        VHV verifies a VH as real and important.
        The AnalysisClient must receive the VHV's agent_id.
        """
        client = _mock_client()
        mock_get_client.return_value = client

        set_vh_context(
            harness_name="fuzz_png",
            sanitizer="address",
            lg_id="dir_chunk",
            agent_id="agent_vhv_001",
        )

        result = update_vulnerability_hypothesis_impl(
            vulnerability_hypothesis_id="vh_abc12345",
            is_checked_by_verifier=True,
            is_crash_found=True,
            pattern="confirmed",
            verification_notes="Confirmed: no bounds check before memcpy",
            poc_guidance="Send chunk with length > 4096",
        )

        assert result["success"] is True
        kw = client.update_vulnerability_hypothesis.call_args[1]
        assert kw["agent_id"] == "agent_vhv_001"
        assert kw["vh_id"] == "vh_abc12345"
        assert kw["is_checked_by_verifier"] is True
        assert kw["is_crash_found"] is True

    @patch("fuzzingbrain.tools.vulnerability_hypotheses._get_client")
    @patch("fuzzingbrain.tools.vulnerability_hypotheses._ensure_client", return_value=None)
    def test_sequential_vhg_then_vhv_agent_id_switches(self, _ensure, mock_get_client):
        """
        VHG creates VH → VHV updates VH. Both in same asyncio Task (sequential).
        Pipeline calls set_vh_agent_id() between them.

        The create must carry VHG's agent_id.
        The update must carry VHV's agent_id — not VHG's.

        This is the real pattern in pipeline._run_verify_agent().
        """
        client = _mock_client()
        mock_get_client.return_value = client

        # --- Phase 1: VHG agent creates VH ---
        set_vh_context(
            harness_name="fuzz_png",
            sanitizer="address",
            lg_id="dir_chunk",
            agent_id="agent_vhg_001",
        )
        create_vulnerability_hypothesis_impl(
            function_name="parse_chunk",
            description="memcpy without bounds check",
        )

        create_kw = client.create_vulnerability_hypothesis.call_args[1]
        assert create_kw["agent_id"] == "agent_vhg_001"

        # --- Phase 2: VHV takes over (same Task, sequential) ---
        # Pipeline calls set_vh_agent_id() in BaseAgent.run_async()
        set_vh_agent_id("agent_vhv_001")

        update_vulnerability_hypothesis_impl(
            vulnerability_hypothesis_id="vh_abc12345",
            is_checked_by_verifier=True,
            is_crash_found=False,
            verification_notes="False positive: length validated in caller",
        )

        update_kw = client.update_vulnerability_hypothesis.call_args[1]
        assert update_kw["agent_id"] == "agent_vhv_001", (
            f"VHV update carried agent_id='{update_kw['agent_id']}' — "
            f"leaked from VHG (expected 'agent_vhv_001')"
        )


class TestLogicGroupContextFlow:
    """
    Logic group planner calls create_logic_group_impl().
    Verify that AnalysisClient.create_logic_group() receives
    the correct fuzzer from logic group context.

    Real scenario: pipeline sets logic_group_context("fuzz_png") before
    running the logic group planner. Planner creates logic groups,
    each tagged with the fuzzer it analyzes.
    """

    @patch("fuzzingbrain.tools.logic_groups._get_client")
    @patch("fuzzingbrain.tools.logic_groups._ensure_client", return_value=None)
    def test_create_logic_group_carries_fuzzer_context(self, _ensure, mock_get_client):
        """
        Logic group planner creates a "chunk_handlers" logic group.
        The AnalysisClient must receive fuzzer="fuzz_png" from context.
        """
        client = _mock_client()
        mock_get_client.return_value = client

        set_logic_group_context("fuzz_png")

        result = create_logic_group_impl(
            name="chunk_handlers",
            risk_level="high",
            risk_reason="Direct parsing of untrusted PNG chunk data",
            core_functions=["png_read_chunk", "png_handle_IDAT"],
        )

        assert result["success"] is True
        kw = client.create_logic_group.call_args[1]
        assert kw["fuzzer"] == "fuzz_png"
        assert kw["name"] == "chunk_handlers"
        assert kw["risk_level"] == "high"

    @patch("fuzzingbrain.tools.logic_groups._get_client")
    @patch("fuzzingbrain.tools.logic_groups._ensure_client", return_value=None)
    def test_planner_creates_multiple_logic_groups_same_fuzzer(
        self, _ensure, mock_get_client
    ):
        """
        Logic group planner creates 3 logic groups in one session.
        All must carry the same fuzzer="fuzz_png" from context.

        Real scenario: planner analyzes call graph, creates logic groups:
        "chunk_handlers" (high), "color_management" (medium), "text_metadata" (low).
        All belong to the same fuzzer.
        """
        client = _mock_client()
        mock_get_client.return_value = client

        set_logic_group_context("fuzz_png")

        logic_groups = [
            ("chunk_handlers", "high", "Direct parsing of untrusted chunk data"),
            ("color_management", "medium", "ICC profile processing with complex math"),
            ("text_metadata", "low", "Text field parsing, mostly safe string ops"),
        ]

        for name, risk, reason in logic_groups:
            create_logic_group_impl(
                name=name,
                risk_level=risk,
                risk_reason=reason,
                core_functions=[f"{name}_func_1", f"{name}_func_2"],
            )

        # All 3 calls must have carried fuzzer="fuzz_png"
        assert client.create_logic_group.call_count == 3
        for call in client.create_logic_group.call_args_list:
            kw = call[1]
            assert kw["fuzzer"] == "fuzz_png", (
                f"Logic group '{kw['name']}' got fuzzer='{kw['fuzzer']}' — "
                f"expected 'fuzz_png' from context"
            )


class TestParallelAgentToolCalls:
    """
    Parallel agents in asyncio.gather() call tool functions concurrently.
    Each agent's tool calls must carry its own context, not the other's.

    Real scenario: _run_verify_agent("verify_1") || _run_verify_agent("verify_2")
    verify_1 processes VHs for "dir_chunk", verify_2 for "dir_icc".
    If context leaks, VHs get tagged to the wrong logic group in the database.
    """

    def test_parallel_create_vh_carries_correct_logic_group(self):
        """
        Two verify agents run concurrently, each creates a VH.
        verify_1's VH must have lg_id="dir_chunk".
        verify_2's VH must have lg_id="dir_icc".

        Cross-contamination here = VHs tagged to wrong logic group = wrong analysis.
        """
        captured = {}

        async def _run():
            event_1 = asyncio.Event()
            event_2 = asyncio.Event()

            async def verify_agent(name, lg_id, my_event, other_event):
                set_vh_context(
                    harness_name="fuzz_png",
                    sanitizer="address",
                    lg_id=lg_id,
                    agent_id=name,
                )
                my_event.set()
                await other_event.wait()

                # Both contexts are set — now call tool function
                mock_client = _mock_client()
                with (
                    patch(
                        "fuzzingbrain.tools.vulnerability_hypotheses._get_client",
                        return_value=mock_client,
                    ),
                    patch(
                        "fuzzingbrain.tools.vulnerability_hypotheses._ensure_client",
                        return_value=None,
                    ),
                ):
                    create_vulnerability_hypothesis_impl(
                        function_name=f"func_{name}",
                        description="test",
                    )
                    captured[name] = mock_client.create_vulnerability_hypothesis.call_args[1]

            await asyncio.gather(
                verify_agent("verify_1", "dir_chunk", event_1, event_2),
                verify_agent("verify_2", "dir_icc", event_2, event_1),
            )

        asyncio.run(_run())

        assert captured["verify_1"]["lg_id"] == "dir_chunk", (
            f"verify_1's VH tagged to '{captured['verify_1']['lg_id']}' — "
            f"leaked from verify_2"
        )
        assert captured["verify_1"]["agent_id"] == "verify_1"

        assert captured["verify_2"]["lg_id"] == "dir_icc", (
            f"verify_2's VH tagged to '{captured['verify_2']['lg_id']}' — "
            f"leaked from verify_1"
        )
        assert captured["verify_2"]["agent_id"] == "verify_2"

    def test_vh_find_and_verify_pipeline_concurrent(self):
        """
        VH Find (Phase 1/2) creates VHs while verify pipeline updates VHs.
        Both run as concurrent asyncio Tasks (poc_fullscan.py:361-387):
          pipeline_task = asyncio.create_task(pipeline.run())
          await _run_phase1_small_pool(...)   # creates VHs
          await _run_phase2_big_pool(...)     # creates more VHs

        VH Find's create_vh must carry agent_id="phase1_vhg".
        Verify's update_vh must carry agent_id="verify_1".
        Neither should see the other's context.
        """
        captured = {}

        async def _run():
            event_1 = asyncio.Event()
            event_2 = asyncio.Event()

            async def vh_find_phase(my_event, other_event):
                # VH Find sets its own context (poc_fullscan.py:404)
                set_vh_context(
                    harness_name="fuzz_png",
                    sanitizer="address",
                    lg_id="dir_chunk",
                    agent_id="phase1_vhg",
                )
                my_event.set()
                await other_event.wait()

                mock_client = _mock_client()
                with (
                    patch(
                        "fuzzingbrain.tools.vulnerability_hypotheses._get_client",
                        return_value=mock_client,
                    ),
                    patch(
                        "fuzzingbrain.tools.vulnerability_hypotheses._ensure_client",
                        return_value=None,
                    ),
                ):
                    create_vulnerability_hypothesis_impl(
                        function_name="png_read_chunk",
                        description="New VH from Phase 1",
                    )
                    captured["vh_find"] = mock_client.create_vulnerability_hypothesis.call_args[
                        1
                    ]

            async def verify_pipeline(my_event, other_event):
                # Verify agent sets its own context (pipeline.py:231)
                set_vh_context(
                    harness_name="fuzz_png",
                    sanitizer="address",
                    lg_id="dir_icc",
                    agent_id="verify_1",
                )
                my_event.set()
                await other_event.wait()

                mock_client = _mock_client()
                with (
                    patch(
                        "fuzzingbrain.tools.vulnerability_hypotheses._get_client",
                        return_value=mock_client,
                    ),
                    patch(
                        "fuzzingbrain.tools.vulnerability_hypotheses._ensure_client",
                        return_value=None,
                    ),
                ):
                    update_vulnerability_hypothesis_impl(
                        vulnerability_hypothesis_id="vh_earlier_001",
                        is_checked_by_verifier=True,
                        is_crash_found=True,
                        pattern="confirmed",
                        verification_notes="Confirmed from earlier VH",
                        poc_guidance="Craft ICC profile",
                    )
                    captured["verify"] = mock_client.update_vulnerability_hypothesis.call_args[
                        1
                    ]

            await asyncio.gather(
                vh_find_phase(event_1, event_2),
                verify_pipeline(event_2, event_1),
            )

        asyncio.run(_run())

        # VH Find created VH with its own context
        assert captured["vh_find"]["agent_id"] == "phase1_vhg"
        assert captured["vh_find"]["lg_id"] == "dir_chunk"
        # Verify pipeline updated VH with its own context
        assert captured["verify"]["agent_id"] == "verify_1"
        assert captured["verify"]["vh_id"] == "vh_earlier_001"


class TestContextLeakBetweenPipelinePhases:
    """
    Pipeline runs phases sequentially in the same asyncio Task:
    1. VHG for Logic group-1 → creates VHs
    2. VHG for Logic group-2 → creates VHs

    Risk: Logic group-2's VHG forgets full context reset,
    its VHs get tagged to Logic group-1's lg_id.
    """

    @patch("fuzzingbrain.tools.vulnerability_hypotheses._get_client")
    @patch("fuzzingbrain.tools.vulnerability_hypotheses._ensure_client", return_value=None)
    def test_set_vh_agent_id_preserves_logic_group(self, _ensure, mock_get_client):
        """
        set_vh_agent_id() does NOT clear lg_id (needed for VHG agents).
        Access control for VHVerifier/POCAgent is handled at agent level
        via include_vh_create_tools, not in the tool itself.
        """
        client = _mock_client()
        mock_get_client.return_value = client

        # --- VH Finding phase: lg_id is set ---
        set_vh_context(
            harness_name="fuzz_png",
            sanitizer="address",
            lg_id="dir_chunk",
            agent_id="vhg_dir1",
        )
        result1 = create_vulnerability_hypothesis_impl(
            function_name="parse_chunk",
            description="test",
        )
        assert result1["success"] is True
        kw_dir1 = client.create_vulnerability_hypothesis.call_args[1]
        assert kw_dir1["lg_id"] == "dir_chunk"

        # set_vh_agent_id preserves lg_id (needed for VHG agents)
        set_vh_agent_id("vhg_dir2")
        from fuzzingbrain.tools.vulnerability_hypotheses import get_vh_context

        _, _, lg_id, agent_id = get_vh_context()
        assert lg_id == "dir_chunk", (
            "set_vh_agent_id must NOT clear lg_id"
        )
        assert agent_id == "vhg_dir2"

    @patch("fuzzingbrain.tools.vulnerability_hypotheses._get_client")
    @patch("fuzzingbrain.tools.vulnerability_hypotheses._ensure_client", return_value=None)
    def test_set_vh_context_resets_logic_group_correctly(self, _ensure, mock_get_client):
        """
        Using full set_vh_context() between logic groups correctly
        resets lg_id — no leak.
        """
        client = _mock_client()
        mock_get_client.return_value = client

        # --- Logic group-1 ---
        set_vh_context(
            harness_name="fuzz_png",
            sanitizer="address",
            lg_id="dir_chunk",
            agent_id="vhg_dir1",
        )
        create_vulnerability_hypothesis_impl(
            function_name="parse_chunk",
            description="test",
        )

        # --- Logic group-2 with full context reset ---
        set_vh_context(
            harness_name="fuzz_png",
            sanitizer="address",
            lg_id="dir_icc",
            agent_id="vhg_dir2",
        )
        create_vulnerability_hypothesis_impl(
            function_name="parse_icc",
            description="test",
        )
        kw_fixed = client.create_vulnerability_hypothesis.call_args[1]
        assert kw_fixed["lg_id"] == "dir_icc"

    def test_parallel_verify_and_poc_update_isolated(self):
        """
        Verifier and PoC agent run concurrently, both call update_vh_impl.
        Verifier updates VH-1 with agent_id="verify_1".
        PoC agent updates VH-2 with agent_id="poc_1".

        Cross-contamination = wrong agent_id in verified_by field.
        """
        captured = {}

        async def _run():
            event_1 = asyncio.Event()
            event_2 = asyncio.Event()

            async def verifier(my_event, other_event):
                set_vh_context(
                    harness_name="fuzz_png",
                    sanitizer="address",
                    lg_id="dir_chunk",
                    agent_id="verify_1",
                )
                my_event.set()
                await other_event.wait()

                mock_client = _mock_client()
                with (
                    patch(
                        "fuzzingbrain.tools.vulnerability_hypotheses._get_client",
                        return_value=mock_client,
                    ),
                    patch(
                        "fuzzingbrain.tools.vulnerability_hypotheses._ensure_client",
                        return_value=None,
                    ),
                ):
                    update_vulnerability_hypothesis_impl(
                        vulnerability_hypothesis_id="vh_001",
                        is_checked_by_verifier=True,
                        is_crash_found=True,
                        pattern="confirmed",
                        verification_notes="Confirmed buffer overflow",
                        poc_guidance="Oversize chunk length",
                    )
                    captured["verifier"] = (
                        mock_client.update_vulnerability_hypothesis.call_args[1]
                    )

            async def poc_agent(my_event, other_event):
                set_vh_context(
                    harness_name="fuzz_png",
                    sanitizer="address",
                    lg_id="dir_icc",
                    agent_id="poc_1",
                )
                my_event.set()
                await other_event.wait()

                mock_client = _mock_client()
                with (
                    patch(
                        "fuzzingbrain.tools.vulnerability_hypotheses._get_client",
                        return_value=mock_client,
                    ),
                    patch(
                        "fuzzingbrain.tools.vulnerability_hypotheses._ensure_client",
                        return_value=None,
                    ),
                ):
                    update_vulnerability_hypothesis_impl(
                        vulnerability_hypothesis_id="vh_002",
                        is_checked_by_verifier=True,
                        is_crash_found=True,
                        pattern="confirmed",
                        verification_notes="Also confirmed",
                        poc_guidance="Crafted ICC profile",
                    )
                    captured["poc"] = mock_client.update_vulnerability_hypothesis.call_args[1]

            await asyncio.gather(
                verifier(event_1, event_2),
                poc_agent(event_2, event_1),
            )

        asyncio.run(_run())

        assert captured["verifier"]["agent_id"] == "verify_1"
        assert captured["verifier"]["vh_id"] == "vh_001"
        assert captured["poc"]["agent_id"] == "poc_1"
        assert captured["poc"]["vh_id"] == "vh_002"

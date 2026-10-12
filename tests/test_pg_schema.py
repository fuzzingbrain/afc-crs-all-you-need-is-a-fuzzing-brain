# SPDX-License-Identifier: Apache-2.0
"""The PostgreSQL schema: the migration matches the models, and each
constraint refuses what docs/db-design.md says it must.

A constraint that is written down but not enforced is worse than none: the
code goes on trusting it. So every rule here is checked by trying to break it.
"""

import hashlib
import threading
import uuid

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, func, insert, select, text, update
from sqlalchemy.dialects.postgresql import UUID, insert as pg_insert
from sqlalchemy.exc import IntegrityError

from fuzzingbrain.db.pg import Base, alembic_config, migrate
from fuzzingbrain.db.pg.models import (
    Agent,
    Crash,
    FunctionAnalysis,
    Harness,
    HarnessBinary,
    LLMCall,
    LLMMessage,
    LogicGroup,
    PocAttempt,
    Run,
    ToolCall,
    VulnerabilityHypothesis,
    Worker,
)


# --- fixtures ---------------------------------------------------------------


@pytest.fixture(scope="module")
def schema_url(pg_server):
    """One migrated database shared by the module; tests roll back."""
    import psycopg

    name = f"fb_schema_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(pg_server, autocommit=True) as conn:
        conn.execute(f'CREATE DATABASE "{name}"')
    url = pg_server.rsplit("/", 1)[0].replace(
        "postgresql://", "postgresql+psycopg://", 1
    ) + f"/{name}"
    migrate(url)
    yield url
    with psycopg.connect(pg_server, autocommit=True) as conn:
        conn.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


@pytest.fixture
def conn(schema_url):
    """A connection inside a transaction that is rolled back afterwards."""
    engine = create_engine(schema_url)
    with engine.connect() as connection:
        outer = connection.begin()
        yield connection
        outer.rollback()
    engine.dispose()


def refused(conn, stmt):
    """True if the database rejects ``stmt`` with an integrity error.

    References are checked at commit; they are forced here so a dangling one
    counts too, then deferred again for the rest of the test.
    """
    savepoint = conn.begin_nested()
    try:
        conn.execute(stmt)
        conn.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))
    except IntegrityError:
        savepoint.rollback()
        return True
    finally:
        conn.execute(text("SET CONSTRAINTS ALL DEFERRED"))
    savepoint.rollback()
    return False


# --- rows -------------------------------------------------------------------


def _id():
    return uuid.uuid4()


def add(conn, mapped, /, **values):
    """Insert one row and return its id (generated server-side for bigint ids)."""
    if isinstance(mapped.__table__.c.id.type, UUID):
        values.setdefault("id", _id())
    return conn.execute(insert(mapped).values(**values).returning(mapped.id)).scalar_one()


def a_run(conn, **over):
    values = dict(project_name="libpng", task_type="poc", scan_mode="full",
                  status="running", config={}, config_given={},
                  workspace_path="/tmp/ws")
    values.update(over)
    return add(conn, Run, **values)


def a_harness(conn, run_id, sanitizers=("address",)):
    harness_id = add(conn, Harness, run_id=run_id, name=f"h_{_id().hex[:6]}",
                     source_path="fuzz/h.c")
    for san in sanitizers:
        conn.execute(insert(HarnessBinary).values(
            harness_id=harness_id, sanitizer=san, binary_path=f"/out/{san}/h"))
    return harness_id


def a_worker(conn, run_id, harness_id):
    return add(conn, Worker, run_id=run_id, harness_id=harness_id,
               status="running", workspace_path="/tmp/ws/w")


def an_agent(conn, run_id, worker_id, agent_type="POCAgent", **over):
    values = dict(run_id=run_id, worker_id=worker_id, agent_type=agent_type,
                  status="running")
    values.update(over)
    return add(conn, Agent, **values)


def a_vh(conn, run_id, worker_id, **over):
    values = dict(run_id=run_id, worker_id=worker_id, function_file="png.c",
                  function_name="png_read_row", finder_description="d",
                  description="d", finder_score=0.6, score=0.6,
                  status="pending_verify")
    values.update(over)
    return add(conn, VulnerabilityHypothesis, **values)


@pytest.fixture
def world(conn):
    """A run with one harness (ASan only), its worker and a VH."""
    run_id = a_run(conn)
    harness_id = a_harness(conn, run_id)
    worker_id = a_worker(conn, run_id, harness_id)
    vh_id = a_vh(conn, run_id, worker_id)
    return dict(run=run_id, harness=harness_id, worker=worker_id, vh=vh_id)


def an_attempt_values(world, by, **over):
    """A VH-agent attempt by agent ``by``; ``over`` replaces any column."""
    values = dict(id=_id(), run_id=world["run"], vh_id=world["vh"],
                  worker_id=world["worker"], agent_id=by, source="vh_agent",
                  harness_id=world["harness"], sanitizer="address", attempt=1,
                  variant=1, blob=b"x", blob_sha256="s", generator_code="def g(): ...",
                  status="no_crash")
    values.update(over)
    return values


# --- the migration ----------------------------------------------------------


def test_the_migration_builds_exactly_the_models(schema_url):
    engine = create_engine(schema_url)
    with engine.connect() as connection:
        ctx = MigrationContext.configure(connection, opts={"compare_type": True})
        assert compare_metadata(ctx, Base.metadata) == []
    engine.dispose()


def test_the_cycle_foreign_keys_exist(schema_url):
    """create_table drops use_alter keys silently; the migration adds them."""
    engine = create_engine(schema_url)
    with engine.connect() as connection:
        names = set(connection.scalars(text(
            "SELECT conname FROM pg_constraint WHERE contype = 'f'")))
    engine.dispose()
    assert {"fk_crashes_first_attempt_id_poc_attempts", "fk_agents_crash_id_crashes",
            "fk_agents_lg_id_logic_groups",
            "fk_agents_vh_id_vulnerability_hypotheses"} <= names


def test_downgrade_removes_every_table_and_upgrade_restores_them(fresh_pg):
    migrate(fresh_pg)
    command.downgrade(alembic_config(fresh_pg), "base")
    engine = create_engine(fresh_pg)
    with engine.connect() as connection:
        left = set(connection.scalars(text(
            "SELECT table_name FROM information_schema.tables"
            " WHERE table_schema = 'public'")))
    assert left == {"alembic_version"}
    migrate(fresh_pg)
    with engine.connect() as connection:
        ctx = MigrationContext.configure(connection)
        assert compare_metadata(ctx, Base.metadata) == []
    engine.dispose()


def test_a_dangling_reference_is_refused_at_commit(schema_url):
    """References are checked at commit (so a run's cascade can finish), but
    they are still checked."""
    engine = create_engine(schema_url)
    with pytest.raises(IntegrityError, match="fk_agents_vh_id"):
        with engine.begin() as c:
            run_id = a_run(c)
            worker_id = a_worker(c, run_id, a_harness(c, run_id))
            an_agent(c, run_id, worker_id, "VHVerifier", vh_id=_id())
    with engine.connect() as c:
        assert c.scalar(select(func.count()).select_from(Run)) == 0
    engine.dispose()


# --- runs, workers, agents --------------------------------------------------


def test_end_reason_exists_exactly_when_completed(conn):
    assert refused(conn, insert(Run).values(
        id=_id(), project_name="p", task_type="poc", scan_mode="full",
        status="completed", config={}, config_given={}, workspace_path="/w"))
    assert refused(conn, insert(Run).values(
        id=_id(), project_name="p", task_type="poc", scan_mode="full",
        status="running", end_reason="timeout", config={}, config_given={},
        workspace_path="/w"))
    a_run(conn, status="completed", end_reason="timeout")


def test_error_holds_a_traceback_exactly_when_status_is_error(conn):
    assert refused(conn, insert(Run).values(
        id=_id(), project_name="p", task_type="poc", scan_mode="full",
        status="error", config={}, config_given={}, workspace_path="/w"))
    a_run(conn, status="error", error="Traceback ...")


def test_one_worker_per_harness(conn, world):
    assert refused(conn, insert(Worker).values(
        id=_id(), run_id=world["run"], harness_id=world["harness"],
        status="queued", workspace_path="/w"))


def test_a_worker_end_reason_includes_work_done(conn, world):
    conn.execute(update(Worker).where(Worker.id == world["worker"]).values(
        status="completed", end_reason="work_done"))


def test_only_a_report_agent_runs_outside_a_worker(conn, world):
    assert refused(conn, insert(Agent).values(
        id=_id(), run_id=world["run"], agent_type="LGPlanningAgent",
        status="running"))


def test_agents_point_at_what_their_type_works_on(conn, world):
    run, worker = world["run"], world["worker"]
    # a verifier needs its VH; a planner may not have one
    assert refused(conn, insert(Agent).values(
        id=_id(), run_id=run, worker_id=worker, agent_type="VHVerifier",
        status="running"))
    assert refused(conn, insert(Agent).values(
        id=_id(), run_id=run, worker_id=worker, agent_type="LGPlanningAgent",
        vh_id=world["vh"], status="running"))
    # a full-scan finder needs its function and logic group
    assert refused(conn, insert(Agent).values(
        id=_id(), run_id=run, worker_id=worker, agent_type="FullVHGenerator",
        status="running"))
    # a report agent needs its crash
    assert refused(conn, insert(Agent).values(
        id=_id(), run_id=run, agent_type="POCReportAgent", status="running"))
    an_agent(conn, run, worker, "VHVerifier", vh_id=world["vh"])


def test_an_agent_that_ran_out_of_turns_is_completed_not_failed(conn, world):
    agent_id = an_agent(conn, world["run"], world["worker"], vh_id=world["vh"])
    conn.execute(update(Agent).where(Agent.id == agent_id).values(
        status="completed", end_reason="max_iterations", iterations=100))


# --- logic groups and function analysis -------------------------------------


def _a_logic_group(conn, world):
    planner = an_agent(conn, world["run"], world["worker"], "LGPlanningAgent")
    return add(conn, LogicGroup, run_id=world["run"], worker_id=world["worker"],
               created_by_agent_id=planner, name="decode", risk_level="high",
               core_functions=["png_read_row"], entry_functions=[])


def test_a_function_is_recorded_once_per_logic_group(conn, world):
    lg = _a_logic_group(conn, world)
    finder = an_agent(conn, world["run"], world["worker"], "FullVHGenerator",
                      function_file="png.c", function_name="f",
                      function_start_line=10, lg_id=lg)
    row = dict(lg_id=lg, function_file="png.c", function_name="f",
               function_start_line=10, function_end_line=20, agent_id=finder)
    conn.execute(insert(FunctionAnalysis).values(**row))
    assert refused(conn, insert(FunctionAnalysis).values(**row))
    # the same name at another line is another function (an overload)
    conn.execute(insert(FunctionAnalysis).values(**{**row, "function_start_line": 30,
                                                     "function_end_line": 40}))


# --- vulnerability hypotheses -----------------------------------------------


@pytest.mark.parametrize("column, value", [
    ("score", 1.5), ("finder_score", -0.1), ("status", "verified"),
    ("sanitizer", "thread")])
def test_a_vh_refuses_out_of_range_values(conn, world, column, value):
    assert refused(conn, update(VulnerabilityHypothesis).where(
        VulnerabilityHypothesis.id == world["vh"]).values({column: value}))


def test_a_sink_line_needs_the_quoted_sink(conn, world):
    assert refused(conn, update(VulnerabilityHypothesis).where(
        VulnerabilityHypothesis.id == world["vh"]).values(sink_line=42))


def test_only_an_injected_vh_may_lack_the_sink(conn, world):
    finder = an_agent(conn, world["run"], world["worker"], "DeltaVHGenerator")
    assert refused(conn, insert(VulnerabilityHypothesis).values(
        id=_id(), run_id=world["run"], worker_id=world["worker"],
        created_by_agent_id=finder, function_file="png.c",
        function_name="png_read_row", finder_description="d", description="d",
        finder_score=0.6, score=0.6, status="pending_verify"))
    a_vh(conn, world["run"], world["worker"], created_by_agent_id=finder,
         sink_code="memcpy(buf, src, len);")


def test_a_vh_status_moves_only_from_the_state_it_was_in(conn, world):
    """The conditional update that replaces claiming: one of two wins."""
    claim = update(VulnerabilityHypothesis).where(
        VulnerabilityHypothesis.id == world["vh"],
        VulnerabilityHypothesis.status == "pending_verify",
    ).values(status="verifying")
    assert conn.execute(claim).rowcount == 1
    assert conn.execute(claim).rowcount == 0


# --- PoC attempts and crashes -----------------------------------------------


def test_an_attempt_must_run_on_a_binary_that_was_built(conn, world):
    agent_id = an_agent(conn, world["run"], world["worker"], vh_id=world["vh"])
    assert refused(conn, insert(PocAttempt).values(
        **an_attempt_values(world, agent_id, sanitizer="undefined")))
    conn.execute(insert(PocAttempt).values(**an_attempt_values(world, agent_id)))
    # and that binary cannot be removed from under the attempt
    assert refused(conn, HarnessBinary.__table__.delete().where(
        HarnessBinary.harness_id == world["harness"]))


def test_each_source_fills_its_own_columns(conn, world):
    agent_id = an_agent(conn, world["run"], world["worker"], vh_id=world["vh"])
    fuzzer_only = dict(vh_id=None, agent_id=None, worker_id=None, attempt=None,
                       variant=None, generator_code=None)
    conn.execute(insert(PocAttempt).values(**an_attempt_values(
        world, agent_id, source="global_fuzzer", **fuzzer_only)))
    # a global-fuzzer input belongs to no VH
    assert refused(conn, insert(PocAttempt).values(**an_attempt_values(
        world, agent_id, source="global_fuzzer",
        **{**fuzzer_only, "vh_id": world["vh"]})))
    # a VH agent input says which attempt and variant it was
    assert refused(conn, insert(PocAttempt).values(
        **an_attempt_values(world, agent_id, attempt=None)))


def test_a_crashed_attempt_names_its_crash_and_keeps_the_report(conn, world):
    agent_id = an_agent(conn, world["run"], world["worker"], vh_id=world["vh"])
    assert refused(conn, insert(PocAttempt).values(**an_attempt_values(
        world, agent_id, status="crashed", sanitizer_output="==1==ERROR")))
    attempt = add(conn, PocAttempt, **an_attempt_values(world, agent_id, status="pending"))
    crash = add(conn, Crash, run_id=world["run"], signature="sig",
                vuln_type="unknown", first_attempt_id=attempt)
    conn.execute(update(PocAttempt).where(PocAttempt.id == attempt).values(
        status="crashed", crash_id=crash, sanitizer_output="==1==ERROR"))
    assert refused(conn, update(PocAttempt).where(PocAttempt.id == attempt).values(
        sanitizer_output=None))


def test_identical_crashes_arriving_together_make_one_crash(fresh_pg):
    """ON CONFLICT is the whole dedup: no read-then-write window."""
    migrate(fresh_pg)
    engine = create_engine(fresh_pg, pool_size=10)
    with engine.begin() as c:
        world = {"run": a_run(c)}
        world["harness"] = a_harness(c, world["run"])
        world["worker"] = a_worker(c, world["run"], world["harness"])
        world["vh"] = a_vh(c, world["run"], world["worker"])
        agent_id = an_agent(c, world["run"], world["worker"], vh_id=world["vh"])
        attempts = [add(c, PocAttempt, **an_attempt_values(
            world, agent_id, status="pending", variant=n)) for n in range(8)]

    barrier = threading.Barrier(len(attempts))
    errors = []

    def report(attempt_id):
        try:
            with engine.begin() as c:
                barrier.wait(timeout=30)
                c.execute(pg_insert(Crash).values(
                    id=_id(), run_id=world["run"], signature="heap-overflow@png_read_row",
                    vuln_type="heap-buffer-overflow", first_attempt_id=attempt_id,
                ).on_conflict_do_nothing(index_elements=["run_id", "signature"]))
                crash_id = c.scalar(select(Crash.id).where(
                    Crash.run_id == world["run"],
                    Crash.signature == "heap-overflow@png_read_row"))
                c.execute(update(PocAttempt).where(PocAttempt.id == attempt_id).values(
                    status="crashed", crash_id=crash_id, sanitizer_output="==1==ERROR"))
        except Exception as e:  # surfaced below; a thread cannot fail the test
            errors.append(e)

    threads = [threading.Thread(target=report, args=(a,)) for a in attempts]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    assert not errors
    with engine.connect() as c:
        assert c.scalar(select(func.count()).select_from(Crash)) == 1
        assert c.scalar(select(func.count(func.distinct(PocAttempt.crash_id)))) == 1
    engine.dispose()


# --- LLM and tool calls -----------------------------------------------------


def _a_message(conn, run_id, content):
    sha = hashlib.sha256(repr(content).encode()).hexdigest()
    conn.execute(pg_insert(LLMMessage).values(
        run_id=run_id, sha256=sha, role="user", content=content,
    ).on_conflict_do_nothing(index_elements=["run_id", "sha256"]))
    return conn.scalar(select(LLMMessage.id).where(
        LLMMessage.run_id == run_id, LLMMessage.sha256 == sha))


def _call_values(run_id, **over):
    values = dict(run_id=run_id, role="finder", model="m", params={},
                  provider="p", input_tokens=10, output_tokens=5, latency_ms=100,
                  success=False, error_msg="rate limited", input_message_ids=[])
    values.update(over)
    return values


def test_a_message_is_stored_once_per_run(conn, world):
    first = _a_message(conn, world["run"], {"text": "system prompt"})
    again = _a_message(conn, world["run"], {"text": "system prompt"})
    assert first == again
    assert conn.scalar(select(func.count()).select_from(LLMMessage)) == 1


def test_a_call_input_reads_back_in_the_order_it_was_sent(conn, world):
    ids = [_a_message(conn, world["run"], {"n": n}) for n in (3, 1, 2)]
    reply = _a_message(conn, world["run"], {"reply": True})
    call = add(conn, LLMCall, **_call_values(
        world["run"], success=True, error_msg=None, input_message_ids=ids,
        output_message_id=reply))
    sent = conn.execute(text(
        "SELECT m.content FROM llm_calls c,"
        " unnest(c.input_message_ids) WITH ORDINALITY AS t(mid, pos)"
        " JOIN llm_messages m ON m.id = t.mid WHERE c.id = :id ORDER BY t.pos"),
        {"id": call}).scalars().all()
    assert sent == [{"n": 3}, {"n": 1}, {"n": 2}]


def test_unreported_counts_stay_null_and_negative_ones_are_refused(conn, world):
    add(conn, LLMCall, **_call_values(world["run"]))  # no cache / reasoning / cost
    assert refused(conn, insert(LLMCall).values(
        **_call_values(world["run"], cache_read_tokens=-1)))


def test_a_failed_call_may_have_no_tokens_but_a_successful_one_must(conn, world):
    add(conn, LLMCall, **_call_values(
        world["run"], input_tokens=None, output_tokens=None))
    reply = _a_message(conn, world["run"], {"reply": True})
    assert refused(conn, insert(LLMCall).values(**_call_values(
        world["run"], success=True, error_msg=None, output_message_id=reply,
        input_tokens=None)))


def test_a_reply_exists_exactly_when_the_call_succeeded(conn, world):
    reply = _a_message(conn, world["run"], {"reply": True})
    assert refused(conn, insert(LLMCall).values(**_call_values(
        world["run"], success=True, error_msg=None)))
    assert refused(conn, insert(LLMCall).values(**_call_values(
        world["run"], output_message_id=reply)))


def test_a_tool_call_hangs_off_the_llm_call_that_asked_for_it(conn, world):
    call = add(conn, LLMCall, **_call_values(world["run"]))
    conn.execute(insert(ToolCall).values(
        run_id=world["run"], llm_call_id=call, tool_name="read_file",
        success=True, latency_ms=3))
    assert refused(conn, insert(ToolCall).values(
        run_id=world["run"], llm_call_id=call, tool_name="read_file",
        success=True, error="Traceback ...", latency_ms=3))


# --- deleting a run ---------------------------------------------------------


def test_deleting_a_run_deletes_everything_it_produced(fresh_pg):
    migrate(fresh_pg)
    engine = create_engine(fresh_pg)
    with engine.begin() as c:
        world = {"run": a_run(c)}
        world["harness"] = a_harness(c, world["run"], ("address", "undefined"))
        world["worker"] = a_worker(c, world["run"], world["harness"])
        world["vh"] = a_vh(c, world["run"], world["worker"])
        lg = _a_logic_group(c, world)
        finder = an_agent(c, world["run"], world["worker"], "FullVHGenerator",
                          function_file="png.c", function_name="f",
                          function_start_line=1, lg_id=lg)
        c.execute(insert(FunctionAnalysis).values(
            lg_id=lg, function_file="png.c", function_name="f",
            function_start_line=1, function_end_line=2, agent_id=finder))
        poc = an_agent(c, world["run"], world["worker"], vh_id=world["vh"])
        attempt = add(c, PocAttempt, **an_attempt_values(world, poc, status="pending"))
        crash = add(c, Crash, run_id=world["run"], signature="s", vuln_type="unknown",
                    first_attempt_id=attempt)
        c.execute(update(PocAttempt).where(PocAttempt.id == attempt).values(
            status="crashed", crash_id=crash, sanitizer_output="out"))
        an_agent(c, world["run"], None, "POCReportAgent", crash_id=crash)
        msg = _a_message(c, world["run"], {"m": 1})
        call = add(c, LLMCall, **_call_values(world["run"], input_message_ids=[msg]))
        c.execute(insert(ToolCall).values(run_id=world["run"], llm_call_id=call,
                                          tool_name="t", success=True, latency_ms=1))

    with engine.begin() as c:
        c.execute(text("DELETE FROM runs WHERE id = :id"), {"id": world["run"]})

    with engine.connect() as c:
        for table in Base.metadata.sorted_tables:
            assert c.scalar(select(func.count()).select_from(table)) == 0, table.name
    engine.dispose()

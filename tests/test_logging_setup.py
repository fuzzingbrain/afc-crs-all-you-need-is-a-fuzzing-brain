# SPDX-License-Identifier: Apache-2.0
"""Standard-library logging: one configuration per process, files by id."""

import logging

from fuzzingbrain.core import logging as fblog


def test_setup_logging_writes_the_process_file(tmp_path):
    path = fblog.setup_logging(tmp_path / "logs", file_name="workers/w1.log", console=False,
                               header="HEADER")
    try:
        logging.getLogger("fuzzingbrain.worker.x").info("hello from a module")
        logging.getLogger("litellm").info("request noise")
        for h in logging.getLogger().handlers:
            h.flush()
        text = path.read_text()
        assert text.startswith("HEADER")
        assert "hello from a module" in text and "fuzzingbrain.worker.x" in text
        assert "request noise" not in text
        assert fblog.get_log_dir() == tmp_path / "logs"
    finally:
        fblog.setup_logging(None, console=False)
        fblog.set_log_dir(None)


def test_file_logger_does_not_propagate(tmp_path):
    main = fblog.setup_logging(tmp_path, console=False)
    try:
        lg = fblog.file_logger("agent.abc", tmp_path / "agents" / "abc.log", prefix="[PoC-1]")
        lg.info("agent only")
        logging.getLogger("fuzzingbrain.x").info("process only")
        fblog.close_file_logger(lg)
        for h in logging.getLogger().handlers:
            h.flush()
        agent = (tmp_path / "agents" / "abc.log").read_text()
        assert "[PoC-1] | agent only" in agent and "process only" not in agent
        assert "agent only" not in main.read_text()
    finally:
        fblog.setup_logging(None, console=False)
        fblog.set_log_dir(None)


def test_events_without_a_path_are_dropped(tmp_path):
    from fuzzingbrain.core import events

    events.set_events_path(None)
    events.emit("anything", x=1)  # no file, no error
    events.set_events_path(tmp_path / "e.jsonl")
    events.emit("x", run_id="r", n=2, skip=None)
    events.set_events_path(None)
    import json

    rec = json.loads((tmp_path / "e.jsonl").read_text())
    assert rec["event"] == "x" and rec["n"] == 2 and "skip" not in rec

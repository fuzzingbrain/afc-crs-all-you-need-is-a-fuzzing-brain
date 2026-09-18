"""Run script for FuzzingBrain-Bench's `external` arm.

The bench stages a challenge, drops a `./submit <file>` next to it, and runs
this as a plain command in that directory. Submission and grading are already
the bench's: `./submit` is a shell script the agent calls like any other, and a
judge thread on the other side grades each candidate and persists it as it goes.
So there is nothing to implement here for either -- the agent gets them by
having a bash tool, which is the whole reason for this base.

What this script owes the bench:

  * honour the turn and wall-clock budgets it is handed, since the api arm and
    claudecode both do and the comparison is meaningless otherwise;
  * report turns and tokens where the bench looks for them.

Both reports are written after EVERY turn, not at the end. The bench hard-kills
this process on its wall clock with no grace period (by design -- no other arm
gets one), so a report written only on exit is a report lost exactly when the
run was most expensive.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path

import typer

from minisweagent.agents.default import DefaultAgent
from minisweagent.agents.fbbench_coach import Coach, forbidden
from minisweagent.exceptions import Submitted
from minisweagent.config import builtin_config_dir, get_config_from_spec
from minisweagent.environments import get_environment
from minisweagent.models import get_model
from minisweagent.utils.serialize import recursive_merge

DEFAULT_CONFIG_FILE = Path(os.getenv("FBBENCH_CONFIG_PATH", builtin_config_dir / "fbbench.yaml"))

app = typer.Typer(rich_markup_mode="rich", add_completion=False)


def _tokens(agent: DefaultAgent) -> dict:
    """Token counts, summed out of the raw provider responses the model layer
    already keeps on each message.

    litellm normalises usage across providers but not the cache fields, which
    are where nearly all of an Anthropic run's input tokens live -- a measured
    fbagent run read 98.3% of its input from cache. Counting only
    prompt_tokens would price such a run at roughly fifty times its cost.
    """
    inp = out = cache_read = cache_write = 0
    for msg in agent.messages:
        usage = ((msg.get("extra") or {}).get("response") or {}).get("usage") or {}
        if not isinstance(usage, dict):
            continue
        out += int(usage.get("completion_tokens") or 0)
        cr = int((usage.get("prompt_tokens_details") or {}).get("cached_tokens") or 0)
        cw = int(usage.get("cache_creation_input_tokens") or 0)
        cache_read += cr
        cache_write += cw
        # prompt_tokens is the total including the cached prefix; the bench
        # wants them apart, so de-total here rather than setting input_is_total
        # and making the bench guess which of the two cache fields was folded in.
        inp += max(0, int(usage.get("prompt_tokens") or 0) - cr)
    return {"input_tokens": inp, "output_tokens": out,
            "cache_read_tokens": cache_read, "cache_write_tokens": cache_write}


_GRADE_RE = re.compile(r"\brun_poc_on_harness\s*\(?\s*([^)\s]+)")


def tool_label(command: str) -> tuple[str, dict]:
    """What to call this command in the trace, and what its inputs were.

    Everything the agent does is bash, so an unlabelled trace renders as 90
    identical `bash` calls -- where the bare model's report shows `setup`,
    `exec` and `run_poc_on_harness` with the candidate path and the harness
    output. You could not see, from our report, which turn submitted what.

    The command still runs as bash and the budget is unchanged; this only names
    the salient part of a compound command, so the report reads like the arm it
    is being compared against.
    """
    if m := _GRADE_RE.search(command):
        return "run_poc_on_harness", {"path": m.group(1), "command": command}
    return "exec", {"command": command}


def _append(message: dict, text: str) -> None:
    """Add text to an observation, whichever shape its content is in."""
    content = message.get("content")
    if isinstance(content, list):
        for block in reversed(content):
            if isinstance(block, dict) and "text" in block:
                block["text"] = str(block["text"]) + text
                return
        content.append({"type": "text", "text": text})
    else:
        message["content"] = str(content or "") + text


def _text_of(message: dict) -> str:
    """The assistant's prose. `content` is a string for most providers and a
    list of blocks for some, and None when the reply was tool calls only."""
    content = message.get("content")
    if isinstance(content, list):
        return "\n".join(str(b.get("text", "")) for b in content if isinstance(b, dict)).strip()
    return str(content or "").strip()


def _flatten(text: str) -> str:
    """One line, no braces.

    The bench finds the report by scanning stdout for a JSON object, with a
    regex that tolerates ONE level of nesting -- `usage` uses it up. The live
    run died on an API error whose text was itself JSON, so the final report
    was unparseable, silently skipped, and the cell recorded 87 turns for a run
    that reached 88. An error message must not be able to hide the report it
    travels in."""
    return " ".join(str(text).replace("{", "(").replace("}", ")").split())[:400]


def _report(agent: DefaultAgent, model_name: str, stop_reason: str) -> dict:
    return {"stop_reason": _flatten(stop_reason), "turns_used": agent.n_turns,
            "cost_usd": round(agent.cost, 6), "model": model_name,
            # `failed` is the flag a reader needs and could not previously get:
            # the agent catches its own exceptions and exits 0, so a run that
            # died on turn 88 was recorded by the bench as terminated "done",
            # indistinguishable from one that finished its work.
            "failed": stop_reason not in ("Submitted", "LimitsExceeded",
                                          "TimeExceeded", "Completed", "running",
                                          "starting", "RepeatedFormatError"),
            "usage": _tokens(agent)}


class _ReportingAgent(DefaultAgent):
    """DefaultAgent that leaves its report on disk and on stdout every turn.

    The bench reads turns from the last JSON object the agent printed and tokens
    from `.fbbench/usage.json`, and it kills this process the moment the wall
    clock runs out. Writing both as we go means a killed run is still costed and
    still counted, and it doubles as the progress stream a long cell otherwise
    has none of.
    """

    def __init__(self, *args, workspace: Path, model_name: str, **kwargs):
        super().__init__(*args, **kwargs)
        self._usage_file = workspace / ".fbbench" / "usage.json"
        self._model_name = model_name
        # The bench rescues this out of the workspace before deleting it and
        # renders transcript.jsonl and report.html from it, so writing it is
        # what gives this arm the same browsable paper trail as the api arm.
        # Without it the bench falls back to reconstructing a transcript from
        # the submissions alone -- every candidate, no reasoning.
        self.coach = Coach(turn_limit=self.config.turn_limit,
                           wall_limit_s=self.config.wall_time_limit_seconds,
                           workspace=workspace)
        self._trace = workspace / ".fbagent-trace.jsonl"
        self._trace.parent.mkdir(parents=True, exist_ok=True)
        self._trace.write_text("")

    def _trace_write(self, **rec) -> None:
        try:
            with self._trace.open("a") as fh:
                fh.write(json.dumps({"step": self.n_turns, **rec}) + "\n")
        except (OSError, TypeError):
            pass  # a lost trace line must not cost the run a turn

    def execute_actions(self, message: dict) -> list[dict]:
        # The guard runs BEFORE the command does. A fuzzer that has already been
        # built is a second oracle sitting in the workspace; refusing after the
        # fact only wastes the turn that built it.
        for action in (message.get("extra") or {}).get("actions", []):
            if (why := forbidden(action.get("command", ""))):
                # The budget line belongs here too. A refusal and a pushback are
                # the turns the model is most likely to conclude it is stuck on,
                # and dropping the one line that says how much room is left is
                # how a run talks itself into stopping.
                why += "\n\n" + self.coach.budget_line(
                    self.n_turns, time.time() - self._start_time)
                obs = self.model.format_observation_messages(
                    message, [{"output": why, "returncode": 126, "exception_info": ""}],
                    self.get_template_vars())
                self._trace_write(kind="tool_result", tool="bash", is_error=True, content=why)
                return self.add_messages(*obs)
        try:
            return self._coached(message)
        except Submitted as e:
            # 1. Don't let me stop. 69 of 77 bare-model runs ended this way with
            # budget in hand. If there is still time and fewer than three
            # distinct faults, this is a question, not an exit.
            if (push := self.coach.may_finish(self.n_turns, time.time() - self._start_time)) is None:
                raise
            push += self._sinks()
            push += "\n\n" + self.coach.budget_line(
                self.n_turns, time.time() - self._start_time)
            self._trace_write(kind="tool_result", tool="bash", is_error=False, content=push)
            # As a TOOL RESULT, not a user message. The assistant turn that
            # raised Submitted carries a tool_use block, and the API requires a
            # tool_result immediately after it; a user message in that slot
            # makes the conversation invalid from there on. The live run died on
            # exactly this, one turn after the first pushback --
            #   "messages.172: tool_use ids were found without tool_result
            #    blocks immediately after"
            # -- so the rule against stopping early ended the run 12 turns and 6
            # minutes short. The refusal path above was always right; this one
            # was not.
            return self.add_messages(*self.model.format_observation_messages(
                message, [{"output": push, "returncode": 0, "exception_info": ""}],
                self.get_template_vars()))

    def _sinks(self) -> str:
        """The agent's own notes, quoted back at it.

        "Re-read your notes" is advice; the notes themselves are a handle. The
        bare model's failures were not from having nothing left to try -- on
        opc-ua-01 it had read the whole decoder, crashed one function, and spent
        52 turns near it."""
        f = Path(self.env.config.cwd or ".") / "sinks.md"
        try:
            text = f.read_text(errors="replace").strip()
        except OSError:
            return ("\n\nYou kept no sinks.md. List what you have read and not "
                    "tried, then go after the most reachable one.")
        return f"\n\nYour own sinks.md:\n{text[:3000]}" if text else ""

    def _coached(self, message: dict) -> list[dict]:
        # What comes back is the OBSERVATION MESSAGES, already rendered through
        # the template -- not the raw {output, returncode} dicts the environment
        # produced. Tracing `output` off these silently wrote empty results.
        # The rendered text is the right thing to trace anyway: it is what the
        # model was actually shown, truncation and all.
        observations = super().execute_actions(message)
        actions = (message.get("extra") or {}).get("actions", [])
        commands = " ; ".join(a.get("command", "") for a in actions)
        # Pair each result with the name its call was given, so the report shows
        # a submit's verdict under `submit` and not under a wall of `bash`.
        names = [tool_label(a.get("command", ""))[0] for a in actions] or ["bash"]
        notes = self.coach.observe(commands, "\n".join(_text_of(o) for o in observations),
                                   self.n_turns, time.time() - self._start_time)
        if notes and observations:
            _append(observations[-1], "\n\n" + "\n".join(notes))
        for i, obs in enumerate(observations):
            self._trace_write(kind="tool_result", tool=names[min(i, len(names) - 1)],
                              is_error=False, content=_text_of(obs)[:20000])
        return observations

    # ---- why there is no context compaction ---------------------------------
    # There was, briefly. Replaying the four recorded v2 cells through it showed
    # it made them 9.7% MORE expensive ($22.52 -> $24.71 modelled), so it came
    # back out. The reason is that eviction rewrites the prompt prefix, which
    # invalidates the cache from the first changed byte: a read at $0.50/MTok
    # becomes a write at $6.25/MTok. One firing must therefore earn back a 12.5x
    # premium on the whole surviving prefix:
    #
    #     elided x turns_remaining  >=  11.5 x context_after
    #
    # At an 80k context that needs ~30k tokens elided with 25 turns left. The
    # measured pool was 7-20k, because 59-69% of this agent's context is the
    # model's own reasoning, which eviction must not touch, and the fixed prompt
    # is another 15-27k. Only the last third is command output.
    #
    # Firing once instead of three times does flip it (-3.1%), but -3% is inside
    # run-to-run noise and not worth a live-run risk. Cost work should go after
    # output tokens instead: on fwupd-01, 92k output tokens re-read ~41 times are
    # 57% of the cache-read bill, so a thinking token really costs ~$45/MTok, not
    # $25. See fb-agent-compaction-and-reach.pdf, and arXiv 2606.11213 S5, which
    # reports the same net-negative-for-caching result independently.

    def query(self) -> dict:
        # Published here rather than after the action, because this is the
        # moment the tokens were actually spent. A turn whose command runs for
        # minutes -- a build, a long ./submit -- would otherwise be unreported
        # for all of it, and a kill in that window would lose the whole run.
        message = super().query()
        self.publish("running")
        if text := _text_of(message):
            self._trace_write(kind="text", text=text)
        for action in (message.get("extra") or {}).get("actions", []):
            name, inp = tool_label(action.get("command", ""))
            self._trace_write(kind="tool_call", tool=name, input=inp)
        return message

    def publish(self, stop_reason: str) -> dict:
        report = _report(self, self._model_name, stop_reason)
        try:
            self._usage_file.parent.mkdir(parents=True, exist_ok=True)
            self._usage_file.write_text(json.dumps(
                {"model": self._model_name, **report["usage"], "input_is_total": False}, indent=2))
        except OSError:
            pass
        print(json.dumps(report), flush=True)
        return report


# NOTE: this script is written INTO the workspace, so the model can read it.
# Keep every word of it generic -- no challenge name, no project, no hint about
# any particular target. An earlier version quoted the run it was designed from
# and named the challenge; on that challenge it would have told the model both
# that the target was hard and roughly where to look.
# ./reach is gone. v2 gives this agent exec inside the challenge image, so it
# runs gdb itself on the graded binary where the image ships one -- the same
# access claudecode and codex always had. A bench-side tracer only this arm
# could call was the asymmetry, not the fix for it.

@app.command(help="Run fb-agent on one staged FuzzingBrain-Bench challenge.")
def main(
    workspace: Path = typer.Option(..., "--workspace", help="Where the agent writes its own artefacts; bind-mounted to /workspace in the challenge image."),
    mcp_socket: str = typer.Option("", "--mcp-socket", help="This episode's bench MCP server. Defaults to $FBBENCH_MCP_SOCKET."),
    task: str = typer.Option(..., "--task", help="The bench's opening instruction."),
    model_name: str = typer.Option(..., "--model", help="Model to run, as the bench names it."),
    max_turns: int = typer.Option(..., "--max-turns", help="Turn budget. One turn is one usable model reply."),
    timeout: int = typer.Option(..., "--timeout", help="Wall-clock budget in seconds."),
    config_spec: list[str] = typer.Option([str(DEFAULT_CONFIG_FILE)], "-c", "--config"),
) -> int:
    config = recursive_merge(*[get_config_from_spec(spec) for spec in config_spec], {
        "agent": {"turn_limit": max_turns, "cost_limit": 0, "wall_time_limit_seconds": timeout},
        "model": {"model_name": model_name},
        # v2: every arm drives one per-episode mcp-server inside the sealed
        # challenge image. There is no host shell to sandbox any more -- cwd is
        # /challenge and read-only, /workspace is writable, and the grader is
        # run_poc_on_harness. The socket is the bench's; refusing to start
        # without it is deliberate, since a silent fall back to a local shell
        # would mean the agent never touched the challenge.
        "environment": {"environment_class": "mcp_bench",
                        "socket_path": mcp_socket or os.environ.get("FBBENCH_MCP_SOCKET", "")},
    })
    # DefaultAgent.run() re-saves this after every turn, so a killed run keeps
    # the conversation up to the kill -- the same reason the report is published
    # per turn rather than at exit.
    config.setdefault("agent", {})["output_path"] = workspace / ".fbbench" / "traj.json"

    agent = _ReportingAgent(
        get_model(config=config.get("model", {})),
        get_environment(config.get("environment", {}), default_type="mcp_bench"),
        workspace=workspace, model_name=model_name, **config.get("agent", {}),
    )

    # One report before the first model call, so a run killed early is costed
    # as zero rather than as nothing -- the bench prints an unreported cost as
    # "$ --", and "we do not know" is a different claim from "it was free".
    agent.publish("starting")
    try:
        stop_reason = (agent.run(task) or {}).get("exit_status") or "Completed"
    except Exception as e:  # noqa: BLE001
        # A crashed agent still submitted candidates the bench has already
        # graded, and still spent money. Report both, then let the cell finish.
        stop_reason = f"{type(e).__name__}: {e}"
        print(f"fb-agent: {stop_reason}", file=sys.stderr, flush=True)
    agent.publish(stop_reason)
    return 0


if __name__ == "__main__":
    app()

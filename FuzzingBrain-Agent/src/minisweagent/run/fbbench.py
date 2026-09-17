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


_SUBMIT_RE = re.compile(r"\./(?:submit|try_poc)\s+(\S+)")
_REACH_RE = re.compile(r"\./reach\s+(\S+)\s+(\S+)")


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
    if m := _SUBMIT_RE.search(command):
        return "submit", {"path": m.group(1), "command": command}
    if m := _REACH_RE.search(command):
        return "reach", {"path": m.group(1), "function": m.group(2), "command": command}
    return "bash", {"command": command}


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
        self._last_prompt_tokens = 0
        self._compacted_at = -10_000
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

    # ---- context compaction -------------------------------------------------
    # 88% of this agent's context is command output: 174 KB of it on fwupd-01,
    # against 2 KB of model text. With no compaction the whole of that is re-read
    # on every turn, and cache reads were 47% of that run's $7.61.
    #
    # The trap is that compaction fights the prompt cache. We run at a 95% hit
    # rate; a cache read costs $0.50/MTok and a cache write $6.25/MTok, so
    # rewriting history converts cheap reads into writes at 12.5x. Compacting
    # every turn would cost more than it saves. So: once, when the context
    # crosses a threshold, and then not again for a long stretch -- one expensive
    # re-write, then cheap again for the rest of the run.
    COMPACT_ABOVE_TOKENS = 60_000   # measured: fwupd-01 averaged ~93k per turn
    COMPACT_KEEP_RECENT = 10        # turns whose output stays verbatim
    COMPACT_COOLDOWN_TURNS = 25     # never twice in quick succession

    def _compact(self) -> None:
        """Stub out old command output, in place.

        Only the CONTENT of observation messages changes. Nothing is removed and
        no role is touched: an assistant tool_use must keep its matching
        tool_result or the next request is rejected outright, which is how an
        earlier version of this agent killed a run 12 turns early.

        Three things survive verbatim, because they are the run's actual state:
        every model message (its reasoning and its commands), any observation
        carrying a ./submit verdict, and the last COMPACT_KEEP_RECENT turns.
        """
        keep_from = max(0, len(self.messages) - self.COMPACT_KEEP_RECENT * 2)
        saved = 0
        for i, m in enumerate(self.messages):
            if i >= keep_from or m.get("role") not in ("tool", "user"):
                continue
            text = _text_of(m)
            if len(text) < 400 or "crash:" in text or "clean: no fault" in text:
                continue          # verdicts are the record; short output is free
            saved += len(text)
            stub = f"<elided: {len(text) // 1024 or 1} KB of output from an earlier turn>"
            if isinstance(m.get("content"), list):
                m["content"] = [{"type": "text", "text": stub}]
            else:
                m["content"] = stub
        self._compacted_at = self.n_turns
        self._trace_write(kind="text",
                          text=f"[compacted] elided ~{saved // 1024} KB of earlier "
                               f"command output, keeping the last "
                               f"{self.COMPACT_KEEP_RECENT} turns and every verdict")
        print(json.dumps({"event": "compacted", "turn": self.n_turns,
                          "elided_bytes": saved}), flush=True)

    def _maybe_compact(self) -> None:
        if self._last_prompt_tokens < self.COMPACT_ABOVE_TOKENS:
            return
        if self.n_turns - self._compacted_at < self.COMPACT_COOLDOWN_TURNS:
            return
        self._compact()

    def query(self) -> dict:
        # Published here rather than after the action, because this is the
        # moment the tokens were actually spent. A turn whose command runs for
        # minutes -- a build, a long ./submit -- would otherwise be unreported
        # for all of it, and a kill in that window would lose the whole run.
        self._maybe_compact()
        message = super().query()
        # The provider's own count of what we just sent -- the only honest
        # measure of context size, and free.
        usage = ((message.get("extra") or {}).get("response") or {}).get("usage") or {}
        if isinstance(usage, dict) and usage.get("prompt_tokens"):
            self._last_prompt_tokens = int(usage["prompt_tokens"])
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
_REACH = r"""#!/bin/bash
# ./reach <input-file> <function>  -- did this input execute that function?
#
# Runs the input under a debugger with a breakpoint on the named function and
# reports whether it was reached. A clean verdict says an input did not crash;
# this says whether it even got there, which is a different problem.
set -u
if [ $# -ne 2 ] || [ ! -f "$1" ]; then
  echo "usage: ./reach <input-file> <function>" >&2; exit 2
fi
h="$(cd "$(dirname "$0")" && pwd)"
DEAD="$h/.fbbench/reach_unavailable"

# Learned once, remembered for the rest of the run: not every image ships a
# debugger, and there is no way to know without asking. Asking costs a turn, so
# asking repeatedly costs one each time.
if [ -f "$DEAD" ]; then cat "$DEAD" >&2; exit 1; fi

id="$(date +%s%N)-$$"
cp -- "$1" "$h/.fbbench/trace_req/$id.bin"
printf '%s' "$2" > "$h/.fbbench/trace_req/$id.tgt"   # .tgt last: it means ready
note_dead() {
  printf '%s\n' "$1" > "$DEAD"
  cat "$DEAD" >&2
  exit 1
}
for i in $(seq 1 1200); do
  if [ -f "$h/.fbbench/trace_res/$id" ]; then
    out=$(cat "$h/.fbbench/trace_res/$id")
    case "$out" in
      *"gdb: not found"*|*"exec: gdb"*|*"No such file or directory"*gdb*)
        note_dead "reach: not available on this challenge - its image ships no debugger. Do not call ./reach again; judge how far an input gets from the ./submit verdict instead (0 ms means it never reached the library)." ;;
    esac
    printf '%s\n' "$out"; exit 0
  fi
  # Unclaimed after 5s means nothing is listening; a claimed one may take minutes.
  if [ "$i" -gt 25 ] && [ -f "$h/.fbbench/trace_req/$id.tgt" ]; then
    rm -f "$h/.fbbench/trace_req/$id."*
    note_dead "reach: not available on this bench build - nothing answers trace requests. Do not call ./reach again; use the ./submit verdict instead."
  fi
  sleep 0.2
done
echo "reach: timed out" >&2; exit 1
"""


def _install_reach(workspace: Path) -> bool:
    """Drop ./reach next to the bench's ./submit, if the tracer is there."""
    if not (workspace / ".fbbench" / "trace_req").is_dir():
        return False
    try:
        script = workspace / "reach"
        script.write_text(_REACH)
        script.chmod(0o755)
        return True
    except OSError:
        return False


@app.command(help="Run fb-agent on one staged FuzzingBrain-Bench challenge.")
def main(
    workspace: Path = typer.Option(..., "--workspace", help="The staged challenge directory."),
    task: str = typer.Option(..., "--task", help="The bench's opening instruction."),
    model_name: str = typer.Option(..., "--model", help="Model to run, as the bench names it."),
    max_turns: int = typer.Option(..., "--max-turns", help="Turn budget. One turn is one usable model reply."),
    timeout: int = typer.Option(..., "--timeout", help="Wall-clock budget in seconds."),
    config_spec: list[str] = typer.Option([str(DEFAULT_CONFIG_FILE)], "-c", "--config"),
) -> int:
    config = recursive_merge(*[get_config_from_spec(spec) for spec in config_spec], {
        "agent": {"turn_limit": max_turns, "cost_limit": 0, "wall_time_limit_seconds": timeout},
        "model": {"model_name": model_name},
        # The bench points $SHELL at a sandbox wrapper that masks the Docker
        # socket and drops the network. Going through /bin/sh instead would step
        # around it silently, and score.json would claim a sandbox this run
        # never had.
        "environment": {"cwd": str(workspace), "executable": os.environ.get("SHELL", "")},
    })
    # DefaultAgent.run() re-saves this after every turn, so a killed run keeps
    # the conversation up to the kill -- the same reason the report is published
    # per turn rather than at exit.
    config.setdefault("agent", {})["output_path"] = workspace / ".fbbench" / "traj.json"

    # 2. Reach. The prompt only mentions ./reach when it is really there, so a
    # bench build without the tracer does not send the model chasing a tool that
    # will answer "no responder".
    has_reach = _install_reach(workspace)

    agent = _ReportingAgent(
        get_model(config=config.get("model", {})),
        get_environment(config.get("environment", {}), default_type="local"),
        workspace=workspace, model_name=model_name, **config.get("agent", {}),
    )
    # extra_template_vars is an ATTRIBUTE, not an AgentConfig field -- passing
    # it as config would be dropped without a word, the way pydantic drops every
    # unknown agent key.
    agent.extra_template_vars["has_reach"] = has_reach

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

# SPDX-License-Identifier: Apache-2.0
"""
CLI entrypoint for the FuzzingBrain agent model.

Drives one target end-to-end. The target's tool server (an MCP server that
exposes setup/read_file/list_directory/write_file/exec/run_input) is launched by
the argv given AFTER a `--` separator, so any transport works — most commonly a
challenge container:

  python -m fuzzingbrain.agent_model \\
      --model claude-haiku-4-5 --max-turns 100 --out /path/to/rundir \\
      -- docker run -i --rm -v /host/ws:/workspace <image> mcp-server

Writes <out>/transcript.jsonl (browsable event log) and <out>/agent_result.json
(turns, tokens, terminated_reason). Candidate inputs are written by the agent
into the target's workspace (e.g. the bind-mounted /workspace), where the caller
grades them.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def _split_mcp_cmd(argv: list[str]) -> tuple[list[str], list[str]]:
    """Split argv on the first bare `--`: (our args, the MCP server argv)."""
    if "--" in argv:
        i = argv.index("--")
        return argv[:i], argv[i + 1:]
    return argv, []


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    our_args, mcp_cmd = _split_mcp_cmd(argv)

    ap = argparse.ArgumentParser(
        prog="python -m fuzzingbrain.agent_model",
        description="FuzzingBrain agent model — drive one target to a PoV.")
    ap.add_argument("--model", default="claude-haiku-4-5", help="LLM model id")
    ap.add_argument("--max-turns", type=int, default=100, help="turn budget")
    ap.add_argument("--temperature", type=float, default=1.0)
    ap.add_argument("--max-tokens", type=int, default=16000)
    ap.add_argument("--out", required=True, help="output dir (transcript + result)")
    ap.add_argument("--api-key", default=None,
                    help="provider API key (else read from env / llm_config)")
    args = ap.parse_args(our_args)

    if not mcp_cmd:
        ap.error("no MCP server command given (append it after `--`)")
    if args.api_key:
        os.environ.setdefault("ANTHROPIC_API_KEY", args.api_key)

    # The CRS applies Anthropic prompt caching by turning the SYSTEM message into
    # a list of content blocks. litellm < ~1.55 cannot serialize a list-typed
    # system message (`can only concatenate str (not "list") to str`), so every
    # call fails and the fallback chain retries until it looks like a hang, then
    # raises LLMAllModelsFailedError. Auto-disable prompt caching on an old or
    # undetectable litellm (unless the user set the flag explicitly), so the
    # agent works out of the box; a modern litellm keeps caching on.
    if "FUZZINGBRAIN_DISABLE_PROMPT_CACHE" not in os.environ:
        try:
            from importlib.metadata import version as _pkg_version
            _lv = _pkg_version("litellm")
            _major, _minor = (int(x) for x in _lv.split(".")[:2])
            if (_major, _minor) < (1, 55):
                os.environ["FUZZINGBRAIN_DISABLE_PROMPT_CACHE"] = "1"
                sys.stderr.write(
                    f"[agent_model] litellm {_lv} < 1.55 cannot serialize cached "
                    "system content — disabling prompt cache for this run "
                    "(upgrade to litellm>=1.55 to re-enable KV-cache savings)\n")
        except Exception:
            os.environ["FUZZINGBRAIN_DISABLE_PROMPT_CACHE"] = "1"

    # Import here so `--help` works without the LLM stack / its heavy deps.
    from .agent import AgentModel
    from .mcp_stdio import StdioMCPClient

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    tpath = out / "transcript.jsonl"
    tfp = open(tpath, "w")

    def on_event(ev: dict) -> None:
        tfp.write(json.dumps(ev, ensure_ascii=False) + "\n")
        tfp.flush()

    transport = StdioMCPClient(mcp_cmd, env=os.environ.copy())
    agent = AgentModel(transport, model=args.model, max_turns=args.max_turns,
                       temperature=args.temperature, max_tokens=args.max_tokens,
                       on_event=on_event)
    result = agent.run()
    tfp.close()

    (out / "agent_result.json").write_text(json.dumps({
        "model": result.model,
        "turns_used": result.turns_used,
        "terminated_reason": result.terminated_reason,
        "duration_s": round(result.duration_s, 1),
        "tested": result.tested,
        "input_tokens": result.input_tokens,
        "output_tokens": result.output_tokens,
        "cache_read_tokens": result.cache_read_tokens,
        "cache_write_tokens": result.cache_write_tokens,
        "plan": result.plan,
        "error": result.error,
    }, indent=2))
    print(json.dumps({"turns_used": result.turns_used, "tested": result.tested,
                      "terminated_reason": result.terminated_reason,
                      "error": result.error}))
    return 0 if result.error is None else 1


if __name__ == "__main__":
    sys.exit(main())

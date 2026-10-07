"""Parse actions & format observations with toolcalls"""

import json
import time

from jinja2 import StrictUndefined, Template

from minisweagent.exceptions import FormatError
from minisweagent.models.utils.openai_multimodal import expand_multimodal_content

BASH_TOOL = {
    "type": "function",
    "function": {
        "name": "bash",
        "description": "Execute a bash command",
        "parameters": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The bash command to execute",
                }
            },
            "required": ["command"],
        },
    },
}


# The FuzzingBrain-Bench tool surface, copied from what the server advertises
# (`tools/list` on the challenge image). Three tools, not the six that
# claudecode's --allowedTools names: that list is permissive, and
# list_directory/read_file/write_file are not on the server. Every arm -- api,
# claudecode, codex and this one -- gets exactly these.
#
# fb-agent used to drive them through one bash-shaped action with the grader
# hidden behind a magic string, and a haiku smoke run spent 30 turns never
# grading: it ran `which run_poc_on_harness`, looking for a binary. An agent
# whose interface looks like a shell will treat everything as a shell.
BENCH_TOOLS = [
    {"type": "function", "function": {
        "name": "setup",
        "description": ("Return task info: the environment (workspace + source paths), "
                        "the target project and language, and the harness configuration."),
        "parameters": {"type": "object", "properties": {}},
    }},
    {"type": "function", "function": {
        "name": "exec",
        "description": ("Run a shell command with /bin/bash -c in the challenge source "
                        "root (/challenge, read-only; write to /workspace or /tmp). This "
                        "is your only filesystem tool: read with cat/sed/head, write with "
                        "printf or a heredoc, list with ls/find. Returns stdout, stderr "
                        "and exit_code."),
        "parameters": {"type": "object", "properties": {
            "cmd": {"type": "string", "description": "The shell command to run."},
            "timeout_s": {"type": "integer",
                          "description": "Wall-clock timeout in seconds (default 60)."},
        }, "required": ["cmd"]},
    }},
    {"type": "function", "function": {
        "name": "run_poc_on_harness",
        "description": ("Run a candidate input through the official sanitizer-instrumented "
                        "harness and return what it printed. THIS IS THE ONLY ORACLE: an "
                        "input you have not run through it does not count. Write the file "
                        "under /workspace with exec first."),
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string",
                     "description": "Path to the candidate input file, under /workspace."},
        }, "required": ["path"]},
    }},
]
_BENCH_BY_NAME = {t["function"]["name"]: t for t in BENCH_TOOLS}


def parse_toolcall_actions(
    tool_calls: list, *, format_error_template: str, template_kwargs: dict | None = None,
    tools: list[dict] | None = None,
) -> list[dict]:
    """Parse tool calls from the response. Raises FormatError if unknown tool or invalid args.

    ``template_kwargs`` are extra variables exposed to ``format_error_template`` (e.g.
    ``{"finish_reason": ...}`` so a template can distinguish a real format mistake from a
    ``max_tokens`` truncation).
    """
    template_kwargs = template_kwargs or {}
    if not tool_calls:
        raise FormatError(
            {
                "role": "user",
                "content": Template(format_error_template, undefined=StrictUndefined).render(
                    error="No tool calls found in the response. Every response MUST include at least one tool call.",
                    actions=[],
                    has_tool_calls=False,
                    **template_kwargs,
                ),
                "extra": {"interrupt_type": "FormatError"},
            }
        )
    actions = []
    for tool_call in tool_calls:
        error_msg = ""
        args = {}
        try:
            args = json.loads(tool_call.function.arguments)
        except Exception as e:
            error_msg = f"Error parsing tool call arguments: {e}."
        name = tool_call.function.name
        known = {t["function"]["name"] for t in (tools or [BASH_TOOL])}
        if name not in known:
            error_msg += f"Unknown tool {name!r}. Available: {', '.join(sorted(known))}."
        elif not isinstance(args, dict):
            error_msg += f"Arguments to {name!r} must be an object."
        else:
            spec = _BENCH_BY_NAME.get(name) or BASH_TOOL
            for req in spec["function"]["parameters"].get("required", []):
                if req not in args:
                    error_msg += f"Missing {req!r} argument in {name!r} call."
        if error_msg:
            raise FormatError(
                {
                    "role": "user",
                    "content": Template(format_error_template, undefined=StrictUndefined).render(
                        actions=[], error=error_msg.strip(), has_tool_calls=True, **template_kwargs
                    ),
                    "extra": {"interrupt_type": "FormatError"},
                }
            )
        # `command` stays populated for everything that reads a trace or
        # screens a command; `tool`/`args` are what the environment dispatches on.
        actions.append({
            "tool": name,
            "args": args,
            "command": args.get("command") or args.get("cmd") or args.get("path") or "",
            "tool_call_id": tool_call.id,
        })
    return actions


def format_toolcall_observation_messages(
    *,
    actions: list[dict],
    outputs: list[dict],
    observation_template: str,
    template_vars: dict | None = None,
    multimodal_regex: str = "",
) -> list[dict]:
    """Format execution outputs into tool result messages."""
    not_executed = {"output": "", "returncode": -1, "exception_info": "action was not executed"}
    padded_outputs = outputs + [not_executed] * (len(actions) - len(outputs))
    results = []
    for action, output in zip(actions, padded_outputs):
        content = Template(observation_template, undefined=StrictUndefined).render(
            output=output, **(template_vars or {})
        )
        msg = {
            "content": content,
            "extra": {
                "raw_output": output.get("output", ""),
                "returncode": output.get("returncode"),
                "timestamp": time.time(),
                "exception_info": output.get("exception_info"),
                **output.get("extra", {}),
            },
        }
        if "tool_call_id" in action:
            msg["tool_call_id"] = action["tool_call_id"]
            msg["role"] = "tool"
        else:
            msg["role"] = "user"  # human issued commands
        if multimodal_regex:
            msg = expand_multimodal_content(msg, pattern=multimodal_regex)
        results.append(msg)
    return results

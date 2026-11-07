"""``fbv3`` -- the command line.

Any C/C++ project, with no task file to write:

    # write harnesses for the targets an agent picks, then hunt bugs in them
    fbv3 run --project libpng --image gcr.io/oss-fuzz/libpng

    # one target you name
    fbv3 run --project zlib --image gcr.io/oss-fuzz/zlib \\
        --function compress2 --overlay /src/compress_fuzzer.c

    # a fuzz target that already exists: the directed stage alone
    fbv3 run --project binutils --prebuilt out/ --binary fuzz_disassemble \\
        --src src/binutils --harness harness/fuzz_disassemble.c

    fbv3 check ...      the same arguments, preflight only (no agent runs)
    fbv3 init ... -o task.json      write the task file those flags describe
    fbv3 run task.json --duration 3600     a task file, with overrides
    fbv3 view runs/<run>            the summary of a finished or running run
    fbv3 clean <run id>             remove containers a crashed run left behind
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from fbv3 import report
from fbv3.config import ConfigError, Task

LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)-28s %(message)s"


def _add_task_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("task", nargs="?", help="a task JSON file (otherwise describe the task with the flags)")
    g = p.add_argument_group("the project")
    g.add_argument("--project", help="project name, e.g. libpng")
    g.add_argument("--image", help="the OSS-Fuzz builder image (has /src and build.sh)")
    g.add_argument("--runner-image", help="image the fuzzers run in (default: the builder image)")
    g.add_argument("--language", choices=("c", "c++"), default=None)
    g.add_argument("--name", help="a name for the run (default: the project)")
    g = p.add_argument_group("what to fuzz")
    g.add_argument("--function", action="append", default=[], metavar="FN",
                   help="target function to write a harness for (repeatable)")
    g.add_argument("--describe", action="append", default=[], metavar="TEXT",
                   help="what to fuzz in the matching --function (repeatable, in the same order)")
    g.add_argument("--overlay", action="append", default=[], metavar="/src/...",
                   help="existing fuzzer source the harness replaces (repeatable, same order)")
    g.add_argument("--discover", type=int, metavar="N",
                   help="let an agent pick N targets (the default when no --function is given)")
    g = p.add_argument_group("an existing fuzz target (directed stage only)")
    g.add_argument("--prebuilt", metavar="DIR", help="build output dir holding the ASan fuzz target")
    g.add_argument("--binary", help="the fuzz target's file name inside --prebuilt")
    g.add_argument("--coverage-build", metavar="DIR", help="build output dir of the coverage build")
    g.add_argument("--src", metavar="DIR", help="the project source the build was made from")
    g.add_argument("--harness", action="append", default=[], metavar="FILE",
                   help="the harness source file(s) of that target (repeatable)")
    g.add_argument("--entry", action="append", default=[], metavar="FN",
                   help="API entry point(s) the target drives (repeatable)")
    g = p.add_argument_group("how much")
    g.add_argument("--stage", action="append", default=[], choices=("discovery", "harness", "directed"),
                   help="run only these stages (repeatable)")
    g.add_argument("--duration", type=int, metavar="SECONDS", help="directed stage budget per target")
    g.add_argument("--rounds", type=int, metavar="N", help="harness generate/review rounds per target")
    g.add_argument("--sessions", type=int, metavar="N", help="agent sessions in flight (default 1)")
    g.add_argument("--mode", choices=("directed", "legacy", "baseline"),
                   help="directed (default), legacy (seed agent + fuzzer), baseline (fuzzer only)")
    g.add_argument("--backend", choices=("claude", "codex"), help="send every role to this backend")
    g.add_argument("--no-review", action="store_true", help="skip the harness reviewer agent")
    g.add_argument("--no-research", action="store_true", help="skip the API research agent")
    g.add_argument("--no-breaker", action="store_true", help="skip the frontier (breaker) agent")
    g.add_argument("-o", "--output", metavar="DIR", help="run directory (default runs/<name>-<stamp>)")
    g.add_argument("--set", action="append", default=[], metavar="a.b=value",
                   help="override any task field, e.g. --set directed.poc_threshold=0.6")


def task_from_args(args) -> Task:
    """A Task from a JSON file, from the flags, or from a file the flags override."""
    data: dict = json.loads(Path(args.task).read_text()) if args.task else {}
    if args.task and not Path(args.task).is_file():
        raise ConfigError(f"no such task file: {args.task}")
    if args.project:
        data["project"] = args.project
    if args.image:
        data["builder_image"] = args.image
    if args.runner_image:
        data["runner_image"] = args.runner_image
    elif not data.get("runner_image") and data.get("builder_image"):
        # base-runner is Ubuntu 20.04; targets from current builder images need
        # its glibc, so the builder image is the safe default runner.
        data["runner_image"] = data["builder_image"]
    if args.language:
        data["language"] = args.language
    if not data.get("project"):
        raise ConfigError("--project is required (or give a task file)")
    data.setdefault("name", args.name or data.get("project"))
    if args.name:
        data["name"] = args.name

    targets = list(data.get("targets") or [])
    for i, fn in enumerate(args.function):
        targets.append({"function": fn,
                        "description": args.describe[i] if i < len(args.describe) else "",
                        "overlay": args.overlay[i] if i < len(args.overlay) else ""})
    if targets:
        data["targets"] = targets

    if args.prebuilt:
        if not args.binary:
            raise ConfigError("--prebuilt needs --binary (the fuzz target's file name)")
        data.setdefault("prebuilt", []).append({
            "name": Path(args.binary).name, "binary": Path(args.binary).name,
            "asan_out": str(Path(args.prebuilt).resolve()),
            "coverage_out": str(Path(args.coverage_build).resolve()) if args.coverage_build else "",
            "source_dir": str(Path(args.src).resolve()) if args.src else "",
            "harness_sources": [str(Path(h).resolve()) for h in args.harness],
            "entries": list(args.entry),
        })

    if args.stage:
        data["stages"] = list(dict.fromkeys(args.stage))
    elif "stages" not in data:
        stages = []
        if not targets and not data.get("prebuilt"):
            stages.append("discovery")
        if targets or "discovery" in stages:
            stages.append("harness")
        stages.append("directed")
        data["stages"] = stages
    if args.discover is not None:
        data.setdefault("discovery", {})["max_targets"] = args.discover
        if "discovery" not in data["stages"]:
            data["stages"] = ["discovery", *data["stages"]]
    if args.duration:
        data.setdefault("directed", {})["duration_seconds"] = args.duration
    if args.mode:
        data.setdefault("directed", {})["mode"] = args.mode
    if args.no_breaker:
        data.setdefault("directed", {})["breaker"] = False
    if args.rounds:
        data.setdefault("harness", {})["max_rounds"] = args.rounds
    if args.no_review:
        data.setdefault("harness", {})["review"] = False
    if args.no_research:
        data.setdefault("harness", {})["research"] = False
    if args.sessions:
        data.setdefault("agents", {})["max_sessions"] = args.sessions
    if args.backend:
        agents = data.setdefault("agents", {})
        roles = agents.setdefault("roles", {})
        for role in ("discoverer", "researcher", "harness", "reviewer", "seed", "mapper", "breaker",
                     "finder", "verifier", "poc", "fp_seed"):
            roles.setdefault(role, {})["backend"] = args.backend
    if args.output:
        data["output"] = str(Path(args.output).resolve())
    for item in args.set:
        _apply_set(data, item)
    return Task.from_dict(data)


def _apply_set(data: dict, item: str) -> None:
    if "=" not in item:
        raise ConfigError(f"--set needs key=value, got {item!r}")
    key, raw = item.split("=", 1)
    try:
        value = json.loads(raw)
    except ValueError:
        value = raw
    node = data
    parts = key.split(".")
    for part in parts[:-1]:
        node = node.setdefault(part, {})
        if not isinstance(node, dict):
            raise ConfigError(f"--set {key}: {part} is not a section")
    node[parts[-1]] = value


# -- commands ---------------------------------------------------------------------------------


def cmd_run(args) -> int:
    from fbv3.run import Runner, preflight

    task = task_from_args(args)
    if args.dry_run:
        print(json.dumps(task.to_dict(), indent=2))
        return 0
    pre = preflight(task)
    print("preflight:")
    print(pre.text())
    if not pre.ok:
        print("\npreflight failed; nothing was started.", file=sys.stderr)
        return 2
    summary = Runner(task, out_dir=Path(args.output) if args.output else None).run()
    print()
    print(report.render(summary))
    print(f"\nrun directory: {summary['run_dir']}")
    return 0 if summary["status"] == "completed" else 1


def cmd_check(args) -> int:
    from fbv3.run import preflight

    task = task_from_args(args)
    pre = preflight(task, build_image=not args.fast)
    print(f"task {task.name}: project {task.project}, stages {', '.join(task.stages)}")
    print(f"  targets: {', '.join(t.function for t in task.targets) or '(discovery)'}")
    print(f"  prebuilt: {', '.join(p.binary for p in task.prebuilt) or '(none)'}")
    print(pre.text())
    return 0 if pre.ok else 2


def cmd_init(args) -> int:
    task = task_from_args(args)
    text = json.dumps(task.to_dict(), indent=2) + "\n"
    if args.output_file:
        Path(args.output_file).write_text(text)
        print(f"wrote {args.output_file}")
    else:
        print(text, end="")
    return 0


def cmd_view(args) -> int:
    summary = report.load(Path(args.run_dir))
    if not summary:
        print(f"no run found in {args.run_dir}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(summary, indent=2, default=str))
    else:
        print(report.render(summary))
    return 0


def cmd_clean(args) -> int:
    from fbv3.sandbox import docker

    n = docker.kill_run_containers(args.run_id)
    print(f"removed {n} container(s) of run {args.run_id}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="fbv3", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    p.add_argument("-q", "--quiet", action="store_true", help="warnings and errors only")
    sub = p.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run a task (preflight, then the stages)",
                         description="Run a task. Preflight runs first; nothing starts unless it passes.")
    _add_task_args(run)
    run.add_argument("--dry-run", action="store_true", help="print the resolved task and stop")
    run.set_defaults(func=cmd_run)

    check = sub.add_parser("check", help="preflight only: logins, images, prebuilt paths")
    _add_task_args(check)
    check.add_argument("--fast", action="store_true", help="do not build the workspace image")
    check.set_defaults(func=cmd_check)

    init = sub.add_parser("init", help="write the task file these flags describe")
    _add_task_args(init)
    init.add_argument("-f", "--output-file", metavar="FILE", help="write here instead of stdout")
    init.set_defaults(func=cmd_init)

    view = sub.add_parser("view", help="summarize a run directory")
    view.add_argument("run_dir")
    view.add_argument("--json", action="store_true")
    view.set_defaults(func=cmd_view)

    clean = sub.add_parser("clean", help="remove the containers of a run (after a hard crash)")
    clean.add_argument("run_id")
    clean.set_defaults(func=cmd_clean)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    level = logging.DEBUG if args.verbose else (logging.WARNING if args.quiet else logging.INFO)
    logging.basicConfig(level=level, format=LOG_FORMAT, datefmt="%H:%M:%S")
    try:
        return args.func(args)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())

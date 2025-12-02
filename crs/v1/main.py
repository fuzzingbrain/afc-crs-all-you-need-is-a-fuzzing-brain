#!/usr/bin/env python3
"""
CRS Local Workflow - Main Entry Point
Read task folder -> Build Fuzzer -> Run strategies
"""
import os
import subprocess
import json
import uuid
import time
import argparse
import stat
from dataclasses import dataclass, field
from typing import Optional, List, Dict

import yaml


# ============================================================================
# Data Models
# ============================================================================

@dataclass
class TaskDetail:
    """Task detail"""
    task_id: str
    type: str  # "full" or "delta"
    deadline: int  # ms timestamp
    focus: str  # e.g. "afc-libpng"
    harnesses_included: bool
    project_name: str  # e.g. "libpng"
    metadata: Dict[str, str] = field(default_factory=dict)
    state: str = "pending"


@dataclass
class ProjectConfig:
    """Project config (from project.yaml)"""
    language: str = "c"
    main_repo: str = ""


@dataclass
class TaskContext:
    """Task context"""
    task_dir: str
    task_detail: TaskDetail
    project_dir: str
    dockerfile_path: str
    fuzzer_dir: str  # address sanitizer fuzzer directory
    project_config: Optional[ProjectConfig] = None
    all_fuzzers: List[str] = field(default_factory=list)
    model: str = "claude-sonnet-4-20250514"


# ============================================================================
# Task Folder Reader
# ============================================================================

def load_task_detail_from_json(task_dir: str) -> Optional[TaskDetail]:
    """Load task detail from task_detail*.json"""
    for root, _, files in os.walk(task_dir):
        for filename in files:
            if filename.startswith("task_detail") and filename.endswith(".json"):
                json_path = os.path.join(root, filename)
                try:
                    with open(json_path, "r") as f:
                        data = json.load(f)
                    return TaskDetail(
                        task_id=data.get("task_id", str(uuid.uuid4())),
                        type=data.get("type", "full"),
                        deadline=data.get("deadline", int(time.time() * 1000) + 3600000),
                        focus=data.get("focus", ""),
                        harnesses_included=data.get("harnesses_included", True),
                        project_name=data.get("project_name", ""),
                        metadata=data.get("metadata", {}),
                        state=data.get("state", "pending"),
                    )
                except Exception as e:
                    print(f"Failed to parse {json_path}: {e}")
    return None


def infer_task_detail_from_directory(task_dir: str) -> TaskDetail:
    """Infer task detail from directory structure"""
    project_name = "test"
    focus_name = "test"

    projects_dir = os.path.join(task_dir, "fuzz-tooling", "projects")
    if os.path.isdir(projects_dir):
        for entry in os.listdir(projects_dir):
            if os.path.isdir(os.path.join(projects_dir, entry)):
                project_name = entry
                focus_name = f"afc-{project_name}"
                print(f"Found project '{project_name}', focus = '{focus_name}'")
                break

    diff_path = os.path.join(task_dir, "diff")
    task_type = "delta" if os.path.isdir(diff_path) else "full"
    print(f"Task type = '{task_type}'")

    return TaskDetail(
        task_id=str(uuid.uuid4()),
        type=task_type,
        deadline=int(time.time() * 1000) + 3600000,
        focus=focus_name,
        harnesses_included=True,
        project_name=project_name,
    )


def read_task_folder(task_dir: str, model: str) -> TaskContext:
    """Read task folder"""
    abs_task_dir = os.path.abspath(task_dir)
    print(f"Task folder: {abs_task_dir}")

    task_detail = load_task_detail_from_json(abs_task_dir)
    if task_detail is None:
        task_detail = infer_task_detail_from_directory(abs_task_dir)

    project_dir = os.path.join(abs_task_dir, task_detail.focus)
    dockerfile_path = os.path.join(abs_task_dir, "fuzz-tooling", "projects", task_detail.project_name)
    # Only use address sanitizer
    fuzzer_dir = os.path.join(abs_task_dir, "fuzz-tooling", "build", "out", f"{task_detail.project_name}-address")

    print(f"Project: {task_detail.project_name}, Type: {task_detail.type}")

    return TaskContext(
        task_dir=abs_task_dir,
        task_detail=task_detail,
        project_dir=project_dir,
        dockerfile_path=dockerfile_path,
        fuzzer_dir=fuzzer_dir,
        model=model,
    )


# ============================================================================
# Fuzzer Builder (only build address sanitizer)
# ============================================================================

def load_project_config(dockerfile_path: str) -> ProjectConfig:
    """Load config from project.yaml"""
    project_yaml_path = os.path.join(dockerfile_path, "project.yaml")
    try:
        with open(project_yaml_path, "r") as f:
            data = yaml.safe_load(f)
        return ProjectConfig(
            language=data.get("language", "c"),
            main_repo=data.get("main_repo", ""),
        )
    except Exception as e:
        print(f"Warning: Could not parse project.yaml ({e})")
        return ProjectConfig()


SKIP_BINARIES = {"jazzer_agent_deploy.jar", "jazzer_driver", "jazzer_driver_with_sanitizer",
                 "jazzer_junit.jar", "llvm-symbolizer", "sancov", "clang", "clang++"}
SKIP_EXTENSIONS = {".bin", ".log", ".class", ".jar", ".zip", ".dict", ".options",
                   ".bc", ".json", ".o", ".a", ".so", ".h", ".c", ".cpp", ".java", ".py", ".sh"}


def find_fuzzers(fuzzer_dir: str) -> List[str]:
    """Scan directory for fuzzer executables"""
    if not os.path.isdir(fuzzer_dir):
        return []
    fuzzers = []
    for entry in os.listdir(fuzzer_dir):
        entry_path = os.path.join(fuzzer_dir, entry)
        if os.path.isdir(entry_path):
            continue
        _, ext = os.path.splitext(entry)
        if ext in SKIP_EXTENSIONS or entry in SKIP_BINARIES:
            continue
        try:
            st = os.stat(entry_path)
            if st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                fuzzers.append(entry)
        except OSError:
            continue
    return fuzzers


def build_fuzzers(task_dir: str, project_name: str, project_dir: str) -> bool:
    """Build address sanitizer fuzzers"""
    import shutil

    build_root = os.path.join(task_dir, "fuzz-tooling", "build")
    out_dir = os.path.join(build_root, "out", f"{project_name}-address")
    work_dir = os.path.join(build_root, "work", f"{project_name}-address")

    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(work_dir, exist_ok=True)

    # Create symlinks
    link_out = os.path.join(build_root, "out", project_name)
    link_work = os.path.join(build_root, "work", project_name)

    for link_path, target in [(link_out, out_dir), (link_work, work_dir)]:
        if os.path.islink(link_path):
            os.unlink(link_path)
        elif os.path.exists(link_path):
            shutil.rmtree(link_path)
        os.symlink(target, link_path)

    # Call helper.py
    helper_script = os.path.join(task_dir, "fuzz-tooling", "infra", "helper.py")
    cmd = ["python3", helper_script, "build_fuzzers", "--clean",
           "--sanitizer", "address", "--engine", "libfuzzer",
           project_name, project_dir]

    print(f"Building fuzzers: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"Build failed:\n{result.stderr[-2000:]}")
        return False

    print("Build successful")
    return True


def prepare_environment(ctx: TaskContext) -> TaskContext:
    """Prepare environment: load config, build fuzzers"""
    ctx.project_config = load_project_config(ctx.dockerfile_path)
    print(f"Language: {ctx.project_config.language}")

    # Check if fuzzers already exist
    existing = find_fuzzers(ctx.fuzzer_dir)
    if existing:
        print(f"Found {len(existing)} existing fuzzers, skipping build")
    else:
        print("No fuzzers found, building...")
        build_fuzzers(ctx.task_dir, ctx.task_detail.project_name, ctx.project_dir)

    # Collect all fuzzers
    fuzzers = find_fuzzers(ctx.fuzzer_dir)
    ctx.all_fuzzers = [os.path.join(ctx.fuzzer_dir, fz) for fz in fuzzers]
    print(f"Fuzzers: {ctx.all_fuzzers}")

    return ctx


# ============================================================================
# Strategy Runner
# ============================================================================

def find_strategies(strategy_dir: str) -> List[str]:
    """Scan strategy directory for all .py files"""
    if not os.path.isdir(strategy_dir):
        return []
    strategies = []
    for entry in os.listdir(strategy_dir):
        if entry.endswith(".py") and not entry.startswith("_"):
            strategies.append(os.path.join(strategy_dir, entry))
    return sorted(strategies)


def run_strategies(ctx: TaskContext) -> None:
    """Run all strategies"""
    # Strategy directory is v1/strategy
    script_dir = os.path.dirname(os.path.abspath(__file__))
    strategy_dir = os.path.join(script_dir, "strategy")

    strategies = find_strategies(strategy_dir)
    if not strategies:
        print(f"No strategies found in {strategy_dir}")
        return

    print(f"\nFound {len(strategies)} strategies:")
    for s in strategies:
        print(f"  - {os.path.basename(s)}")

    # Run each strategy for each fuzzer
    for fuzzer_path in ctx.all_fuzzers:
        fuzzer_name = os.path.basename(fuzzer_path)
        print(f"\n{'='*60}")
        print(f"Fuzzer: {fuzzer_name}")
        print(f"{'='*60}")

        for strategy_path in strategies:
            strategy_name = os.path.basename(strategy_path)
            print(f"\n[Running] {strategy_name}")

            # Run strategy script with args
            cmd = [
                "python3", strategy_path,
                "--fuzzer", fuzzer_path,
                "--project", ctx.task_detail.project_name,
                "--focus", ctx.task_detail.focus,
                "--language", ctx.project_config.language if ctx.project_config else "c",
                "--task-type", ctx.task_detail.type,
                "--task-dir", ctx.task_dir,
                "--model", ctx.model,
            ]

            print(f"Command: {' '.join(cmd)}")

            try:
                result = subprocess.run(cmd, cwd=ctx.task_dir, timeout=3600)  # 1 hour timeout
                if result.returncode == 0:
                    print(f"[OK] {strategy_name} completed successfully")
                else:
                    print(f"[FAIL] {strategy_name} exited with code {result.returncode}")
            except subprocess.TimeoutExpired:
                print(f"[TIMEOUT] {strategy_name} timed out")
            except Exception as e:
                print(f"[ERROR] {strategy_name}: {e}")


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="CRS Local Workflow")
    parser.add_argument("task_path", help="Path to task directory")
    parser.add_argument("--model", "-m", default="claude-sonnet-4-20250514", help="AI model")
    parser.add_argument("--skip-build", action="store_true", help="Skip fuzzer build")

    args = parser.parse_args()

    print("=" * 60)
    print("CRS Local Workflow (v1)")
    print("=" * 60)

    # Step 1: Read task folder
    ctx = read_task_folder(args.task_path, args.model)

    # Step 2: Build Fuzzer (only address sanitizer)
    if not args.skip_build:
        ctx = prepare_environment(ctx)
    else:
        print("\n[Skipping build]")
        # Still need to collect existing fuzzers
        fuzzers = find_fuzzers(ctx.fuzzer_dir)
        ctx.all_fuzzers = [os.path.join(ctx.fuzzer_dir, fz) for fz in fuzzers]
        ctx.project_config = load_project_config(ctx.dockerfile_path)

    # Step 3: Run strategies
    if ctx.all_fuzzers:
        run_strategies(ctx)
    else:
        print("\nNo fuzzers available, cannot run strategies")

    print("\n" + "=" * 60)
    print("Done!")
    print("=" * 60)


if __name__ == "__main__":
    main()

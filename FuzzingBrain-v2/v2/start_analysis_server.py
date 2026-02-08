#!/usr/bin/env python3
"""
启动 Analysis Server (用于测试)
使用现有的预构建 workspace，跳过 build 步骤

用法:
    python start_analysis_server.py lcms-001      # lcms 项目
    python start_analysis_server.py ws-delta-01   # wireshark 项目
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from fuzzingbrain.analyzer.server import AnalysisServer
from fuzzingbrain.db import MongoDB


def load_sp_config(sp_name: str) -> dict:
    """从 preset-sp 目录加载 SP 配置"""
    preset_dir = Path(__file__).parent / "experiment" / "preset-sp"
    sp_file = preset_dir / sp_name / "sp.json"

    if not sp_file.exists():
        available = [d.name for d in preset_dir.iterdir() if d.is_dir() and (d / "sp.json").exists()]
        raise FileNotFoundError(
            f"SP file not found: {sp_file}\n"
            f"Available: {available}"
        )

    with open(sp_file) as f:
        return json.load(f)


async def main(sp_name: str):
    # 加载 SP 配置获取 task_id
    sp = load_sp_config(sp_name)
    task_id = sp.get("task_id", "48a64b24")

    # 从 sp_name 推断项目名
    if sp_name.startswith("ws-"):
        project_name = "wireshark"
    elif sp_name.startswith("lcms-"):
        project_name = "lcms"
    else:
        project_name = sp_name.split("-")[0]

    workspace = Path(f"./workspace/{project_name}_{task_id}")

    # 预构建目录 - 根据项目不同有不同结构
    if project_name == "wireshark":
        prebuild_dir = workspace / "fuzz-tooling-address/build"
    else:
        prebuild_dir = workspace / "fuzz-tooling/build/out"

    print(f"Starting Analysis Server...")
    print(f"SP: {sp_name}")
    print(f"Project: {project_name}")
    print(f"Task ID: {task_id}")
    print(f"Workspace: {workspace}")
    print(f"Prebuild dir: {prebuild_dir}")

    # 连接 MongoDB
    MongoDB.connect()

    server = AnalysisServer(
        task_id=task_id,
        task_path=str(workspace),
        project_name=project_name,
        sanitizers=["address"],
        ossfuzz_project=project_name,
        language="c",
        prebuild_dir=str(prebuild_dir),
    )

    print(f"Socket path: {server.socket_path}")

    result = await server.start()

    if result.success:
        print(f"\nServer started successfully!")
        print(f"Socket: {server.socket_path}")
        print(f"Fuzzers: {len(server.fuzzers)}")
        print("\nServer running. Press Ctrl+C to stop.")

        # 保持运行
        await server.serve_forever()
    else:
        print(f"Failed to start server: {result.error}")
        return 1

    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="启动 Analysis Server")
    parser.add_argument(
        "sp_name",
        nargs="?",
        default="lcms-001",
        help="SP名称 (对应 experiment/preset-sp/<name>/sp.json)"
    )
    args = parser.parse_args()

    try:
        sys.exit(asyncio.run(main(args.sp_name)))
    except KeyboardInterrupt:
        print("\nServer stopped.")
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)

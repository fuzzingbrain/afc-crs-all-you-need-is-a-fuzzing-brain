#!/usr/bin/env python3
"""
启动 Analysis Server (用于测试)
使用现有的预构建 workspace，跳过 build 步骤
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from fuzzingbrain.analyzer.server import AnalysisServer
from fuzzingbrain.db import MongoDB


async def main():
    task_id = "48a64b24"  # 和 preset-sp/*.json 保持一致
    workspace = Path(f"./workspace/lcms_{task_id}")

    # 预构建目录
    prebuild_dir = workspace / "fuzz-tooling/build/out"

    print(f"Starting Analysis Server...")
    print(f"Task ID: {task_id}")
    print(f"Workspace: {workspace}")
    print(f"Prebuild dir: {prebuild_dir}")

    # 连接 MongoDB
    MongoDB.connect()

    server = AnalysisServer(
        task_id=task_id,
        task_path=str(workspace),
        project_name="lcms",
        sanitizers=["address"],
        ossfuzz_project="lcms",
        language="c",
        skip_build=True,  # 跳过 build，使用预构建
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
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        print("\nServer stopped.")

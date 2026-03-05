#!/usr/bin/env python3
"""
Patch0 Full Strategy - LLM-guided patch generation for full scans

Full-scan variant of patch0. The core patch logic is identical to delta;
the only difference is that full scan has no commit diff context, so the
patch prompt relies more heavily on crash log and function analysis.
"""
import os
import sys
from typing import Dict, Any, Tuple

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from strategies.patch0_delta_new import Patch0DeltaStrategy
from common.config import StrategyConfig
from core.patch_strategy import INITIAL_PATCH_TEMPLATE
from common.utils import get_commit_info, truncate_output


class Patch0FullStrategy(Patch0DeltaStrategy):
    """
    Patch0 Full Strategy: Same as Patch0 Delta but for full scan.

    In full scan mode, commit_diff is empty so the patch prompt
    relies on crash log and function analysis alone.
    """

    def get_strategy_name(self) -> str:
        return "patch0_full"


def main():
    """Main entry point for Patch0 Full strategy."""
    import argparse

    parser = argparse.ArgumentParser(description="Patch0 Full Strategy")
    parser.add_argument("fuzzer_path", help="Path to fuzzer executable")
    parser.add_argument("project_name", help="Project name")
    parser.add_argument("focus", help="Focus directory")
    parser.add_argument("language", help="Project language")

    parser.add_argument("--max-iterations", dest="max_iterations", type=int, default=5)
    parser.add_argument("--patching-timeout", dest="patching_timeout", type=int, default=30)
    parser.add_argument("--pov-metadata-dir", dest="pov_metadata_dir", type=str,
                        default="successful_povs")
    parser.add_argument("--patch-workspace-dir", type=str, default="patch_workspace")
    parser.add_argument("--model", type=str, default="")
    parser.add_argument("--log-dir", type=str, default="./logs")

    args = parser.parse_args()

    config = StrategyConfig(
        strategy_name="patch0_full",
        fuzzer_path=args.fuzzer_path,
        project_name=args.project_name,
        focus=args.focus,
        language=args.language,
        do_patch=True,
        full_scan=True,
        max_iterations=args.max_iterations,
        patching_timeout_minutes=args.patching_timeout,
        pov_metadata_dir=args.pov_metadata_dir,
        patch_workspace_dir=args.patch_workspace_dir,
        log_dir=args.log_dir,
        models=[args.model] if args.model else None,
    )

    strategy = Patch0FullStrategy(config)
    success = strategy.run()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

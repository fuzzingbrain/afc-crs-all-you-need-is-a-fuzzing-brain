#!/usr/bin/env python3
"""
XS0 Delta Strategy (Refactored Version)
LLM-guided test harness generation for vulnerability triggering
"""
import sys
import os
import argparse

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
import openlit
from opentelemetry import trace
from loguru import logger

from core.pov_strategy import PoVStrategy
from common.config import StrategyConfig
from common.llm.models import CLAUDE_MODEL_SONNET_4, CLAUDE_MODEL_OPUS_4

# Load environment variables
load_dotenv()

# Configure loguru for early messages (before StrategyLogger is created)
logger.remove()
logger.add(lambda msg: print(msg, end=""), format="{message}\n", level="INFO")

# Initialize openlit (telemetry)
# Note: If telemetry backend is not configured, you may see export failures (safe to ignore)
try:
    logger.info("Initializing telemetry (openlit)...")
    openlit.init(application_name="afc-crs-all-you-need-is-a-fuzzing-brain")
    logger.info("Telemetry initialized successfully")
except Exception as e:
    logger.warning(f"Failed to initialize telemetry (openlit): {e}")
    logger.info("Continuing without telemetry tracking...")


class XS0DeltaStrategy(PoVStrategy):
    """XS0 Delta Strategy - Basic POV generation with delta scan"""

    def get_strategy_name(self) -> str:
        return "xs0_delta"

    def get_span_name(self) -> str:
        return "xs0_basic_fuzzing_delta"

    def get_system_prompt(self) -> str:
        """XS0 specific system prompt"""
        # TODO: Migrate the actual system prompt from jeff/xs0_delta.py
        return "You are a security researcher specializing in vulnerability exploitation."

    def create_initial_prompt(self, fuzzer_code: str, commit_diff: str, sanitizer: str) -> str:
        """
        Create XS0-specific initial prompt for POV generation
        """
        # TODO: Migrate the actual prompt generation logic from jeff/xs0_delta.py
        return f"""
        You are analyzing a fuzzer for potential vulnerabilities.

        Fuzzer Code:
        {fuzzer_code}

        Recent Changes (Delta Scan):
        {commit_diff}

        Sanitizer: {sanitizer}

        Generate a test harness to trigger the vulnerability.
        """


def main():
    """Main entry point - compatible with goroutine calling"""
    parser = argparse.ArgumentParser(description="XS0 Delta Strategy (Refactored)")

    # Required arguments
    parser.add_argument("fuzzer_path", help="Path to the fuzzer")
    parser.add_argument("project_name", help="Project name")
    parser.add_argument("focus", help="Focus")
    parser.add_argument("language", help="Language")

    # Optional arguments
    parser.add_argument("--test-nginx", dest="test_nginx", type=lambda x: x.lower() == 'true',
                        default=False, help="Whether to test Nginx (true/false)")
    parser.add_argument("--do-patch", dest="do_patch", type=lambda x: x.lower() == 'true',
                        default=False, help="Whether to apply patches (true/false)")
    parser.add_argument("--do-patch-only", dest="do_patch_only", type=lambda x: x.lower() == 'true',
                        default=False, help="Whether to only run patching (true/false)")
    parser.add_argument("--full-scan", dest="full_scan", type=lambda x: x.lower() == 'true',
                        default=False, help="Whether full scan (default is delta-scan)")
    parser.add_argument("--max-iterations", dest="max_iterations", type=int,
                        default=5, help="Maximum number of iterations")
    parser.add_argument("--fuzzing-timeout", dest="fuzzing_timeout", type=int,
                        default=30, help="Fuzzing timeout in minutes")
    parser.add_argument("--patching-timeout", dest="patching_timeout", type=int,
                        default=30, help="Patching timeout in minutes")
    parser.add_argument("--pov-metadata-dir", dest="pov_metadata_dir", type=str,
                        default="successful_povs", help="Directory to store POV metadata")
    parser.add_argument("--patch-workspace-dir", dest="patch_workspace_dir",
                        default="patch_workspace", help="Directory for patch workspace")
    parser.add_argument("--check-patch-success", action="store_true",
                        help="Check for successful patches and exit early if found")
    parser.add_argument("--model", type=str, default="", help="Specify the model to use")
    parser.add_argument("--cpv", type=str, default="cpv12", help="CPV number to test")

    args = parser.parse_args()

    # Set up models
    models = [CLAUDE_MODEL_SONNET_4, CLAUDE_MODEL_OPUS_4]
    if args.model:
        models = [args.model]

    # Create configuration
    config = StrategyConfig(
        strategy_name='xs0_delta',
        fuzzer_path=args.fuzzer_path,
        project_name=args.project_name,
        focus=args.focus,
        language=args.language,
        test_nginx=args.test_nginx,
        do_patch=args.do_patch,
        do_patch_only=args.do_patch_only,
        full_scan=args.full_scan,
        max_iterations=args.max_iterations,
        fuzzing_timeout_minutes=args.fuzzing_timeout,
        patching_timeout_minutes=args.patching_timeout,
        pov_metadata_dir=args.pov_metadata_dir,
        patch_workspace_dir=args.patch_workspace_dir,
        check_patch_success=args.check_patch_success,
        cpv=args.cpv,
        models=models,
        use_control_flow=True  # XS0 specific
    )

    # Execute strategy
    strategy = XS0DeltaStrategy(config)
    success = strategy.run()

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())

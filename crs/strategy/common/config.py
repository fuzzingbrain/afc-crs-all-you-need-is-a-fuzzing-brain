"""
Strategy Configuration
Replaces global variables with a clean config object
"""
import os
from pathlib import Path
from typing import Optional, List
from dataclasses import dataclass, field

from common.llm.models import DEFAULT_MODELS


@dataclass
class StrategyConfig:
    """Configuration for a strategy execution"""

    # Required fields
    strategy_name: str
    fuzzer_path: str
    project_name: str
    focus: str
    language: str

    # Strategy parameters
    do_patch: bool = False
    do_patch_only: bool = False
    full_scan: bool = False
    max_iterations: int = 5
    fuzzing_timeout_minutes: int = 45
    patching_timeout_minutes: int = 30

    # Model configuration
    models: List[str] = field(default_factory=list)

    # Directory configuration
    pov_metadata_dir: str = "successful_povs"
    patch_metadata_dir: str = "successful_patches"
    patch_workspace_dir: str = "patch_workspace"

    # Optional parameters
    test_nginx: bool = False
    check_patch_success: bool = False
    cpv: str = "cpv12"
    pov_phase: int = 0
    patch_phase: int = 0

    # Strategy-specific flags
    use_control_flow: bool = True
    unharnessed: bool = False

    # Logging configuration
    log_dir: str = "./logs"

    # Environment variables (read once at init)
    api_key_id: Optional[str] = field(init=False)

    # Computed fields
    fuzzer_name: str = field(init=False)
    fuzz_dir: str = field(init=False)
    sanitizer: str = field(init=False)
    project_dir: str = field(init=False)
    project_src_dir: str = field(init=False)
    pov_success_dir: str = field(init=False)
    patch_success_dir: str = field(init=False)

    def __post_init__(self):
        """Initialize computed fields and read environment variables"""
        # Read environment variables
        self.api_key_id = os.environ.get("COMPETITION_API_KEY_ID")

        # Set default models if not specified
        if not self.models:
            self.models = DEFAULT_MODELS.copy()

        # Ensure log directory exists
        os.makedirs(self.log_dir, exist_ok=True)

        # Normalize language
        if not self.language.startswith('c'):
            self.language = "java"
        else:
            self.language = "c"

        # Compute fuzzer info
        self.fuzzer_name = os.path.basename(self.fuzzer_path)
        self.fuzz_dir = os.path.dirname(self.fuzzer_path)

        # Extract sanitizer
        base_name = os.path.basename(self.fuzz_dir)
        parts = base_name.split("-")
        self.sanitizer = parts[-1] if parts[-1] != self.project_name else "address"

        # Compute project directories
        if "/fuzz-tooling/build/out" in self.fuzzer_path:
            self.project_dir = self.fuzzer_path.split("/fuzz-tooling/build/out")[0] + "/"
        else:
            self.project_dir = os.path.dirname(os.path.dirname(self.fuzzer_path))

        self.project_src_dir = os.path.join(self.project_dir, f"{self.focus}-{self.sanitizer}")

        # Compute success directories
        self.pov_success_dir = os.path.join(self.fuzz_dir, self.pov_metadata_dir)
        self.patch_success_dir = os.path.join(self.fuzz_dir, self.patch_metadata_dir)

    def debug_print(self):
        """Print debug information about the configuration"""
        print(f"DEBUG: strategy_name = {self.strategy_name}")
        print(f"DEBUG: language = {self.language}")
        print(f"DEBUG: fuzzer_name = {self.fuzzer_name}")
        print(f"DEBUG: sanitizer = {self.sanitizer}")
        print(f"DEBUG: project_dir = {self.project_dir}")
        print(f"DEBUG: project_src_dir = {self.project_src_dir}")
        print(f"DEBUG: pov_success_dir = {self.pov_success_dir}")
        print(f"DEBUG: patch_success_dir = {self.patch_success_dir}")
        print(f"DEBUG: max_iterations = {self.max_iterations}")
        print(f"DEBUG: models = {self.models}")

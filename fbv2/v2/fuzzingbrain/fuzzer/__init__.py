"""
Fuzzer Worker Module

Dual-layer fuzzer architecture with Agent-guided seed generation.

Components:
- FuzzerManager: Top-level manager for all fuzzers
- FuzzerInstance: Single fuzzer process wrapper
- FuzzerMonitor: Background crash directory monitoring
- SeedAgent: AI-powered seed generation
- seed_tools: MCP tools for seed generation
"""

from .models import (
    FuzzerStatus,
    FuzzerType,
    GlobalFuzzerConfig,
    SPFuzzerConfig,
    CrashRecord,
    FuzzerStats,
    SeedInfo,
)

from .instance import FuzzerInstance

from .monitor import FuzzerMonitor

from .manager import (
    FuzzerManager,
    register_fuzzer_manager,
    get_fuzzer_manager,
    unregister_fuzzer_manager,
)

from .seed_tools import (
    set_seed_context,
    update_seed_context,
    get_seed_context,
    clear_seed_context,
    create_seed,
    get_seed_context_info,
    create_seed_impl,
)

from .seed_agent import SeedAgent


__all__ = [
    # Models
    "FuzzerStatus",
    "FuzzerType",
    "GlobalFuzzerConfig",
    "SPFuzzerConfig",
    "CrashRecord",
    "FuzzerStats",
    "SeedInfo",
    # Instance
    "FuzzerInstance",
    # Monitor
    "FuzzerMonitor",
    # Manager
    "FuzzerManager",
    "register_fuzzer_manager",
    "get_fuzzer_manager",
    "unregister_fuzzer_manager",
    # Seed Tools
    "set_seed_context",
    "update_seed_context",
    "get_seed_context",
    "clear_seed_context",
    "create_seed",
    "get_seed_context_info",
    "create_seed_impl",
    # Seed Agent
    "SeedAgent",
]

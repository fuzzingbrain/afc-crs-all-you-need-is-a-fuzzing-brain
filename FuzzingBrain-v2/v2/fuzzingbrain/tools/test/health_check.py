"""
Tool Health Check

Runs validation tests on all tools using a simple test project.

The test project is a permanent directory structure at:
    fuzzingbrain/tools/test/test_project/
    ├── config.json           # Project configuration
    ├── coverage_fuzzer/      # Coverage-instrumented fuzzer (symlink or copy)
    ├── source/               # Source code for context display
    ├── corpus/               # Test inputs
    └── output/               # Coverage output (persistent, avoid /tmp Docker Snap issues)
"""

import base64
import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any

# Test project directory (permanent structure)
TEST_PROJECT_DIR = Path(__file__).parent / "test_project"


@dataclass
class ToolTestResult:
    """Result of a single tool test"""
    tool_name: str
    passed: bool
    message: str
    details: Optional[Dict[str, Any]] = None


@dataclass
class HealthCheckResult:
    """Overall health check result"""
    all_passed: bool
    tool_results: List[ToolTestResult] = field(default_factory=list)
    prerequisites_ok: bool = False
    prerequisite_errors: List[str] = field(default_factory=list)

    def summary(self) -> str:
        """Generate summary string"""
        lines = ["=" * 60]
        lines.append("FuzzingBrain Tools Health Check")
        lines.append("=" * 60)

        # Prerequisites
        lines.append("\nPrerequisites:")
        if self.prerequisites_ok:
            lines.append("  [OK] All prerequisites satisfied")
        else:
            for err in self.prerequisite_errors:
                lines.append(f"  [FAIL] {err}")

        # Tool results
        lines.append("\nTool Tests:")
        for result in self.tool_results:
            status = "[OK]" if result.passed else "[FAIL]"
            lines.append(f"  {status} {result.tool_name}: {result.message}")

        # Summary
        passed = sum(1 for r in self.tool_results if r.passed)
        total = len(self.tool_results)
        lines.append(f"\nResult: {passed}/{total} tests passed")
        lines.append("=" * 60)

        return "\n".join(lines)


def check_prerequisites() -> tuple[bool, List[str]]:
    """Check that all prerequisites are met"""
    errors = []

    # Check Docker
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=10,
        )
        if result.returncode != 0:
            errors.append("Docker is not running")
    except FileNotFoundError:
        errors.append("Docker is not installed")
    except subprocess.TimeoutExpired:
        errors.append("Docker check timed out")

    # Check test project exists
    if not TEST_PROJECT_DIR.exists():
        errors.append(f"Test project not found: {TEST_PROJECT_DIR}")
    else:
        # Check for required subdirectories
        required_dirs = ["coverage_fuzzer", "source", "corpus", "output"]
        for d in required_dirs:
            if not (TEST_PROJECT_DIR / d).exists():
                errors.append(f"Test project missing: {d}/")

        # Check for test input in corpus/
        corpus_dir = TEST_PROJECT_DIR / "corpus"
        if corpus_dir.exists() and not any(corpus_dir.iterdir()):
            errors.append("Test project missing: corpus/ is empty")

        # Check for config
        if not (TEST_PROJECT_DIR / "config.json").exists():
            errors.append("Test project missing: config.json")

    return len(errors) == 0, errors


def load_test_config() -> Optional[Dict[str, Any]]:
    """Load test project config"""
    config_path = TEST_PROJECT_DIR / "config.json"
    if not config_path.exists():
        return None
    with open(config_path) as f:
        return json.load(f)


def test_coverage_list_fuzzers() -> ToolTestResult:
    """Test list_available_fuzzers tool"""
    try:
        from ..coverage import list_fuzzers_impl, set_coverage_context

        config = load_test_config()
        if not config:
            return ToolTestResult(
                tool_name="list_available_fuzzers",
                passed=False,
                message="Test project config not found",
            )

        # Set context with docker_image and work_dir from config
        set_coverage_context(
            coverage_fuzzer_dir=TEST_PROJECT_DIR / "coverage_fuzzer",
            project_name=config.get("project_name", "test"),
            src_dir=TEST_PROJECT_DIR / "source",
            docker_image=config.get("docker_image"),
            work_dir=TEST_PROJECT_DIR / "output",
        )

        # Run tool (use direct-call impl, not MCP wrapper)
        result = list_fuzzers_impl()

        if not result.get("success"):
            return ToolTestResult(
                tool_name="list_available_fuzzers",
                passed=False,
                message=f"Tool failed: {result.get('error')}",
                details=result,
            )

        fuzzers = result.get("fuzzers", [])
        if len(fuzzers) == 0:
            return ToolTestResult(
                tool_name="list_available_fuzzers",
                passed=False,
                message="No fuzzers found in test project",
                details=result,
            )

        return ToolTestResult(
            tool_name="list_available_fuzzers",
            passed=True,
            message=f"Found {len(fuzzers)} fuzzer(s): {', '.join(fuzzers)}",
            details=result,
        )

    except Exception as e:
        return ToolTestResult(
            tool_name="list_available_fuzzers",
            passed=False,
            message=f"Exception: {e}",
        )


def test_coverage_run() -> ToolTestResult:
    """Test run_coverage tool"""
    try:
        from ..coverage import run_coverage_impl, set_coverage_context, list_fuzzers_impl

        config = load_test_config()
        if not config:
            return ToolTestResult(
                tool_name="run_coverage",
                passed=False,
                message="Test project config not found",
            )

        # Set context with docker_image and work_dir
        set_coverage_context(
            coverage_fuzzer_dir=TEST_PROJECT_DIR / "coverage_fuzzer",
            project_name=config.get("project_name", "test"),
            src_dir=TEST_PROJECT_DIR / "source",
            docker_image=config.get("docker_image"),
            work_dir=TEST_PROJECT_DIR / "output",
        )

        # Get fuzzer name (prefer from config, fallback to first available)
        fuzzer_name = config.get("fuzzer_name")
        if not fuzzer_name:
            fuzzers_result = list_fuzzers_impl()
            if not fuzzers_result.get("success") or not fuzzers_result.get("fuzzers"):
                return ToolTestResult(
                    tool_name="run_coverage",
                    passed=False,
                    message="No fuzzers available for testing",
                )
            fuzzer_name = fuzzers_result["fuzzers"][0]

        # Load test input from corpus/
        corpus_dir = TEST_PROJECT_DIR / "corpus"
        test_inputs = list(corpus_dir.iterdir()) if corpus_dir.exists() else []
        if not test_inputs:
            return ToolTestResult(
                tool_name="run_coverage",
                passed=False,
                message="No test inputs in corpus/",
            )

        test_input = test_inputs[0].read_bytes()
        input_b64 = base64.b64encode(test_input).decode()

        # Run coverage (use direct-call impl, not MCP wrapper)
        result = run_coverage_impl(
            fuzzer_name=fuzzer_name,
            input_data_base64=input_b64,
        )

        if not result.get("success"):
            return ToolTestResult(
                tool_name="run_coverage",
                passed=False,
                message=f"Coverage failed: {result.get('error')}",
                details=result,
            )

        func_count = len(result.get("executed_functions", []))
        return ToolTestResult(
            tool_name="run_coverage",
            passed=True,
            message=f"Coverage executed, {func_count} functions reached",
            details=result,
        )

    except Exception as e:
        return ToolTestResult(
            tool_name="run_coverage",
            passed=False,
            message=f"Exception: {e}",
        )


def test_coverage_feedback() -> ToolTestResult:
    """Test get_coverage_feedback tool"""
    try:
        from ..coverage import get_feedback_impl, set_coverage_context, list_fuzzers_impl

        config = load_test_config()
        if not config:
            return ToolTestResult(
                tool_name="get_coverage_feedback",
                passed=False,
                message="Test project config not found",
            )

        # Set context with docker_image and work_dir
        set_coverage_context(
            coverage_fuzzer_dir=TEST_PROJECT_DIR / "coverage_fuzzer",
            project_name=config.get("project_name", "test"),
            src_dir=TEST_PROJECT_DIR / "source",
            docker_image=config.get("docker_image"),
            work_dir=TEST_PROJECT_DIR / "output",
        )

        # Get fuzzer name (prefer from config, fallback to first available)
        fuzzer_name = config.get("fuzzer_name")
        if not fuzzer_name:
            fuzzers_result = list_fuzzers_impl()
            if not fuzzers_result.get("success") or not fuzzers_result.get("fuzzers"):
                return ToolTestResult(
                    tool_name="get_coverage_feedback",
                    passed=False,
                    message="No fuzzers available for testing",
                )
            fuzzer_name = fuzzers_result["fuzzers"][0]

        # Load test input from corpus/
        corpus_dir = TEST_PROJECT_DIR / "corpus"
        test_inputs = list(corpus_dir.iterdir()) if corpus_dir.exists() else []
        if not test_inputs:
            return ToolTestResult(
                tool_name="get_coverage_feedback",
                passed=False,
                message="No test inputs in corpus/",
            )

        test_input = test_inputs[0].read_bytes()
        input_b64 = base64.b64encode(test_input).decode()

        # Get feedback (use direct-call impl, not MCP wrapper)
        result = get_feedback_impl(
            fuzzer_name=fuzzer_name,
            input_data_base64=input_b64,
        )

        if not result.get("success"):
            return ToolTestResult(
                tool_name="get_coverage_feedback",
                passed=False,
                message=f"Feedback failed: {result.get('error')}",
                details=result,
            )

        feedback_len = len(result.get("feedback", ""))
        return ToolTestResult(
            tool_name="get_coverage_feedback",
            passed=True,
            message=f"Feedback generated ({feedback_len} chars)",
            details={"feedback_preview": result.get("feedback", "")[:200]},
        )

    except Exception as e:
        return ToolTestResult(
            tool_name="get_coverage_feedback",
            passed=False,
            message=f"Exception: {e}",
        )


def run_health_check(verbose: bool = False) -> HealthCheckResult:
    """
    Run full health check on all tools.

    Args:
        verbose: Print detailed output

    Returns:
        HealthCheckResult with all test results
    """
    result = HealthCheckResult(all_passed=False)

    # Check prerequisites
    prereq_ok, prereq_errors = check_prerequisites()
    result.prerequisites_ok = prereq_ok
    result.prerequisite_errors = prereq_errors

    if not prereq_ok:
        if verbose:
            print(result.summary())
        return result

    # Run tool tests
    tests = [
        test_coverage_list_fuzzers,
        test_coverage_run,
        test_coverage_feedback,
    ]

    for test_func in tests:
        if verbose:
            print(f"Running: {test_func.__name__}...")

        test_result = test_func()
        result.tool_results.append(test_result)

        if verbose:
            status = "OK" if test_result.passed else "FAIL"
            print(f"  [{status}] {test_result.message}")

    # Set overall result
    result.all_passed = all(r.passed for r in result.tool_results)

    if verbose:
        print(result.summary())

    return result


def main():
    """CLI entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="FuzzingBrain Tools Health Check")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    result = run_health_check(verbose=True)

    sys.exit(0 if result.all_passed else 1)


if __name__ == "__main__":
    main()

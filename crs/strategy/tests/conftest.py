"""
Pytest Configuration and Shared Fixtures - Enterprise Grade

This module provides:
1. Global pytest configuration
2. Reusable test fixtures
3. Test utilities and helpers
4. Mock data generators

All fixtures follow pytest best practices:
- Descriptive names
- Proper scoping (function/class/module/session)
- Clean teardown
- Type hints for better IDE support

References:
- https://docs.pytest.org/en/stable/reference/fixtures.html
- https://testing.googleblog.com/2024/01/effective-testing-practices-at-google.html
"""

import os
import sys
import tempfile
import shutil
from pathlib import Path
from typing import Dict, Any, Generator
from unittest.mock import Mock, MagicMock

import pytest

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ============================================================================
# Session-scoped Fixtures (created once per test session)
# ============================================================================

@pytest.fixture(scope="session")
def project_root() -> Path:
    """
    Returns the project root directory.

    Scope: session (created once, shared across all tests)
    """
    return PROJECT_ROOT


@pytest.fixture(scope="session")
def test_data_dir(project_root: Path) -> Path:
    """
    Returns the test data directory containing sample files.

    Scope: session
    """
    data_dir = project_root / "tests" / "fixtures" / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


# ============================================================================
# Module-scoped Fixtures (created once per test module)
# ============================================================================

@pytest.fixture(scope="module")
def sample_fuzzer_code() -> str:
    """
    Sample fuzzer source code for testing.

    Returns a realistic C fuzzer harness example.
    Scope: module (shared across tests in same file)
    """
    return '''
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <png.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) {
        return 0;
    }

    png_structp png_ptr = png_create_read_struct(
        PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png_ptr) {
        return 0;
    }

    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        png_destroy_read_struct(&png_ptr, NULL, NULL);
        return 0;
    }

    // Process PNG data
    png_set_sig_bytes(png_ptr, 0);
    png_read_info(png_ptr, info_ptr);

    png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
    return 0;
}
'''.strip()


@pytest.fixture(scope="module")
def sample_commit_diff() -> str:
    """
    Sample git commit diff introducing a vulnerability.

    Returns a realistic diff showing buffer overflow fix.
    Scope: module
    """
    return '''
diff --git a/png_read.c b/png_read.c
index 1234567..abcdefg 100644
--- a/png_read.c
+++ b/png_read.c
@@ -156,8 +156,12 @@ void png_read_iCCP(png_structp png_ptr, png_infop info_ptr,
     }

     profile_length = png_get_uint_32(buf);
-
-    memcpy(profile_buffer, input_data, profile_length);
+
+    // Fix: Add buffer size check to prevent overflow
+    if (profile_length > MAX_PROFILE_SIZE) {
+        png_error(png_ptr, "iCCP: profile too large");
+    }
+    memcpy(profile_buffer, input_data, profile_length);

     png_set_iCCP(png_ptr, info_ptr, profile_name,
                  compression_type, profile_buffer, profile_length);
'''.strip()


# ============================================================================
# Function-scoped Fixtures (created for each test function)
# ============================================================================

@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """
    Creates a temporary directory for test isolation.

    Automatically cleaned up after test completes.
    Scope: function (new directory for each test)

    Example:
        def test_file_operations(temp_dir):
            test_file = temp_dir / "test.txt"
            test_file.write_text("hello")
            assert test_file.exists()
    """
    temp_path = Path(tempfile.mkdtemp(prefix="crs_test_"))
    try:
        yield temp_path
    finally:
        # Cleanup
        if temp_path.exists():
            shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def mock_config() -> Mock:
    """
    Creates a mock StrategyConfig object for testing.

    Returns a configured Mock with realistic default values.
    Scope: function

    Example:
        def test_strategy(mock_config):
            mock_config.language = "c"
            assert strategy.validate(mock_config)
    """
    config = Mock()
    config.strategy_name = "test_strategy"
    config.fuzzer_path = "/test/fuzzer"
    config.project_name = "test_project"
    config.focus = "test_focus"
    config.language = "c"
    config.sanitizer = "address"
    config.max_iterations = 5
    config.fuzzing_timeout_minutes = 45
    config.models = ["claude-sonnet-4-20250514", "claude-opus-4-20250514"]
    config.pov_phase = 0
    config.project_dir = "/test/project"
    config.fuzz_dir = "/test/fuzz"
    config.fuzzer_name = "test_fuzzer"
    return config


@pytest.fixture
def mock_logger() -> Mock:
    """
    Creates a mock StrategyLogger for testing.

    Captures log calls without actual logging.
    Scope: function

    Example:
        def test_logging(mock_logger):
            function_under_test(logger=mock_logger)
            mock_logger.log.assert_called_once()
    """
    logger = Mock()
    logger.log = Mock()
    logger.error = Mock()
    logger.warning = Mock()
    return logger


@pytest.fixture
def mock_llm_client() -> Mock:
    """
    Creates a mock LLM client for testing without API calls.

    Provides realistic mock responses.
    Scope: function

    Example:
        def test_llm_interaction(mock_llm_client):
            mock_llm_client.chat.return_value = "mock response"
            result = generate_pov(mock_llm_client)
            assert "mock" in result
    """
    client = Mock()

    # Mock successful response
    client.chat.return_value = '''
```python
# Mock LLM generated code
with open("x1.bin", "wb") as f:
    f.write(b"test data")
```
'''

    return client


@pytest.fixture
def sample_blob_data() -> bytes:
    """
    Returns sample binary blob data for testing.

    Simulates a PNG file header.
    Scope: function
    """
    # PNG file signature + minimal IHDR chunk
    return (
        b'\x89PNG\r\n\x1a\n'  # PNG signature
        b'\x00\x00\x00\rIHDR'  # IHDR chunk
        b'\x00\x00\x00\x01'  # Width: 1
        b'\x00\x00\x00\x01'  # Height: 1
        b'\x08\x02\x00\x00\x00'  # Bit depth, color type, etc.
    )


# ============================================================================
# Parametrize Fixtures (data-driven testing)
# ============================================================================

@pytest.fixture(params=["c", "java"])
def language(request) -> str:
    """
    Parametrized fixture for testing both C and Java.

    Tests using this fixture will run twice (once for each language).

    Example:
        def test_language_support(language):
            # This test runs twice: language="c", then language="java"
            config = StrategyConfig(language=language)
            assert config.language in ["c", "java"]
    """
    return request.param


@pytest.fixture(params=["address", "memory", "undefined"])
def sanitizer(request) -> str:
    """
    Parametrized fixture for testing different sanitizers.

    Example:
        def test_sanitizer_detection(sanitizer):
            # Runs 3 times: address, memory, undefined
            prompt = create_prompt(sanitizer=sanitizer)
            assert sanitizer.capitalize() in prompt
    """
    return request.param


# ============================================================================
# Auto-use Fixtures (automatically applied to all tests)
# ============================================================================

@pytest.fixture(autouse=True)
def reset_environment():
    """
    Resets environment variables before each test.

    Ensures test isolation by cleaning up env vars.
    Scope: function, autouse=True (runs for every test)
    """
    # Save original environment
    original_env = os.environ.copy()

    yield

    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env)


# ============================================================================
# Helper Functions (not fixtures, but test utilities)
# ============================================================================

def assert_valid_prompt(prompt: str) -> None:
    """
    Helper function to validate prompt structure.

    Args:
        prompt: The prompt string to validate

    Raises:
        AssertionError: If prompt doesn't meet requirements
    """
    assert len(prompt) > 0, "Prompt cannot be empty"
    assert "fuzzer" in prompt.lower() or "vulnerability" in prompt.lower(), \
        "Prompt must mention fuzzer or vulnerability"


def create_mock_fuzzer_output(crashed: bool = False) -> str:
    """
    Creates realistic mock fuzzer output for testing.

    Args:
        crashed: Whether the fuzzer should report a crash

    Returns:
        Fuzzer output string
    """
    if crashed:
        return '''
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 1234567890
INFO: Loaded 1 modules   (1234 inline 8-bit counters): 1234 [0x12345678, 0x12345abc)
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7f1234567890
READ of size 100 at 0x7f1234567890 thread T0
    #0 0x12345678 in png_read_iCCP png_read.c:165
    #1 0x23456789 in LLVMFuzzerTestOneInput fuzzer.c:25
    #2 0x34567890 in fuzzer::Fuzzer::ExecuteCallback
'''
    else:
        return '''
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 1234567890
INFO: Loaded 1 modules   (1234 inline 8-bit counters): 1234 [0x12345678, 0x12345abc)
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
#1234   NEW    cov: 123 ft: 456 corp: 10/120b exec/s: 100 rss: 45Mb
#2345   REDUCE cov: 125 ft: 458 corp: 11/125b lim: 4096 exec/s: 105 rss: 46Mb
Done 10000 runs in 95 second(s)
'''


# ============================================================================
# Pytest Hooks (advanced customization)
# ============================================================================

def pytest_configure(config):
    """
    Pytest hook called before test collection.

    Adds custom markers and configuration.
    """
    config.addinivalue_line(
        "markers", "enterprise: Enterprise-grade test (requires full setup)"
    )


def pytest_collection_modifyitems(config, items):
    """
    Pytest hook to modify test collection.

    Automatically adds markers based on test location.
    """
    for item in items:
        # Add 'unit' marker to all tests in tests/unit/
        if "tests/unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)

        # Add 'integration' marker to tests in tests/integration/
        elif "tests/integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)

        # Add 'regression' marker to tests in tests/regression/
        elif "tests/regression" in str(item.fspath):
            item.add_marker(pytest.mark.regression)

"""
CRS Strategy Test Suite - Enterprise Grade

This test suite follows industry best practices and provides comprehensive
testing coverage for the CRS strategy implementation.

Test Organization:
==================
- unit/: Unit tests for individual functions and classes
  * Fast execution (<1s per test)
  * No external dependencies
  * Mock all I/O operations

- integration/: Integration tests for component interactions
  * Test multiple components working together
  * May use mocked external services
  * Moderate execution time (~5-30s)

- regression/: Regression tests comparing old vs new implementations
  * Ensure refactored code maintains exact same behavior
  * May be slower due to comprehensive checks
  * Critical for ensuring no functionality is lost

- fixtures/: Shared test data and mock objects
  * Reusable test fixtures
  * Sample data files
  * Mock responses

Test Categories (Markers):
==========================
@pytest.mark.unit - Fast, isolated unit tests
@pytest.mark.integration - Multi-component integration tests
@pytest.mark.regression - Old vs new equivalence tests
@pytest.mark.slow - Tests taking >5 seconds
@pytest.mark.requires_llm - Tests needing actual LLM API

Usage Examples:
===============
# Run all tests
pytest

# Run only unit tests (fast)
pytest -m unit

# Run tests excluding slow ones
pytest -m "not slow"

# Run specific test file
pytest tests/unit/test_text_utils.py

# Run with coverage report
pytest --cov

# Run with detailed output
pytest -vv

# Run failed tests only (from last run)
pytest --lf

Code Coverage Standards:
========================
- Minimum coverage: 80% (enforced by CI)
- Target coverage: 90%+
- Critical paths: 100%

All tests must pass before merging PRs.

Version: 1.0.0
Author: CRS Development Team
License: Proprietary
"""

__version__ = "1.0.0"
__author__ = "CRS Development Team"

# Test suite metadata
TEST_SUITE_NAME = "CRS Strategy Tests"
MINIMUM_COVERAGE = 80
TARGET_COVERAGE = 90

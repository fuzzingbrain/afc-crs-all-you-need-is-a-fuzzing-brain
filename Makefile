# ============================================================================
# CRS Multi-Language Test Orchestration Makefile - Enterprise Grade
# ============================================================================
# This Makefile provides a unified interface for running tests across
# both Go and Python codebases in the CRS project.
#
# Usage:
#   make help          - Show all available commands
#   make test          - Run all tests (Go + Python)
#   make test-python   - Run only Python tests
#   make test-go       - Run only Go tests
#   make test-fast     - Run fast tests only (for quick feedback)
# ============================================================================

.PHONY: help test test-all test-go test-python test-fast test-coverage clean install

# Colors for output
GREEN  := \033[0;32m
YELLOW := \033[0;33m
RED    := \033[0;31m
BLUE   := \033[0;34m
NC     := \033[0m# No Color

# Default target
.DEFAULT_GOAL := help

# ----------------------------------------------------------------------------
# Help
# ----------------------------------------------------------------------------
help:
	@echo ""
	@echo "$(BLUE)═══════════════════════════════════════════════════════════════$(NC)"
	@echo "$(BLUE)  CRS Testing Commands - Multi-language Test Orchestration$(NC)"
	@echo "$(BLUE)═══════════════════════════════════════════════════════════════$(NC)"
	@echo ""
	@echo "$(GREEN)Main Commands:$(NC)"
	@echo "  make test              - Run all tests (Go + Python)"
	@echo "  make test-fast         - Run fast tests only (quick feedback)"
	@echo "  make test-coverage     - Run tests with coverage reports"
	@echo "  make install           - Install test dependencies"
	@echo "  make clean             - Clean test artifacts"
	@echo ""
	@echo "$(GREEN)Python-specific:$(NC)"
	@echo "  make test-python       - Run all Python tests"
	@echo "  make test-python-unit  - Run Python unit tests only"
	@echo "  make test-python-integration - Run Python integration tests"
	@echo "  make test-python-watch - Auto-run tests on file changes"
	@echo ""
	@echo "$(GREEN)Go-specific:$(NC)"
	@echo "  make test-go           - Run all Go tests"
	@echo "  make test-go-race      - Run Go tests with race detector"
	@echo "  make test-go-coverage  - Run Go tests with coverage"
	@echo ""
	@echo "$(GREEN)Utilities:$(NC)"
	@echo "  make lint              - Run code linters"
	@echo "  make format            - Format code (Go + Python)"
	@echo "  make help              - Show this help message"
	@echo ""

# ----------------------------------------------------------------------------
# Installation
# ----------------------------------------------------------------------------
install: install-python install-go
	@echo "$(GREEN)✓ All dependencies installed$(NC)"

install-python:
	@echo "$(BLUE)📦 Installing Python test dependencies...$(NC)"
	cd crs/strategy && pip install -r requirements.txt
	cd crs/strategy && pip install -r requirements-test.txt
	@echo "$(GREEN)✓ Python dependencies installed$(NC)"

install-go:
	@echo "$(BLUE)📦 Installing Go dependencies...$(NC)"
	cd crs && go mod download
	@echo "$(GREEN)✓ Go dependencies installed$(NC)"

# ----------------------------------------------------------------------------
# All Tests
# ----------------------------------------------------------------------------
test-all: test-go test-python
	@echo ""
	@echo "$(GREEN)════════════════════════════════════════$(NC)"
	@echo "$(GREEN)✅ All tests passed!$(NC)"
	@echo "$(GREEN)════════════════════════════════════════$(NC)"
	@echo ""

test: test-all

# ----------------------------------------------------------------------------
# Fast Tests (for quick feedback during development)
# ----------------------------------------------------------------------------
test-fast:
	@echo "$(YELLOW)⚡ Running fast tests only...$(NC)"
	@echo ""
	@echo "$(BLUE)🔵 Go tests (short mode)...$(NC)"
	cd crs && go test ./... -short
	@echo ""
	@echo "$(BLUE)🐍 Python unit tests (fast)...$(NC)"
	cd crs/strategy && pytest -m "unit and not slow" -v
	@echo ""
	@echo "$(GREEN)✅ Fast tests passed!$(NC)"

# ----------------------------------------------------------------------------
# Python Tests
# ----------------------------------------------------------------------------
test-python:
	@echo "$(BLUE)🐍 Running Python tests...$(NC)"
	@echo ""
	cd crs/strategy && pytest
	@echo ""
	@echo "$(GREEN)✓ Python tests passed$(NC)"

test-python-unit:
	@echo "$(BLUE)🐍 Running Python unit tests...$(NC)"
	@echo ""
	cd crs/strategy && pytest -m unit -v
	@echo ""
	@echo "$(GREEN)✓ Python unit tests passed$(NC)"

test-python-integration:
	@echo "$(BLUE)🐍 Running Python integration tests...$(NC)"
	@echo ""
	cd crs/strategy && pytest -m integration -v
	@echo ""
	@echo "$(GREEN)✓ Python integration tests passed$(NC)"

test-python-regression:
	@echo "$(BLUE)🐍 Running Python regression tests...$(NC)"
	@echo ""
	cd crs/strategy && pytest -m regression -v
	@echo ""
	@echo "$(GREEN)✓ Python regression tests passed$(NC)"

test-python-coverage:
	@echo "$(BLUE)🐍 Running Python tests with coverage...$(NC)"
	@echo ""
	cd crs/strategy && pytest --cov --cov-report=html --cov-report=term
	@echo ""
	@echo "$(YELLOW)📊 Coverage report: crs/strategy/htmlcov/index.html$(NC)"

test-python-watch:
	@echo "$(BLUE)🐍 Auto-running Python tests on file changes...$(NC)"
	@echo "$(YELLOW)Press Ctrl+C to stop$(NC)"
	@echo ""
	cd crs/strategy && pytest-watch -- -v

# ----------------------------------------------------------------------------
# Go Tests
# ----------------------------------------------------------------------------
test-go:
	@echo "$(BLUE)🔵 Running Go tests...$(NC)"
	@echo ""
	cd crs && go test ./... -v
	@echo ""
	@echo "$(GREEN)✓ Go tests passed$(NC)"

test-go-race:
	@echo "$(BLUE)🔵 Running Go tests with race detector...$(NC)"
	@echo ""
	cd crs && go test ./... -v -race
	@echo ""
	@echo "$(GREEN)✓ Go tests passed (with race detection)$(NC)"

test-go-coverage:
	@echo "$(BLUE)🔵 Running Go tests with coverage...$(NC)"
	@echo ""
	cd crs && go test ./... -coverprofile=coverage.out
	cd crs && go tool cover -html=coverage.out -o coverage.html
	@echo ""
	@echo "$(YELLOW)📊 Coverage report: crs/coverage.html$(NC)"

test-go-static-analysis:
	@echo "$(BLUE)🔵 Running Go tests (static-analysis)...$(NC)"
	@echo ""
	cd static-analysis && go test ./... -v
	@echo ""
	@echo "$(GREEN)✓ Static-analysis tests passed$(NC)"

# ----------------------------------------------------------------------------
# Coverage (combined)
# ----------------------------------------------------------------------------
test-coverage: test-go-coverage test-python-coverage
	@echo ""
	@echo "$(GREEN)════════════════════════════════════════$(NC)"
	@echo "$(GREEN)✅ Coverage reports generated!$(NC)"
	@echo "$(GREEN)════════════════════════════════════════$(NC)"
	@echo ""
	@echo "$(YELLOW)📊 Go coverage:     crs/coverage.html$(NC)"
	@echo "$(YELLOW)📊 Python coverage: crs/strategy/htmlcov/index.html$(NC)"
	@echo ""

# ----------------------------------------------------------------------------
# Code Quality
# ----------------------------------------------------------------------------
lint: lint-python lint-go
	@echo "$(GREEN)✓ All linters passed$(NC)"

lint-python:
	@echo "$(BLUE)🐍 Running Python linters...$(NC)"
	cd crs/strategy && flake8 common core strategies --max-line-length=120
	@echo "$(GREEN)✓ Python lint passed$(NC)"

lint-go:
	@echo "$(BLUE)🔵 Running Go linters...$(NC)"
	cd crs && go vet ./...
	cd static-analysis && go vet ./...
	@echo "$(GREEN)✓ Go lint passed$(NC)"

format: format-python format-go
	@echo "$(GREEN)✓ All code formatted$(NC)"

format-python:
	@echo "$(BLUE)🐍 Formatting Python code...$(NC)"
	cd crs/strategy && black common core strategies tests --line-length=120
	@echo "$(GREEN)✓ Python code formatted$(NC)"

format-go:
	@echo "$(BLUE)🔵 Formatting Go code...$(NC)"
	cd crs && go fmt ./...
	cd static-analysis && go fmt ./...
	@echo "$(GREEN)✓ Go code formatted$(NC)"

# ----------------------------------------------------------------------------
# Clean
# ----------------------------------------------------------------------------
clean:
	@echo "$(BLUE)🧹 Cleaning test artifacts...$(NC)"
	rm -rf crs/coverage.out crs/coverage.html
	rm -rf crs/strategy/htmlcov crs/strategy/.coverage crs/strategy/coverage.xml
	rm -rf crs/strategy/.pytest_cache
	rm -rf crs/strategy/tests/logs/*.log
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	@echo "$(GREEN)✓ Cleaned test artifacts$(NC)"

# ----------------------------------------------------------------------------
# CI Simulation (run what CI will run)
# ----------------------------------------------------------------------------
ci-test: install test-fast lint
	@echo ""
	@echo "$(GREEN)════════════════════════════════════════$(NC)"
	@echo "$(GREEN)✅ CI simulation passed!$(NC)"
	@echo "$(GREEN)════════════════════════════════════════$(NC)"
	@echo ""

# ----------------------------------------------------------------------------
# Development Helpers
# ----------------------------------------------------------------------------
dev-setup: install
	@echo "$(BLUE)🔧 Setting up development environment...$(NC)"
	@echo "$(GREEN)✓ Development environment ready$(NC)"
	@echo ""
	@echo "Quick start:"
	@echo "  make test-fast    - Run fast tests"
	@echo "  make test         - Run all tests"
	@echo "  make help         - Show all commands"

// Package executor provides fuzzing task execution and distribution capabilities
// for the CRS (Coverage-guided Fuzzing as a Service) system.
//
// The package is organized into several modules based on functionality:
//
// Task Execution (task_execution.go):
//   - ExecuteFuzzingTask: Main entry point for executing fuzzing tasks on worker nodes
//   - Orchestrates the complete fuzzing workflow including POV generation and patching
//
// Task Distribution (task_distribution.go):
//   - DistributeFuzzingTasks: Distributes fuzzing tasks across worker nodes
//   - Used by web service for task scheduling
//
// POV Strategies (pov_strategies.go):
//   - Implements various strategies for generating Proof-of-Vulnerability (POV)
//   - Supports both basic and advanced multi-phase POV generation
//   - Includes sequential and parallel execution modes
//
// Patch Strategies (patch_strategies.go):
//   - Implements patching strategies for vulnerability remediation
//   - Supports both POV-based and POV-less (XPatch) patching
//   - SARIF-based patching for static analysis results
//
// Environment Preparation (environment.go):
//   - Project configuration loading
//   - Build environment setup
//   - Fuzzer preparation
//
// Fuzzer Discovery (fuzzer.go):
//   - Discovers available fuzzer binaries
//   - Filters and validates fuzzer executables
//
// The executor package is designed to be independent of the service layer,
// accepting all necessary parameters through well-defined structs.
// This design enables:
//   - Easy testing without service dependencies
//   - Reusability across different service implementations
//   - Clear separation of concerns between orchestration and execution
package executor

package executor

import "errors"

// Sentinel errors for common execution failures
// These can be checked using errors.Is()
var (
	// ErrPOVNotFound indicates that no Proof-of-Vulnerability was generated within the deadline
	ErrPOVNotFound = errors.New("failed to find POV within deadline")

	// ErrPatchNotFound indicates that no valid patch was generated within the deadline
	ErrPatchNotFound = errors.New("failed to find patch within deadline")

	// ErrNoFuzzers indicates that no fuzzer binaries were found in the specified directory
	ErrNoFuzzers = errors.New("no fuzzers found")

	// ErrDeadlineExceeded indicates that the task deadline was exceeded
	ErrDeadlineExceeded = errors.New("task deadline exceeded")
)

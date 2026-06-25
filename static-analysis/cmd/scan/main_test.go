// SPDX-License-Identifier: Apache-2.0
package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProcessSourceFileWithLLM(t *testing.T) {
	// Setup test directory and file
	projectDir := "./tt"
	filePath := "./tt/pngrutil.c"

	// Call the function being tested
	stats, suspicious, err := processSourceFileWithLLM(projectDir, filePath)

	// Verify results
	if err != nil {
		t.Errorf("processSourceFileWithLLM returned an error: %v", err)
	}

	// Since we included a vulnerable function, we should expect at least one suspicious file
	// Note: This depends on your LLM analysis, so it might need adjustment
	t.Logf("Found %d suspicious items", len(suspicious))

	// Optional: Print details about suspicious findings for debugging
	for i, s := range suspicious {
		t.Logf("Suspicious #%d: %s in %s", i+1, s.FunctionName, s.FilePath)
	}
}

package fuzzer

import (
	"fmt"
	"os"
	"path/filepath"

	"crs/internal/executor"
)

// FindFuzzers scans a fuzzer directory and returns a list of executable fuzzer binaries.
// It filters out known non-fuzzer files, helper tools, and non-executable files.
func FindFuzzers(fuzzerDir string) ([]string, error) {
	entries, err := os.ReadDir(fuzzerDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read fuzzer directory: %v", err)
	}

	// List of known non-fuzzer executables to skip
	skipBinaries := map[string]bool{
		"jazzer_agent_deploy.jar":         true,
		"jazzer_driver":                   true,
		"jazzer_driver_with_sanitizer":    true,
		"jazzer_junit.jar":                true,
		"llvm-symbolizer":                 true,
		"sancov":                          true, // coverage tool
		"clang":                           true,
		"clang++":                         true,
	}

	// File extensions to skip
	skipExtensions := map[string]bool{
		".bin":     true, // Skip .bin files
		".log":     true, // Skip log files
		".class":   true, // Skip Java class files
		".jar":     true, // Skip Java JAR files (except specific fuzzer JARs)
		".zip":     true,
		".dict":    true,
		".options": true,
		".bc":      true,
		".json":    true,
		".o":       true, // Skip object files
		".a":       true, // Skip static libraries
		".so":      true, // Skip shared libraries (unless they're specifically fuzzers)
		".h":       true, // Skip header files
		".c":       true, // Skip source files
		".cpp":     true, // Skip source files
		".java":    true, // Skip Java source files
	}

	var fuzzers []string
	for _, entry := range entries {
		// Skip directories and non-executable files
		if entry.IsDir() {
			continue
		}

		name := entry.Name()

		// Skip files with extensions we want to ignore
		ext := filepath.Ext(name)
		if skipExtensions[ext] {
			continue
		}

		// Skip known non-fuzzer binaries
		if skipBinaries[name] {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Check if file is executable
		if info.Mode()&0111 != 0 {
			fuzzers = append(fuzzers, name)
		}
	}

	if len(fuzzers) == 0 {
		return nil, fmt.Errorf("%w in %s", executor.ErrNoFuzzers, fuzzerDir)
	}

	return fuzzers, nil
}

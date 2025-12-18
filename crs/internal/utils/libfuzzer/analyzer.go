package libfuzzer

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"crs/internal/utils/helpers"
)

// IsCrashOutput checks if the output contains crash indicators
func IsCrashOutput(output string) bool {
	// Check for common crash indicators that always represent errors
	errorIndicators := []string{
		"ERROR: AddressSanitizer:",
		"ERROR: MemorySanitizer:",
		"WARNING: MemorySanitizer:",
		"ERROR: ThreadSanitizer:",
		"ERROR: UndefinedBehaviorSanitizer:",
		"SEGV on unknown address",
		"Segmentation fault",
		"AddressSanitizer: heap-buffer-overflow",
		"AddressSanitizer: heap-use-after-free",
		"UndefinedBehaviorSanitizer: undefined-behavior",
		"ERROR: HWAddressSanitizer:",
		"WARNING: ThreadSanitizer:",
		"runtime error:", // UBSan generic line
		"AddressSanitizer:DEADLYSIGNAL",
		"libfuzzer exit=1",
		"Java Exception: com.code_intelligence.jazzer",
	}

	// Optional: Enable timeout detection as crash
	if os.Getenv("DETECT_TIMEOUT_CRASH") == "1" {
		errorIndicators = append(errorIndicators, "ERROR: libFuzzer: timeout")
		errorIndicators = append(errorIndicators, "libfuzzer exit=99")
	}

	// Optional: Enable leak detection as crash (disabled by default)
	// LeakSanitizer detects memory leaks which are usually not security issues
	// Enable this for comprehensive testing or resource leak detection
	if os.Getenv("DETECT_LEAK_AS_CRASH") == "1" {
		errorIndicators = append(errorIndicators, "ERROR: LeakSanitizer:")
	}

	for _, indicator := range errorIndicators {
		if strings.Contains(output, indicator) {
			return true
		}
	}

	// For MemorySanitizer, we need to be more careful
	if strings.Contains(output, "MemorySanitizer:") {
		// Only count as crash if it's an ERROR, not a WARNING
		// if !strings.Contains(output, "ERROR: MemorySanitizer:") {
		//     return false // It's a warning, not an error
		// }

		// Ignore issues in system libraries or fuzzer infrastructure
		ignoredPatterns := []string{
			"in start_thread",
			"in __clone",
			"in fuzzer::",
			"in std::__Fuzzer::",
			"in __msan_",
			"in operator new",
		}

		for _, pattern := range ignoredPatterns {
			if strings.Contains(output, pattern) {
				// This is likely an infrastructure issue, not a real crash
				return false
			}
		}

		// If we get here, it's a MemorySanitizer error not in the ignored patterns
		return true
	}

	// For ThreadSanitizer, only count ERROR reports, not WARNINGs
	if strings.Contains(output, "ThreadSanitizer:") {
		// if !strings.Contains(output, "ERROR: ThreadSanitizer:") {
		//     return false // It's a warning, not an error
		// }

		// Similar to MSAN, ignore infrastructure issues
		ignoredPatterns := []string{
			"in start_thread",
			"in __clone",
			"in fuzzer::",
			"in std::__Fuzzer::",
		}

		for _, pattern := range ignoredPatterns {
			if strings.Contains(output, pattern) {
				return false
			}
		}

		return true
	}

	// For LeakSanitizer (when enabled via DETECT_LEAK_AS_CRASH=1)
	// Only count as crash if it's an ERROR, not a warning or summary
	if os.Getenv("DETECT_LEAK_AS_CRASH") == "1" && strings.Contains(output, "LeakSanitizer:") {
		if strings.Contains(output, "ERROR: LeakSanitizer:") {
			return true
		}
		return false // It's a warning or summary, not an error
	}

	return false
}

// filterInstrumentedLines filters out INFO logs and VM warnings from output
func filterInstrumentedLines(output string) string {
	lines := strings.Split(output, "\n")
	var filteredLines []string

	for _, line := range lines {
		// Skip info logs and VM warnings
		if strings.HasPrefix(line, "INFO:") ||
			strings.Contains(line, "Server VM warning:") {
			continue
		}

		// Keep all other lines
		filteredLines = append(filteredLines, line)
	}

	return strings.Join(filteredLines, "\n")
}

// extractCrashOutput extracts crash-related output with 4KB size limit
func extractCrashOutput(output string) string {
	// Maximum size to return (4KB)
	const maxSize = 4096

	// Helper function to limit output size
	limitSize := func(start int) string {
		if len(output)-start > maxSize {
			return output[start : start+maxSize]
		}
		return output[start:]
	}

	// Look for AddressSanitizer error
	asanIndex := strings.Index(output, "ERROR: AddressSanitizer")
	if asanIndex != -1 {
		return limitSize(asanIndex)
	}

	// Look for other sanitizer errors
	ubsanIndex := strings.Index(output, "ERROR: UndefinedBehaviorSanitizer")
	if ubsanIndex != -1 {
		return limitSize(ubsanIndex)
	}

	msanIndex := strings.Index(output, "ERROR: MemorySanitizer")
	if msanIndex != -1 {
		return limitSize(msanIndex)
	}
	{
		msanIndex := strings.Index(output, "WARNING: MemorySanitizer")
		if msanIndex != -1 {
			return limitSize(msanIndex)
		}
	}

	// Look for libFuzzer crash indicator
	libfuzzerIndex := strings.Index(output, "==ERROR: libFuzzer")
	if libfuzzerIndex != -1 {
		return limitSize(libfuzzerIndex)
	}

	// Look for SEGV indicator
	segvIndex := strings.Index(output, "SUMMARY: AddressSanitizer: SEGV")
	if segvIndex != -1 {
		// Try to find the start of the error report
		errorStart := strings.LastIndex(output[:segvIndex], "==")
		if errorStart != -1 {
			return limitSize(errorStart)
		}
		return limitSize(segvIndex)
	}

	// If no specific error marker found, return the last 4KB of output
	if len(output) > maxSize {
		return output[len(output)-maxSize:]
	}

	return output
}

// generateCrashSignature generates a signature for a crash based on output and sanitizer
func generateCrashSignature(output string, sanitizer string) string {
	// Extract the crash location from the stack trace
	crashLocation := extractCrashLocation(output, sanitizer)

	// If we couldn't extract a specific location, fall back to a hash
	if crashLocation != "" {
		return crashLocation
	}

	return generateVulnerabilitySignature0(output, sanitizer)
}

// extractCrashLocation extracts the crash location from the output
func extractCrashLocation(output string, sanitizer string) string {
	// Look for the #0 line in the stack trace which indicates the crash point
	lines := strings.Split(output, "\n")

	// First try to find the #0 line which is the most reliable indicator
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#0 ") {
			// Extract the function and location after "in"
			parts := strings.SplitN(line, " in ", 2)
			if len(parts) < 2 {
				continue
			}

			// Get the function name and file location
			funcInfo := parts[1]

			// Clean up any extra information in parentheses
			if idx := strings.Index(funcInfo, " ("); idx != -1 {
				funcInfo = funcInfo[:idx]
			}

			// Remove column information (e.g., ":13" in "file.c:123:13")
			if lastColonIdx := strings.LastIndex(funcInfo, ":"); lastColonIdx != -1 {
				// Check if there's another colon before this one (for the line number)
				prevColonIdx := strings.LastIndex(funcInfo[:lastColonIdx], ":")
				if prevColonIdx != -1 {
					// This is likely a column number, remove it
					funcInfo = funcInfo[:lastColonIdx]
				}
			}

			return funcInfo
		}
	}

	// If we couldn't find a #0 line, look for sanitizer-specific patterns
	switch strings.ToLower(sanitizer) {
	case "address", "asan":
		return extractASANFallbackLocation(output)
	case "undefined", "ubsan":
		return extractUBSANFallbackLocation(output)
	case "memory", "msan":
		return extractMSANFallbackLocation(output)
	}

	// If all else fails, look for any file path with a line number
	for _, line := range lines {
		if strings.Contains(line, "/src/") && strings.Contains(line, ".c:") {
			// This might be a file reference
			re := regexp.MustCompile(`(/src/[^:]+:\d+)`)
			matches := re.FindStringSubmatch(line)
			if len(matches) > 0 {
				return matches[1]
			}
		}
	}

	return ""
}

// extractASANFallbackLocation extracts location from ASAN output if #0 line isn't found
func extractASANFallbackLocation(output string) string {
	// Look for "SUMMARY: AddressSanitizer: <type> <location>"
	summaryRegex := regexp.MustCompile(`SUMMARY: AddressSanitizer: \w+ ([^(]+)`)
	matches := summaryRegex.FindStringSubmatch(output)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}

	return ""
}

// extractUBSANFallbackLocation extracts location from UBSAN output
func extractUBSANFallbackLocation(output string) string {
	// Look for the file and line where UBSAN detected the issue
	ubsanRegex := regexp.MustCompile(`([^:]+:\d+:\d+): runtime error:`)
	matches := ubsanRegex.FindStringSubmatch(output)
	if len(matches) > 1 {
		return matches[1]
	}

	return ""
}

// extractMSANFallbackLocation extracts location from MSAN output
func extractMSANFallbackLocation(output string) string {
	// Look for "WARNING: MemorySanitizer: <description> <location>"
	msanRegex := regexp.MustCompile(`MemorySanitizer:.*? at ([^:]+:\d+)`)
	matches := msanRegex.FindStringSubmatch(output)
	if len(matches) > 1 {
		return matches[1]
	}

	return ""
}

// generateVulnerabilitySignature0 generates a signature based on crash type
func generateVulnerabilitySignature0(output string, sanitizer string) string {
	// This is a simplified implementation - you may want to enhance this
	// based on your specific needs and the structure of your crash outputs

	// Extract key information from the crash output based on sanitizer type
	var signature string

	switch sanitizer {
	case "address":
		// For AddressSanitizer, look for the crash location and type
		if loc := extractASANCrashLocation(output); loc != "" {
			signature = "ASAN:" + loc
		} else {
			// Fallback to a hash of the entire output
			signature = "ASAN:generic:" + helpers.HashString(output)
		}

	case "undefined":
		// For UndefinedBehaviorSanitizer
		if loc := extractUBSANCrashLocation(output); loc != "" {
			signature = "UBSAN:" + loc
		} else {
			signature = "UBSAN:generic:" + helpers.HashString(output)
		}

	case "memory":
		// For MemorySanitizer
		if loc := extractMSANCrashLocation(output); loc != "" {
			signature = "MSAN:" + loc
		} else {
			signature = "MSAN:generic:" + helpers.HashString(output)
		}

	default:
		// For other sanitizers or unknown types
		signature = sanitizer + ":generic:" + helpers.HashString(output)
	}
	log.Printf("Extracted signature: %s", signature)

	return signature
}

// extractASANCrashLocation extracts crash location from AddressSanitizer output
func extractASANCrashLocation(output string) string {
	// Look for common AddressSanitizer patterns
	// Example: "ERROR: AddressSanitizer: heap-buffer-overflow on address 0x614000000074"

	// This is a simplified implementation - you would want to enhance this
	// with more sophisticated regex patterns based on your actual crash outputs

	// Look for the crash type and function
	typeRegex := regexp.MustCompile(`AddressSanitizer: ([a-zA-Z0-9_-]+)`)
	funcRegex := regexp.MustCompile(`in ([a-zA-Z0-9_]+) .*`)

	var crashType, crashFunc string

	if matches := typeRegex.FindStringSubmatch(output); len(matches) > 1 {
		crashType = matches[1]
	}

	if matches := funcRegex.FindStringSubmatch(output); len(matches) > 1 {
		crashFunc = matches[1]
	}

	if crashType != "" && crashFunc != "" {
		return crashType + ":" + crashFunc
	} else if crashType != "" {
		return crashType
	}

	return ""
}

// extractUBSANCrashLocation extracts crash location from UndefinedBehaviorSanitizer output
func extractUBSANCrashLocation(output string) string {
	// Similar implementation for UndefinedBehaviorSanitizer
	typeRegex := regexp.MustCompile(`runtime error: ([a-zA-Z0-9_-]+)`)
	funcRegex := regexp.MustCompile(`in ([a-zA-Z0-9_]+) .*`)

	var crashType, crashFunc string

	if matches := typeRegex.FindStringSubmatch(output); len(matches) > 1 {
		crashType = matches[1]
	}

	if matches := funcRegex.FindStringSubmatch(output); len(matches) > 1 {
		crashFunc = matches[1]
	}

	if crashType != "" && crashFunc != "" {
		return crashType + ":" + crashFunc
	} else if crashType != "" {
		return crashType
	}

	return ""
}

// extractMSANCrashLocation extracts crash location from MemorySanitizer output
func extractMSANCrashLocation(output string) string {
	// Similar implementation for MemorySanitizer
	typeRegex := regexp.MustCompile(`MemorySanitizer: ([a-zA-Z0-9_-]+)`)
	funcRegex := regexp.MustCompile(`in ([a-zA-Z0-9_]+) .*`)

	var crashType, crashFunc string

	if matches := typeRegex.FindStringSubmatch(output); len(matches) > 1 {
		crashType = matches[1]
	}

	if matches := funcRegex.FindStringSubmatch(output); len(matches) > 1 {
		crashFunc = matches[1]
	}

	if crashType != "" && crashFunc != "" {
		return crashType + ":" + crashFunc
	} else if crashType != "" {
		return crashType
	}

	return ""
}

// getFuzzerArgs builds Docker command arguments for running libFuzzer
func getFuzzerArgs(containerName, fuzzDir, fuzzerName, language, sanitizer, taskDir string) []string {
	// Get available CPU cores
	numCPU := runtime.NumCPU()

	// Determine the seed corpus path
	seedCorpusName := fmt.Sprintf("%s_seed_corpus", fuzzerName)
	seedCorpusPath := filepath.Join(taskDir, seedCorpusName)

	// Docker run arguments
	dockerArgs := []string{
		"run",
		"--privileged",
		"--platform", "linux/amd64",
		"--rm",
		"--name=" + containerName,
	}

	numOfJobs := numCPU
	if numCPU >= 180 {
		numOfJobs = numCPU - 12
	} else if numCPU >= 32 {
		numOfJobs = numCPU - 4
	} else {
		numOfJobs = numCPU - 2
	}

	// Resource arguments based on VM size
	var resourceArgs []string
	if numCPU >= 180 { // Likely M192is_v2 or similar high-end VM
		resourceArgs = []string{
			"--shm-size=512g",
			"--memory=3072g",
			fmt.Sprintf("--cpus=%d", numCPU-12), // Reserve some CPUs for system
		}
	} else if numCPU >= 32 { // Medium-sized VM
		resourceArgs = []string{
			"--shm-size=16g",
			"--memory=96g",
			fmt.Sprintf("--cpus=%d", numCPU-4),
		}
	} else { // Smaller VM like D5_v2
		resourceArgs = []string{
			"--shm-size=8g",
			"--memory=42g",
			fmt.Sprintf("--cpus=%d", numCPU-2),
		}
	}

	if strings.HasPrefix(language, "j") {
		//FOR JAVA, use only 1/4 of the resources for fuzzing
		if numOfJobs > numCPU/4 {
			numOfJobs = numCPU / 4
		}
		// max 16
		if numOfJobs > 16 {
			numOfJobs = 16
		}

		resourceArgs = []string{
			"--shm-size=16g",
			"--memory=40g",
			fmt.Sprintf("--cpus=%d", 16),
		}
	}

	numOfWorkers := numOfJobs

	// Environment variables
	envArgs := []string{
		"-e", "FUZZING_ENGINE=libfuzzer",
		"-e", fmt.Sprintf("SANITIZER=%s", sanitizer),
		"-e", "RUN_FUZZER_MODE=interactive",
		// "-e", "UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1",
		"-e", "HELPER=True",
	}

	// Volume mounts
	volumeArgs := []string{
		"-v", fmt.Sprintf("%s:/out", fuzzDir),
	}

	// Add dynamic seed corpus volume mount if the directory exists
	if _, err := os.Stat(seedCorpusPath); err == nil {
		volumeArgs = append(volumeArgs, "-v", fmt.Sprintf("%s:/additional_corpus", seedCorpusPath))
	}

	//TODO LLM to generate fuzz dict and save to {fuzzerName}_custom.dict
	customDictPath := filepath.Join(taskDir, fmt.Sprintf("%s_custom.dict", fuzzerName))
	hasDictionary := false
	if _, err := os.Stat(customDictPath); err == nil {
		hasDictionary = true
		volumeArgs = append(volumeArgs, "-v", fmt.Sprintf("%s:/additional_dict", customDictPath))
	}

	// Create a persistent corpus directory
	hasCorpus := true
	corpusDir := filepath.Join(taskDir, fmt.Sprintf("%s_corpus", fuzzerName))
	if _, err := os.Stat(corpusDir); os.IsNotExist(err) {
		if err := os.MkdirAll(corpusDir, 0755); err != nil {
			hasCorpus = false
			log.Printf("failed to create corpus directory: %v", err)
		}
	}

	volumeArgs = append(volumeArgs, "-v", fmt.Sprintf("%s:/corpus", corpusDir))

	// Container and command
	containerArgs := []string{
		"ghcr.io/aixcc-finals/base-runner:v1.3.0",
		"run_fuzzer",
		fuzzerName,
	}
	// Common fuzzer options
	commonFuzzerOpts := []string{
		"-verbosity=0",
		"-entropic=1",
		"-entropic_scale_per_exec_time=1", // optimize generation strategy for higher coverage and higher speed; weak for mutating detail values.
		"-cross_over_uniform_dist=1",
		"-prefer_small=1",
		"-use_value_profile=1",
		"-fork=1",
		"-shrink=1",
		"-reduce_inputs=1",
		"-use_counters=1",
		"-artifact_prefix=/out/crashes/",
	}

	if hasDictionary {
		commonFuzzerOpts = append(commonFuzzerOpts, "-dict=/additional_dict")
	}
	if hasCorpus {
		commonFuzzerOpts = append(commonFuzzerOpts, "/corpus")
	}

	// Specific fuzzer options based on VM size
	var fuzzerOpts []string
	if numCPU >= 180 { // Likely M192is_v2 or similar high-end VM
		fuzzerOpts = []string{
			"-max_total_time=7200",
			fmt.Sprintf("-jobs=%d", numOfJobs),
			fmt.Sprintf("-workers=%d", numOfWorkers),
			"-print_final_stats=1",
			"-reload=300",
			// "-timeout=30",
			"-timeout_exitcode=99",
			"-rss_limit_mb=262144",
			"-malloc_limit_mb=131072",
			"-max_len=168276",
			"-detect_leaks=0",
		}
	} else if numCPU >= 32 { // Medium-sized VM
		fuzzerOpts = []string{
			"-max_total_time=7200",
			fmt.Sprintf("-jobs=%d", numOfJobs),
			fmt.Sprintf("-workers=%d", numOfWorkers),
			"-print_final_stats=1",
			"-reload=300",
			// "-timeout=15",
			"-timeout_exitcode=99",
			"-rss_limit_mb=32768",
			"-malloc_limit_mb=16384",
			"-max_len=168276",
		}
	} else { // Smaller VM like D5_v2
		fuzzerOpts = []string{
			"-max_total_time=7200",
			fmt.Sprintf("-jobs=%d", numOfJobs),
			fmt.Sprintf("-workers=%d", numOfWorkers),
			"-print_final_stats=1",
			"-reload=300",
			// "-timeout=10",
			"-timeout_exitcode=99",
			"-rss_limit_mb=16384",
			"-malloc_limit_mb=8192",
			"-max_len=168276",
		}
	}

	// Add dynamic seed corpus directory as an argument if it exists
	var corpusArgs []string
	if _, err := os.Stat(seedCorpusPath); err == nil {
		corpusArgs = append(corpusArgs, "/additional_corpus")
	}

	// Combine all arguments in the correct order
	var cmdArgs []string
	cmdArgs = append(cmdArgs, dockerArgs...)
	cmdArgs = append(cmdArgs, resourceArgs...)
	cmdArgs = append(cmdArgs, envArgs...)
	cmdArgs = append(cmdArgs, volumeArgs...)
	cmdArgs = append(cmdArgs, containerArgs...)
	cmdArgs = append(cmdArgs, commonFuzzerOpts...)
	cmdArgs = append(cmdArgs, fuzzerOpts...)
	cmdArgs = append(cmdArgs, corpusArgs...)

	return cmdArgs
}

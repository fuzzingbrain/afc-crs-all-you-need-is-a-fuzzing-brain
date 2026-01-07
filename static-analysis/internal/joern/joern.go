package joern

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"static-analysis/internal/engine/models"
)

// CPG creation timeout - 30 minutes should be enough for most projects
const cpgCreationTimeout = 5 * time.Minute

// AnalyzeProjectDirs runs Joern analysis on multiple project directories using local Joern installation
// This creates a combined CPG and saves it for Python to query directly
func AnalyzeProjectDirs(projectDirs []string, language string, fuzzers []string) (*models.AnalysisResults, error) {
	if len(projectDirs) == 0 {
		return nil, fmt.Errorf("no project directories specified")
	}

	// Normalize language names for Joern
	language = normalizeLanguage(language)

	log.Printf("Starting Joern analysis for %s project at %v", language, projectDirs)

	projectDir := projectDirs[0] // Use first directory for path resolution

	// Determine where to save the CPG based on project directory
	// Look for parent directory that might be the task directory
	taskDir := findTaskDirectory(projectDir)
	cpgOutputDir := filepath.Join(taskDir, "static_analysis")
	cpgPath := filepath.Join(cpgOutputDir, "cpg.bin")

	// Create output directory
	if err := os.MkdirAll(cpgOutputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create CPG output directory: %w", err)
	}

	// For C/C++/Java projects, also look for fuzzer directories that might be conditionally compiled
	// (e.g., behind CMake flags like DNP3_FUZZING=ON) and include them explicitly
	// Note: We store these separately because joern-parse may not include them due to build configs
	var fuzzerDirs []string
	if language == "c" || language == "cpp" || language == "java" {
		// First, check if any of the additional project directories are fuzzer directories
		for i := 1; i < len(projectDirs); i++ {
			dir := projectDirs[i]
			if hasSourceFiles(dir) && (hasFuzzerFiles(dir) || strings.Contains(strings.ToLower(dir), "fuzz")) {
				fuzzerDirs = append(fuzzerDirs, dir)
				log.Printf("Found fuzzer directory from projectDirs: %s", dir)
			}
		}

		// Then search within the primary project directory for fuzzer subdirectories
		additionalDirs := findFuzzerDirectories(projectDir)
		for _, fuzzerDir := range additionalDirs {
			fuzzerDirs = append(fuzzerDirs, fuzzerDir)
			log.Printf("Found fuzzer subdirectory: %s", fuzzerDir)
		}
	}

	// Step 1: Create CPG (Code Property Graph)
	log.Println("Creating Code Property Graph...")
	if err := createCPG(projectDirs, cpgPath, language); err != nil {
		return nil, fmt.Errorf("failed to create CPG: %w", err)
	}

	log.Printf("CPG saved to %s for Python queries", cpgPath)

	// Step 2: Extract basic analysis results from CPG
	log.Println("Extracting analysis results from CPG...")
	results, err := extractBasicResults(cpgPath, projectDir, fuzzers, language)

	// Step 2.5: If we have fuzzer directories, parse them separately to find fuzzer entry points
	// This is needed because joern-parse only analyzes the primary directory
	if err == nil && len(fuzzerDirs) > 0 {
		log.Printf("Parsing %d fuzzer directories separately to find fuzzer entry points...", len(fuzzerDirs))

		// Parse each fuzzer directory individually since joern-parse only supports single directory
		for i, fuzzerDir := range fuzzerDirs {
			fuzzerCpgPath := fmt.Sprintf("%s.fuzzers.%d", cpgPath, i)
			log.Printf("Parsing fuzzer directory %d: %s", i, fuzzerDir)

			if err := createCPG([]string{fuzzerDir}, fuzzerCpgPath, language); err != nil {
				log.Printf("Failed to parse fuzzer directory %s: %v", fuzzerDir, err)
				continue
			}

			// Extract entry points from this fuzzer CPG
			fuzzerResults, err := extractBasicResults(fuzzerCpgPath, projectDir, fuzzers, language)
			if err != nil {
				log.Printf("Failed to extract results from fuzzer CPG %s: %v", fuzzerDir, err)
				continue
			}

			if len(fuzzerResults.ReachableFunctions) > 0 {
				log.Printf("Found %d fuzzer entry points in %s!", len(fuzzerResults.ReachableFunctions), fuzzerDir)
				for entryPoint := range fuzzerResults.ReachableFunctions {
					log.Printf("  - %s", entryPoint)
				}
			} else if len(fuzzerResults.Functions) > 0 {
				log.Printf("Found %d functions but no entry points in %s", len(fuzzerResults.Functions), fuzzerDir)
			}

			// Merge: keep main CPG's functions and call graph, but add fuzzer entry points
			for entryPoint, reachable := range fuzzerResults.ReachableFunctions {
				results.ReachableFunctions[entryPoint] = reachable
			}

			// Add fuzzer functions to the main results
			for name, fn := range fuzzerResults.Functions {
				if _, exists := results.Functions[name]; !exists {
					results.Functions[name] = fn
				}
			}

			// Add fuzzer call graph edges
			for _, call := range fuzzerResults.CallGraph.Calls {
				results.CallGraph.Calls = append(results.CallGraph.Calls, call)
			}
			for caller, callees := range fuzzerResults.CallGraphAdj {
				results.CallGraphAdj[caller] = append(results.CallGraphAdj[caller], callees...)
			}
		}

		log.Printf("After merging fuzzer directories: %d total functions, %d entry points",
			len(results.Functions), len(results.ReachableFunctions))
	}
	if err != nil {
		log.Printf("Warning: failed to extract results from CPG: %v", err)
		// Return empty results but don't fail - CPG is still usable by Python
		results = &models.AnalysisResults{
			Functions:          make(map[string]*models.FunctionDefinition),
			CallGraph:          &models.CallGraph{Calls: []models.MethodCall{}},
			ReachableFunctions: make(map[string][]string),
			Paths:              make(map[string][][]string),
			CallGraphAdj:       make(map[string][]string),
		}
	}

	log.Printf("Joern analysis complete: %d functions, %d reachable sets",
		len(results.Functions), len(results.ReachableFunctions))
	log.Printf("CPG available at %s for Python queries", cpgPath)

	// If Joern produced no results, treat it as a failure
	if len(results.Functions) == 0 && len(results.ReachableFunctions) == 0 {
		return nil, fmt.Errorf("Joern analysis produced no results (likely crashed during extraction)")
	}

	return results, nil
}

// extractBasicResults runs Joern queries to extract function metadata and reachability
func extractBasicResults(cpgPath, projectDir string, fuzzers []string, language string) (*models.AnalysisResults, error) {
	results := &models.AnalysisResults{
		Functions:          make(map[string]*models.FunctionDefinition),
		CallGraph:          &models.CallGraph{Calls: []models.MethodCall{}},
		ReachableFunctions: make(map[string][]string),
		Paths:              make(map[string][][]string),
		CallGraphAdj:       make(map[string][]string),
	}

	// Determine entry point patterns based on language
	// We'll construct Joern queries that properly handle pattern matching
	var entryPointQueries string

	switch language {
	case "c", "c++", "cpp":
		// For C/C++, look for:
		// 1. LLVMFuzzerTestOneInput (exact match)
		// 2. Any function with LLVMFuzzerTestOneInput in name (regex)
		// 3. Functions named "main"
		// 4. Functions in files matching fuzz patterns (fallback for custom harnesses)
		entryPointQueries = `cpg.method.name("LLVMFuzzerTestOneInput").l ++ cpg.method.filter(_.name.matches(".*LLVMFuzzerTestOneInput.*")).l ++ cpg.method.name("main").l ++ cpg.method.filter(m => m.filename.matches("(?i).*fuzz.*\\.c") && !m.name.startsWith("<")).l`
	case "java":
		// For Java, look for common fuzzer method patterns
		entryPointQueries = `cpg.method.filter(_.name.matches(".*fuzzerTestOneInput.*")).l ++ cpg.method.filter(_.name.matches(".*fuzzerInitialize.*")).l ++ cpg.method.filter(_.name.matches(".*testOneInput.*")).l ++ cpg.method.filter(m => m.filename.matches("(?i).*fuzz.*\\.java") && !m.name.startsWith("<")).l`
	default:
		// Default: try both C and Java patterns
		entryPointQueries = `cpg.method.name("LLVMFuzzerTestOneInput").l ++ cpg.method.filter(_.name.matches(".*fuzzerTestOneInput.*")).l ++ cpg.method.name("main").l ++ cpg.method.filter(m => m.filename.matches("(?i).*fuzz.*") && !m.name.startsWith("<")).l`
	}

	// Create a Joern script to extract data
	script := fmt.Sprintf(`
importCpg("%s")

// Extract all functions
cpg.method.foreach { m =>
  val name = m.fullName
  val file = m.filename
  val startLine = m.lineNumber.getOrElse(0)
  val endLine = m.lineNumberEnd.getOrElse(0)
  val sig = m.signature
  println(s"FUNC|||${name}|||${file}|||${startLine}|||${endLine}|||${sig}")
}

// Extract call graph
cpg.call.foreach { c =>
  val caller = c.method.fullName.headOption.getOrElse("unknown")
  val callee = c.calledMethod.fullName.headOption.getOrElse(c.name)
  println(s"CALL|||${caller}|||${callee}")
}

// Find entry points and compute reachability
def findReachable(startMethod: io.shiftleft.codepropertygraph.generated.nodes.Method, maxDepth: Int = 100): List[String] = {
  import scala.collection.mutable
  val visited = mutable.Set[String]()
  val queue = mutable.Queue[(String, Int)]((startMethod.fullName, 0))
  val result = mutable.ListBuffer[String]()

  while (queue.nonEmpty) {
    val (currentName, depth) = queue.dequeue()
    if (!visited.contains(currentName) && depth < maxDepth) {
      visited.add(currentName)
      // Escape regex special characters in function names (e.g., "main:int(int,char[]*)")
      val escapedName = java.util.regex.Pattern.quote(currentName)
      val currentMethods = cpg.method.fullName(escapedName).l
      currentMethods.foreach { m =>
        m.callOut.foreach { call =>
          call.calledMethod.foreach { callee =>
            val calleeName = callee.fullName
            if (!visited.contains(calleeName)) {
              queue.enqueue((calleeName, depth + 1))
              result += calleeName
            }
          }
        }
      }
    }
  }
  result.toList
}

// Find entry points (fuzzer functions) - language-aware patterns
val entryPoints = %s
entryPoints.foreach { m =>
  val reachable = findReachable(m, 100)
  println(s"ENTRY|||${m.fullName}|||${reachable.size}")
  reachable.foreach(f => println(s"REACHABLE|||${m.fullName}|||${f}"))
}

println("DONE")
exit
`, cpgPath, entryPointQueries)

	// Write script to temp file
	scriptPath := cpgPath + ".sc"
	if err := os.WriteFile(scriptPath, []byte(script), 0644); err != nil {
		return nil, fmt.Errorf("failed to write query script: %w", err)
	}
	// Keep script for debugging - don't delete it
	// defer os.Remove(scriptPath)

	// Run Joern with the script
	cmd := exec.Command("joern", "--script", scriptPath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Set working directory to cpgOutputDir so Joern creates its workspace there
	// instead of in the current working directory
	cpgOutputDir := filepath.Dir(cpgPath)
	cmd.Dir = cpgOutputDir

	log.Printf("Running Joern queries to extract results (workspace: %s)...", cpgOutputDir)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("Joern query failed: %w\nStderr: %s", err, stderr.String())
	}

	// Parse output
	lines := strings.Split(stdout.String(), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "FUNC|||") {
			parts := strings.Split(line, "|||")
			if len(parts) >= 6 {
				name := parts[1]
				filePath := parts[2]
				startLine := 0
				endLine := 0
				if parts[3] != "" {
					fmt.Sscanf(parts[3], "%d", &startLine)
				}
				if parts[4] != "" {
					fmt.Sscanf(parts[4], "%d", &endLine)
				}

				// Try to read source code
				sourceCode := ""
				absFilePath := filePath
				if !filepath.IsAbs(filePath) && projectDir != "" {
					absFilePath = filepath.Join(projectDir, filePath)
				}
				if absFilePath != "" && startLine > 0 && endLine > 0 {
					sourceCode = extractSourceCode(absFilePath, startLine, endLine)
				}

				results.Functions[name] = &models.FunctionDefinition{
					Name:       name,
					FilePath:   filePath,
					StartLine:  startLine,
					EndLine:    endLine,
					SourceCode: sourceCode,
				}
			}
		} else if strings.HasPrefix(line, "CALL|||") {
			parts := strings.Split(line, "|||")
			if len(parts) >= 3 {
				caller := parts[1]
				callee := parts[2]
				results.CallGraph.Calls = append(results.CallGraph.Calls, models.MethodCall{
					Caller: caller,
					Callee: callee,
				})
				results.CallGraphAdj[caller] = append(results.CallGraphAdj[caller], callee)
			}
		} else if strings.HasPrefix(line, "ENTRY|||") {
			parts := strings.Split(line, "|||")
			if len(parts) >= 2 {
				entryPoint := parts[1]
				// Initialize the entry point in ReachableFunctions map even if it has 0 reachable functions
				if _, exists := results.ReachableFunctions[entryPoint]; !exists {
					results.ReachableFunctions[entryPoint] = []string{}
				}
			}
		} else if strings.HasPrefix(line, "REACHABLE|||") {
			parts := strings.Split(line, "|||")
			if len(parts) >= 3 {
				entryPoint := parts[1]
				reachable := parts[2]
				results.ReachableFunctions[entryPoint] = append(results.ReachableFunctions[entryPoint], reachable)
			}
		}
	}

	log.Printf("Extracted %d functions, %d call edges, %d entry points",
		len(results.Functions), len(results.CallGraph.Calls), len(results.ReachableFunctions))

	// Java-specific fallback: If we have entry points but no reachable functions,
	// Joern's Java call graph extraction likely failed. Fall back to marking all functions as reachable.
	if language == "java" {
		hasEmptyReachability := false
		for entryPoint, reachable := range results.ReachableFunctions {
			if len(reachable) == 0 {
				hasEmptyReachability = true
				log.Printf("Warning: Entry point %s has 0 reachable functions (Joern Java limitation)", entryPoint)
			}
		}

		if hasEmptyReachability && len(results.Functions) > 0 {
			log.Printf("Applying Java fallback: marking all %d functions as reachable from entry points", len(results.Functions))
			allFunctionNames := make([]string, 0, len(results.Functions))
			for name := range results.Functions {
				// Skip operators and synthetic methods
				if !strings.HasPrefix(name, "<operator>") && !strings.HasPrefix(name, "<unresolvedNamespace>") {
					allFunctionNames = append(allFunctionNames, name)
				}
			}

			// Update each entry point to have all functions as reachable
			for entryPoint := range results.ReachableFunctions {
				if len(results.ReachableFunctions[entryPoint]) == 0 {
					results.ReachableFunctions[entryPoint] = allFunctionNames
					log.Printf("Marked %d functions as reachable from %s", len(allFunctionNames), entryPoint)
				}
			}
		}
	}

	return results, nil
}

// extractSourceCode reads source code lines from a file
func extractSourceCode(filePath string, startLine, endLine int) string {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return ""
	}

	lines := strings.Split(string(data), "\n")
	if startLine < 1 || endLine > len(lines) || startLine > endLine {
		return ""
	}

	// Lines are 1-indexed in our model
	return strings.Join(lines[startLine-1:endLine], "\n")
}

// createTempCombinedDir creates a temporary directory with symlinks to all source directories
// This is needed because javasrc2cpg only accepts a single input directory
func createTempCombinedDir(sourceDirs []string) (string, func(), error) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "joern-combined-*")
	if err != nil {
		return "", nil, err
	}

	cleanup := func() {
		os.RemoveAll(tempDir)
	}

	// Create symlinks for each source directory
	for i, srcDir := range sourceDirs {
		// Get absolute path
		absSrcDir, err := filepath.Abs(srcDir)
		if err != nil {
			cleanup()
			return "", nil, fmt.Errorf("failed to get absolute path for %s: %w", srcDir, err)
		}

		// Create symlink with unique name
		linkName := fmt.Sprintf("src%d", i)
		linkPath := filepath.Join(tempDir, linkName)

		if err := os.Symlink(absSrcDir, linkPath); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("failed to create symlink %s -> %s: %w", linkPath, absSrcDir, err)
		}

		log.Printf("Created symlink: %s -> %s", linkPath, absSrcDir)
	}

	return tempDir, cleanup, nil
}

// normalizeLanguage converts language names to the format expected by Joern
func normalizeLanguage(language string) string {
	language = strings.ToLower(strings.TrimSpace(language))

	// Map of language aliases to canonical Joern language names
	languageMap := map[string]string{
		"jvm":  "java",
		"c++":  "cpp",
		"c":    "c",
		"cpp":  "cpp",
		"java": "java",
	}

	if normalized, ok := languageMap[language]; ok {
		return normalized
	}

	// Return as-is if not in map (Joern will handle the error)
	return language
}

// findTaskDirectory finds the task directory from a project directory
// It walks up the directory tree looking for characteristic files
func findTaskDirectory(projectDir string) string {
	// Walk up from projectDir looking for task_detail.json or fuzz-tooling
	current := projectDir
	for i := 0; i < 5; i++ {
		// Check if this directory has task markers
		if _, err := os.Stat(filepath.Join(current, "task_detail.json")); err == nil {
			return current
		}
		if _, err := os.Stat(filepath.Join(current, "fuzz-tooling")); err == nil {
			return current
		}

		// Go up one level
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}

	// If we can't find task directory, use projectDir
	return projectDir
}

// findFuzzerDirectories searches for common fuzzer directory locations
// that might be excluded from the main build due to conditional compilation
func findFuzzerDirectories(projectDir string) []string {
	var fuzzerDirs []string

	// Common fuzzer directory patterns to check
	// NOTE: More specific patterns (e.g., tests/fuzzer) should come before general ones (e.g., tests)
	patterns := []string{
		"cpp/tests/fuzz",
		"tests/fuzz",
		"test/fuzz",
		"tests/fuzzer",      // flatbuffers uses this
		"test/fuzzer",
		"fuzz",
		"fuzzing",
		"cpp/fuzz",
		"src/fuzz",
		"src/test/fuzz",
		"src/test/java/fuzz",
		"fuzzer",
		"fuzzers",
	}

	for _, pattern := range patterns {
		candidatePath := filepath.Join(projectDir, pattern)
		if stat, err := os.Stat(candidatePath); err == nil && stat.IsDir() {
			// Check if this directory contains actual source files
			if hasSourceFiles(candidatePath) {
				fuzzerDirs = append(fuzzerDirs, candidatePath)
			}
		}
	}

	// Also check if tests/test directories contain fuzzer files directly
	// (e.g., jq has jq_fuzz_*.c files directly in tests/ directory)
	// But only if we haven't already found a more specific fuzzer subdirectory
	testDirPatterns := []string{
		"tests",
		"test",
		"cpp/tests",
	}

	for _, pattern := range testDirPatterns {
		candidatePath := filepath.Join(projectDir, pattern)
		if stat, err := os.Stat(candidatePath); err == nil && stat.IsDir() {
			// Skip if we've already found a fuzzer subdirectory within this test directory
			hasSubdirFuzzer := false
			for _, existingDir := range fuzzerDirs {
				// Check if existingDir is a subdirectory of candidatePath
				// e.g., if we found "tests/fuzzer", skip adding "tests"
				if strings.HasPrefix(existingDir, candidatePath + string(filepath.Separator)) {
					hasSubdirFuzzer = true
					break
				}
			}

			if !hasSubdirFuzzer {
				// Check if this directory contains files with "fuzz" in the name
				if hasFuzzerFiles(candidatePath) {
					fuzzerDirs = append(fuzzerDirs, candidatePath)
				}
			}
		}
	}

	return fuzzerDirs
}

// hasSourceFiles checks if a directory contains C/C++ or Java source files
func hasSourceFiles(dir string) bool {
	var hasSource bool

	// Walk the directory to find source files
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Continue walking even if there's an error
		}
		if info.IsDir() {
			return nil
		}

		// Check for common source file extensions
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".c" || ext == ".cpp" || ext == ".cc" || ext == ".cxx" ||
		   ext == ".h" || ext == ".hpp" || ext == ".hh" || ext == ".hxx" ||
		   ext == ".java" {
			hasSource = true
			return filepath.SkipAll // Found a source file, stop walking
		}

		return nil
	})

	return hasSource
}

// hasFuzzerFiles checks if a directory contains source files with "fuzz" in their name
// This helps detect fuzzer files that are in test directories but not in dedicated fuzz subdirs
func hasFuzzerFiles(dir string) bool {
	var hasFuzzer bool

	// Only check files directly in this directory (not subdirectories)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := strings.ToLower(entry.Name())
		ext := strings.ToLower(filepath.Ext(name))

		// Check if it's a source file with "fuzz" in the name
		if (ext == ".c" || ext == ".cpp" || ext == ".cc" || ext == ".cxx" || ext == ".java") &&
			strings.Contains(name, "fuzz") {
			hasFuzzer = true
			break
		}
	}

	return hasFuzzer
}

// createCPG creates a Code Property Graph using local Joern installation
func createCPG(projectDirs []string, cpgPath, language string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cpgCreationTimeout)
	defer cancel()

	var cmd *exec.Cmd
	var tempDir string
	var cleanupFunc func()

	// For Java with multiple directories, create a temporary directory with symlinks
	// because javasrc2cpg only accepts a single input directory
	if language == "java" && len(projectDirs) > 1 {
		var err error
		tempDir, cleanupFunc, err = createTempCombinedDir(projectDirs)
		if err != nil {
			return fmt.Errorf("failed to create temporary combined directory: %w", err)
		}
		defer cleanupFunc()
		log.Printf("Created temporary combined directory: %s", tempDir)
		projectDirs = []string{tempDir}
	}

	switch language {
	case "c", "c++", "cpp":
		// Use joern-parse for C/C++ - only supports single directory
		// IMPORTANT: Explicitly specify --language to avoid auto-detection issues
		// (e.g., njs has both .c and .js files, and joern would pick JavaScript)
		// If multiple directories are provided, use the first one (main repo)
		// and let simple analysis handle the others (e.g., fuzzer harnesses)
		primaryDir := projectDirs[0]
		if len(projectDirs) > 1 {
			log.Printf("Warning: joern-parse only supports single directory. Using primary directory: %s", primaryDir)
			log.Printf("Other directories will be analyzed with simple regex-based analysis: %v", projectDirs[1:])
		}
		// Exclude directories that are typically not relevant for fuzzing analysis
		// and can significantly slow down CPG creation
		args := []string{primaryDir, "--output", cpgPath, "--language", "newc",
			"--frontend-args",
			"--exclude", "tutorials",
			"--exclude", "docs",
			"--exclude", "documentation",
			"--exclude", "examples",
			"--exclude", "third_party",
			"--exclude", "vendor",
		}
		cmd = exec.CommandContext(ctx, "joern-parse", args...)
	case "java":
		// Use javasrc2cpg for Java - only supports single directory
		if len(projectDirs) != 1 {
			return fmt.Errorf("javasrc2cpg requires exactly one input directory (got %d)", len(projectDirs))
		}
		cmd = exec.CommandContext(ctx, "javasrc2cpg", projectDirs[0], "--output", cpgPath)
	default:
		return fmt.Errorf("unsupported language: %s", language)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Set working directory to the CPG output directory
	cpgOutputDir := filepath.Dir(cpgPath)
	cmd.Dir = cpgOutputDir

	log.Printf("Running: %s (workdir: %s) [timeout: %v]", strings.Join(cmd.Args, " "), cpgOutputDir, cpgCreationTimeout)
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("CPG creation timed out after %v - codebase may be too large", cpgCreationTimeout)
		}
		return fmt.Errorf("CPG creation failed: %w\nStdout: %s\nStderr: %s",
			err, stdout.String(), stderr.String())
	}

	// Check if CPG was created
	if _, err := os.Stat(cpgPath); os.IsNotExist(err) {
		// Sometimes Joern creates cpg.bin.tmp or cpg.bin.zip, check for those
		tmpPath := cpgPath + ".tmp"
		zipPath := cpgPath + ".zip"
		if _, err := os.Stat(tmpPath); err == nil {
			// Rename .tmp to the expected name
			if err := os.Rename(tmpPath, cpgPath); err != nil {
				return fmt.Errorf("failed to rename CPG from .tmp: %w", err)
			}
		} else if _, err := os.Stat(zipPath); err == nil {
			// Rename .zip to the expected name
			if err := os.Rename(zipPath, cpgPath); err != nil {
				return fmt.Errorf("failed to rename CPG from .zip: %w", err)
			}
		} else {
			return fmt.Errorf("CPG file was not created at %s", cpgPath)
		}
	}

	log.Printf("CPG created successfully at %s", cpgPath)
	return nil
}

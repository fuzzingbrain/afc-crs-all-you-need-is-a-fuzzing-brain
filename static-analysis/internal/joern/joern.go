package joern

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"static-analysis/internal/engine/models"
)

// AnalyzeProjectDirs runs Joern analysis on multiple project directories using local Joern installation
// This creates a combined CPG and saves it for Python to query directly
func AnalyzeProjectDirs(projectDirs []string, language string, fuzzers []string) (*models.AnalysisResults, error) {
	if len(projectDirs) == 0 {
		return nil, fmt.Errorf("no project directories specified")
	}
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

	// For C/C++ projects, also look for fuzzer directories that might be conditionally compiled
	// (e.g., behind CMake flags like DNP3_FUZZING=ON) and include them explicitly
	// Note: We store these separately because joern-parse may not include them due to CMake configs
	var fuzzerDirs []string
	if language == "c" || language == "c++" || language == "cpp" {
		fuzzerDirs = findFuzzerDirectories(projectDir)
		for _, fuzzerDir := range fuzzerDirs {
			log.Printf("Found fuzzer directory: %s", fuzzerDir)
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

	// Step 2.5: If no entry points found and we have fuzzer directories, parse fuzzer dirs separately
	if err == nil && len(results.ReachableFunctions) == 0 && len(fuzzerDirs) > 0 {
		log.Printf("No entry points found in initial CPG. Parsing fuzzer directories separately to find entry points...")

		// Parse just the fuzzer directories to find entry points
		fuzzerCpgPath := cpgPath + ".fuzzers"
		if err := createCPG(fuzzerDirs, fuzzerCpgPath, language); err == nil {
			// Extract entry points from fuzzer-only CPG
			fuzzerResults, err := extractBasicResults(fuzzerCpgPath, projectDir, fuzzers, language)
			if err == nil && len(fuzzerResults.ReachableFunctions) > 0 {
				log.Printf("Found %d entry points in fuzzer directories!", len(fuzzerResults.ReachableFunctions))

				// Merge: keep main CPG's functions and call graph, but add fuzzer entry points
				// The main CPG has all the library functions, the fuzzer CPG has the entry points
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

				log.Printf("Merged results: %d total functions, %d entry points",
					len(results.Functions), len(results.ReachableFunctions))
			}
			// Keep the fuzzer CPG for reference
			// Don't delete fuzzerCpgPath - it may be useful for debugging
		} else {
			log.Printf("Failed to parse fuzzer directories: %v", err)
		}
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
	var entryPointPatterns []string
	switch language {
	case "c", "c++", "cpp":
		entryPointPatterns = []string{".*LLVMFuzzerTestOneInput.*"}
	case "java":
		entryPointPatterns = []string{
			".*fuzzerTestOneInput.*",
			".*fuzzerInitialize.*",
			".*testOneInput.*",
		}
	default:
		entryPointPatterns = []string{".*LLVMFuzzerTestOneInput.*", ".*fuzzerTestOneInput.*"}
	}

	// Build the entry point search queries
	entryPointQueries := ""
	for i, pattern := range entryPointPatterns {
		if i > 0 {
			entryPointQueries += " ++ "
		}
		entryPointQueries += fmt.Sprintf(`cpg.method.fullName("%s").l`, pattern)
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
      val currentMethods = cpg.method.fullName(currentName).l
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
	patterns := []string{
		"cpp/tests/fuzz",
		"tests/fuzz",
		"test/fuzz",
		"fuzz",
		"fuzzing",
		"cpp/fuzz",
		"src/fuzz",
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
	testDirPatterns := []string{
		"tests",
		"test",
		"cpp/tests",
	}

	for _, pattern := range testDirPatterns {
		candidatePath := filepath.Join(projectDir, pattern)
		if stat, err := os.Stat(candidatePath); err == nil && stat.IsDir() {
			// Check if this directory contains files with "fuzz" in the name
			if hasFuzzerFiles(candidatePath) {
				fuzzerDirs = append(fuzzerDirs, candidatePath)
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
		if (ext == ".c" || ext == ".cpp" || ext == ".cc" || ext == ".cxx") &&
			strings.Contains(name, "fuzz") {
			hasFuzzer = true
			break
		}
	}

	return hasFuzzer
}

// createCPG creates a Code Property Graph using local Joern installation
func createCPG(projectDirs []string, cpgPath, language string) error {
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
		// Use joern-parse for C/C++ - supports multiple directories
		args := append([]string{}, projectDirs...)
		args = append(args, "--output", cpgPath)
		cmd = exec.Command("joern-parse", args...)
	case "java":
		// Use javasrc2cpg for Java - only supports single directory
		if len(projectDirs) != 1 {
			return fmt.Errorf("javasrc2cpg requires exactly one input directory (got %d)", len(projectDirs))
		}
		cmd = exec.Command("javasrc2cpg", projectDirs[0], "--output", cpgPath)
	default:
		return fmt.Errorf("unsupported language: %s", language)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Set working directory to the CPG output directory
	cpgOutputDir := filepath.Dir(cpgPath)
	cmd.Dir = cpgOutputDir

	log.Printf("Running: %s (workdir: %s)", strings.Join(cmd.Args, " "), cpgOutputDir)
	if err := cmd.Run(); err != nil {
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

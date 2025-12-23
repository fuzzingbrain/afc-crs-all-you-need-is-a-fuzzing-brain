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

	// Step 1: Create CPG (Code Property Graph)
	log.Println("Creating Code Property Graph...")
	if err := createCPG(projectDirs, cpgPath, language); err != nil {
		return nil, fmt.Errorf("failed to create CPG: %w", err)
	}

	log.Printf("CPG saved to %s for Python queries", cpgPath)

	// Step 2: Extract basic analysis results from CPG
	log.Println("Extracting analysis results from CPG...")
	results, err := extractBasicResults(cpgPath, projectDir, fuzzers, language)
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

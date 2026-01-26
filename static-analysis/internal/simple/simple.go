package simple

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"static-analysis/internal/engine/models"
)

// findFuzzerSourceDirs extracts fuzzer source directories from fuzzer binary paths
func findFuzzerSourceDirs(fuzzers []string, projectDir string) []string {
	var dirs []string
	seen := make(map[string]bool)

	for _, fuzzerPath := range fuzzers {
		// Fuzzer path format: /path/to/workspace/project/fuzz-tooling/build/out/project-address/fuzzer_binary
		// We want to find: /path/to/workspace/project/fuzz-tooling/projects/project/

		// Look for "fuzz-tooling/build/out" in the path
		if strings.Contains(fuzzerPath, "fuzz-tooling/build/out") {
			// Split and reconstruct to find the base
			parts := strings.Split(fuzzerPath, "fuzz-tooling/build/out")
			if len(parts) >= 2 {
				base := parts[0] // e.g., /path/to/workspace/project/
				// Get the project name from the path after "out/"
				outParts := strings.Split(parts[1], "/")
				if len(outParts) >= 2 {
					projectName := strings.TrimSuffix(outParts[1], "-address")
					projectName = strings.TrimSuffix(projectName, "-memory")
					projectName = strings.TrimSuffix(projectName, "-undefined")

					// Construct fuzzer source directory
					fuzzerSourceDir := filepath.Join(base, "fuzz-tooling", "projects", projectName)
					if !seen[fuzzerSourceDir] {
						seen[fuzzerSourceDir] = true
						dirs = append(dirs, fuzzerSourceDir)
					}
				}
			}
		}
	}

	// Also try to find fuzz-tooling/projects relative to projectDir
	// projectDir might be like /workspace/project/repo, so we need to go up
	if strings.HasSuffix(projectDir, "-address") || strings.HasSuffix(projectDir, "/repo") {
		parentDir := filepath.Dir(projectDir)
		if strings.HasSuffix(parentDir, "/repo") {
			parentDir = filepath.Dir(parentDir)
		}

		fuzzerToolingProjects := filepath.Join(parentDir, "fuzz-tooling", "projects")
		if info, err := os.Stat(fuzzerToolingProjects); err == nil && info.IsDir() {
			// Add all project directories under fuzz-tooling/projects
			entries, err := os.ReadDir(fuzzerToolingProjects)
			if err == nil {
				for _, entry := range entries {
					if entry.IsDir() {
						dir := filepath.Join(fuzzerToolingProjects, entry.Name())
						if !seen[dir] {
							seen[dir] = true
							dirs = append(dirs, dir)
						}
					}
				}
			}
		}
	}

	return dirs
}

// AnalyzeProjectDirs performs simple regex-based analysis for C/C++ and Java projects across multiple directories
func AnalyzeProjectDirs(projectDirs []string, language string, fuzzers []string) (*models.AnalysisResults, error) {
	if len(projectDirs) == 0 {
		return nil, fmt.Errorf("no project directories specified")
	}

	log.Printf("Starting simple analysis for %s project at %v", language, projectDirs)

	results := &models.AnalysisResults{
		Functions:          make(map[string]*models.FunctionDefinition),
		CallGraph:          &models.CallGraph{Calls: []models.MethodCall{}},
		ReachableFunctions: make(map[string][]string),
		Paths:              make(map[string][][]string),
		CallGraphAdj:       make(map[string][]string),
	}

	// Scan all provided directories
	dirsToScan := append([]string{}, projectDirs...)

	// Find all source files
	var sourceFiles []string
	var extensions []string
	if language == "java" {
		extensions = []string{".java"}
	} else {
		extensions = []string{".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}
	}

	for _, scanDir := range dirsToScan {
		log.Printf("Scanning directory: %s", scanDir)
		err := filepath.Walk(scanDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			for _, validExt := range extensions {
				if ext == validExt {
					sourceFiles = append(sourceFiles, path)
					break
				}
			}
			return nil
		})
		if err != nil {
			log.Printf("Warning: error walking directory %s: %v", scanDir, err)
		}
	}

	log.Printf("Found %d source files to analyze", len(sourceFiles))

	// Two-pass approach to avoid order-dependent bugs:
	// Pass 1: Parse all files to extract functions only
	// Pass 2: Build call graph now that all functions are known

	projectDir := projectDirs[0] // Use first directory for relative path calculation

	// Pass 1: Extract all function definitions
	for _, filePath := range sourceFiles {
		if err := parseFunctionsOnly(filePath, projectDir, language, results); err != nil {
			log.Printf("Warning: failed to parse functions from %s: %v", filePath, err)
		}
	}
	log.Printf("Extracted %d functions", len(results.Functions))

	// Pass 2: Build call graph now that all functions are known
	// Skip for large codebases (>10000 files) to avoid timeout
	if len(sourceFiles) > 10000 {
		log.Printf("Skipping call graph building for large codebase (%d files)", len(sourceFiles))
	} else {
		for _, filePath := range sourceFiles {
			if err := parseCallsOnly(filePath, projectDir, language, results); err != nil {
				log.Printf("Warning: failed to parse calls from %s: %v", filePath, err)
			}
		}
		log.Printf("Built call graph with %d edges", len(results.CallGraph.Calls))
	}

	// Find fuzzer entry points directly from parsed functions
	entryPoints := make([]string, 0)
	entryPointName := "LLVMFuzzerTestOneInput"
	if language == "java" {
		entryPointName = "fuzzerTestOneInput"
	}

	for funcName := range results.Functions {
		if strings.Contains(funcName, entryPointName) {
			entryPoints = append(entryPoints, funcName)
		}
	}

	log.Printf("Found %d entry points", len(entryPoints))

	// If no entry points found, log debug info
	if len(entryPoints) == 0 {
		log.Printf("DEBUG: No entry points found. Searching for '%s' in %d functions:", entryPointName, len(results.Functions))
		count := 0
		for funcName, funcDef := range results.Functions {
			if count < 10 {
				log.Printf("  Sample function key: %s, name: %s", funcName, funcDef.Name)
				count++
			}
			// Extra check: log if any function has similar name
			if strings.Contains(strings.ToLower(funcName), "fuzzer") || strings.Contains(strings.ToLower(funcDef.Name), "fuzzer") {
				log.Printf("  Found fuzzer-related function: %s (name: %s)", funcName, funcDef.Name)
			}
		}
	}

	// Compute reachability from each entry point
	for _, entryPoint := range entryPoints {
		reachable := findReachableFunctions(entryPoint, results.CallGraphAdj, 100)
		results.ReachableFunctions[entryPoint] = reachable
		log.Printf("Entry point %s has %d reachable functions", entryPoint, len(reachable))
	}

	log.Printf("Simple analysis complete: %d functions, %d entry points",
		len(results.Functions), len(results.ReachableFunctions))

	return results, nil
}

// AnalyzeProject performs simple regex-based analysis for C/C++ and Java projects
// This version automatically finds fuzzer source directories
func AnalyzeProject(projectDir string, language string, fuzzers []string) (*models.AnalysisResults, error) {
	log.Printf("Starting simple analysis for %s project at %s", language, projectDir)

	results := &models.AnalysisResults{
		Functions:          make(map[string]*models.FunctionDefinition),
		CallGraph:          &models.CallGraph{Calls: []models.MethodCall{}},
		ReachableFunctions: make(map[string][]string),
		Paths:              make(map[string][][]string),
		CallGraphAdj:       make(map[string][]string),
	}

	// Determine directories to scan
	dirsToScan := []string{projectDir}

	// Extract fuzzer source directories from fuzzer binary paths
	// Fuzzer path format: /path/to/workspace/project/fuzz-tooling/build/out/project-address/fuzzer_binary
	// Fuzzer sources are in: /path/to/workspace/project/fuzz-tooling/projects/project/
	if len(fuzzers) > 0 {
		fuzzerSourceDirs := findFuzzerSourceDirs(fuzzers, projectDir)
		for _, dir := range fuzzerSourceDirs {
			if _, err := os.Stat(dir); err == nil {
				dirsToScan = append(dirsToScan, dir)
				log.Printf("Added fuzzer source directory to scan: %s", dir)
			}
		}
	}

	// Find all source files
	var sourceFiles []string
	var extensions []string
	if language == "java" {
		extensions = []string{".java"}
	} else {
		extensions = []string{".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}
	}

	for _, scanDir := range dirsToScan {
		err := filepath.Walk(scanDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			for _, validExt := range extensions {
				if ext == validExt {
					sourceFiles = append(sourceFiles, path)
					break
				}
			}
			return nil
		})

		if err != nil {
			log.Printf("Warning: failed to walk directory %s: %v", scanDir, err)
		}
	}

	log.Printf("Found %d source files to analyze across %d directories", len(sourceFiles), len(dirsToScan))

	// Two-pass approach to avoid order-dependent bugs:
	// Pass 1: Extract all function definitions
	for _, filePath := range sourceFiles {
		if err := parseFunctionsOnly(filePath, projectDir, language, results); err != nil {
			log.Printf("Warning: failed to parse functions from %s: %v", filePath, err)
		}
	}
	log.Printf("Extracted %d functions", len(results.Functions))

	// Pass 2: Build call graph now that all functions are known
	// Skip for large codebases (>10000 files) to avoid timeout
	if len(sourceFiles) > 10000 {
		log.Printf("Skipping call graph building for large codebase (%d files)", len(sourceFiles))
	} else {
		for _, filePath := range sourceFiles {
			if err := parseCallsOnly(filePath, projectDir, language, results); err != nil {
				log.Printf("Warning: failed to parse calls from %s: %v", filePath, err)
			}
		}
		log.Printf("Built call graph with %d edges", len(results.CallGraph.Calls))
	}

	// Extract entry points from fuzzers
	entryPoints := extractEntryPoints(fuzzers, language, results)
	log.Printf("Found %d entry points", len(entryPoints))

	// Compute reachability from each entry point
	for _, entryPoint := range entryPoints {
		reachable := findReachableFunctions(entryPoint, results.CallGraphAdj, 100)
		results.ReachableFunctions[entryPoint] = reachable
		log.Printf("Entry point %s has %d reachable functions", entryPoint, len(reachable))

		// Compute paths (simplified - just direct calls)
		for _, target := range reachable {
			compositeKey := fmt.Sprintf("%s-%s", entryPoint, target)
			if len(results.CallGraphAdj[entryPoint]) > 0 {
				results.Paths[compositeKey] = [][]string{{entryPoint, target}}
			}
		}
	}

	return results, nil
}

// parseFunctionsOnly extracts only function definitions from a source file (pass 1)
func parseFunctionsOnly(filePath, projectDir, language string, results *models.AnalysisResults) error {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	contentStr := string(content)

	relPath, _ := filepath.Rel(projectDir, filePath)

	var funcRegex *regexp.Regexp
	if language == "java" {
		funcRegex = regexp.MustCompile(`(?m)^\s*(public|private|protected|static|\s)+[\w<>\[\]]+\s+(\w+)\s*\([^)]*\)\s*\{`)
	} else {
		// Match C/C++ functions with brace on same line OR next line
		// This will match functions like:
		// int foo() {
		// OR
		// int
		// foo(args)
		// {
		// Note: We need at least one return type token ([\w:*]+) followed by whitespace and then the function name
		funcRegex = regexp.MustCompile(`(?m)^\s*(?:extern\s+"C"\s+)?(?:inline\s+)?(?:static\s+)?(?:const\s+)?[\w:*]+[\s*]+(\w+)\s*\([^)]*\)(?:\s*\{|$)`)
	}

	// Split content into lines for processing
	lines := strings.Split(contentStr, "\n")

	lineNum := 0
	for lineNum < len(lines) {
		line := lines[lineNum]
		lineNum++

		// For C/C++, check if this looks like a function return type
		// If so, combine with next line(s) to get full declaration
		var combinedLine string
		if language != "java" {
			// Check if line looks like a return type (ends with a type, no opening brace)
			trimmed := strings.TrimSpace(line)
			if len(trimmed) > 0 && !strings.Contains(line, "{") && !strings.Contains(line, ";") {
				// Might be a return type on its own line, combine with next line
				combinedLine = line
				if lineNum < len(lines) {
					combinedLine += " " + lines[lineNum]
					// Also check the line after for opening brace
					if lineNum+1 < len(lines) && strings.Contains(lines[lineNum+1], "{") {
						combinedLine += " " + lines[lineNum+1]
					}
				}
			} else {
				combinedLine = line
			}
		} else {
			combinedLine = line
		}

		// Check for function definition
		if matches := funcRegex.FindStringSubmatch(combinedLine); len(matches) > 0 {
			funcName := ""
			if language == "java" && len(matches) > 2 {
				funcName = matches[2]
			} else if len(matches) > 1 {
				funcName = matches[1]
			}

			// Filter out C/C++ keywords
			if funcName != "" && !isCKeyword(funcName) {
				fullFuncName := fmt.Sprintf("%s.%s", relPath, funcName)

				// Extract function body (up to 50 lines from current position)
				bodyLines := []string{}
				startLine := lineNum - 1 // We already incremented lineNum
				endLine := startLine + 50
				if endLine > len(lines) {
					endLine = len(lines)
				}
				for i := startLine; i < endLine; i++ {
					bodyLines = append(bodyLines, lines[i])
				}

				results.Functions[fullFuncName] = &models.FunctionDefinition{
					Name:       funcName,
					FilePath:   relPath,
					StartLine:  startLine + 1, // 1-indexed for display
					EndLine:    endLine,
					SourceCode: strings.Join(bodyLines, "\n"),
				}
			}
		}
	}

	return nil
}

// parseCallsOnly extracts function calls and builds the call graph (pass 2)
func parseCallsOnly(filePath, projectDir, language string, results *models.AnalysisResults) error {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	contentStr := string(content)

	relPath, _ := filepath.Rel(projectDir, filePath)

	var funcRegex *regexp.Regexp
	var callRegex *regexp.Regexp

	if language == "java" {
		funcRegex = regexp.MustCompile(`(?m)^\s*(public|private|protected|static|\s)+[\w<>\[\]]+\s+(\w+)\s*\([^)]*\)\s*\{`)
		callRegex = regexp.MustCompile(`\b(\w+)\s*\(`)
	} else {
		funcRegex = regexp.MustCompile(`(?m)^\s*(?:extern\s+"C"\s+)?(?:inline\s+)?(?:static\s+)?[\w:*\s]+\s+(\w+)\s*\([^)]*\)\s*\{`)
		callRegex = regexp.MustCompile(`\b(\w+)\s*\(`)
	}

	lines := strings.Split(contentStr, "\n")
	lineNum := 0
	var currentFunction string
	braceDepth := 0

	for lineNum < len(lines) {
		line := lines[lineNum]
		lineNum++

		// For C/C++, combine lines for multi-line function declarations
		var combinedLine string
		if language != "java" {
			trimmed := strings.TrimSpace(line)
			// If line looks like it might be a return type without opening brace
			if len(trimmed) > 0 && !strings.Contains(line, "{") && !strings.Contains(line, ";") && lineNum < len(lines) {
				combinedLine = line + " " + lines[lineNum]
				// Also check if the opening brace is on the line after that
				if lineNum+1 < len(lines) && strings.Contains(lines[lineNum+1], "{") {
					combinedLine += " " + lines[lineNum+1]
				}
			} else {
				combinedLine = line
			}
		} else {
			combinedLine = line
		}

		// Track brace depth to know when we're inside a function
		braceDepth += strings.Count(line, "{") - strings.Count(line, "}")

		// Check for function definition to track current function (use combinedLine for multi-line declarations)
		if matches := funcRegex.FindStringSubmatch(combinedLine); len(matches) > 0 {
			funcName := ""
			if language == "java" && len(matches) > 2 {
				funcName = matches[2]
			} else if len(matches) > 1 {
				funcName = matches[1]
			}

			// Filter out C/C++ keywords
			if funcName != "" && (language == "java" || !isCKeyword(funcName)) {
				currentFunction = fmt.Sprintf("%s.%s", relPath, funcName)
			}
		}

		// Check for function calls (use original line, not combined, to avoid double-counting)
		if currentFunction != "" && braceDepth > 0 {
			callMatches := callRegex.FindAllStringSubmatch(line, -1)
			for _, match := range callMatches {
				if len(match) > 1 {
					calleeName := match[1]
					// Skip common keywords and constructors
					if !isKeyword(calleeName, language) {
						// Try to find the full function name (now all functions are known)
						fullCallee := findFullFunctionName(calleeName, results.Functions, relPath)
						if fullCallee != "" {
							// Only add if the callee actually exists in functions map
							if _, exists := results.Functions[fullCallee]; exists {
								results.CallGraph.Calls = append(results.CallGraph.Calls, models.MethodCall{
									Caller: currentFunction,
									Callee: fullCallee,
								})
								results.CallGraphAdj[currentFunction] = append(results.CallGraphAdj[currentFunction], fullCallee)
							}
						}
					}
				}
			}
		}

		// Reset current function when we exit it
		if braceDepth == 0 && currentFunction != "" {
			currentFunction = ""
		}
	}

	return nil
}

// parseFile extracts functions and calls from a source file
func parseFile(filePath, projectDir, language string, results *models.AnalysisResults) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	content, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	contentStr := string(content)

	relPath, _ := filepath.Rel(projectDir, filePath)

	var funcRegex *regexp.Regexp
	var callRegex *regexp.Regexp

	if language == "java" {
		// Java function pattern: public/private/protected void/int/String methodName(...)
		funcRegex = regexp.MustCompile(`(?m)^\s*(public|private|protected|static|\s)+[\w<>\[\]]+\s+(\w+)\s*\([^)]*\)\s*\{`)
		// Java call pattern: methodName(...)
		callRegex = regexp.MustCompile(`\b(\w+)\s*\(`)
	} else {
		// C/C++ function pattern: return_type function_name(...)
		// Updated to handle: extern "C" int func(...), inline void func(...), etc.
		funcRegex = regexp.MustCompile(`(?m)^\s*(?:extern\s+"C"\s+)?(?:inline\s+)?(?:static\s+)?[\w:*\s]+\s+(\w+)\s*\([^)]*\)\s*\{`)
		// C/C++ call pattern: function_name(...)
		callRegex = regexp.MustCompile(`\b(\w+)\s*\(`)
	}

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	lineNum := 0
	var currentFunction string
	var functionStart int
	braceDepth := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Track brace depth to know when we're inside a function
		braceDepth += strings.Count(line, "{") - strings.Count(line, "}")

		// Check for function definition
		if matches := funcRegex.FindStringSubmatch(line); len(matches) > 0 {
			funcName := ""
			if language == "java" && len(matches) > 2 {
				funcName = matches[2]
			} else if len(matches) > 1 {
				funcName = matches[1]
			}

			if funcName != "" {
				currentFunction = fmt.Sprintf("%s.%s", relPath, funcName)
				_ = functionStart // Mark as used
				functionStart = lineNum

				// Extract function body (simplified - just a few lines)
				bodyLines := []string{}
				tmpScanner := bufio.NewScanner(strings.NewReader(contentStr))
				tmpLine := 0
				for tmpScanner.Scan() {
					tmpLine++
					if tmpLine >= lineNum && tmpLine < lineNum+50 {
						bodyLines = append(bodyLines, tmpScanner.Text())
					}
					if tmpLine >= lineNum+50 {
						break
					}
				}

				results.Functions[currentFunction] = &models.FunctionDefinition{
					Name:       funcName,
					FilePath:   relPath,
					StartLine:  lineNum,
					EndLine:    lineNum + len(bodyLines),
					SourceCode: strings.Join(bodyLines, "\n"),
				}
			}
		}

		// Check for function calls
		if currentFunction != "" && braceDepth > 0 {
			callMatches := callRegex.FindAllStringSubmatch(line, -1)
			for _, match := range callMatches {
				if len(match) > 1 {
					calleeName := match[1]
					// Skip common keywords and constructors
					if !isKeyword(calleeName, language) {
						// Try to find the full function name
						fullCallee := findFullFunctionName(calleeName, results.Functions, relPath)
						if fullCallee != "" {
							results.CallGraph.Calls = append(results.CallGraph.Calls, models.MethodCall{
								Caller: currentFunction,
								Callee: fullCallee,
							})
							results.CallGraphAdj[currentFunction] = append(results.CallGraphAdj[currentFunction], fullCallee)
						}
					}
				}
			}
		}

		// Reset current function when we exit it
		if braceDepth == 0 && currentFunction != "" {
			currentFunction = ""
		}
	}

	return scanner.Err()
}

// isKeyword checks if a name is a language keyword
func isKeyword(name, language string) bool {
	if language == "java" {
		keywords := map[string]bool{
			"if": true, "else": true, "for": true, "while": true, "return": true,
			"new": true, "this": true, "super": true, "try": true, "catch": true,
			"throw": true, "throws": true, "class": true, "interface": true,
			"public": true, "private": true, "protected": true, "static": true,
			"final": true, "void": true, "int": true, "String": true, "boolean": true,
		}
		return keywords[name]
	} else {
		keywords := map[string]bool{
			"if": true, "else": true, "for": true, "while": true, "return": true,
			"sizeof": true, "typeof": true, "switch": true, "case": true,
			"break": true, "continue": true, "goto": true, "typedef": true,
			"struct": true, "union": true, "enum": true, "static": true,
			"extern": true, "const": true, "volatile": true, "printf": true,
			"fprintf": true, "sprintf": true, "memcpy": true, "malloc": true,
			"free": true,
		}
		return keywords[name]
	}
}

// isCKeyword checks if a name is a C/C++ keyword
func isCKeyword(name string) bool {
	return isKeyword(name, "c")
}

// findFullFunctionName tries to match a simple function name to a full function identifier
func findFullFunctionName(simpleName string, functions map[string]*models.FunctionDefinition, currentFile string) string {
	// First try in the same file
	for fullName, funcDef := range functions {
		if funcDef.Name == simpleName && strings.HasPrefix(fullName, currentFile) {
			return fullName
		}
	}

	// Then try in any file
	for fullName, funcDef := range functions {
		if funcDef.Name == simpleName {
			return fullName
		}
	}

	// Return a default name if not found
	return fmt.Sprintf("%s.%s", currentFile, simpleName)
}

// extractEntryPoints finds entry point functions from fuzzer binaries
func extractEntryPoints(fuzzers []string, language string, results *models.AnalysisResults) []string {
	var entryPoints []string

	entryPointName := "LLVMFuzzerTestOneInput"
	if language == "java" {
		entryPointName = "fuzzerTestOneInput"
	}

	// First, try exact name matching
	for fullName, funcDef := range results.Functions {
		if funcDef.Name == entryPointName {
			entryPoints = append(entryPoints, fullName)
			log.Printf("Found entry point (exact match): %s", fullName)
		}
	}

	// If no exact matches, try substring matching on both full name and function name
	if len(entryPoints) == 0 {
		for fullName, funcDef := range results.Functions {
			if strings.Contains(fullName, entryPointName) || strings.Contains(funcDef.Name, entryPointName) {
				entryPoints = append(entryPoints, fullName)
				log.Printf("Found entry point (substring match): %s", fullName)
			}
		}
	}

	// If still no entry points found, create synthetic ones based on fuzzer binaries
	if len(entryPoints) == 0 && len(fuzzers) > 0 {
		log.Println("Warning: No entry points found in source, creating synthetic ones based on fuzzer binaries")
		for _, fuzzer := range fuzzers {
			baseName := filepath.Base(fuzzer)
			if language == "java" {
				entryPoints = append(entryPoints, baseName+".fuzzerTestOneInput")
			} else {
				entryPoints = append(entryPoints, baseName+".LLVMFuzzerTestOneInput")
			}
			log.Printf("Created synthetic entry point: %s", entryPoints[len(entryPoints)-1])
		}
	}

	// If still nothing, log a warning
	if len(entryPoints) == 0 {
		log.Printf("Warning: No entry points found and no fuzzer binaries provided")
		log.Printf("Available functions: %d", len(results.Functions))
		// Debug: print first few function names
		count := 0
		for fullName, funcDef := range results.Functions {
			if count < 5 {
				log.Printf("  Sample function: %s (name: %s)", fullName, funcDef.Name)
				count++
			}
		}
	}

	return entryPoints
}

// findReachableFunctions performs BFS to find all reachable functions from an entry point
func findReachableFunctions(entryPoint string, callGraph map[string][]string, maxDepth int) []string {
	visited := make(map[string]bool)
	queue := []string{entryPoint}
	depth := make(map[string]int)
	depth[entryPoint] = 0

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if visited[current] {
			continue
		}
		visited[current] = true

		currentDepth := depth[current]
		if currentDepth >= maxDepth {
			continue
		}

		// Add all callees to the queue
		for _, callee := range callGraph[current] {
			if !visited[callee] {
				queue = append(queue, callee)
				if _, exists := depth[callee]; !exists {
					depth[callee] = currentDepth + 1
				}
			}
		}
	}

	// Convert visited map to slice
	var reachable []string
	for funcName := range visited {
		if funcName != entryPoint {
			reachable = append(reachable, funcName)
		}
	}

	return reachable
}

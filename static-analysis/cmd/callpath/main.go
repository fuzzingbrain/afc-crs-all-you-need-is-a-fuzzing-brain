// SPDX-License-Identifier: Apache-2.0
package main

import (
	"regexp"

	"encoding/json"
	"flag"
	"fmt"
	"github.com/antlr4-go/antlr/v4"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"static-analysis/internal/parser/c"
	c_parser "static-analysis/internal/parser/c/grammar"
	"strings"
	"sync"
	"time"
	// "static-analysis/internal/parser/java"
	java_parser "static-analysis/internal/parser/java/grammar"
)

type AnalysisResults struct {
	Functions map[string]*FunctionDefinition `json:"functions"`
	CallGraph *CallGraph                     `json:"callGraph"`
	Paths     map[string][][]string          `json:"paths"` // Map from target to paths
}

// FunctionDefinition represents a function definition with its source code
type FunctionDefinition struct {
	Name       string
	FilePath   string
	StartLine  int
	EndLine    int
	SourceCode string
}

// CFunctionVisitor for C/C++ files
type CFunctionVisitor struct {
	*c_parser.BaseCListener // Use pointer to BaseCListener
	Functions               map[string]*FunctionDefinition
	CurrentFile             string
	LineMap                 map[int]c.LineInfo
	SourceLines             []string
	CurrentFunc             string
	CurrentStart            int
	InFunctionDef           bool
}

func NewCFunctionVisitor(filePath string, lineMap map[int]c.LineInfo, sourceLines []string) *CFunctionVisitor {
	return &CFunctionVisitor{
		BaseCListener: new(c_parser.BaseCListener), // Use new() to create a pointer
		Functions:     make(map[string]*FunctionDefinition),
		CurrentFile:   filePath,
		LineMap:       lineMap,
		SourceLines:   sourceLines,
	}
}

// EnterFunctionDefinition is called when entering a function definition
func (v *CFunctionVisitor) EnterFunctionDefinition(ctx *c_parser.FunctionDefinitionContext) {

	// Get function name from declarator
	declarator := ctx.Declarator()
	if declarator == nil {
		return
	}
	// Extract function name - this is simplified and might need enhancement
	funcText := declarator.GetText()

	// Use regex to extract the function name
	namePattern := regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)\s*\(`)
	matches := namePattern.FindStringSubmatch(funcText)

	if len(matches) > 1 {
		v.CurrentFunc = matches[1]
	} else {
		// Fallback to a simpler approach
		v.CurrentFunc = fmt.Sprintf("func_%d", ctx.GetStart().GetLine())
	}

	// Get start and end line numbers
	startLine := ctx.GetStart().GetLine()
	endLine := ctx.GetStop().GetLine()

	// MAIN PROBLEM: PREPROCESSING C SOURCE CODE
	// C PARSER does not work very well
	//  v.CurrentFunc LLVMFuzzerTestOneInput, startLine: 100, endLine: 105
	// if strings.Contains(v.CurrentFile, "libpng_read_fuzzer.cc") {
	// 	fmt.Printf(" v.CurrentFunc %s, startLine: %d, endLine: %d\n",  v.CurrentFunc,startLine, endLine)
	// }

	// Map to original line numbers if line map is available
	if v.LineMap != nil {
		if lineInfo, ok := v.LineMap[startLine]; ok {
			startLine = lineInfo.Line
		}
		if lineInfo, ok := v.LineMap[endLine]; ok {
			endLine = lineInfo.Line
		}
	}

	// Extract source code
	sourceCode := ""
	if startLine <= endLine && startLine <= len(v.SourceLines) && endLine <= len(v.SourceLines) {
		// Adjust for 0-based array indexing
		startIdx := startLine - 1
		endIdx := endLine
		if endIdx > len(v.SourceLines) {
			endIdx = len(v.SourceLines)
		}
		sourceLines := v.SourceLines[startIdx:endIdx]
		sourceCode = strings.Join(sourceLines, "\n")
	}

	// Store the function definition immediately

	v.Functions[v.CurrentFile+"."+v.CurrentFunc] = &FunctionDefinition{
		Name:       v.CurrentFunc,
		FilePath:   v.CurrentFile,
		StartLine:  startLine,
		EndLine:    endLine,
		SourceCode: sourceCode,
	}

	// fmt.Printf("Found function: %s (lines %d-%d)\n", v.CurrentFunc, startLine, endLine)

	// We still set these in case ExitFunctionDefinition wants to use them
	v.CurrentStart = startLine
	v.InFunctionDef = true
}

// ExitFunctionDefinition is called when exiting a function definition
func (v *CFunctionVisitor) ExitFunctionDefinition(ctx *c_parser.FunctionDefinitionContext) {
	if !v.InFunctionDef {
		return
	}

	endLine := ctx.GetStop().GetLine()
	if v.LineMap != nil {
		if lineInfo, ok := v.LineMap[endLine]; ok {
			endLine = lineInfo.Line
		}
	}

	// Extract source code
	sourceCode := ""
	if v.CurrentStart <= endLine && v.CurrentStart <= len(v.SourceLines) && endLine <= len(v.SourceLines) {
		// Adjust for 0-based array indexing
		startIdx := v.CurrentStart - 1
		endIdx := endLine
		if endIdx > len(v.SourceLines) {
			endIdx = len(v.SourceLines)
		}
		sourceLines := v.SourceLines[startIdx:endIdx]
		sourceCode = strings.Join(sourceLines, "\n")
	}

	// fmt.Printf("Completed function: %s (lines %d-%d)\n", v.CurrentFunc, v.CurrentStart, endLine)
	v.Functions[v.CurrentFile+"."+v.CurrentFunc] = &FunctionDefinition{
		Name:       v.CurrentFunc,
		FilePath:   v.CurrentFile,
		StartLine:  v.CurrentStart,
		EndLine:    endLine,
		SourceCode: sourceCode,
	}

	v.InFunctionDef = false
}

// processCFile processes a C/C++ file and returns the functions found
func processCFile(filePath string) (map[string]*FunctionDefinition, error) {
	// Read the file
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}

	// Skip preprocessing and use the original source directly
	sourceContent := string(content)
	sourceLines := strings.Split(sourceContent, "\n")

	// Create a simple line map that maps each line to itself
	lineMap := make(map[int]c.LineInfo)
	for i := range sourceLines {
		lineMap[i+1] = c.LineInfo{
			File: filePath,
			Line: i + 1,
		}
	}

	// Create input stream for ANTLR
	input := antlr.NewInputStream(sourceContent)
	// Create lexer
	lexer := c_parser.NewCLexer(input)
	tokens := antlr.NewCommonTokenStream(lexer, 0)

	// Create parser
	parser := c_parser.NewCParser(tokens)

	// Create error listener
	errorListener := &ErrorListener{FilePath: filePath}
	parser.RemoveErrorListeners()
	parser.AddErrorListener(errorListener)

	// Parse the input
	tree := parser.CompilationUnit()

	// Create visitor
	visitor := NewCFunctionVisitor(filePath, lineMap, sourceLines)

	// Walk the tree with our visitor
	antlr.ParseTreeWalkerDefault.Walk(visitor, tree)

	return visitor.Functions, nil
}

// ErrorListener is a custom error listener for ANTLR
type ErrorListener struct {
	antlr.DefaultErrorListener
	FilePath string
	Errors   []string
}

// SyntaxError is called when a syntax error is encountered
func (l *ErrorListener) SyntaxError(recognizer antlr.Recognizer, offendingSymbol interface{}, line, column int, msg string, e antlr.RecognitionException) {
	l.Errors = append(l.Errors, fmt.Sprintf("Syntax error at %s:%d:%d: %s", l.FilePath, line, column, msg))
}

type MethodCall struct {
	Caller string
	Callee string
}

// CallGraph represents a directed graph of method calls
type CallGraph struct {
	Calls []MethodCall
}

// JavaFunctionVisitor for Java files
type JavaFunctionVisitor struct {
	*java_parser.BaseJavaParserListener // Embed the base listener
	Functions                           map[string]*FunctionDefinition
	CurrentFile                         string
	SourceLines                         []string
	CurrentClass                        string
	CurrentFunc                         string
	CurrentStart                        int
	InFunctionDef                       bool
	CallGraph                           *CallGraph
}

func NewJavaFunctionVisitor(filePath string, sourceLines []string) *JavaFunctionVisitor {
	return &JavaFunctionVisitor{
		BaseJavaParserListener: &java_parser.BaseJavaParserListener{},
		Functions:              make(map[string]*FunctionDefinition),
		CurrentFile:            filePath,
		SourceLines:            sourceLines,
		CallGraph:              &CallGraph{Calls: []MethodCall{}},
	}
}

func (v *JavaFunctionVisitor) EnterMethodCall(ctx *java_parser.MethodCallContext) {
	if v.CurrentFunc == "" {
		return // Not inside a method
	}

	// Extract the called method name
	if identifierCtx := ctx.Identifier(); identifierCtx != nil {
		calledMethod := identifierCtx.GetText()

		// Add to call graph
		v.CallGraph.Calls = append(v.CallGraph.Calls, MethodCall{
			Caller: v.CurrentClass + "." + v.CurrentFunc,
			Callee: calledMethod,
		})

		// fmt.Printf("Found method call: %s -> %s\n", v.CurrentFunc, calledMethod)
	}
}

// EnterMethodDeclaration is called when entering a method declaration
func (v *JavaFunctionVisitor) EnterMethodDeclaration(ctx *java_parser.MethodDeclarationContext) {
	// Get method name directly from the identifier context
	var methodName string

	// The method name is in the identifier child
	if identifierCtx := ctx.Identifier(); identifierCtx != nil {
		methodName = identifierCtx.GetText()
	} else {
		fmt.Println("Could not find method name")
		return
	}

	// Prepend class name if present
	if v.CurrentClass != "" {
		methodName = v.CurrentClass + "." + methodName
	}

	startLine := ctx.GetStart().GetLine()
	endLine := ctx.GetStop().GetLine()

	// fmt.Printf("Found method: %s lines [%d-%d]\n", methodName,startLine,endLine)

	// Extract source code
	sourceCode := ""
	if startLine <= endLine && startLine <= len(v.SourceLines) {
		sourceLines := v.SourceLines[startLine-1 : min(endLine, len(v.SourceLines))]
		sourceCode = strings.Join(sourceLines, "\n")
	}

	// Add to function definitions
	v.Functions[v.CurrentFile+"."+methodName] = &FunctionDefinition{
		Name:       methodName,
		FilePath:   v.CurrentFile,
		StartLine:  startLine,
		EndLine:    endLine,
		SourceCode: sourceCode,
	}

	// Set current function info
	v.CurrentFunc = methodName
	v.CurrentStart = startLine
	v.InFunctionDef = true
}
func (v *JavaFunctionVisitor) EnterClassDeclaration(ctx *java_parser.ClassDeclarationContext) {
	// Extract class name directly from the identifier
	if identifier := ctx.Identifier(); identifier != nil {
		v.CurrentClass = identifier.GetText()
		// fmt.Printf("Found class: %s\n", v.CurrentClass)
	} else {
		fmt.Println("Could not find class name")
	}
}

// Add this method to reset class name when exiting a class
func (v *JavaFunctionVisitor) ExitClassDeclaration(ctx *java_parser.ClassDeclarationContext) {
	v.CurrentClass = ""
}

// findFuzzerSource locates the source code of the fuzzer by analyzing build scripts and source files
func findFuzzerSource(fuzzerPath, projectDir, projectName string, language string) (string, string, error) {
	fmt.Printf("Looking for source of fuzzer at %s\n", fuzzerPath)

	// Extract the fuzzer name from the path
	fuzzerName := filepath.Base(fuzzerPath)
	// Extract the working directory (everything before "fuzz-tooling")
	workDir := filepath.Dir(fuzzerPath)
	if strings.Contains(fuzzerPath, "fuzz-tooling") {
		parts := strings.Split(fuzzerPath, "fuzz-tooling")
		if len(parts) > 0 {
			workDir = parts[0]
			// Remove trailing slash if present
			workDir = strings.TrimSuffix(workDir, "/")
		}
	}

	fmt.Printf("Working directory: %s\n", workDir)

	// For Java fuzzers, first check for a direct match in the projects directory
	if language == "java" {
		projectsDir := filepath.Join(workDir, "fuzz-tooling/projects", projectName)
		javaFuzzerPath := filepath.Join(projectsDir, fuzzerName+".java")

		if _, err := os.Stat(javaFuzzerPath); err == nil {
			content, err := os.ReadFile(javaFuzzerPath)
			if err != nil {
				fmt.Printf("Error reading Java fuzzer file %s: %v\n", javaFuzzerPath, err)
			} else {
				fmt.Printf("Found Java fuzzer source: %s\n", javaFuzzerPath)
				return javaFuzzerPath, string(content), nil
			}
		}
	}

	// check if the oss project path contains fuzzer source

	// Extract the base name without _fuzzer suffix if present
	baseName := fuzzerName
	if strings.Contains(baseName, "_fuzzer") {
		baseName = strings.Replace(baseName, "_fuzzer", "", 1)
	}
	// Collect potential source files
	sourceFiles := make(map[string]string)
	var extensions []string

	if language == "c" {
		extensions = []string{".c", ".cc", ".cpp", ".h", ".hpp"}
	} else {
		extensions = []string{".java"}
	}
	// Search in fuzz-tooling/projects/{projectName}
	projectPath := filepath.Join(workDir, "fuzz-tooling/projects", projectName)
	if _, err := os.Stat(projectPath); err == nil {
		err := filepath.Walk(projectPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() {
				ext := strings.ToLower(filepath.Ext(path))
				for _, validExt := range extensions {
					if ext == validExt {
						// Check if the file name matches common fuzzer naming patterns
						fileName := filepath.Base(path)
						fileBase := strings.TrimSuffix(fileName, filepath.Ext(fileName))

						// If we find a likely match, return it immediately
						if isLikelySourceForFuzzer(fileBase, fuzzerName, baseName) {
							_, err := os.ReadFile(path)
							if err != nil {
								fmt.Printf("Error reading likely match file %s: %v\n", path, err)
							} else {
								fmt.Printf("Found likely match for fuzzer source: %s\n", path)
								return fmt.Errorf("found:%s", path) // Use error to break out of walk
							}
						}

						// Otherwise, add to potential source files
						content, err := os.ReadFile(path)
						if err != nil {
							fmt.Printf("Error reading source file %s: %v\n", path, err)
						} else { // Limit to ~50KB
							sourceFiles[path] = string(content)
						}
						break
					}
				}

			}
			return nil
		})

		// Check if we found a likely match
		if err != nil && strings.HasPrefix(err.Error(), "found:") {
			path := strings.TrimPrefix(err.Error(), "found:")
			content, _ := os.ReadFile(path)
			return path, stripLicenseText(string(content)), nil
		}
	} else {
		fmt.Printf("Error walking project path: %v\n", err)
	}

	// Look for fuzz directories
	fuzzDirs := []string{}
	// Look for any directory under the root path that contains "fuzz" in its name
	err := filepath.Walk(projectDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip very deep directories
		if strings.Count(path, string(os.PathSeparator))-strings.Count(projectDir, string(os.PathSeparator)) > 5 {
			return filepath.SkipDir
		}

		if info.IsDir() && strings.Contains(strings.ToLower(info.Name()), "fuzz") {
			if !contains(fuzzDirs, path) {
				fuzzDirs = append(fuzzDirs, path)
				fmt.Printf("Found fuzzer directory: %s\n", path)
			}
		}
		return nil
	})

	if err != nil {
		fmt.Printf("Error walking for fuzz directories: %v\n", err)
	}

	// If no fuzz directories found, look more broadly
	if len(fuzzDirs) == 0 {
		fuzzerRelatedDirs := []string{}

		err := filepath.Walk(projectDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			// Skip very deep directories
			if strings.Count(path, string(os.PathSeparator))-strings.Count(projectDir, string(os.PathSeparator)) > 7 {
				return filepath.SkipDir
			}

			if info.IsDir() {
				lowerDir := strings.ToLower(info.Name())
				if strings.Contains(lowerDir, "fuzz") || strings.Contains(lowerDir, "test") || strings.Contains(lowerDir, "harness") {
					fuzzerRelatedDirs = append(fuzzerRelatedDirs, path)
				}
			}

			// Also check for directories containing fuzzer-related files
			if info.IsDir() {
				files, err := os.ReadDir(path)
				if err == nil {
					hasFuzzerFiles := false
					for _, file := range files {
						if !file.IsDir() {
							lowerFile := strings.ToLower(file.Name())
							if strings.Contains(lowerFile, "fuzz") || strings.Contains(lowerFile, "_test") || strings.Contains(lowerFile, "test_") {
								hasFuzzerFiles = true
								break
							}
						}
					}

					if hasFuzzerFiles {
						fuzzerRelatedDirs = append(fuzzerRelatedDirs, path)
					}
				}
			}

			return nil
		})

		if err != nil {
			fmt.Printf("Error walking for fuzzer-related directories: %v\n", err)
		}

		// Add unique directories to our fuzzDirs list
		for _, dirPath := range fuzzerRelatedDirs {
			if !contains(fuzzDirs, dirPath) {
				fuzzDirs = append(fuzzDirs, dirPath)
			}
		}
	}

	fmt.Printf("Found %d potential fuzzer-related directories\n", len(fuzzDirs))

	// Search in fuzz directories
	for _, fuzzDir := range fuzzDirs {
		err := filepath.Walk(fuzzDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if !info.IsDir() {
				ext := strings.ToLower(filepath.Ext(path))
				for _, validExt := range extensions {
					if ext == validExt {
						// Check if the file name matches common fuzzer naming patterns
						fileName := filepath.Base(path)
						fileBase := strings.TrimSuffix(fileName, filepath.Ext(fileName))

						// If we find a likely match, return it immediately
						if isLikelySourceForFuzzer(fileBase, fuzzerName, baseName) {
							_, err := os.ReadFile(path)
							if err != nil {
								fmt.Printf("Error reading likely match file %s: %v\n", path, err)
							} else {
								fmt.Printf("Found likely match for fuzzer source: %s\n", path)
								return fmt.Errorf("found:%s", path) // Use error to break out of walk
							}
						}

						// Otherwise, add to potential source files
						content, err := os.ReadFile(path)
						if err != nil {
							fmt.Printf("Error reading source file %s: %v\n", path, err)
						} else { // Limit to ~50KB
							sourceFiles[path] = string(content)
						}
						break
					}
				}
			}
			return nil
		})

		// Check if we found a likely match
		if err != nil && strings.HasPrefix(err.Error(), "found:") {
			path := strings.TrimPrefix(err.Error(), "found:")
			content, _ := os.ReadFile(path)
			return path, stripLicenseText(string(content)), nil
		}
	}

	fmt.Printf("Collected %d potential source files\n", len(sourceFiles))

	// If we only found one source file, just return it directly
	if len(sourceFiles) == 1 {
		for path, content := range sourceFiles {
			fmt.Printf("Only one source file found, returning it: %s\n", path)
			return path, stripLicenseText(content), nil
		}
	}

	// If we have too many source files, filter them to the most likely candidates
	if len(sourceFiles) > 20 {
		filteredSourceFiles := make(map[string]string)

		// Prioritize files with names similar to the fuzzer
		for path, content := range sourceFiles {
			fileName := filepath.Base(path)
			if strings.Contains(fileName, fuzzerName) || strings.Contains(fileName, baseName) {
				filteredSourceFiles[path] = content
			}
		}

		// If we still have too few, add files that mention the fuzzer name in their content
		if len(filteredSourceFiles) < 5 {
			count := 0
			for path, content := range sourceFiles {
				if _, exists := filteredSourceFiles[path]; !exists {
					if strings.Contains(content, fuzzerName) || strings.Contains(content, baseName) {
						filteredSourceFiles[path] = content
						count++
						if count >= 10 {
							break
						}
					}
				}
			}
		}

		sourceFiles = filteredSourceFiles
		fmt.Printf("Filtered to %d most likely source files\n", len(sourceFiles))
	}

	// Fall back to the most likely file based on name
	for path, content := range sourceFiles {
		fileName := filepath.Base(path)
		fileBase := strings.TrimSuffix(fileName, filepath.Ext(fileName))

		if fileBase == fuzzerName || fileBase == baseName {
			fmt.Printf("Falling back to likely fuzzer source: %s\n", path)
			return path, stripLicenseText(content), nil
		}
	}

	// If we still haven't found anything, return an error
	return "", "// Could not find the source code for the fuzzer", fmt.Errorf("could not identify fuzzer source")
}

// isLikelySourceForFuzzer checks if a file is likely to be the source for a fuzzer
func isLikelySourceForFuzzer(fileBase, fuzzerName, baseName string) bool {
	// Direct matches
	if fileBase == fuzzerName || fileBase == baseName {
		return true
	}

	// Common fuzzer naming patterns
	if fileBase == fuzzerName+"_fuzzer" || fileBase == baseName+"_fuzzer" {
		return true
	}

	if fileBase == "fuzz_"+fuzzerName || fileBase == "fuzz_"+baseName {
		return true
	}

	if fileBase == fuzzerName+"_fuzz" || fileBase == baseName+"_fuzz" {
		return true
	}

	// For Java fuzzers
	if strings.HasSuffix(fileBase, "Fuzzer") && (strings.Contains(fileBase, fuzzerName) || strings.Contains(fileBase, baseName)) {
		return true
	}

	return false
}

// stripLicenseText removes license headers from source code
func stripLicenseText(content string) string {
	lines := strings.Split(content, "\n")

	// Skip license header if present
	startLine := 0
	inLicense := false

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Check for common license header patterns
		if i == 0 && (strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "//")) {
			inLicense = true
		}

		// End of license block
		if inLicense && (strings.HasSuffix(trimmed, "*/") || trimmed == "") {
			startLine = i + 1
			inLicense = false
		}

		// If we've gone past the license and found actual code, break
		if !inLicense && i > 10 && trimmed != "" && !strings.HasPrefix(trimmed, "//") && !strings.HasPrefix(trimmed, "/*") {
			break
		}
	}

	// If we skipped too many lines, reset to beginning
	if startLine > 20 {
		startLine = 0
	}

	return strings.Join(lines[startLine:], "\n")
}

// contains checks if a string slice contains a specific string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Update the main

func main() {
	// Parse command-line arguments
	projectDir := flag.String("dir", "", "Root directory to analyze")
	outputJson := flag.String("json", "analysis_results.json", "JSON output file path")
	fuzzerPath := flag.String("fuzzer", "", "Path to fuzzer executable file")
	numWorkers := flag.Int("workers", runtime.NumCPU(), "Number of parallel workers")
	targetFuncFlag := flag.String("target", "", "Target function to find paths to (optional)")
	maxDepth := flag.Int("depth", 10, "Maximum depth for path finding")
	projectName := flag.String("project", "", "Project name (for finding fuzzer source)")
	flag.Parse()

	// Ensure project source directory is provided
	if *projectDir == "" {
		fmt.Fprintf(os.Stderr, "Error: Project directory (-dir) is required\n")
		flag.Usage()
		os.Exit(1)
	}

	if *fuzzerPath == "" {
		fmt.Fprintf(os.Stderr, "Error: fuzzerPath (-fuzzer) is required\n")
		flag.Usage()
		os.Exit(1)
	}

	var language string
	var entryPoint string
	var fuzzerClassName string
	// STEP 1: Determine language based on fuzzer path

	// Extract fuzzer name
	fuzzerName := filepath.Base(*fuzzerPath)
	firstChar := ""
	if len(fuzzerName) > 0 {
		firstChar = string(fuzzerName[0])
	}

	if (firstChar != "" && firstChar == strings.ToUpper(firstChar)) ||
		strings.Contains(*fuzzerPath, "jazzer_agent_deploy.jar") {
		language = "java"
		fuzzerClassName = fuzzerName
		fmt.Printf("Detected Java fuzzer: %s\n", fuzzerClassName)

	} else {
		language = "c"
		fmt.Printf("Detected C/C++ fuzzer\n")
	}

	// Use project name from flag, or extract from fuzzer path if not provided
	projectNameValue := *projectName
	if projectNameValue == "" {
		// Try to extract project name from fuzzer path
		parts := strings.Split(*fuzzerPath, "/")
		for i, part := range parts {
			if part == "out" && i < len(parts)-1 {
				projectNameValue = parts[i+1]

				// Strip sanitizer suffix from project name (only one will match)
				if strings.HasSuffix(projectNameValue, "-address") {
					projectNameValue = strings.TrimSuffix(projectNameValue, "-address")
				} else if strings.HasSuffix(projectNameValue, "-memory") {
					projectNameValue = strings.TrimSuffix(projectNameValue, "-memory")
				} else if strings.HasSuffix(projectNameValue, "-undefined") {
					projectNameValue = strings.TrimSuffix(projectNameValue, "-undefined")
				}
				break
			}
		}
	}
	// STEP 2: Find fuzzer source code
	var fuzzerSourceCode string

	fmt.Printf("Looking for fuzzer source code (project: %s)...\n", projectNameValue)
	fuzzerSourcePath, fuzzerSourceCode, err := findFuzzerSource(*fuzzerPath, *projectDir, projectNameValue, language)
	if err != nil {
		fmt.Printf("Warning: %v\n", err)
	} else {
		fmt.Printf("Found fuzzer source code (%d bytes)\n", len(fuzzerSourceCode))
	}

	// Find all C/C++ and Java files to analyze
	var cFilesToAnalyze []string
	var javaFilesToAnalyze []string

	if language == "java" {
		entryPoint = fuzzerSourcePath + "." + "fuzzerTestOneInput"
		javaFilesToAnalyze = append(javaFilesToAnalyze, fuzzerSourcePath)

	} else {
		cFilesToAnalyze = append(cFilesToAnalyze, fuzzerSourcePath)
		entryPoint = fuzzerSourcePath + "." + "LLVMFuzzerTestOneInput"
	}

	if true {
		err = filepath.Walk(*projectDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			// Skip directories
			if info.IsDir() {
				return nil
			}

			// Skip files in certain directories
			if !shouldSkipFile(path) {
				// Check file extension
				ext := strings.ToLower(filepath.Ext(path))
				if ext == ".c" || ext == ".cpp" || ext == ".h" || ext == ".hpp" {
					if language == "c" {
						cFilesToAnalyze = append(cFilesToAnalyze, path)
						// fmt.Printf("Found %s\n", path)
					}
				} else if ext == ".java" {
					if language == "java" {
						javaFilesToAnalyze = append(javaFilesToAnalyze, path)
						// fmt.Printf("Found %s\n", path)
					}
				}
			}

			return nil
		})

		if err != nil {
			fmt.Printf("Error finding files: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Printf("Found %d C/C++ files and %d Java files to analyze\n",
		len(cFilesToAnalyze), len(javaFilesToAnalyze))

	// Initialize results
	results := AnalysisResults{
		Functions: make(map[string]*FunctionDefinition),
		CallGraph: &CallGraph{Calls: []MethodCall{}},
		Paths:     make(map[string][][]string),
	}

	startTime := time.Now()
	fmt.Printf("Starting analysis with %d workers...\n", *numWorkers)

	// Process files based on language
	if language == "c" {
		processCFiles(&results, cFilesToAnalyze, *numWorkers)
	} else {
		processJavaFiles(&results, javaFilesToAnalyze, *numWorkers)
	}
	// Find all paths from entry point
	if *targetFuncFlag != "" {
		fmt.Printf("Finding paths from %s to %s (max depth: %d)...\n",
			entryPoint, *targetFuncFlag, *maxDepth)
		paths := findAllPaths(&results, entryPoint, *targetFuncFlag, *maxDepth)
		results.Paths[*targetFuncFlag] = paths

		fmt.Printf("Found %d paths to target function\n", len(paths))

		// Print a few example paths
		if len(paths) > 0 {
			fmt.Println("Example paths:")
			for i := 0; i < min(3, len(paths)); i++ {
				fmt.Printf("  Path %d: %s\n", i+1, strings.Join(paths[i], " -> "))
			}
		}
	} else {
		// If no target specified, find reachable functions from entry point
		reachable := findReachableFunctions(&results, entryPoint, *maxDepth)
		fmt.Printf("Found %d reachable functions from entry point %s\n", len(reachable), entryPoint)

		if false {
			fmt.Println("\n=== REACHABLE FUNCTIONS FROM ENTRY POINT ===")

			// Group by file path for better readability
			filePathToFuncs := make(map[string][]string)
			for _, funcName := range reachable {
				if strings.Contains(funcName, ".") {
					parts := strings.Split(funcName, ".")
					filePath := strings.Join(parts[:len(parts)-1], ".")
					simpleName := parts[len(parts)-1]
					filePathToFuncs[filePath] = append(filePathToFuncs[filePath], simpleName)
				} else {
					filePathToFuncs[entryPoint] = append(filePathToFuncs[entryPoint], funcName)
				}
			}

			// Sort file paths for consistent output
			filePaths := make([]string, 0, len(filePathToFuncs))
			for filePath := range filePathToFuncs {
				filePaths = append(filePaths, filePath)
			}
			sort.Strings(filePaths)

			// Print functions grouped by file
			for _, filePath := range filePaths {
				funcs := filePathToFuncs[filePath]
				sort.Strings(funcs)
				// fmt.Printf("\n%s (%d functions):\n", filePath, len(funcs))
				for _, funcName := range funcs {
					// Find a sample path to this function for debugging
					paths := findAllPaths(&results, entryPoint, funcName, *maxDepth)
					pathInfo := "  (no path found)"
					if len(paths) > 0 {
						pathInfo = fmt.Sprintf("  (example path: %s)", strings.Join(paths[0], " -> "))
					}
					fmt.Printf("  - %s%s\n", funcName, pathInfo)
				}
			}

			fmt.Println("\n=== END REACHABLE FUNCTIONS ===\n")

		}
		// Store paths for each reachable function
		for _, func_ := range reachable {
			paths := findAllPaths(&results, entryPoint, func_, *maxDepth)
			if len(paths) > 0 {
				results.Paths[func_] = paths
			}
		}
	}

	// Write results to JSON file
	jsonData, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling JSON: %v\n", err)
		os.Exit(1)
	}

	err = os.WriteFile(*outputJson, jsonData, 0644)
	if err != nil {
		fmt.Printf("Error writing JSON file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Analysis completed in %v. Results written to %s\n",
		time.Since(startTime), *outputJson)
}

// processCFiles processes C/C++ files in parallel
func processCFiles(results *AnalysisResults, files []string, numWorkers int) {
	var wg sync.WaitGroup
	fileChan := make(chan string, len(files))
	resultChan := make(chan map[string]*FunctionDefinition, len(files))

	// Start worker goroutines
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for filePath := range fileChan {
				functions, err := processCFile(filePath)
				if err != nil {
					fmt.Printf("Error processing %s: %v\n", filePath, err)
					continue
				}
				resultChan <- functions
			}
		}()
	}

	// Send files to workers
	for _, file := range files {
		fileChan <- file
	}
	close(fileChan)

	// Wait for all workers to finish
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	for functions := range resultChan {
		for name, def := range functions {
			results.Functions[name] = def
		}
	}

	// Build call graph for C functions
	buildCCallGraph(results)
	// printCallGraph(results.CallGraph)
}

// processJavaFiles processes Java files in parallel
func processJavaFiles(results *AnalysisResults, files []string, numWorkers int) {
	var wg sync.WaitGroup
	fileChan := make(chan string, len(files))
	resultChan := make(chan struct {
		functions map[string]*FunctionDefinition
		calls     []MethodCall
	}, len(files))

	// Start worker goroutines
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for filePath := range fileChan {
				functions, calls, err := processJavaFile(filePath)
				if err != nil {
					fmt.Printf("Error processing %s: %v\n", filePath, err)
					continue
				}
				resultChan <- struct {
					functions map[string]*FunctionDefinition
					calls     []MethodCall
				}{functions, calls}
			}
		}()
	}

	// Send files to workers
	for _, file := range files {
		fileChan <- file
	}
	close(fileChan)

	// Wait for all workers to finish
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	for result := range resultChan {
		for name, def := range result.functions {
			results.Functions[name] = def
		}
		results.CallGraph.Calls = append(results.CallGraph.Calls, result.calls...)
	}
}

// processJavaFile processes a Java file and returns functions and method calls
func processJavaFile(filePath string) (map[string]*FunctionDefinition, []MethodCall, error) {
	// Read the file
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading file: %v", err)
	}

	sourceContent := string(content)
	sourceLines := strings.Split(sourceContent, "\n")

	// Create input stream for ANTLR
	input := antlr.NewInputStream(sourceContent)

	// Create lexer
	lexer := java_parser.NewJavaLexer(input)
	tokens := antlr.NewCommonTokenStream(lexer, 0)

	// Create parser
	parser := java_parser.NewJavaParser(tokens)

	// Create error listener
	errorListener := &ErrorListener{FilePath: filePath}
	parser.RemoveErrorListeners()
	parser.AddErrorListener(errorListener)

	// Parse the input
	tree := parser.CompilationUnit()

	// Create visitor
	visitor := NewJavaFunctionVisitor(filePath, sourceLines)

	// Walk the tree with our visitor
	antlr.ParseTreeWalkerDefault.Walk(visitor, tree)

	return visitor.Functions, visitor.CallGraph.Calls, nil
}

// stripComments removes comments from source code
func stripComments(source string) string {
	// For both C/C++ and Java
	// Remove block comments (/* ... */)
	blockCommentPattern := regexp.MustCompile(`/\*[\s\S]*?\*/`)
	result := blockCommentPattern.ReplaceAllString(source, "")

	// Remove line comments (// ...)
	lineCommentPattern := regexp.MustCompile(`//.*`)
	result = lineCommentPattern.ReplaceAllString(result, "")

	return result
}

// Cache for function body extraction
var functionBodyCache = make(map[string]string)

// extractFunctionBody extracts the body of a function, removing the function definition
func extractFunctionBody(fullCallerName string, sourceCode string) string {
	// Check if we have this in the cache
	if cachedBody, exists := functionBodyCache[fullCallerName]; exists {
		return cachedBody
	}

	// Extract the simple function name from the fully qualified name
	callerName := fullCallerName
	if strings.Contains(fullCallerName, ".") {
		parts := strings.Split(fullCallerName, ".")
		callerName = parts[len(parts)-1]
	}

	// Clean the source code by removing comments
	cleanedContent := stripComments(sourceCode)

	// First, find the function definition
	funcDefPattern := regexp.MustCompile(`(?:^|\n|\s)(?:static\s+|extern\s+)?(?:void|int|char|float|double|size_t|unsigned|long|short|struct|enum|\w+_t|\w+\s*\*)\s+` +
		regexp.QuoteMeta(callerName) + `\s*\(`)

	// Find all matches of the function definition
	defMatches := funcDefPattern.FindAllStringIndex(cleanedContent, -1)

	// Create a content string with the function definition removed
	contentWithoutDef := cleanedContent
	if len(defMatches) > 0 {
		// Find the opening brace after the function definition
		// defStart := defMatches[0][0]
		defEnd := defMatches[0][1]

		// Find the opening brace
		braceIndex := strings.Index(cleanedContent[defEnd:], "{")
		if braceIndex != -1 {
			// Remove everything up to and including the opening brace
			contentWithoutDef = cleanedContent[defEnd+braceIndex+1:]
		}
	}

	// Store in cache
	functionBodyCache[fullCallerName] = contentWithoutDef

	return contentWithoutDef
}

// buildCCallGraph builds a call graph for C functions by analyzing function bodies
func buildCCallGraph(results *AnalysisResults) {
	// Simple regex-based approach to find function calls
	// This is a simplified approach and might miss some calls or have false positives
	callPattern := regexp.MustCompile(`\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(`)

	// Use a map to track unique calls
	uniqueCalls := make(map[string]bool)

	// First, collect all function names that appear in the code
	allFunctionNames := make(map[string]bool)
	for funcName := range results.Functions {
		allFunctionNames[funcName] = true
	}

	// Scan all function bodies to find potential function calls
	for callerName, callerDef := range results.Functions {
		cleanedContent := stripComments(callerDef.SourceCode)
		// contentWithoutDef:=extractFunctionBody(callerName, cleanedContent)
		// matches := callPattern.FindAllStringSubmatch(contentWithoutDef, -1)
		matches := callPattern.FindAllStringSubmatch(cleanedContent, -1)

		for _, match := range matches {
			if len(match) > 1 {
				calleeName := match[1]
				// Skip if the callee is the same as the caller (recursive call)
				// Check both the simple name and the fully qualified name
				if calleeName == callerName || strings.HasSuffix(callerName, "."+calleeName) {
					continue
				}

				// Add to the set of all function names
				allFunctionNames[calleeName] = true
			}
		}
	}

	// Now build the call graph, including calls to functions not in our original set
	for callerName, callerDef := range results.Functions {

		cleanedContent := stripComments(callerDef.SourceCode)
		// contentWithoutDef:=extractFunctionBody(callerName, cleanedContent)
		// matches := callPattern.FindAllStringSubmatch(contentWithoutDef, -1)
		matches := callPattern.FindAllStringSubmatch(cleanedContent, -1)
		// Track unique callees for this caller
		callerCallees := make(map[string]bool)

		for _, match := range matches {
			if len(match) > 1 {
				calleeName := match[1]
				// Skip if the callee is the same as the caller (recursive call)
				// Check both the simple name and the fully qualified name
				if calleeName == callerName || strings.HasSuffix(callerName, "."+calleeName) {
					continue
				}

				// Skip common C keywords and constructs that might be mistaken for function calls
				if isCommonCKeyword(calleeName) {
					continue
				}

				// Create a unique key for this caller-callee pair
				callKey := callerName + " -> " + calleeName

				// fmt.Printf("callKey '%s'\n", callKey)

				// Only add if we haven't seen this call before
				if !callerCallees[calleeName] {
					callerCallees[calleeName] = true

					// Also check if we've seen this exact call before (for duplicate file paths)
					if !uniqueCalls[callKey] {
						uniqueCalls[callKey] = true
						// Add the call to our graph
						results.CallGraph.Calls = append(results.CallGraph.Calls, MethodCall{
							Caller: callerName,
							Callee: calleeName,
						})

					}
				}
			}
		}
	}

	fmt.Printf("Built call graph with %d calls\n", len(results.CallGraph.Calls))
}

// isCommonCKeyword returns true if the given string is a common C keyword or construct
// that might be mistaken for a function call
func isCommonCKeyword(s string) bool {
	keywords := map[string]bool{
		"if":      true,
		"while":   true,
		"for":     true,
		"switch":  true,
		"return":  true,
		"sizeof":  true,
		"typedef": true,
	}

	return keywords[s]
}

// findAllPaths finds all paths from source to target in the call graph
func findAllPaths(results *AnalysisResults, fullyQualifiedSource, target string, maxDepth int) [][]string {
	graph := results.CallGraph

	// fmt.Printf("\nDEBUG: Finding paths from '%s' to '%s' (max depth: %d)\n", fullyQualifiedSource, target, maxDepth)

	// Build a mapping from simple function names to their fully qualified versions
	simpleToQualified := make(map[string][]string)
	qualifiedToSimple := make(map[string]string)

	// First populate from Functions map
	for funcName := range results.Functions {
		if strings.Contains(funcName, ".") {
			parts := strings.Split(funcName, ".")
			simpleName := parts[len(parts)-1]
			simpleToQualified[simpleName] = append(simpleToQualified[simpleName], funcName)
			qualifiedToSimple[funcName] = simpleName

			// fmt.Printf("funcName: '%s' simpleName: '%s'\n", funcName, simpleName)

		} else {
			// This is already a simple name
			fmt.Printf("shoud never be there funcName: '%s'\n", funcName)
			if _, exists := simpleToQualified[funcName]; !exists {
				simpleToQualified[funcName] = []string{funcName}
			}
		}
	}

	// Check if source exists in the call graph
	sourceFound := false
	for _, call := range graph.Calls {
		if call.Caller == fullyQualifiedSource {
			sourceFound = true
			// fmt.Printf("DEBUG: Source '%s' found as caller in call graph\n", fullyQualifiedSource)
			break
		}
	}
	if !sourceFound {
		fmt.Printf("DEBUG: Warning - Source '%s' not found as caller in call graph\n", fullyQualifiedSource)

		// Check if simple name of source exists
		if strings.Contains(fullyQualifiedSource, ".") {
			simpleName := qualifiedToSimple[fullyQualifiedSource]
			for _, call := range graph.Calls {
				if strings.HasSuffix(call.Caller, "."+simpleName) {
					fmt.Printf("DEBUG: Found source as simple name in '%s'\n", call.Caller)
					break
				}
			}
		}
	}

	// Check if target exists in the call graph
	targetFound := false
	for _, call := range graph.Calls {
		if call.Callee == target {
			targetFound = true
			// fmt.Printf("DEBUG: Target '%s' found as callee in call graph\n", target)
			break
		}
		if call.Caller == target {
			targetFound = true
			// fmt.Printf("DEBUG: Target '%s' found as caller in call graph\n", target)
			break
		}
	}
	if !targetFound {
		fmt.Printf("DEBUG: Warning - Target '%s' not found in call graph\n", target)

		// Check if simple name of target exists
		if !strings.Contains(target, ".") {
			for _, call := range graph.Calls {
				if strings.HasSuffix(call.Caller, "."+target) || call.Callee == target {
					// fmt.Printf("DEBUG: Found target as simple name in call graph\n")
					break
				}
			}
		}
	}

	// Build adjacency list for faster lookup
	adjList := make(map[string][]string)
	for _, call := range graph.Calls {

		// Add connections from caller to fully qualified callees
		if !strings.Contains(call.Callee, ".") {
			for _, qualifiedCallee := range simpleToQualified[call.Callee] {
				if strings.Contains(qualifiedCallee, ".") && qualifiedCallee != call.Callee {
					adjList[call.Caller] = append(adjList[call.Caller], qualifiedCallee)
				}
			}
		} else {
			// Add direct connection
			adjList[call.Caller] = append(adjList[call.Caller], call.Callee)
		}

		// Add connections from simple caller name to callee
		// if strings.Contains(call.Caller, ".") {
		// 	simpleCaller := qualifiedToSimple[call.Caller]
		// 	adjList[simpleCaller] = append(adjList[simpleCaller], call.Callee)

		// 	// Also add connections from simple caller to qualified callees
		// 	if !strings.Contains(call.Callee, ".") {
		// 		for _, qualifiedCallee := range simpleToQualified[call.Callee] {
		// 			if strings.Contains(qualifiedCallee, ".") && qualifiedCallee != call.Callee {
		// 				adjList[simpleCaller] = append(adjList[simpleCaller], qualifiedCallee)
		// 			}
		// 		}
		// 	}
		// }
	}

	// Check if source exists in adjacency list
	if neighbors, exists := adjList[fullyQualifiedSource]; exists {
		// fmt.Printf("DEBUG: Source '%s' has %d neighbors in adjacency list\n",  fullyQualifiedSource, len(neighbors))
		if len(neighbors) > 0 {
			// fmt.Printf("DEBUG: First few neighbors: %v\n", neighbors[:min(5, len(neighbors))])
			// fmt.Printf("DEBUG: All neighbors: %v\n", neighbors)

		}
	} else {
		fmt.Printf("DEBUG: Warning - Source '%s' not found in adjacency list\n", fullyQualifiedSource)
	}

	// Determine target nodes (could be simple or qualified)
	targetNodes := []string{}
	if !strings.Contains(target, ".") {
		// If target is a simple name, add all qualified versions
		for _, qualifiedTarget := range simpleToQualified[target] {
			if qualifiedTarget != target {
				targetNodes = append(targetNodes, qualifiedTarget)
			}
		}
	} else {
		targetNodes = append(targetNodes, target)
	}

	// fmt.Printf("DEBUG: Target nodes: %v\n", targetNodes)

	var paths [][]string
	var dfs func(current string, path []string, depth int)

	visited := make(map[string]bool)

	dfs = func(current string, path []string, depth int) {
		// Base case: reached maximum depth
		if depth > maxDepth {
			return
		}

		// Base case: found target
		for _, targetNode := range targetNodes {
			if current == targetNode {
				pathCopy := make([]string, len(path))
				copy(pathCopy, path)
				paths = append(paths, pathCopy)
				return
			}
		}

		// Mark as visited to avoid cycles
		visited[current] = true

		// Explore neighbors
		for _, neighbor := range adjList[current] {
			if !visited[neighbor] {
				path = append(path, neighbor)
				dfs(neighbor, path, depth+1)
				path = path[:len(path)-1] // Backtrack
			}
		}

		// Unmark as visited when backtracking
		visited[current] = false
	}

	// Start DFS from fully qualified source
	dfs(fullyQualifiedSource, []string{fullyQualifiedSource}, 0)

	// // If source is fully qualified, also try with simple name
	// if strings.Contains(fullyQualifiedSource, ".") {
	// 	if simpleName, exists := qualifiedToSimple[fullyQualifiedSource]; exists {
	// 		if !visited[simpleName] { // Only if not already visited
	// 			fmt.Printf("DEBUG: Also trying with simple name '%s'\n", simpleName)
	// 			dfs(simpleName, []string{simpleName}, 0)
	// 		}
	// 	}
	// }

	// fmt.Printf("DEBUG: Found %d paths\n", len(paths))
	// 	// Print the paths for debugging
	// 	if len(paths) > 0 {
	// 		// fmt.Println("DEBUG: Paths found:")
	// 		for i, path := range paths {
	// 			// Limit to first 10 paths to avoid excessive output
	// 			if i >= 10 {
	// 				fmt.Printf("DEBUG: ... and %d more paths\n", len(paths)-10)
	// 				break
	// 			}
	// 			fmt.Printf("DEBUG: Path %d: %s\n", i+1, strings.Join(path, " -> "))
	// 		}
	// 	} else {
	// 		fmt.Println("DEBUG: No paths found")
	// 	}

	return paths
}

// printCallGraph prints all the calls in the call graph for debugging
func printCallGraph(graph *CallGraph) {
	fmt.Println("\n=== CALL GRAPH ===")

	// Count calls per caller for better formatting
	callerCounts := make(map[string]int)
	for _, call := range graph.Calls {
		callerCounts[call.Caller]++
	}

	// Group calls by caller for more readable output
	callerToCallees := make(map[string][]string)
	for _, call := range graph.Calls {
		callerToCallees[call.Caller] = append(callerToCallees[call.Caller], call.Callee)
	}

	// Print in sorted order
	callers := make([]string, 0, len(callerToCallees))
	for caller := range callerToCallees {
		callers = append(callers, caller)
	}
	sort.Strings(callers)

	for _, caller := range callers {
		callees := callerToCallees[caller]
		fmt.Printf("%s (%d calls):\n", caller, len(callees))

		// Sort callees for consistent output
		sort.Strings(callees)
		for _, callee := range callees {
			fmt.Printf("  → %s\n", callee)
		}
		fmt.Println()
	}

	fmt.Printf("Total: %d calls between %d functions\n", len(graph.Calls), len(callerToCallees))
	fmt.Println("===================\n")
}

// findReachableFunctions finds all functions reachable from the source
func findReachableFunctions(results *AnalysisResults, fullyQualifiedSource string, maxDepth int) []string {
	graph := results.CallGraph

	// fmt.Printf("\nDEBUG: Finding reachable functions from '%s' (max depth: %d)\n", fullyQualifiedSource, maxDepth)

	// Check if the entry point exists in the call graph
	entryPointExists := false
	for _, call := range graph.Calls {
		// fmt.Printf("call.Caller: %s\n", call.Caller)

		if call.Caller == fullyQualifiedSource {

			entryPointExists = true
			// fmt.Printf("DEBUG: Entry point '%s' found as caller in call graph\n", fullyQualifiedSource)
			break
		}
	}
	if !entryPointExists {
		fmt.Printf("DEBUG: Warning - Entry point '%s' not found as caller in call graph\n", fullyQualifiedSource)
	}

	// Build a mapping from simple function names to their fully qualified versions
	simpleToQualified := make(map[string][]string)
	for funcName := range results.Functions {
		parts := strings.Split(funcName, ".")
		if len(parts) > 1 {
			// This is a fully qualified name
			simpleName := parts[len(parts)-1]
			simpleToQualified[simpleName] = append(simpleToQualified[simpleName], funcName)
		} else {
			// This is already a simple name
			if _, exists := simpleToQualified[funcName]; !exists {
				simpleToQualified[funcName] = []string{funcName}
			}
		}
	}

	// Build adjacency list
	adjList := make(map[string][]string)
	for _, call := range graph.Calls {
		// Add the direct connection as it exists in the call graph
		adjList[call.Caller] = append(adjList[call.Caller], call.Callee)

		// Also add connections to all fully qualified versions of the callee
		for _, qualifiedCallee := range simpleToQualified[call.Callee] {
			if qualifiedCallee != call.Callee { // Avoid duplicates
				adjList[call.Caller] = append(adjList[call.Caller], qualifiedCallee)
			}
		}

		// Extract simple name of caller
		callerParts := strings.Split(call.Caller, ".")
		callerSimpleName := callerParts[len(callerParts)-1]

		// Add connections from simple caller name to callee
		// This helps when searching from a simple function name
		adjList[callerSimpleName] = append(adjList[callerSimpleName], call.Callee)

		// Also add connections from simple caller to qualified callees
		for _, qualifiedCallee := range simpleToQualified[call.Callee] {
			if qualifiedCallee != call.Callee {
				adjList[callerSimpleName] = append(adjList[callerSimpleName], qualifiedCallee)
			}
		}
	}

	// BFS to find reachable functions
	visited := make(map[string]bool)
	queue := []struct {
		node  string
		depth int
	}{{fullyQualifiedSource, 0}}

	// Also try with simple name if we provided a fully qualified name
	if strings.Contains(fullyQualifiedSource, ".") {
		parts := strings.Split(fullyQualifiedSource, ".")
		simpleName := parts[len(parts)-1]
		queue = append(queue, struct {
			node  string
			depth int
		}{simpleName, 0})
	}

	// Mark all starting points as visited
	for _, item := range queue {
		visited[item.node] = true
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if current.depth >= maxDepth {
			continue
		}

		for _, neighbor := range adjList[current.node] {
			if !visited[neighbor] {
				visited[neighbor] = true
				queue = append(queue, struct {
					node  string
					depth int
				}{neighbor, current.depth + 1})
			}
		}
	}

	// Convert visited map to slice
	var reachable []string
	for node := range visited {
		if node != fullyQualifiedSource {
			reachable = append(reachable, node)
		}
	}

	return reachable
}

// shouldSkipFile returns true if the file should be skipped
func shouldSkipFile(filePath string) bool {
	// List of directories to exclude
	excludeDirs := []string{
		"contrib",      // All contrib code (often has platform dependencies)
		"libpng_build", // Build artifacts
		"/version/",    // Test code
		"test/",        // Test code
		"tests/",       // Test code
		"/Test",        // Test code
		"/test",        // Test code
		"scripts",      // Build scripts
		"arm",          // ARM-specific code
		"intel",        // Intel-specific code
		"mips",         // MIPS-specific code
		"powerpc",      // PowerPC-specific code
		"loongarch",    // LoongArch-specific code
	}

	// Check if the file is in an excluded directory
	for _, dir := range excludeDirs {
		if strings.Contains(filePath, dir) {
			return true
		}
	}

	// Also skip files that are likely to cause issues
	problematicFiles := []string{
		"rpng2-win.c",
		"iowin32.c",
		"iowin32.h",
		"android-ndk.c",
		"linux-auxv.c",
	}

	for _, file := range problematicFiles {
		if strings.HasSuffix(filePath, file) {
			return true
		}
	}

	return false
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs" // Needed for filepath.WalkDir
	"log"
	"math"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"static-analysis/internal/parser/c"
	c_parser "static-analysis/internal/parser/c/grammar"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/antlr4-go/antlr/v4"
	"gopkg.in/yaml.v3"

	// "static-analysis/internal/parser/java"
	"static-analysis/internal/engine/models"
	"static-analysis/internal/joern"
	java_parser "static-analysis/internal/parser/java/grammar"
	"static-analysis/internal/simple"
)

// ---------------------------------------------------------------------------
// Ensure that only one goroutine initialises each temporary project directory.
// Key  = absolute path to the temp dir
// Value = *sync.Mutex protecting that directory
var tempDirLocks sync.Map // map[string]*sync.Mutex

func getTempDirLock(dir string) *sync.Mutex {
	// LoadOrStore returns the existing value if present, otherwise stores & returns the new one.
	mu, _ := tempDirLocks.LoadOrStore(dir, &sync.Mutex{})
	return mu.(*sync.Mutex)
}

// hasSourceFiles checks if a directory contains source code files (not just build scripts)
func hasSourceFiles(dir string) bool {
	sourceExtensions := map[string]bool{
		".c": true, ".cc": true, ".cpp": true, ".cxx": true, ".c++": true, // C/C++
		".h": true, ".hh": true, ".hpp": true, ".hxx": true, ".h++": true, // C/C++ headers
		".java": true, // Java
		".rs":   true, // Rust
		".go":   true, // Go
		".py":   true, // Python
	}

	foundSourceFile := false
	filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // Skip errors, continue walking
		}
		if !d.IsDir() {
			ext := strings.ToLower(filepath.Ext(path))
			if sourceExtensions[ext] {
				foundSourceFile = true
				return filepath.SkipAll // Found a source file, stop walking
			}
		}
		return nil
	})

	return foundSourceFile
}

// ---------------------------------------------------------------------------

// CFunctionVisitor for C/C++ files
type CFunctionVisitor struct {
	*c_parser.BaseCListener // Use pointer to BaseCListener
	Functions               map[string]*models.FunctionDefinition
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
		Functions:     make(map[string]*models.FunctionDefinition),
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

	v.Functions[v.CurrentFile+"."+v.CurrentFunc] = &models.FunctionDefinition{
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
	v.Functions[v.CurrentFile+"."+v.CurrentFunc] = &models.FunctionDefinition{
		Name:       v.CurrentFunc,
		FilePath:   v.CurrentFile,
		StartLine:  v.CurrentStart,
		EndLine:    endLine,
		SourceCode: sourceCode,
	}

	v.InFunctionDef = false
}

// processCFile processes a C/C++ file and returns the functions found
func processCFile(filePath string) (map[string]*models.FunctionDefinition, error) {
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

// JavaFunctionVisitor for Java files
type JavaFunctionVisitor struct {
	*java_parser.BaseJavaParserListener // Embed the base listener
	Functions                           map[string]*models.FunctionDefinition
	CurrentFile                         string
	SourceLines                         []string
	CurrentClass                        string
	CurrentFunc                         string
	CurrentStart                        int
	InFunctionDef                       bool
	CallGraph                           *models.CallGraph
}

func NewJavaFunctionVisitor(filePath string, sourceLines []string) *JavaFunctionVisitor {
	return &JavaFunctionVisitor{
		BaseJavaParserListener: &java_parser.BaseJavaParserListener{},
		Functions:              make(map[string]*models.FunctionDefinition),
		CurrentFile:            filePath,
		SourceLines:            sourceLines,
		CallGraph:              &models.CallGraph{Calls: []models.MethodCall{}},
	}
}

func (v *JavaFunctionVisitor) EnterMethodCall(ctx *java_parser.MethodCallContext) {
	if v.CurrentFunc == "" {
		return // Not inside a method
	}

	// Extract the called method name
	if identifierCtx := ctx.Identifier(); identifierCtx != nil {
		calledMethod := identifierCtx.GetText()

		//TODO: handle empty CurrentClass
		//TODO: handle repeated call edge

		// Add to call graph
		v.CallGraph.Calls = append(v.CallGraph.Calls, models.MethodCall{
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

	// // Prepend class name if present
	// if v.CurrentClass != "" {
	//     methodName = v.CurrentClass + "." + methodName
	// }

	startLine := ctx.GetStart().GetLine()
	endLine := ctx.GetStop().GetLine()

	// fmt.Printf("Found method: %s lines [%d-%d]\n", v.CurrentClass+"."+methodName,startLine,endLine)

	// Extract source code
	sourceCode := ""
	if startLine <= endLine && startLine <= len(v.SourceLines) {
		sourceLines := v.SourceLines[startLine-1 : min(endLine, len(v.SourceLines))]
		sourceCode = strings.Join(sourceLines, "\n")
	}

	// Add to function definitions
	v.Functions[v.CurrentFile+"."+methodName] = &models.FunctionDefinition{
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

// dirHasFuzzerEntry returns true if the directory (recursively, depth≤2)
// has a .java or C/C++ source file that references either
//   - fuzzerTestOneInput            (Java)
//   - LLVMFuzzerTestOneInput        (C/C++)
func dirHasFuzzerEntry(dir string) bool {
	targetFuncs := []string{"fuzzerTestOneInput", "LLVMFuzzerTestOneInput"}
	validExt := map[string]struct{}{
		".c": {}, ".cc": {}, ".cpp": {}, ".cxx": {}, ".java": {},
	}

	found := false
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			// Stop descending if we are more than two levels below the start dir
			if strings.Count(p, string(os.PathSeparator))-strings.Count(dir, string(os.PathSeparator)) > 2 {
				return filepath.SkipDir
			}
			return nil
		}
		if _, ok := validExt[strings.ToLower(filepath.Ext(p))]; !ok {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		for _, tf := range targetFuncs {
			if strings.Contains(string(data), tf) {
				found = true
				return filepath.SkipDir // early termination
			}
		}
		return nil
	})
	return found
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

	// Look for fuzz directories
	fuzzDirs := []string{}

	//--------------------------------------------------------------------
	// 1.  Look inside fuzz-tooling/projects/<proj>/pkgs for already
	//     unpacked “*_fuzzer/” directories **or** *_fuzzer.tar.gz archives
	//--------------------------------------------------------------------
	pkgsDir := filepath.Join(workDir, "fuzz-tooling/projects", projectName, "pkgs")
	if stat, err := os.Stat(pkgsDir); err == nil && stat.IsDir() {
		entries, _ := os.ReadDir(pkgsDir)
		for _, e := range entries {
			name := e.Name()
			abs := filepath.Join(pkgsDir, name)

			// (a) directory ending in “…fuzzer”
			if e.IsDir() && strings.Contains(strings.ToLower(name), "fuzzer") {
				if !contains(fuzzDirs, abs) {
					fuzzDirs = append(fuzzDirs, abs)
					fmt.Printf("Added extracted pkg dir: %s\n", abs)
				}
				continue
			}

			// (b) *_fuzzer.tar.gz archive
			if !e.IsDir() && strings.HasSuffix(name, ".tar.gz") &&
				strings.Contains(strings.ToLower(name), "fuzzer") {

				dirName := strings.TrimSuffix(name, ".tar.gz")
				extracted := filepath.Join(pkgsDir, dirName)

				// Already expanded once?  Just record the folder and continue.
				if dirExists(extracted) {
					fuzzDirs = append(fuzzDirs, extracted)
					fmt.Printf("Archive %s already extracted → %s (skipped)\n", abs, extracted)
					continue
				}

				cmd := exec.Command("tar", "-xzf", abs, "-C", pkgsDir, "--skip-old-files")
				if out, err := cmd.CombinedOutput(); err != nil {
					fmt.Printf("Error extracting %s: %v (%s)\n", abs, err, string(out))
				} else {
					fuzzDirs = append(fuzzDirs, extracted)
					fmt.Printf("Extracted %s to %s\n", abs, extracted)
				}
			}
		}
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
						// Read once
						data, err := os.ReadFile(path)
						if err != nil {
							fmt.Printf("Error reading source file %s: %v\n", path, err)
							break
						}

						text := string(data)
						// Ensure the canonical entry-point symbol is present
						if !(strings.Contains(text, "LLVMFuzzerTestOneInput") ||
							strings.Contains(text, "fuzzerTestOneInput")) {
							// Skip non-harness files
							break
						}

						// Check if the file name matches common fuzzer naming patterns
						fileName := filepath.Base(path)
						fileBase := strings.TrimSuffix(fileName, filepath.Ext(fileName))

						// If we find a likely match, return it immediately
						if isLikelySourceForFuzzer(fileBase, fuzzerName, baseName) {
							fmt.Printf("Found likely match for fuzzer source: %s\n", path)
							return fmt.Errorf("found:%s", path) // break out of Walk
						}

						// Otherwise, add to candidate set (≤50 KB)
						if len(data) < 50_000 {
							sourceFiles[path] = text
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

	// Look for any directory under the root path that contains "fuzz" in its name
	err := filepath.Walk(projectDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip very deep directories
		if strings.Count(path, string(os.PathSeparator))-strings.Count(projectDir, string(os.PathSeparator)) > 5 {
			return filepath.SkipDir
		}

		if info.IsDir() && (strings.Contains(strings.ToLower(info.Name()), "fuzz") || strings.Contains(strings.ToLower(info.Name()), "/test")) {
			if dirHasFuzzerEntry(path) && !contains(fuzzDirs, path) {
				fuzzDirs = append(fuzzDirs, path)
				fmt.Printf("Found fuzzer directory with entry point: %s\n", path)
				if len(fuzzDirs) >= 2 {
					return filepath.SkipDir
				}
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

	// ------------------------------------------------------------------
	// Fallback-selection: pick the most plausible source file
	// ------------------------------------------------------------------

	var bestPath string
	for path, content := range sourceFiles {
		fileName := filepath.Base(path)
		fileBase := strings.TrimSuffix(fileName, filepath.Ext(fileName))

		//for curl only
		// if fileName == "curl_fuzzer.cc" {
		// 	return path, stripLicenseText(content), nil
		// }

		hasEntry := strings.Contains(content, "LLVMFuzzerTestOneInput") ||
			strings.Contains(content, "fuzzerTestOneInput")

		// Prefer files that satisfy the heuristic *and* contain the entry point
		if hasEntry && (isLikelySourceForFuzzer(fileBase, fuzzerName, baseName) ||
			strings.Contains(fileBase, baseName) || strings.Contains(baseName, fileBase)) {
			fmt.Printf("Heuristic fallback pick for fuzzer source: %s\n", path)
			return path, stripLicenseText(content), nil
		}

		// Remember first source file with the entry point as last-resort
		if bestPath == "" && hasEntry && (strings.Contains(fileName, ".c") || strings.Contains(fileName, ".java")) {
			bestPath = path
		}

		// log.Printf("[Not Matched findFuzzerSource]: fuzzerName: %s path: %s\n", fuzzerName, path)
	}

	// Use the last-resort file only if it contains the entry point
	if bestPath != "" {
		fmt.Printf("Last-resort fallback to: %s\n", bestPath)
		return bestPath, stripLicenseText(sourceFiles[bestPath]), nil
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

func downloadAndVerifySource(taskDir string, source models.SourceDetail) error {

	outPath := path.Join(taskDir, fmt.Sprintf("%s.tar.gz", source.Type))

	maxRetries := 3
	for attempt := 1; attempt <= maxRetries; attempt++ {
		log.Printf("Downloading %s (attempt %d/%d): %s", source.Type, attempt, maxRetries, source.URL)

		// Create HTTP client with timeout
		client := &http.Client{
			Timeout: 5 * time.Minute,
		}

		// Make request
		resp, err := client.Get(source.URL)
		if err != nil {
			log.Printf("Download error: %v", err)
			if attempt == maxRetries {
				return fmt.Errorf("failed to download source after %d attempts: %v", maxRetries, err)
			}
			continue
		}
		defer resp.Body.Close()

		// Check response status
		if resp.StatusCode != http.StatusOK {
			log.Printf("Download failed with status %d", resp.StatusCode)
			if attempt == maxRetries {
				return fmt.Errorf("download failed with status %d after %d attempts", resp.StatusCode, maxRetries)
			}
			continue
		}

		// Check Content-Length
		expectedSize := resp.ContentLength
		// if expectedSize > 0 {
		//     log.Printf("Expected file size: %d bytes", expectedSize)
		//     // For repo.tar.gz, expect around 1.6MB
		//     if source.Type == models.SourceTypeRepo && expectedSize < 1_000_000 {
		//         log.Printf("Warning: repo.tar.gz seems too small (%d bytes)", expectedSize)
		//         if attempt == maxRetries {
		//             return fmt.Errorf("repo.tar.gz too small: %d bytes", expectedSize)
		//         }
		//         continue
		//     }
		// }

		// Create output file
		out, err := os.Create(outPath)
		if err != nil {
			return fmt.Errorf("failed to create output file: %v", err)
		}
		defer out.Close()

		// Calculate SHA256 while copying
		h := sha256.New()
		written, err := io.Copy(io.MultiWriter(out, h), resp.Body)
		if err != nil {
			log.Printf("Download incomplete: %v", err)
			os.Remove(outPath) // Clean up partial file
			if attempt == maxRetries {
				return fmt.Errorf("failed to save file after %d attempts: %v", maxRetries, err)
			}
			continue
		}

		// Verify downloaded size matches Content-Length
		if expectedSize > 0 && written != expectedSize {
			log.Printf("Size mismatch. Expected: %d, Got: %d", expectedSize, written)
			os.Remove(outPath) // Clean up incomplete file
			if attempt == maxRetries {
				return fmt.Errorf("incomplete download after %d attempts. Expected: %d, Got: %d",
					maxRetries, expectedSize, written)
			}
			continue
		}

		// Verify minimum size for repo.tar.gz
		// if source.Type == models.SourceTypeRepo && written < 1_000_000 {
		//     log.Printf("repo.tar.gz too small: %d bytes", written)
		//     os.Remove(outPath) // Clean up suspicious file
		//     if attempt == maxRetries {
		//         return fmt.Errorf("repo.tar.gz too small after %d attempts: %d bytes", maxRetries, written)
		//     }
		//     continue
		// }

		// Verify SHA256
		downloadedHash := hex.EncodeToString(h.Sum(nil))
		if downloadedHash != source.SHA256 {
			log.Printf("SHA256 mismatch for %s\nExpected: %s\nGot:      %s",
				source.Type, source.SHA256, downloadedHash)
			os.Remove(outPath) // Clean up invalid file
			if attempt == maxRetries {
				return fmt.Errorf("SHA256 mismatch for %s after %d attempts", source.Type, maxRetries)
			}
			continue
		}

		// Verify the file on disk
		if stat, err := os.Stat(outPath); err != nil {
			log.Printf("Failed to stat downloaded file: %v", err)
			if attempt == maxRetries {
				return fmt.Errorf("failed to verify file after download: %v", err)
			}
			continue
		} else {
			log.Printf("Successfully downloaded %s: %s (%d bytes)",
				source.Type, outPath, stat.Size())
		}

		return nil
	}

	return fmt.Errorf("failed to download and verify %s after %d attempts", source.Type, maxRetries)
}

func extractSources(taskDir string, is_delta bool) error {
	// Extract repo archive
	repoCmd := exec.Command("tar", "-xzf", path.Join(taskDir, "repo.tar.gz"))
	repoCmd.Dir = taskDir
	var repoOutput bytes.Buffer
	repoCmd.Stdout = &repoOutput
	repoCmd.Stderr = &repoOutput
	if err := repoCmd.Run(); err != nil {
		log.Printf("Repo extraction output:\n%s", repoOutput.String())
		return fmt.Errorf("failed to extract repo: %v", err)
	}

	//for debug only
	if os.Getenv("LOCAL_TEST") != "" {

		srcPath := "/crs-workdir/ccbe076c-eecf-40a5-81aa-eb2f99cc3ccd-20250609-182345/fuzz-tooling"
		dstPath := "/crs-workdir/ccbe076c-eecf-40a5-81aa-eb2f99cc3ccd/fuzz-tooling"

		if err := robustCopyDir(srcPath, dstPath); err != nil {
			log.Printf("[LOCAL_TEST SQLITE3] failed to copy fuzz-tooling files: %v", err)
		} else {
			log.Printf("[LOCAL_TEST SQLITE3] fuzz-tooling files copied to %s", dstPath)
		}

	} else {
		// Extract fuzz-tooling archive
		toolingCmd := exec.Command("tar", "-xzf", path.Join(taskDir, "fuzz-tooling.tar.gz"))
		toolingCmd.Dir = taskDir
		var toolingOutput bytes.Buffer
		toolingCmd.Stdout = &toolingOutput
		toolingCmd.Stderr = &toolingOutput
		if err := toolingCmd.Run(); err != nil {
			log.Printf("Tooling extraction output:\n%s", toolingOutput.String())
			return fmt.Errorf("failed to extract fuzz-tooling: %v", err)
		}
	}
	if is_delta {
		toolingCmd := exec.Command("tar", "-xzf", path.Join(taskDir, "diff.tar.gz"))
		toolingCmd.Dir = taskDir
		var toolingOutput bytes.Buffer
		toolingCmd.Stdout = &toolingOutput
		toolingCmd.Stderr = &toolingOutput
		if err := toolingCmd.Run(); err != nil {
			log.Printf("Tooling extraction output:\n%s", toolingOutput.String())
			return fmt.Errorf("failed to extract diff: %v", err)
		}
	}
	// Log directory contents for debugging
	// s.logDirectoryContents(taskDir)

	return nil
}

type ProjectConfig struct {
	Sanitizers []string `yaml:"sanitizers"`
	Language   string   `yaml:"language"`
	MainRepo   string   `yaml:"main_repo"`
}

func loadProjectConfig(projectYAMLPath string) (*ProjectConfig, error) {
	data, err := os.ReadFile(projectYAMLPath)
	if err != nil {
		return nil, err
	}
	var cfg ProjectConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// BuildFuzzerWithAFCImage builds the fuzzer harnesses for a project using helper.py
func BuildFuzzerWithAFCImage(taskDir, projectName, sanitizer, sanitizerProjectDir string) (string, error) {
	// Build the command to run helper.py for building fuzzers
	buildCmd := exec.Command("python3",
		filepath.Join(taskDir, "fuzz-tooling/infra/helper.py"),
		"build_fuzzers",
		"--clean",
		"--sanitizer", sanitizer,
		"--engine", "libfuzzer",
		projectName,
		sanitizerProjectDir,
	)

	var cmdOutput bytes.Buffer
	buildCmd.Stdout = &cmdOutput
	buildCmd.Stderr = &cmdOutput

	log.Printf("Building fuzzer harnesses for %s with sanitizer %s\nCommand: %v",
		projectName, sanitizer, buildCmd.Args)

	if err := buildCmd.Run(); err != nil {
		output := cmdOutput.String()
		lines := strings.Split(output, "\n")

		// Truncate output if it's very long
		if len(lines) > 30 {
			firstLines := lines[:10]
			lastLines := lines[len(lines)-20:]

			truncatedOutput := strings.Join(firstLines, "\n") +
				"\n\n[...TRUNCATED " + fmt.Sprintf("%d", len(lines)-30) + " LINES...]\n\n" +
				strings.Join(lastLines, "\n")

			output = truncatedOutput
		}

		return output, err
	}

	return cmdOutput.String(), nil
}

// Inside the loop: for _, sanitizer := range cfg.Sanitizers { ... }
func buildFuzzersDocker(taskDir, projectDir, sanitizerDir string, sanitizer string, language string, projectName string) error {

	sanitizerProjectDir := fmt.Sprintf("%s-%s", projectDir, sanitizer)

	// Create the directory if it doesn't exist
	if err := os.MkdirAll(sanitizerProjectDir, 0755); err != nil {
		return fmt.Errorf("failed to create sanitizer-specific project directory: %v", err)
	}

	// Copy the project files to the sanitizer-specific directory
	// Using cp command for simplicity and to handle hidden files
	cpCmd := exec.Command("cp", "-r", fmt.Sprintf("%s/.", projectDir), sanitizerProjectDir)
	log.Printf("Copying project files from %s to %s, language=%s", projectDir, sanitizerProjectDir, language)
	if output, err := cpCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to copy project files to sanitizer-specific directory: %v\nOutput: %s", err, string(output))
	}

	// Check for build.patch in the project's directory
	projectToolingDir := filepath.Join(taskDir, "fuzz-tooling", "projects", projectName)
	buildPatchPath := filepath.Join(projectToolingDir, "build.patch")

	// If build.patch exists, copy it to both the root and project subdirectory in the sanitizer directory
	if _, err := os.Stat(buildPatchPath); err == nil {
		log.Printf("Found build.patch at %s", buildPatchPath)

		// Copy to the root of the sanitizer directory
		rootPatchPath := filepath.Join(sanitizerProjectDir, "build.patch")
		cpRootPatchCmd := exec.Command("cp", buildPatchPath, rootPatchPath)
		if err := cpRootPatchCmd.Run(); err != nil {
			log.Printf("Warning: Failed to copy build.patch to root of sanitizer directory: %v", err)
		} else {
			log.Printf("Copied build.patch to %s", rootPatchPath)
		}

		// Also copy to the project subdirectory within the sanitizer directory
		// This handles cases where the patch needs to be in the project directory
		projectSubdir := filepath.Join(sanitizerProjectDir, projectName)
		if err := os.MkdirAll(projectSubdir, 0755); err != nil {
			log.Printf("Warning: Failed to create project subdirectory in sanitizer directory: %v", err)
		} else {
			projectPatchPath := filepath.Join(projectSubdir, "build.patch")
			cpProjectPatchCmd := exec.Command("cp", buildPatchPath, projectPatchPath)
			if err := cpProjectPatchCmd.Run(); err != nil {
				log.Printf("Warning: Failed to copy build.patch to project subdirectory: %v", err)
			} else {
				log.Printf("Copied build.patch to %s", projectPatchPath)
			}
		}
	}

	// docker_image := fmt.Sprintf("gcr.io/oss-fuzz/%s", projectName)
	docker_image := fmt.Sprintf("aixcc-afc/%s", projectName)

	workDir := filepath.Join(taskDir, "fuzz-tooling", "build", "work", fmt.Sprintf("%s-%s", projectName, sanitizer))
	cmdArgs := []string{
		"run",
		"--privileged",
		"--shm-size=8g",
		"--platform", "linux/amd64",
		"--rm",
		"-e", "FUZZING_ENGINE=libfuzzer",
		"-e", fmt.Sprintf("SANITIZER=%s", sanitizer),
		"-e", "ARCHITECTURE=x86_64",
		"-e", fmt.Sprintf("PROJECT_NAME=%s", projectName),
		"-e", "HELPER=True",
		"-e", fmt.Sprintf("FUZZING_LANGUAGE=%s", language),
		// Mount the original source directory
		"-v", fmt.Sprintf("%s:/src/%s", sanitizerProjectDir, projectName),
		// Mount your output directory (e.g., /out)
		"-v", fmt.Sprintf("%s:/out", sanitizerDir),
		// Mount a work directory
		"-v", fmt.Sprintf("%s:/work", workDir),
		// "-v", "/usr/include:/usr/include",
		"-t", docker_image,
	}

	docker_image_bear := fmt.Sprintf("%s-with-bear", projectName)

	cmdArgs0 := cmdArgs
	isBearUsed := false
	//for C/C++ projects only
	if strings.HasPrefix(language, "c") || strings.HasPrefix(language, "C") {
		isBearUsed = true

		//0. Create a temporary directory for the Dockerfile in the task directory to avoid permission issues
		tmpDir := filepath.Join(taskDir, ".docker-build-tmp")
		if err := os.MkdirAll(tmpDir, 0755); err != nil {
			return fmt.Errorf("failed to create temporary directory: %v", err)
		}
		defer os.RemoveAll(tmpDir) // Clean up when done
		log.Printf("Created temporary directory for Docker build: %s", tmpDir)

		//1. write a new Dockerfile with the following content
		dockerfileContent := fmt.Sprintf(`FROM %s

		RUN apt-get update && \
			apt-get install -y lsb-release wget software-properties-common gnupg && \
			wget https://apt.llvm.org/llvm.sh && \
			chmod +x llvm.sh && \
			./llvm.sh 17 && \
			rm llvm.sh && \
			rm -rf /var/lib/apt/lists/*

		RUN apt-get update && apt-get install -y bear cmake build-essential
		`, docker_image)

		// Write the Dockerfile
		dockerfilePath := filepath.Join(tmpDir, "Dockerfile")
		if err := os.WriteFile(dockerfilePath, []byte(dockerfileContent), 0644); err != nil {
			return fmt.Errorf("failed to write Dockerfile: %v", err)
		}
		log.Printf("Wrote Dockerfile to: %s", dockerfilePath)

		//2. build a new docker image {docker_image_bear}
		// Verify files exist before Docker build
		if files, err := os.ReadDir(tmpDir); err == nil {
			log.Printf("Files in %s:", tmpDir)
			for _, f := range files {
				log.Printf("  - %s", f.Name())
			}
		}

		buildCmd := exec.Command("docker", "build", "-t", docker_image_bear, ".")
		buildCmd.Dir = tmpDir
		log.Printf("Running docker build in directory: %s, command: %v", tmpDir, buildCmd.Args)
		if output, err := buildCmd.CombinedOutput(); err != nil {
			log.Printf("Docker build failed. Trying with explicit Dockerfile path...")
			// Try with explicit Dockerfile path
			buildCmd2 := exec.Command("docker", "build", "-f", dockerfilePath, "-t", docker_image_bear, tmpDir)
			if output2, err2 := buildCmd2.CombinedOutput(); err2 != nil {
				return fmt.Errorf("failed to build Docker image (both attempts): %v\nOutput1: %s\nOutput2: %s", err2, output, output2)
			}
			log.Printf("Successfully built Docker image with explicit path: %s", docker_image_bear)
		} else {
			log.Printf("Successfully built Docker image: %s", docker_image_bear)
		}

		//3. set cmdArgs
		cmdArgs = []string{
			"run",
			"--privileged",
			"--shm-size=8g",
			"--platform", "linux/amd64",
			"--rm",
			"-e", "FUZZING_ENGINE=libfuzzer",
			"-e", fmt.Sprintf("SANITIZER=%s", sanitizer),
			"-e", "ARCHITECTURE=x86_64",
			"-e", fmt.Sprintf("PROJECT_NAME=%s", projectName),
			"-e", "HELPER=True",
			"-e", fmt.Sprintf("FUZZING_LANGUAGE=%s", language),
			"-v", fmt.Sprintf("%s:/src/%s", sanitizerProjectDir, projectName), // source
			"-v", fmt.Sprintf("%s:/out", sanitizerDir), // /out
			"-v", fmt.Sprintf("%s:/work", workDir), // /work
			"-t", docker_image_bear,
			"bash", "-c", fmt.Sprintf(`set -eu
		cd /src/%[1]s
		
		# 1. Autotools-style build
		if [ -f configure ] || [ -f configure.ac ] || [ -f configure.in ]; then
		  [ -x configure ] || autoreconf -i
		  ./configure
		  bear -o /out/compile_commands.json compile

		# 2. CMake-based build
		elif [ -f CMakeLists.txt ]; then
		  mkdir -p build && cd build
		  cmake ..
		  bear -o /out/compile_commands.json compile
				  
		# 3. Plain makefile
		else
		  bear -o /out/compile_commands.json compile
		fi`, projectName),
		}
	}

	buildCmd := exec.Command("docker", cmdArgs...)

	// Optional: set the buildCmd working directory if you want
	// buildCmd.Dir = projectDir

	var buildOutput bytes.Buffer
	buildCmd.Stdout = &buildOutput
	buildCmd.Stderr = &buildOutput

	log.Printf("Running Docker build for sanitizer=%s, project=%s\nCommand: %v",
		sanitizer, projectName, buildCmd.Args)

	if err := buildCmd.Run(); err != nil {
		//try one more time
		//docker run --privileged --shm-size=2g --platform linux/amd64 --rm -i -e FUZZING_ENGINE=libfuzzer -e SANITIZER=address -e ARCHITECTURE=x86_64 -e PROJECT_NAME=freerdp -e HELPER=True -e FUZZING_LANGUAGE=c -v /crs-workdir/019771f9-5050-7160-b767-a88a490a106e/round-exhibition3-freerdp-address:/local-source-mount:ro -v /crs-workdir/019771f9-5050-7160-b767-a88a490a106e/fuzz-tooling/build/out/freerdp/:/out -v /crs-workdir/019771f9-5050-7160-b767-a88a490a106e/fuzz-tooling/build/work/freerdp:/work -t aixcc-afc/freerdp:latest /bin/bash -c
		//'pushd $SRC && rm -rf /src/FreeRDP && cp -r /local-source-mount /src/FreeRDP && popd && bear -o /out/compile_commands.json compile'
		cmdArgs1 := []string{
			"run",
			"--privileged",
			"--shm-size=8g",
			"--platform", "linux/amd64",
			"--rm",
			"-e", "FUZZING_ENGINE=libfuzzer",
			"-e", fmt.Sprintf("SANITIZER=%s", sanitizer),
			"-e", "ARCHITECTURE=x86_64",
			"-e", fmt.Sprintf("PROJECT_NAME=%s", projectName),
			"-e", "HELPER=True",
			"-e", fmt.Sprintf("FUZZING_LANGUAGE=%s", language),
			// Mount the original source directory
			"-v", fmt.Sprintf("%s:/local-source-mount:ro", sanitizerProjectDir),
			// Mount your output directory (e.g., /out)
			"-v", fmt.Sprintf("%s:/out", sanitizerDir),
			// Mount a work directory
			"-v", fmt.Sprintf("%s:/work", workDir),
			// "-v", "/usr/include:/usr/include",
			"-t", docker_image_bear,
			// "bear", "-o", "/out/compile_commands.json", "compile",
			"bash", "-c", fmt.Sprintf(
				"pushd $SRC && rm -rf /src/%s && cp -r /local-source-mount /src/%s && popd && "+
					"bear -o /out/compile_commands.json compile",
				projectName, projectName),
		}

		buildCmd1 := exec.Command("docker", cmdArgs1...)
		var buildOutput1 bytes.Buffer
		buildCmd1.Stdout = &buildOutput1
		buildCmd1.Stderr = &buildOutput1

		if err := buildCmd1.Run(); err == nil {
			log.Printf("Bear build successful!. cmdArgs1: %v\n", cmdArgs1)
			return nil
		}

		if isBearUsed {
			log.Printf("Bear failed. Build fuzzer output:\n%s", buildOutput.String())
		} else {
			log.Printf("Failed to build fuzzers with sanitizer=%s: %v\nOutput: %s",
				sanitizer, err, buildOutput.String())
			log.Printf("Docker command cmdArgs0: %v", cmdArgs0)
		}

		log.Printf("Try build fuzzers in the standard way with infra/helper.py ...\n")
		buildCmd0 := exec.Command("python3", "fuzz-tooling/infra/helper.py", "build_fuzzers", "--sanitizer", sanitizer, "--engine", "libfuzzer", projectName, sanitizerProjectDir)
		var buildOutput0 bytes.Buffer
		buildCmd0.Dir = taskDir

		buildCmd0.Stdout = &buildOutput0
		buildCmd0.Stderr = &buildOutput0
		if err := buildCmd0.Run(); err != nil {
			if isBearUsed {
				log.Printf("Both Bear and standard fuzzer build failed! fuzzer output:\n%s", buildOutput0.String())
				return fmt.Errorf("[BUG] Both Bear and standard fuzzer build failed. sanitizer=%s: %v\nOutput: %s",
					sanitizer, err, buildOutput0.String())
			} else {
				return fmt.Errorf("[BUG] The standard fuzzer build failed. sanitizer=%s: %v\nOutput: %s",
					sanitizer, err, buildOutput0.String())
			}
		} else {
			//copy all files in ourdir to sanitizerDir
			outDir := filepath.Join(taskDir, "fuzz-tooling", "build", "out", projectName)
			// Copy all files from workDir to sanitizerDir
			if err := CopyFilesFromDir(outDir, sanitizerDir); err != nil {
				log.Printf("Failed to copy files: %v", err)
				return err
			}

			log.Printf("Successfully copied all files from %s to %s", outDir, sanitizerDir)
		}

	}
	//TESTING ONLY
	if false {
		//TODO BuildFuzzerWithAFCImage
		buildOutput, err := BuildFuzzerWithAFCImage(taskDir, projectName, sanitizer, sanitizerProjectDir)
		if err != nil {
			log.Printf("BuildFuzzerWithAFCImage Failed to build fuzzers with sanitizer=%s: %v\nOutput: %s",
				sanitizer, err, buildOutput)
		} else {
			log.Printf("BuildFuzzerWithAFCImage Successfully built all fuzzers: %s", buildOutput)
		}
	}
	currentUser := os.Getuid()
	if currentUser != 0 {
		// After Docker completes, fix permissions on the output directory
		fixPermCmd := exec.Command("sudo", "chmod", "-R", "777", sanitizerDir)
		if err := fixPermCmd.Run(); err != nil {
			log.Printf("Warning: Failed to fix permissions on %s: %v", sanitizerDir, err)
		}

		// Also fix permissions on work directory
		fixWorkPermCmd := exec.Command("sudo", "chmod", "-R", "777", workDir)
		if err := fixWorkPermCmd.Run(); err != nil {
			log.Printf("Warning: Failed to fix permissions on %s: %v", workDir, err)
		}
	}
	// log.Printf("Build fuzzer output:\n%s", buildOutput.String())
	return nil
}

// CopyFilesFromDir copies all files from srcDir to dstDir
func CopyFilesFromDir(srcDir, dstDir string) error {
	// Ensure the destination directory exists
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	// Read the source directory
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return fmt.Errorf("failed to read source directory: %w", err)
	}

	// Copy each file
	for _, entry := range entries {
		// Skip directories
		if entry.IsDir() {
			continue
		}

		srcPath := filepath.Join(srcDir, entry.Name())
		dstPath := filepath.Join(dstDir, entry.Name())

		// Read source file
		srcFile, err := os.Open(srcPath)
		if err != nil {
			return fmt.Errorf("failed to open source file %s: %w", srcPath, err)
		}
		defer srcFile.Close()

		// Get file info for permissions
		srcInfo, err := srcFile.Stat()
		if err != nil {
			return fmt.Errorf("failed to stat source file %s: %w", srcPath, err)
		}

		// Create destination file
		dstFile, err := os.OpenFile(dstPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, srcInfo.Mode())
		if err != nil {
			return fmt.Errorf("failed to create destination file %s: %w", dstPath, err)
		}
		defer dstFile.Close()

		// Copy content
		if _, err := io.Copy(dstFile, srcFile); err != nil {
			return fmt.Errorf("failed to copy file content from %s to %s: %w", srcPath, dstPath, err)
		}
	}

	return nil
}

func findFuzzers(fuzzerDir string) ([]string, error) {
	entries, err := os.ReadDir(fuzzerDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read fuzzer directory: %v", err)
	}

	// List of known non-fuzzer executables to skip
	skipBinaries := map[string]bool{
		"jazzer_agent_deploy.jar":      true,
		"jazzer_driver":                true,
		"jazzer_driver_with_sanitizer": true,
		"jazzer_junit.jar":             true,
		"llvm-symbolizer":              true,
		"sancov":                       true, // coverage tool
		"clang":                        true,
		"clang++":                      true,
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
		return nil, fmt.Errorf("no fuzzers found in %s", fuzzerDir)
	}

	log.Printf("Found %d fuzzers in %s: %v", len(fuzzers), fuzzerDir, fuzzers)
	return fuzzers, nil
}

// Check if directory exists
func dirExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false // Directory doesn't exist
		}
		// If there's some other error (like permission denied),
		// we'll also return false to be safe
		return false
	}

	// Make sure it's a directory, not a file
	return info.IsDir()
}

// Helper function to check if a file exists (not a directory)
func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
		// Other errors like permission denied
		fmt.Printf("Warning: Error checking file %s: %v\n", path, err)
		return false
	}
	// Make sure it's a file, not a directory
	return !info.IsDir()
}

// findAllPathsParallel finds paths from all fuzzers to reachable functions in parallel
// with a maximum depth and timeout duration.
func findAllPathsParallel(results *models.AnalysisResults, javaFuzzerSourceFiles []string, maxDepth int, timeoutDuration time.Duration) {
	log.Printf("Starting parallel path finding with max depth %d and timeout %v", maxDepth, timeoutDuration)
	startTime := time.Now()

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeoutDuration)

	// Channel to collect paths from goroutines - use a large buffer
	pathsChan := make(chan struct {
		entryPoint string
		targetFunc string
		paths      [][]string
	}, 10000) // Large buffer to reduce blocking

	// Wait group to track when all goroutines are done
	var wg sync.WaitGroup

	// Track all entry points and functions to process
	var entryPoints []string
	var allReachableFunctions []string

	// First pass: collect all entry points and reachable functions
	log.Printf("Finding all reachable functions from entry points...")
	firstPassStart := time.Now()

	for _, fuzzerSourcePath := range javaFuzzerSourceFiles {
		entryPoint := fuzzerSourcePath + "." + "fuzzerTestOneInput"
		entryPoints = append(entryPoints, entryPoint)

		// Find reachable functions with a lower depth for speed
		reachable := findReachableFunctions(results, entryPoint, 3)
		log.Printf("Found %d reachable functions from entry point %s", len(reachable), entryPoint)

		for _, func_ := range reachable {
			// Avoid duplicates
			isDuplicate := false
			for _, existing := range allReachableFunctions {
				if existing == func_ {
					isDuplicate = true
					break
				}
			}
			if !isDuplicate {
				allReachableFunctions = append(allReachableFunctions, func_)
			}
		}
	}

	log.Printf("Found total of %d unique reachable functions from %d entry points in %v",
		len(allReachableFunctions), len(entryPoints), time.Since(firstPassStart))

	// Second pass: find paths for all functions in parallel with work queue
	funcQueue := make(chan struct {
		entryPoint string
		targetFunc string
	}, len(entryPoints)*len(allReachableFunctions))

	// Create workers to process the queue
	numPathWorkers := runtime.NumCPU() * 2 // Twice as many workers as CPUs
	for i := 0; i < numPathWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			jobCount := 0
			for {
				select {
				case <-ctx.Done():
					// Timeout or cancelation
					log.Printf("Worker %d stopping: context done (processed %d jobs)", workerID, jobCount)
					return
				default:
					// Try to get a job
					select {
					case <-ctx.Done():
						log.Printf("Worker %d stopping: context done in job fetch (processed %d jobs)", workerID, jobCount)
						return
					case job, ok := <-funcQueue:
						if !ok {
							// Channel closed, no more work
							log.Printf("Worker %d stopping: queue closed (processed %d jobs)", workerID, jobCount)
							return
						}

						// Use a per-job timeout to prevent individual jobs from taking too long
						jobCtx, jobCancel := context.WithTimeout(ctx, 30*time.Second)

						// Create a done channel for the job
						jobDone := make(chan [][]string, 1)

						// Start the path finding in a separate goroutine
						go func() {
							// This will stop if the job context is canceled
							paths := findAllPathsWithContext(jobCtx, results, job.entryPoint, job.targetFunc, maxDepth)
							select {
							case <-jobCtx.Done():
								// Don't try to send results if context is done
							case jobDone <- paths:
								// Successfully sent paths
							}
						}()

						// Wait for the job to complete or timeout
						var paths [][]string
						select {
						case <-jobCtx.Done():
							log.Printf("Worker %d: Job timed out (%s -> %s)",
								workerID, job.entryPoint, job.targetFunc)
						case paths = <-jobDone:
							// Successfully got paths
							if len(paths) > 0 {
								// Try to send results with timeout
								sendTimer := time.NewTimer(5 * time.Second)
								select {
								case <-ctx.Done():
									sendTimer.Stop()
									log.Printf("Worker %d: Main context done while sending results", workerID)
									return
								case pathsChan <- struct {
									entryPoint string
									targetFunc string
									paths      [][]string
								}{job.entryPoint, job.targetFunc, paths}:
									sendTimer.Stop()
									// Successfully sent
								case <-sendTimer.C:
									log.Printf("Worker %d: Timed out sending results, discarding", workerID)
								}
							}
						}

						// Clean up the job context
						jobCancel()
						jobCount++
					}
				}
			}
		}(i)
	}

	// Feed the work queue with all entry point + target function combinations
	log.Printf("Dispatching %d path finding tasks to %d workers...",
		len(entryPoints)*len(allReachableFunctions), numPathWorkers)

	// Start a goroutine to feed the queue
	queueFeederDone := make(chan struct{})
	go func() {
		defer close(queueFeederDone)
		jobCount := 0

		for _, entryPoint := range entryPoints {
			for _, targetFunc := range allReachableFunctions {
				select {
				case <-ctx.Done():
					log.Printf("Queue feeder stopping: context done after queueing %d jobs", jobCount)
					return
				default:
					// Try to send with timeout to avoid blocking forever
					sendTimer := time.NewTimer(5 * time.Second)
					select {
					case <-ctx.Done():
						sendTimer.Stop()
						log.Printf("Queue feeder stopping: context done in job send after queueing %d jobs", jobCount)
						return
					case funcQueue <- struct {
						entryPoint string
						targetFunc string
					}{entryPoint, targetFunc}:
						sendTimer.Stop()
						jobCount++
						if jobCount%1000 == 0 {
							log.Printf("Queued %d/%d jobs...",
								jobCount, len(entryPoints)*len(allReachableFunctions))
						}
					case <-sendTimer.C:
						log.Printf("Queue feeder: Timed out sending job to queue after %d jobs", jobCount)
						return
					}
				}
			}
		}
		log.Printf("All %d jobs successfully queued", jobCount)
	}()

	// Collect results with timeout protection
	resultCollector := make(chan struct {
		count int
		funcs int
	}, 1)

	// Start a goroutine to collect results
	go func() {
		pathCount := 0
		functionCount := 0
		functionSet := make(map[string]bool)

		for {
			select {
			case <-ctx.Done():
				// Context done, report what we have and exit
				resultCollector <- struct {
					count int
					funcs int
				}{pathCount, functionCount}
				return

			case pathResult, ok := <-pathsChan:
				if !ok {
					// Channel closed, we're done
					resultCollector <- struct {
						count int
						funcs int
					}{pathCount, functionCount}
					return
				}

				if _, exists := results.Paths[pathResult.targetFunc]; !exists {
					// First time we're adding paths for this function
					functionSet[pathResult.targetFunc] = true
					functionCount++
				}

				// Add all paths we found
				results.Paths[pathResult.targetFunc] = append(
					results.Paths[pathResult.targetFunc],
					pathResult.paths...,
				)
				pathCount += len(pathResult.paths)

				// Periodically log progress
				if pathCount%1000 == 0 {
					log.Printf("Progress: Found %d paths to %d functions so far (%v elapsed)",
						pathCount, functionCount, time.Since(startTime))
				}
			}
		}
	}()

	// Wait for the queue feeder to finish or timeout
	select {
	case <-ctx.Done():
		log.Printf("Main timeout occurred, stopping queue feeder")
	case <-queueFeederDone:
		log.Printf("Queue feeder completed successfully")
	}

	// Always close the function queue
	close(funcQueue)

	// Wait for workers to finish with a timeout
	workersDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(workersDone)
	}()

	// Use a separate timeout for waiting for workers
	workerWaitTimeout := 30 * time.Second
	select {
	case <-time.After(workerWaitTimeout):
		log.Printf("Workers didn't finish within %v after queue closure. Proceeding anyway.",
			workerWaitTimeout)
	case <-workersDone:
		log.Printf("All workers completed successfully")
	}

	// Close the results channel to signal end of results
	close(pathsChan)

	// Wait for result collector to report final counts
	var finalCounts struct {
		count int
		funcs int
	}

	// Use a timeout for getting final counts
	select {
	case finalCounts = <-resultCollector:
		log.Printf("Result collector reported final counts: %d paths, %d functions",
			finalCounts.count, finalCounts.funcs)
	case <-time.After(10 * time.Second):
		log.Printf("Timed out waiting for result collector, proceeding with deduplication")
	}

	// Always cancel the main context when we're done
	cancel()

	// Remove any duplicate paths if we found any
	log.Printf("Starting path deduplication...")
	dedupStart := time.Now()
	deduplicatedCount := dedupPathsInResults(results)
	log.Printf("Deduplication completed in %v, removed %d duplicates",
		time.Since(dedupStart), deduplicatedCount)

	// Final summary
	log.Printf("Path finding operation completed in %v", time.Since(startTime))
}

// findAllPathsWithContext is a context-aware version of findAllPaths
func findAllPathsWithContext(ctx context.Context, results *models.AnalysisResults, source, target string, maxDepth int) [][]string {
	// Check context frequently to allow cancellation
	if ctx.Err() != nil {
		return nil
	}

	// Use a channel to get results from the original function
	resultChan := make(chan [][]string, 1)

	go func() {
		paths := findAllPaths(results, source, target, maxDepth)
		select {
		case <-ctx.Done():
			// Context done, don't try to send results
		case resultChan <- paths:
			// Successfully sent results
		}
	}()

	// Wait for results or context cancellation
	select {
	case <-ctx.Done():
		return nil
	case paths := <-resultChan:
		return paths
	}
}

// dedupPathsInResults removes duplicate paths from results
func dedupPathsInResults(results *models.AnalysisResults) int {
	totalDuplicates := 0
	for targetFunc, pathsList := range results.Paths {
		if len(pathsList) <= 1 {
			continue // No need to deduplicate 0 or 1 paths
		}

		seen := make(map[string]bool)
		unique := make([][]string, 0, len(pathsList))

		for _, path := range pathsList {
			// Create a string key for the path
			key := strings.Join(path, "|")
			if !seen[key] {
				seen[key] = true
				unique = append(unique, path)
			}
		}

		duplicatesRemoved := len(pathsList) - len(unique)
		totalDuplicates += duplicatesRemoved

		if duplicatesRemoved > 0 {
			results.Paths[targetFunc] = unique
		}
	}
	return totalDuplicates
}

// Environment variables for API Keys (adjust as needed)
var (
	openAIKey    = os.Getenv("OPENAI_API_KEY")
	anthropicKey = os.Getenv("ANTHROPIC_API_KEY")
	geminiKey    = os.Getenv("GEMINI_API_KEY")
)

// LLMModels we want to compare; you can adapt these to real endpoints
var (
	CLAUDE_MODEL        = "claude-3-7-sonnet-latest"
	OPENAI_MODEL        = "chatgpt-4o-latest"
	GEMINI_MODEL_PRO_25 = "gemini-2.5-pro-preview-03-25"
	GEMINI_MODEL        = "gemini-2.0-flash-thinking-exp-01-21"
)

var (
	MODELS = []string{CLAUDE_MODEL, OPENAI_MODEL, GEMINI_MODEL_PRO_25, GEMINI_MODEL}
)

func invokeModel(modelName, prompt string) (string, error) {

	var client = &http.Client{}
	var body []byte
	var req *http.Request
	var resp *http.Response
	var err error

	var responseText string

	lowerName := strings.ToLower(modelName)

	// Prepare request body based on the model
	switch {
	case strings.HasPrefix(lowerName, "chatgpt-"):
		apiKey := os.Getenv("OPENAI_API_KEY")
		if apiKey == "" {
			return responseText, fmt.Errorf("Missing OPENAI_API_KEY")
		}
		payload := map[string]interface{}{
			"model": modelName,
			"messages": []map[string]string{
				{"role": "user", "content": prompt},
			},
		}
		body, _ = json.Marshal(payload)
		req, err = http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+apiKey)

	case strings.HasPrefix(lowerName, "claude-"):
		apiKey := os.Getenv("ANTHROPIC_API_KEY")
		if apiKey == "" {
			return responseText, fmt.Errorf("Missing ANTHROPIC_API_KEY")
		}
		payload := map[string]interface{}{
			"model":      modelName,
			"max_tokens": 1024,
			"messages": []map[string]string{
				{"role": "user", "content": prompt},
			},
		}
		body, _ = json.Marshal(payload)
		req, err = http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-api-key", apiKey)
		req.Header.Set("anthropic-version", "2023-06-01")

	case strings.HasPrefix(lowerName, "gemini-"):
		apiKey := os.Getenv("GEMINI_API_KEY")
		if apiKey == "" {
			return responseText, fmt.Errorf("Missing GEMINI_API_KEY")
		}
		url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", modelName, apiKey)
		payload := map[string]interface{}{
			"contents": []map[string]interface{}{
				{
					"parts": []map[string]string{
						{"text": prompt},
					},
				},
			},
		}
		body, _ = json.Marshal(payload)
		req, err = http.NewRequest("POST", url, bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")

	default:
		return responseText, fmt.Errorf("Unsupported model: " + modelName)
	}

	if err != nil {
		return responseText, fmt.Errorf("Failed to create request: " + err.Error())
	}

	// Retry logic (up to 3 times)
	var respBody []byte
	for attempt := 1; attempt <= 3; attempt++ {
		resp, err = client.Do(req)
		if err != nil {
			if attempt == 3 {
				return responseText, fmt.Errorf("HTTP request failed after 3 attempts: %v", err)
			}
			time.Sleep(time.Duration(attempt) * time.Second)
			continue
		}
		defer resp.Body.Close()

		respBody, err = io.ReadAll(resp.Body)
		if err != nil {
			if attempt == 3 {
				return responseText, fmt.Errorf("Failed to read response after 3 attempts: %v", err)
			}
			time.Sleep(time.Duration(attempt) * time.Second)
			continue
		}

		// Retry if HTTP status indicates rate limiting or server error
		if resp.StatusCode >= 500 || resp.StatusCode == 429 {
			if attempt == 3 {
				return responseText, fmt.Errorf("LLM returned error after 3 retries (status %d): %s", resp.StatusCode, string(respBody))
			}
			time.Sleep(time.Duration(attempt) * time.Second)
			continue
		}

		break // success
	}

	respStr := string(respBody)

	switch {
	case strings.HasPrefix(lowerName, "chatgpt-"):
		// Parse OpenAI response format
		var openaiResp struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		}
		if err := json.Unmarshal(respBody, &openaiResp); err == nil && len(openaiResp.Choices) > 0 {
			responseText = openaiResp.Choices[0].Message.Content
		} else {
			responseText = respStr // Fallback to raw response
		}

	case strings.HasPrefix(lowerName, "claude-"):
		// Parse Anthropic response format
		var anthropicResp struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		}
		if err := json.Unmarshal(respBody, &anthropicResp); err == nil && len(anthropicResp.Content) > 0 {
			responseText = anthropicResp.Content[0].Text
		} else {
			// Try alternate format
			var altAnthropicResp struct {
				Content struct {
					Text string `json:"text"`
				} `json:"content"`
			}
			if err := json.Unmarshal(respBody, &altAnthropicResp); err == nil {
				responseText = altAnthropicResp.Content.Text
			} else {
				responseText = respStr // Fallback to raw response
			}
		}
	case strings.HasPrefix(lowerName, "gemini-"):
		// Parse Gemini response format
		var geminiResp struct {
			Candidates []struct {
				Content struct {
					Parts []struct {
						Text string `json:"text"`
					} `json:"parts"`
				} `json:"content"`
			} `json:"candidates"`
		}
		if err := json.Unmarshal(respBody, &geminiResp); err == nil &&
			len(geminiResp.Candidates) > 0 &&
			len(geminiResp.Candidates[0].Content.Parts) > 0 {
			responseText = geminiResp.Candidates[0].Content.Parts[0].Text
		} else {
			responseText = respStr // Fallback to raw response
		}

	default:
		responseText = respStr
	}

	if strings.HasPrefix(modelName, "claude-") {
		fmt.Println("PROMPT:", prompt)
		fmt.Println("RESPONSE:", responseText)
	}

	return responseText, nil
}

func callLLM(modelToUse, prompt string) (string, error) {
	var modifiedScriptContent string

	modifiedScriptRaw, err := invokeModel(modelToUse, prompt)
	if err != nil {
		return modifiedScriptContent, fmt.Errorf("llm call failed: %w", err)
	}

	// 3.5 Extract the script from the LLM response (remove markdown code block)
	pattern := fmt.Sprintf("(?s)```(?i:(?:%s))?\\n(.*?)```", "bash|dockerfile")
	re := regexp.MustCompile(pattern) // (?s) makes . match newline
	matches := re.FindStringSubmatch(modifiedScriptRaw)

	if len(matches) > 1 {
		modifiedScriptContent = strings.TrimSpace(matches[1])
		log.Println("Successfully extracted modified script from LLM response.")
	} else {
		log.Printf("Warning: Could not extract bash code block from LLM response. Using raw response:\n%s", modifiedScriptRaw)
		// Fallback: Try to use the raw response, maybe removing introductory lines
		modifiedScriptContent = cleanLLMResponseFallback(modifiedScriptRaw)
		if modifiedScriptContent == "" {
			return modifiedScriptContent, fmt.Errorf("failed to extract usable script from LLM response")
		}
	}

	// log.Printf("======modifiedScriptContent=======\n%s", modifiedScriptContent)
	return modifiedScriptContent, nil
}

// findScriptRecursive searches for a scriptName recursively within startDir.
// Returns the full path if found, or an empty string otherwise.
func findScriptRecursive(startDir, scriptName string) (string, error) {
	var foundPath string
	err := filepath.WalkDir(startDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Skip paths we can't access, but log it
			log.Printf("Warning: Cannot access path %s during recursive search: %v", path, err)
			return filepath.SkipDir // Skip this directory if error occurs on entering it
		}
		// If we've already found the script, stop searching
		if foundPath != "" {
			return filepath.SkipDir // Stop searching further down this path
		}
		// Check if the current entry is the file we're looking for
		if !d.IsDir() && d.Name() == scriptName {
			foundPath = path
			log.Printf("Recursively found script at: %s", foundPath)
			return filepath.SkipAll // Stop the entire walk
		}
		return nil // Continue walking
	})

	if err != nil && err != filepath.SkipAll { // SkipAll is expected when found
		return "", fmt.Errorf("error walking directory %s to find %s: %w", startDir, scriptName, err)
	}

	return foundPath, nil
}

// stripBashComments removes all Bash comments (lines starting with #) from a script.
// It preserves shebang lines (#!/bin/bash) and only removes comments that start at the beginning of a line.
func stripBashComments(script string) string {
	lines := strings.Split(script, "\n")
	var result []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Preserve shebang line
		if strings.HasPrefix(trimmed, "#!") {
			result = append(result, line)
			continue
		}

		// Skip comment lines (lines that start with #)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Keep non-comment lines
		result = append(result, line)
	}

	return strings.Join(result, "\n")
}
func SetupClang17Dockerfile(modelName, dockerfilePath, projectDir, history string) error {
	log.Println("Setting up LLVM/Clang-17 Dockerfile environment...")
	var err error
	var modifiedScriptContent string
	dockerfileFullPath := filepath.Join(dockerfilePath, "Dockerfile")
	dockerfileBytes, err := os.ReadFile(dockerfileFullPath)
	if err != nil {
		return fmt.Errorf("failed to read build script %s: %w", dockerfileFullPath, err)
	}
	dockerfileContent := string(dockerfileBytes)
	dockerfileContent = stripBashComments(dockerfileContent)

	{

		prompt := fmt.Sprintf(`Modify the following Dockerfile to install clang-17 and the related LLVM 17 packages.
Set environment variables so that CC and CXX point to clang-17 and clang++-17.
You can use the following:
# Install LLVM/Clang 17
RUN wget https://apt.llvm.org/llvm.sh && \
    chmod +x llvm.sh && \
    ./llvm.sh 17 all

# Set clang-17 as the default CC/CXX via update-alternatives.
RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-17 100 && \
    update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-17 100

# Use clang-17 by default in all subsequent steps:
ENV CC=clang-17
ENV CXX=clang++-17


Do NOT add any explanations, comments, or introductory text. Only output the complete modified Dockerfile content enclosed in a single markdown code block.
		
Original Dockerfile (%s):
--- START DOCKERFILE ---
%s
--- END DOCKERFILE ---

%s`, dockerfileFullPath, dockerfileContent, history)

		modifiedScriptContent, err = callLLM(modelName, prompt)
		if err != nil {
			log.Printf("Error callLLM: %v", err.Error())
			return err
		} else {
			log.Printf("Saving modified Dockerfile to %s", dockerfileFullPath)
			err = os.WriteFile(dockerfileFullPath, []byte(modifiedScriptContent), 0755) // Make executable
			return err
		}
	}
	return nil
}

func SetupLLVMBitcodeEnvironment(modelName, dockerfilePath, projectDir, history string) (string, error) {
	log.Println("Setting up LLVM bitcode environment...")
	var err error
	var modifiedScriptContent string
	//1. find build.sh in dockerfilePath
	//if not exist, then search projectDir
	buildScriptName := "build.sh"
	buildScriptPath := filepath.Join(dockerfilePath, buildScriptName)

	if !fileExists(buildScriptPath) {
		log.Printf("build.sh not found in %s, checking %s", dockerfilePath, projectDir)
		buildScriptPath, err = findScriptRecursive(projectDir, buildScriptName)
		if err != nil {
			log.Printf("Error: %v", err)
			return modifiedScriptContent, err // Return error from walking
		}
		if buildScriptPath == "" {
			return modifiedScriptContent, fmt.Errorf("%s not found in %s, %s, or recursively within %s",
				buildScriptName, dockerfilePath, projectDir, projectDir)
		}
	}
	log.Printf("Found build script: %s", buildScriptPath)

	//2. check if build.sh contains oss-fuzz-build.sh
	//if yes, search oss-fuzz-build.sh in projectDir
	// Read the build script content
	buildScriptBytes, err := os.ReadFile(buildScriptPath)
	if err != nil {
		return modifiedScriptContent, fmt.Errorf("failed to read build script %s: %w", buildScriptPath, err)
	}
	buildScriptContent := string(buildScriptBytes)

	// 2. Check for oss-fuzz-build.sh redirection
	scriptToModifyPath := buildScriptPath
	ossFuzzBuildMarker := "oss-fuzz-build.sh"

	if strings.Contains(buildScriptContent, ossFuzzBuildMarker) {
		// Assume oss-fuzz-build.sh is in the project directory for simplicity
		// A more robust solution might parse the path from build.sh
		ossFuzzBuildPath := filepath.Join(projectDir, ossFuzzBuildMarker)
		if !fileExists(ossFuzzBuildPath) {
			log.Printf("%s not found directly in %s, searching recursively...", ossFuzzBuildMarker, projectDir)
			// Search recursively under projectDir
			ossFuzzBuildPath, err = findScriptRecursive(projectDir, ossFuzzBuildMarker)
			if err != nil {
				// Don't fail the whole process, just warn and modify build.sh
				log.Printf("Warning: Error searching for %s recursively: %v. Modifying build.sh directly.", ossFuzzBuildMarker, err)
			}
		}
		// Check if we found it (either directly or recursively)
		if ossFuzzBuildPath != "" && fileExists(ossFuzzBuildPath) {
			log.Printf("Found redirection to %s, will modify that script instead.", ossFuzzBuildPath)
			scriptToModifyPath = ossFuzzBuildPath
		} else {
			log.Printf("Warning: %s mentioned in build.sh, but not found directly or recursively within %s. Modifying build.sh directly.", ossFuzzBuildMarker, projectDir)
		}
	}

	backupPath := scriptToModifyPath + ".bak"

	{
		// Check if the backup file exists
		if _, err := os.Stat(backupPath); err == nil {
			// Backup file exists, copy its content to the original file
			backupContent, err := os.ReadFile(backupPath)
			if err != nil {
				log.Printf("Error reading backup file: %v", err)
				return modifiedScriptContent, fmt.Errorf("failed to read backup file: %v", err)
			}

			err = os.WriteFile(scriptToModifyPath, backupContent, 0644)
			if err != nil {
				log.Printf("Error writing to original file: %v", err)
				return modifiedScriptContent, fmt.Errorf("failed to write to original file: %v", err)
			}

			log.Printf("Successfully restored content from backup to %s", scriptToModifyPath)
		} else if os.IsNotExist(err) {
			log.Printf("No backup file found at %s", backupPath)
		} else {
			log.Printf("Error checking for backup file: %v", err)
			return modifiedScriptContent, fmt.Errorf("error checking for backup file: %v", err)
		}
	}

	ossFuzzBytes, err := os.ReadFile(scriptToModifyPath)
	if err != nil {
		return modifiedScriptContent, fmt.Errorf("failed to read %s: %w", scriptToModifyPath, err)
	}
	scriptToModifyContent := string(ossFuzzBytes)

	scriptToModifyContent = stripBashComments(scriptToModifyContent)

	log.Printf("Asking LLM to modify script: %s", scriptToModifyPath)
	//3. ask AI model to modify build.sh to emit LLVM bitcode files
	// if oss-fuzz-build.sh exist, modify oss-fuzz-build.sh instead
	// note: make sure to use llvm-17.0.8
	// callLLM(modelName, prompt string)

	//Ensure that necessary flags like '-flto', '-femit-llvm', or equivalent build system options are added for C/C++ projects.
	//The goal is to produce bitcode suitable for static analysis.

	// Please use LLVM/Clang-17 to generate bitcode:
	// CC=clang-17
	// CXX=clang++-17
	prompt := fmt.Sprintf(`Modify the following build script to generate LLVM bitcode files (.bc) alongside the regular build artifacts.
Make sure your modified script will work successfully, e.g., avoid errors such as clang: error: -emit-llvm cannot be used when linking, and configure: error: C compiler cannot create executables.
Do NOT add any explanations, comments, or introductory text. Only output the complete modified script content enclosed in a single bash markdown code block.

Original Script:
--- START SCRIPT ---
%s
--- END SCRIPT ---

%s
`, scriptToModifyContent, history)

	modifiedScriptContent, err = callLLM(modelName, prompt)

	//4. save rewrite build.sh or oss-fuzz-build.sh
	if err != nil {
		fmt.Printf("Error callLLM: %v", err.Error())
		return modifiedScriptContent, err
	} else {
		if !fileExists(backupPath) {
			log.Printf("Backing up original script to %s", backupPath)
			if err := os.Rename(scriptToModifyPath, backupPath); err != nil {
				// If rename fails (e.g., cross-device link), try copy+delete
				log.Printf("Rename failed (%v), trying copy+delete for backup", err)
				if errCopy := copyFile(scriptToModifyPath, backupPath); errCopy != nil {
					log.Printf("Warning: Failed to create backup copy %s: %v", backupPath, errCopy)
					// Proceed without backup? Or return error? Decided to proceed.
				} else {
					if errDel := os.Remove(scriptToModifyPath); errDel != nil {
						log.Printf("Warning: Failed to remove original script after backup copy: %v", errDel)
					}
				}
			}
		}
		// log.Printf("Saving modified script to %s", scriptToModifyPath)
		err = os.WriteFile(scriptToModifyPath, []byte(modifiedScriptContent), 0755) // Make executable
		if err != nil {
			// Attempt to restore backup if write fails
			log.Printf("Failed to write modified script: %v. Attempting to restore backup...", err)
			if errRestore := os.Rename(backupPath, scriptToModifyPath); errRestore != nil {
				log.Printf("CRITICAL: Failed to restore backup %s: %v", backupPath, errRestore)
			}
			return modifiedScriptContent, fmt.Errorf("failed to write modified script %s: %w", scriptToModifyPath, err)
		}

		log.Printf("Successfully modified and saved build script: %s", scriptToModifyPath)
	}
	return modifiedScriptContent, nil
	//5. later, the bc files will be analyzed by wpa.
	//eg.. wpa -ander -dump-callgraph libpng_read_fuzzer.ll

}

// copyFile copies a file from src to dst.
func copyFile(src, dst string) error {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()

	if _, err := io.Copy(destination, source); err != nil {
		return err
	}
	// Preserve permissions
	return os.Chmod(dst, sourceFileStat.Mode())
}

// cleanLLMResponseFallback tries to remove common introductory phrases.
func cleanLLMResponseFallback(rawResponse string) string {
	lines := strings.Split(rawResponse, "\n")
	cleanedLines := []string{}
	started := false
	shebangFound := false

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if strings.HasPrefix(trimmedLine, "#!/") {
			shebangFound = true
			started = true
		}
		// Skip common introductory phrases if we haven't found the shebang yet
		if !started && (strings.HasPrefix(trimmedLine, "Here is the modified script") ||
			strings.HasPrefix(trimmedLine, "Okay, here's the modified") ||
			trimmedLine == "") {
			continue
		}
		started = true // Start collecting lines once we pass the intro
		cleanedLines = append(cleanedLines, line)
	}

	// If no shebang was found, the fallback might be risky, but return it anyway
	if !shebangFound {
		log.Println("Warning: Fallback cleaning did not find shebang. Using potentially incomplete response.")
	}

	return strings.Join(cleanedLines, "\n")
}

// PullAFCDockerImage runs the helper.py script to build and pull Docker images for the project
func PullAFCDockerImage(taskDir string, projectName string) (string, error) {

	// Build the command to run helper.py
	helperCmd := exec.Command("python3",
		filepath.Join(taskDir, "fuzz-tooling/infra/helper.py"),
		"build_image",
		"--pull",
		projectName,
	)

	var cmdOutput bytes.Buffer
	helperCmd.Stdout = &cmdOutput
	helperCmd.Stderr = &cmdOutput

	log.Printf("Building and pulling Docker images for %s\nCommand: %v", projectName, helperCmd.Args)

	if err := helperCmd.Run(); err != nil {
		output := cmdOutput.String()
		lines := strings.Split(output, "\n")

		// Truncate output if it's very long
		if len(lines) > 30 {
			firstLines := lines[:10]
			lastLines := lines[len(lines)-20:]

			truncatedOutput := strings.Join(firstLines, "\n") +
				"\n\n[...TRUNCATED " + fmt.Sprintf("%d", len(lines)-30) + " LINES...]\n\n" +
				strings.Join(lastLines, "\n")

			output = truncatedOutput
		}

		return output, err
	}

	dstImage := fmt.Sprintf("aixcc-afc/%s", projectName)
	// Check if dstImage already exists
	checkDstCmd := exec.Command("docker", "image", "inspect", dstImage)
	if err := checkDstCmd.Run(); err != nil {

		// Tag the image as aixcc-afc/<projectName>
		srcImage := fmt.Sprintf("gcr.io/oss-fuzz/%s", projectName)

		// Check if srcImage exists
		checkSrcCmd := exec.Command("docker", "image", "inspect", srcImage)
		if err := checkSrcCmd.Run(); err != nil {
			log.Printf("Source image %s does not exist, cannot tag.", srcImage)
			return cmdOutput.String() + "\nSource image does not exist.", fmt.Errorf("source image %s does not exist", srcImage)
		}

		tagCmd := exec.Command("docker", "tag", srcImage, dstImage)
		var tagOutput bytes.Buffer
		tagCmd.Stdout = &tagOutput
		tagCmd.Stderr = &tagOutput
		if err := tagCmd.Run(); err != nil {
			log.Printf("Failed to tag image: %s -> %s\nOutput: %s", srcImage, dstImage, tagOutput.String())
			return cmdOutput.String() + "\n" + tagOutput.String(), err
		}
		log.Printf("Tagged image as %s", dstImage)
	}
	return cmdOutput.String(), nil
}
func BuildDockerImage(dockerfilePath, dockerfileFullPath, projectName string) (string, error) {

	// build docker image
	buildCmd := exec.Command("docker",
		"build",
		"--no-cache",
		"-t", "aixcc-afc/"+projectName,
		"--file", dockerfileFullPath,
		dockerfilePath,
	)
	var buildOutput bytes.Buffer
	buildCmd.Stdout = &buildOutput
	buildCmd.Stderr = &buildOutput

	log.Printf("Building docker image aixcc-afc/%s\nCommand: %v", projectName, buildCmd.Args)
	var dockerOutput string
	if err := buildCmd.Run(); err != nil {

		dockerOutput = buildOutput.String()
		lines := strings.Split(dockerOutput, "\n")

		// Truncate output if it's very long
		if len(lines) > 30 { // if we have more than 30 lines (10 first + 20 last)
			firstLines := lines[:10]
			lastLines := lines[len(lines)-20:]

			// Join them with a notice about truncation
			truncatedOutput := strings.Join(firstLines, "\n") +
				"\n\n[...TRUNCATED " + fmt.Sprintf("%d", len(lines)-30) + " LINES...]\n\n" +
				strings.Join(lastLines, "\n")

			dockerOutput = truncatedOutput
		}

		return dockerOutput, err
	}

	return dockerOutput, nil

}
func BuildDockerImageWithRetry(dockerfilePath, dockerfileFullPath, projectName string, projectDir string) (string, error) {
	history := ""
	maxAttempts := 5
	for _, modelName := range MODELS {
		log.Printf("Trying model: %s", modelName)
		for attempt := 1; attempt <= maxAttempts; attempt++ {
			log.Printf("Attempt %d/%d: Setting up Clang 17 Dockerfile", attempt, maxAttempts)
			err := SetupClang17Dockerfile(modelName, dockerfilePath, projectDir, history)
			if err != nil {
				break
			}

			dockerOutput, err := BuildDockerImage(dockerfilePath, dockerfileFullPath, projectName)
			if err != nil {

				formattedOutput := fmt.Sprintf("Docker build output:\n%s", dockerOutput)
				history += fmt.Sprintf("Attempt %d failed:\n%s\n", attempt, formattedOutput)

				log.Printf("Attempt %d failed: %v", attempt, err)

				if attempt == maxAttempts {
					return dockerOutput, fmt.Errorf("failed to build Docker image after %d attempts: %v",
						maxAttempts, err)
				}

				// Wait before retrying
				time.Sleep(2 * time.Second)
				continue
			}

			// If we reach here, the build succeeded
			log.Printf("Docker build succeeded on attempt %d", attempt)
			return dockerOutput, nil
		}
	}
	// Should never reach here, but just in case
	return "", fmt.Errorf("failed to build Docker image after %d attempts", maxAttempts)
}

func BuildFuzzersWithRetry(taskDir, dockerfilePath, projectDir, sanitizerDir, sanitizer, language string, projectName string) error {
	history := ""
	maxAttempts := 5

	for _, modelName := range MODELS {
		log.Printf("Trying model: %s", modelName)
		for attempt := 1; attempt <= maxAttempts; attempt++ {
			log.Printf("Attempt %d/%d: Building fuzzers with --sanitizer=%s", attempt, maxAttempts, sanitizer)

			// Setup environment before each attempt, passing in history from previous failures
			modifiedScriptContent, err := SetupLLVMBitcodeEnvironment(modelName, dockerfilePath, projectDir, history)

			if err != nil {
				break
			}
			history += fmt.Sprintf("--- START MODIFIED SCRIPT (Attempt %d)---\n%s\n--- END MODIFIED SCRIPT ---\n\n", attempt, modifiedScriptContent)

			log.Printf("Building fuzzers with --sanitizer=%s", sanitizer)

			var errorOutput string
			if err := buildFuzzersDocker(taskDir, projectDir, sanitizerDir, sanitizer, language, projectName); err != nil {
				errorOutput = err.Error()
				lines := strings.Split(errorOutput, "\n")

				// Truncate error output if it's very long
				if len(lines) > 30 { // if we have more than 30 lines (10 first + 20 last)
					firstLines := lines[:10]
					lastLines := lines[len(lines)-20:]

					// Join them with a notice about truncation
					truncatedOutput := strings.Join(firstLines, "\n") +
						"\n\n[...TRUNCATED " + fmt.Sprintf("%d", len(lines)-30) + " LINES...]\n\n" +
						strings.Join(lastLines, "\n")

					errorOutput = truncatedOutput
				}

				log.Printf("Attempt %d failed: Error building fuzzers for sanitizer %s: %v",
					attempt, sanitizer, err)

				history += fmt.Sprintf("Attempt %d failed:\n%s\n", attempt, errorOutput)

				if attempt == maxAttempts {
					return fmt.Errorf("failed to build fuzzers with sanitizer %s after %d attempts: %v",
						sanitizer, maxAttempts, err)
				}

				// Wait before retrying
				time.Sleep(2 * time.Second)
				continue
			} else {

				// Check if bitcode files are generated
				bitcodeFiles, err := filepath.Glob(filepath.Join(taskDir, "**", "*.bc"))
				if err != nil {
					log.Printf("Error searching for bitcode files: %v", err)
					history += fmt.Sprintf("Attempt %d failed: Error searching for bitcode files: %v\n", attempt, err)
					continue
				}

				if len(bitcodeFiles) == 0 {
					history += fmt.Sprintf("Attempt %d failed: Bitcode files are not generated, please try a different approach\n", attempt)
					log.Printf("Attempt %d failed: Bitcode files are not generated", attempt)
					continue
				}

				log.Printf("Bitcode files: %v", bitcodeFiles)
			}

			// If we reach here, the build succeeded
			log.Printf("Fuzzer build succeeded on attempt %d", attempt)
			return nil
		}
	}
	// Should never reach here, but just in case
	return fmt.Errorf("failed to build fuzzers with sanitizer %s after %d attempts", sanitizer, maxAttempts)
}

func TryLoadQXJsonResults(taskID string, focus string) (*models.CodeqlAnalysisResults, error) {
	taskDir := path.Join(getWorkDir(), taskID)
	outputJson := path.Join(taskDir, fmt.Sprintf("%s_qx.json", focus))
	if !fileExists(outputJson) {
		return nil, fmt.Errorf("The file %v does not exist", outputJson)
	}

	log.Printf("outputJson %s, try loading...", outputJson)

	results := models.CodeqlAnalysisResults{
		Functions:          make(map[string]*models.FunctionDefinition),
		ReachableFunctions: make(map[string][]string),
		Paths:              make(map[string]map[string][][]string),
	}

	// File exists, try to load it
	err := loadResultsFromJsonContentQX(&results, outputJson)
	if err != nil {
		return &results, err
	}

	return &results, nil
}

func loadResultsFromJsonContentQX(results *models.CodeqlAnalysisResults, outputJson string) error {
	log.Printf("Found existing analysis results at %s, loading...", outputJson)

	// Read the file
	fileData, err := os.ReadFile(outputJson)
	if err != nil {
		log.Printf("Warning: Failed to read existing results file: %v", err)
	} else {
		// Try to unmarshal the JSON into results
		err = json.Unmarshal(fileData, results)
		if err != nil {
			log.Printf("Warning: Failed to parse existing results file: %v", err)
		} else {
			// Successfully loaded existing results
			log.Printf("Successfully loaded existing QX analysis results with %d functions, %d reachable function sections (fuzzers), and %d target paths",
				len(results.Functions), len(results.ReachableFunctions), len(results.Paths))

			// Validate the loaded data
			if results.Functions == nil {
				results.Functions = make(map[string]*models.FunctionDefinition)
			}
			if results.ReachableFunctions == nil {
				results.ReachableFunctions = make(map[string][]string)
			}
			if results.Paths == nil {
				results.Paths = make(map[string]map[string][][]string)
			}
		}
	}

	return err
}

var (
	WORK_DIR = "/crs-workdir"
)

func getWorkDir() string {
	if v := os.Getenv("CRS_WORK_DIR"); v != "" {
		return v
	}
	return WORK_DIR
}

func TryLoadJsonResults(taskID string, focus string) (*models.AnalysisResults, error) {
	// taskDir := path.Join(getWorkDir(), taskID)
	outputJson := path.Join(getWorkDir(), fmt.Sprintf("%s.json", focus))
	if !fileExists(outputJson) {
		log.Printf("Error")
		log.Printf("The file %v does not exist", outputJson)
		return nil, fmt.Errorf("The file %v does not exist", outputJson)
	}

	log.Printf("outputJson %s, try loading...", outputJson)

	results := models.AnalysisResults{
		Functions:          make(map[string]*models.FunctionDefinition),
		CallGraph:          &models.CallGraph{Calls: []models.MethodCall{}},
		ReachableFunctions: make(map[string][]string),
		Paths:              make(map[string][][]string),
	}

	// File exists, try to load it
	err := loadResultsFromJsonContent(&results, outputJson)
	if err != nil {
		return &results, err
	}

	return &results, nil
}

func loadResultsFromJsonContent(results *models.AnalysisResults, outputJson string) error {
	log.Printf("Found existing analysis results at %s, loading...", outputJson)

	// Read the file
	fileData, err := os.ReadFile(outputJson)
	if err != nil {
		log.Printf("Warning: Failed to read existing results file: %v", err)
	} else {
		// Try to unmarshal the JSON into results
		err = json.Unmarshal(fileData, results)
		if err != nil {
			log.Printf("Warning: Failed to parse existing results file: %v", err)
		} else {
			// Successfully loaded existing results
			log.Printf("Successfully loaded existing analysis results with %d functions, %d calls, %d reachable functions, and %d target paths",
				len(results.Functions), len(results.CallGraph.Calls), len(results.ReachableFunctions), len(results.Paths))

			// Validate the loaded data
			if results.Functions == nil {
				results.Functions = make(map[string]*models.FunctionDefinition)
			}
			if results.CallGraph == nil {
				results.CallGraph = &models.CallGraph{Calls: []models.MethodCall{}}
			} else if results.CallGraph.Calls == nil {
				results.CallGraph.Calls = []models.MethodCall{}
			}
			if results.ReachableFunctions == nil {
				results.ReachableFunctions = make(map[string][]string)
			}
			if results.Paths == nil {
				results.Paths = make(map[string][][]string)
			}
		}
	}

	return err
}

// Global map to hold a mutex for each taskDir being processed for cloning
var (
	taskDirCloningLocks   = make(map[string]*sync.Mutex)
	taskDirCloningLocksMu sync.Mutex // Mutex to protect access to the taskDirCloningLocks map
)

// Helper function to get or create a mutex for a given taskDir's cloning operations
func getCloningLockForTaskDir(taskDir string) *sync.Mutex {
	taskDirCloningLocksMu.Lock()
	defer taskDirCloningLocksMu.Unlock()

	lock, exists := taskDirCloningLocks[taskDir]
	if !exists {
		lock = &sync.Mutex{}
		taskDirCloningLocks[taskDir] = lock
	}
	return lock
}

// Helper function to execute a command and stream its output (remains the same)
func runCommandAndStreamOutput(cmd *exec.Cmd, commandDesc string) error {
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdout pipe for %s: %v", commandDesc, err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to get stderr pipe for %s: %v", commandDesc, err)
	}

	fmt.Printf("[Go INFO] Running command: %s %v\n", cmd.Path, cmd.Args)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start %s: %v", commandDesc, err)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stdoutPipe)
		for scanner.Scan() {
			fmt.Printf("[%s STDOUT]: %s\n", commandDesc, scanner.Text())
		}
	}()
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			fmt.Printf("[%s STDERR]: %s\n", commandDesc, scanner.Text())
		}
	}()

	err = cmd.Wait()
	wg.Wait() // Ensure all output is flushed
	if err != nil {
		return fmt.Errorf("%s command failed: %v", commandDesc, err)
	}
	fmt.Printf("[Go INFO] %s command completed successfully.\n", commandDesc)
	return nil
}

func cloneOssFuzzAndMainRepoOnce(taskDir, projectName, sanitizerDir string) error {

	// Acquire lock for this specific taskDir to synchronize cloning operations
	cloningLock := getCloningLockForTaskDir(taskDir)
	cloningLock.Lock()
	fmt.Printf("[Go INFO] Acquired cloning lock for taskDir: %s\n", taskDir)
	defer func() {
		cloningLock.Unlock()
		fmt.Printf("[Go INFO] Released cloning lock for taskDir: %s\n", taskDir)
	}()

	if _, err := os.Stat(sanitizerDir); os.IsNotExist(err) {
		fmt.Printf("[Go INFO] Sanitizer directory %s not found. Creating... (taskDir: %s)\n", sanitizerDir, taskDir)
		if errMkdir := os.MkdirAll(sanitizerDir, 0755); errMkdir != nil {
			// Release lock before returning error if MkdirAll fails, as it's not a shared resource issue
			// cloningLock.Unlock() // Consider if this specific error should bypass the main defer
			// fmt.Printf("[Go INFO] Released cloning lock for taskDir: %s due to sanitizerDir creation error\n", taskDir)
			return fmt.Errorf("failed to create sanitizer directory %s for taskDir %s: %v", sanitizerDir, taskDir, errMkdir)
		}
		fmt.Printf("[Go INFO] Successfully created sanitizer directory %s (taskDir: %s)\n", sanitizerDir, taskDir)
	} else if err != nil {
		// Release lock before returning error if Stat fails for sanitizerDir
		// cloningLock.Unlock()
		// fmt.Printf("[Go INFO] Released cloning lock for taskDir: %s due to sanitizerDir stat error\n", taskDir)
		return fmt.Errorf("failed to stat sanitizer directory %s for taskDir %s: %v", sanitizerDir, taskDir, err)
	} else {
		fmt.Printf("[Go INFO] Sanitizer directory %s already exists. (taskDir: %s)\n", sanitizerDir, taskDir)
	}

	// 1. Define paths
	ossFuzzDir := filepath.Join(taskDir, "oss-fuzz")
	mainRepoDir := filepath.Join(taskDir, "main_repo")

	// 2. Clone OSS-Fuzz if it doesn't exist
	// This block is now protected by cloningLock
	if _, err := os.Stat(ossFuzzDir); os.IsNotExist(err) {
		fmt.Printf("[Go INFO] OSS-Fuzz directory %s not found. Cloning (taskDir: %s)...\n", ossFuzzDir, taskDir)
		cmd := exec.Command("git", "clone", "--depth", "1", "https://github.com/google/oss-fuzz", ossFuzzDir)
		if errCmd := runCommandAndStreamOutput(cmd, "git-clone-oss-fuzz"); errCmd != nil {
			return fmt.Errorf("failed to clone OSS-Fuzz for taskDir %s: %v", taskDir, errCmd)
		}
	} else if err != nil {
		return fmt.Errorf("failed to stat OSS-Fuzz directory %s for taskDir %s: %v", ossFuzzDir, taskDir, err)
	} else {
		fmt.Printf("[Go INFO] OSS-Fuzz directory %s already exists. Skipping clone (taskDir: %s).\n", ossFuzzDir, taskDir)
		return nil
	}

	// 3. Read project.yaml to get main_repo URL
	// This block is also protected by cloningLock
	projectYamlPath := filepath.Join(ossFuzzDir, "projects", projectName, "project.yaml")
	var cfg ProjectConfig
	var mainRepoURL string
	maxYamlAttempts := 3
	yamlAttemptDelay := 5 * time.Second

	for attempt := 0; attempt < maxYamlAttempts; attempt++ {
		if _, err := os.Stat(projectYamlPath); err == nil {
			yamlFile, errFile := os.ReadFile(projectYamlPath)
			if errFile != nil {
				// If reading fails even if file exists (e.g. mid-clone by another process that failed partially before this lock), error out
				return fmt.Errorf("failed to read %s on attempt %d (taskDir: %s): %v", projectYamlPath, attempt+1, taskDir, errFile)
			}
			errUnmarshal := yaml.Unmarshal(yamlFile, &cfg)
			if errUnmarshal != nil {
				return fmt.Errorf("failed to unmarshal %s on attempt %d (taskDir: %s): %v", projectYamlPath, attempt+1, taskDir, errUnmarshal)
			}
			mainRepoURL = cfg.MainRepo
			if mainRepoURL == "" {
				// If main_repo is empty, it's a config error, no point retrying this specific step
				return fmt.Errorf("main_repo URL is empty in %s on attempt %d (taskDir: %s)", projectYamlPath, attempt+1, taskDir)
			}
			fmt.Printf("[Go INFO] Successfully loaded and parsed %s on attempt %d. Main repo URL: %s (taskDir: %s)\n", projectYamlPath, attempt+1, mainRepoURL, taskDir)
			break
		} else if os.IsNotExist(err) {
			fmt.Printf("[Go INFO] Attempt %d/%d: %s not found. Waiting %s (taskDir: %s)...\n", attempt+1, maxYamlAttempts, projectYamlPath, yamlAttemptDelay, taskDir)
			if attempt < maxYamlAttempts-1 {
				time.Sleep(yamlAttemptDelay)
			} else {
				return fmt.Errorf("failed to find %s after %d attempts (taskDir: %s): %v", projectYamlPath, maxYamlAttempts, taskDir, err)
			}
		} else {
			return fmt.Errorf("failed to stat %s on attempt %d (taskDir: %s): %v", projectYamlPath, attempt+1, taskDir, err)
		}
	}
	if mainRepoURL == "" {
		return fmt.Errorf("critical: could not determine main_repo URL from %s after all attempts (taskDir: %s)", projectYamlPath, taskDir)
	}

	// 4. Clone Main Repo if it doesn't exist
	// This block is also protected by cloningLock
	if _, err := os.Stat(mainRepoDir); os.IsNotExist(err) {
		fmt.Printf("[Go INFO] Main project repository directory %s not found. Cloning from %s (taskDir: %s)...\n", mainRepoDir, mainRepoURL, taskDir)
		cmd := exec.Command("git", "clone", "--depth", "1", mainRepoURL, mainRepoDir)
		if errCmd := runCommandAndStreamOutput(cmd, "git-clone-main-repo"); errCmd != nil {
			return fmt.Errorf("failed to clone main project repository for taskDir %s: %v", taskDir, errCmd)
		}
	} else if err != nil {
		return fmt.Errorf("failed to stat main project repository directory %s for taskDir %s: %v", mainRepoDir, taskDir, err)
	} else {
		fmt.Printf("[Go INFO] Main project repository directory %s already exists. Skipping clone (taskDir: %s).\n", mainRepoDir, taskDir)
		return nil
	}

	// Cloning and setup part is done, lock will be released by defer.
	fmt.Printf("[Go INFO] Repository setup complete for taskDir: %s. Proceeding to call Python script.\n", taskDir)
	return nil
}

// robustCopyDir copies a directory recursively with fault tolerance,
// continuing even if individual file operations fail
func robustCopyDir(src, dst string) error {
	var copyErrors []string

	// Get properties of source directory
	srcInfo, err := os.Lstat(src)
	if err != nil {
		log.Printf("Warning: error getting stats for source directory %s: %v", src, err)
		return fmt.Errorf("error getting stats for source directory: %w", err)
	}

	// Check if source is a symlink
	if srcInfo.Mode()&os.ModeSymlink != 0 {
		// It's a symlink, read the link target
		linkTarget, err := os.Readlink(src)
		if err != nil {
			log.Printf("Warning: error reading symlink %s: %v", src, err)
			return fmt.Errorf("error reading symlink %s: %w", src, err)
		}

		// Create a symlink at the destination with the same target
		if err := os.Symlink(linkTarget, dst); err != nil {
			log.Printf("Warning: error creating symlink %s -> %s: %v", dst, linkTarget, err)
			return fmt.Errorf("error creating symlink: %w", err)
		}
		return nil
	}

	// Create the destination directory with the same permissions
	if err = os.MkdirAll(dst, srcInfo.Mode()); err != nil {
		log.Printf("Warning: error creating destination directory %s: %v", dst, err)
		return fmt.Errorf("error creating destination directory: %w", err)
	}

	// Read the source directory
	entries, err := os.ReadDir(src)
	if err != nil {
		log.Printf("Warning: error reading source directory %s: %v", src, err)
		return fmt.Errorf("error reading source directory: %w", err)
	}

	// Copy each entry
	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		// Use Lstat instead of Stat to detect symlinks
		entryInfo, err := os.Lstat(srcPath)
		if err != nil {
			log.Printf("Warning: skipping %s due to error: %v", srcPath, err)
			copyErrors = append(copyErrors, fmt.Sprintf("error getting stats for %s: %v", srcPath, err))
			continue // Skip this file but continue with others
		}

		// Handle different file types
		if entryInfo.Mode()&os.ModeSymlink != 0 {
			// It's a symlink, read the link target
			linkTarget, err := os.Readlink(srcPath)
			if err != nil {
				log.Printf("Warning: skipping symlink %s due to error: %v", srcPath, err)
				copyErrors = append(copyErrors, fmt.Sprintf("error reading symlink %s: %v", srcPath, err))
				continue // Skip this symlink but continue with others
			}

			// Create a symlink at the destination with the same target
			if err := os.Symlink(linkTarget, dstPath); err != nil {
				log.Printf("Warning: failed to create symlink %s -> %s: %v", dstPath, linkTarget, err)
				copyErrors = append(copyErrors, fmt.Sprintf("error creating symlink %s: %v", dstPath, err))
				// Continue despite the error
			}
		} else if entryInfo.IsDir() {
			// Recursively copy the subdirectory
			if err = robustCopyDir(srcPath, dstPath); err != nil {
				log.Printf("Warning: error copying directory %s: %v", srcPath, err)
				copyErrors = append(copyErrors, fmt.Sprintf("error copying directory %s: %v", srcPath, err))
				// Continue despite the error
			}
		} else {
			// Copy the regular file
			if err = copyFile(srcPath, dstPath); err != nil {
				log.Printf("Warning: error copying file %s: %v", srcPath, err)
				copyErrors = append(copyErrors, fmt.Sprintf("error copying file %s: %v", srcPath, err))
				// Continue despite the error
			}
		}
	}

	// If we had any errors, return a summary but only after completing as much as possible
	if len(copyErrors) > 0 {
		return fmt.Errorf("completed with %d errors: %s", len(copyErrors), strings.Join(copyErrors[:min(5, len(copyErrors))], "; "))
	}

	return nil
}
func EngineMainAnalysis(taskDetail models.TaskDetail) (models.AnalysisResults, error) {

	taskID := taskDetail.TaskID.String()
	taskDir := path.Join(WORK_DIR, taskID)
	return EngineMainAnalysisCore(taskDetail, taskDir)
}

func EngineMainAnalysisCore(taskDetail models.TaskDetail, taskDir string) (models.AnalysisResults, error) {

	outputJson := path.Join(taskDir, fmt.Sprintf("%s.json", taskDetail.Focus))

	results := models.AnalysisResults{
		Functions:          make(map[string]*models.FunctionDefinition),
		CallGraph:          &models.CallGraph{Calls: []models.MethodCall{}},
		ReachableFunctions: make(map[string][]string),
		Paths:              make(map[string][][]string),
	}

	// Check if the output JSON file already exists
	if fileExists(outputJson) {
		// File exists, try to load it
		err := loadResultsFromJsonContent(&results, outputJson)
		if err != nil {
			return results, nil
		}
		// If we reach here, loading failed, so we'll continue with a fresh analysis
		log.Printf("Proceeding with fresh analysis due to loading errors")
	} else {
		log.Printf("No existing analysis results found at %s, performing fresh analysis", outputJson)
	}

	var language string

	// Try to get language from task detail first
	if taskDetail.Language != "" {
		language = taskDetail.Language
	} else {
		// Fall back to reading from project.yaml
		projectYamlPath := filepath.Join(taskDir, "fuzz-tooling", "projects", taskDetail.ProjectName, "project.yaml")
		yamlData, err := os.ReadFile(projectYamlPath)
		if err == nil {
			var cfg ProjectConfig
			if unmarshalErr := yaml.Unmarshal(yamlData, &cfg); unmarshalErr == nil {
				language = cfg.Language
			} else {
				log.Printf("Warning: Could not parse project.yaml (%v). Language will be auto-detected.", unmarshalErr)
			}
		} else {
			log.Printf("Warning: Could not read project.yaml (%v). Language will be auto-detected.", err)
		}
	}

	projectDir := path.Join(taskDir, taskDetail.Focus)

	// Build list of directories to analyze
	// Some projects have fuzzer sources in fuzz-tooling/projects/<project>
	dirsToAnalyze := []string{projectDir}

	// Check if fuzzer source directory contains actual source files
	fuzzerSourceDir := filepath.Join(taskDir, "fuzz-tooling", "projects", taskDetail.ProjectName)
	if stat, err := os.Stat(fuzzerSourceDir); err == nil && stat.IsDir() {
		if hasSourceFiles(fuzzerSourceDir) {
			dirsToAnalyze = append(dirsToAnalyze, fuzzerSourceDir)
			log.Printf("Found fuzzer sources in %s, including in analysis", fuzzerSourceDir)
		} else {
			log.Printf("Skipping %s (no source files found, likely only build scripts)", fuzzerSourceDir)
		}
	}

	// Find fuzzer binaries
	var allFuzzers []string
	// Try to determine sanitizer from metadata, default to "address"
	sanitizer := "address"
	if taskDetail.Metadata != nil {
		if san, ok := taskDetail.Metadata["sanitizer"]; ok && san != "" {
			sanitizer = san
		}
	}

	fuzzerDir := filepath.Join(taskDir, "fuzz-tooling", "build", "out", fmt.Sprintf("%s-%s", taskDetail.ProjectName, sanitizer))
	if fuzzers, err := findFuzzers(fuzzerDir); err == nil {
		allFuzzers = fuzzers
		log.Printf("Found %d fuzzer binaries in %s", len(allFuzzers), fuzzerDir)
	} else {
		log.Printf("Warning: Could not find fuzzer binaries in %s: %v", fuzzerDir, err)
		log.Printf("Will attempt to find entry points by searching for LLVMFuzzerTestOneInput in source code")
	}

	// Try Joern first (more powerful), fall back to simple analysis if it fails
	log.Printf("Attempting Joern-based analysis for language: %s", language)
	log.Printf("Analyzing directories: %v", dirsToAnalyze)
	joernResults, err := joern.AnalyzeProjectDirs(dirsToAnalyze, language, allFuzzers)
	if err != nil {
		log.Printf("Joern analysis failed: %v", err)
		log.Printf("Falling back to simple regex-based analysis...")

		// Fall back to simple analysis
		simpleResults, simpleErr := simple.AnalyzeProjectDirs(dirsToAnalyze, language, allFuzzers)
		if simpleErr != nil {
			log.Printf("Simple analysis also failed: %v", simpleErr)
			log.Printf("Falling back to legacy analysis method...")
		} else {
			// Use simple analysis results
			results = *simpleResults
			log.Printf("Simple analysis succeeded: %d functions, %d reachable sets",
				len(results.Functions), len(results.ReachableFunctions))
		}
	} else {
		// Check if Joern computed reachability properly
		hasReachability := false
		for _, reachable := range joernResults.ReachableFunctions {
			if len(reachable) > 0 {
				hasReachability = true
				break
			}
		}

		// If Joern found entry points but no reachability, use simple analysis
		if len(joernResults.ReachableFunctions) > 0 && !hasReachability {
			log.Printf("Joern found entry points but computed 0 reachable functions, trying simple analysis...")
			simpleResults, simpleErr := simple.AnalyzeProjectDirs(dirsToAnalyze, language, allFuzzers)
			if simpleErr == nil && len(simpleResults.ReachableFunctions) > 0 {
				// Use simple analysis results entirely (functions, call graph, and reachability)
				// because Joern and simple analysis use incompatible key formats
				results = *simpleResults
				log.Printf("Using simple analysis results: %d functions, %d entry points (Joern reachability failed)",
					len(results.Functions), len(results.ReachableFunctions))
			} else {
				// Use Joern results as-is
				results = *joernResults
				log.Printf("Joern analysis succeeded: %d functions, %d reachable sets (empty)",
					len(results.Functions), len(results.ReachableFunctions))
			}
		} else {
			// Use Joern results
			results = *joernResults
			log.Printf("Joern analysis succeeded: %d functions, %d reachable sets",
				len(results.Functions), len(results.ReachableFunctions))
		}
	}

	if true {
		fmt.Printf("Saving results to %s language: %s\n", outputJson, language)

		// save to json and keep in memory
		jsonData, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			fmt.Printf("Error marshaling JSON: %v\n", err)
		} else {
			// Write results to JSON file
			err = os.WriteFile(outputJson, jsonData, 0644)
			if err != nil {
				fmt.Printf("Error writing JSON file: %v\n", err)
			}
		}

	}

	return results, nil
}

func filterSanitizerFunctions(funcs []string) []string {
	filtered := make([]string, 0, len(funcs))
	for _, fn := range funcs {
		if strings.HasPrefix(fn, "__asan_") ||
			strings.HasPrefix(fn, "__sanitizer_") ||
			strings.HasPrefix(fn, "llvm.") ||
			strings.HasPrefix(fn, "__assert_") {
			continue // skip helper/runtime functions
		}
		filtered = append(filtered, fn)
	}
	return filtered
}

// -----------------------------------------------------------------------------
// NEW HELPER
// -----------------------------------------------------------------------------
func ProcessFuzzerCallPaths(
	fuzzer string,
	projectDir string,
	projectName string,
	language string,
	results *models.AnalysisResults,
	resultsMu *sync.Mutex,
) {
	// 1) Locate the fuzzer source file
	fuzzerSourcePath, _, err := findFuzzerSource(fuzzer, projectDir, projectName, language)
	if err != nil {
		log.Printf("Failed to locate fuzzer source for %s: %v", fuzzer, err)
		return
	}
	entryPoint := fuzzerSourcePath + ".LLVMFuzzerTestOneInput"

	// 2) Locate reachable C functions in the call‑graph
	callGraphDot := fmt.Sprintf("%s.dot", fuzzer)

	// check if callGraphDot exists, if not, try
	if !fileExists(callGraphDot) {
		log.Printf("[ProcessFuzzerCallPaths failed] callGraphDot does not exist: %s", callGraphDot)
		return
		// fuzzerDir := filepath.Dir(fuzzer)
		// fuzzerBase := filepath.Base(fuzzerSourcePath)
		// fuzzerBase = strings.TrimSuffix(fuzzerBase, filepath.Ext(fuzzerBase))
		// fuzzer_new := filepath.Join(fuzzerDir, fuzzerBase)
		// log.Printf("Updated fuzzer %s -> fuzzer_new %s", fuzzer, fuzzer_new)
		// fuzzer = fuzzer_new
		// callGraphDot = fmt.Sprintf("%s.dot", fuzzer)
	}

	targetFunctionNames := findAllReachableCFunctions(callGraphDot)
	targetFunctionNames = filterSanitizerFunctions(targetFunctionNames)
	resultsMu.Lock()
	if results.ReachableFunctions == nil {
		results.ReachableFunctions = make(map[string][]string)
	}
	results.ReachableFunctions[entryPoint] = targetFunctionNames
	resultsMu.Unlock()

	// 3) For each reachable function, collect the call paths
	if true {
		//TODO: this is too expensive, change to on-demand
		err := GetCCallPathsParallel(projectDir, fuzzer, callGraphDot, entryPoint, targetFunctionNames, results, resultsMu)
		if err != nil {
			log.Printf("[ERROR GetCCallPathsParallel failed] fuzzer %s: %v", fuzzer, err)
		}

	}
}

// extractPaths converts []models.CallPath → [][]string
// and merges any function information found in the CallPath nodes
// into results.Functions.
func extractPaths(results *models.AnalysisResults, mu *sync.Mutex, cps []models.CallPath) [][]string {

	all := make([][]string, 0, len(cps))

	for _, cp := range cps {
		if len(cp.Nodes) == 0 {
			continue
		}

		path := make([]string, 0, len(cp.Nodes))

		for _, n := range cp.Nodes {
			fn := n.Function
			path = append(path, fn)

			// ── Merge node data into results.Functions ──────────────────────────
			mu.Lock()
			fd, ok := results.Functions[fn]
			if !ok {
				fd = &models.FunctionDefinition{Name: fn}
				results.Functions[fn] = fd
			}
			// Fill in any missing fields.
			if fd.FilePath == "" && n.File != "" {
				fd.FilePath = n.File
			}
			if fd.SourceCode == "" && n.Body != "" {
				fd.SourceCode = n.Body
			}
			if fd.StartLine == 0 {
				if line, err := strconv.Atoi(n.Line); err == nil {
					fd.StartLine = line
				}
			}

			mu.Unlock()
			// EndLine is unknown here; leave as‑is unless you have better data.
		}
		// ---------------------------------------------------------------------

		all = append(all, path)
	}

	return all
}
func findAllReachableCFunctions(dotFile string) []string {
	cmd := exec.Command("python3", "/app/strategyx/legacy_strategy/parse_callgraph_full.py", dotFile)
	cmd.Dir = filepath.Dir(dotFile) // json will be written here
	if err := cmd.Run(); err != nil {
		log.Printf("[findAllReachableCFunctions failed] parse_callgraph_full.py %s %v", dotFile, err)
		return nil
	}

	dotBase := filepath.Base(dotFile)

	outJSON := filepath.Join(filepath.Dir(dotFile), dotBase+"_reachable.json")
	data, err := os.ReadFile(outJSON)
	if err != nil {
		log.Printf("cannot read %s: %v", outJSON, err)
		return nil
	}

	var parsed struct {
		ReachableFunctions []string `json:"reachable_functions"`
		NumReachable       int      `json:"num_reachable"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		log.Printf("bad json: %v", err)
		return nil
	}
	return parsed.ReachableFunctions
}

func CopyExtAPIFileIfNotExists() error {

	dst := "/usr/local/lib/extapi.bc"
	src := "/app/strategyx/legacy_strategy/extapi.bc"

	if _, err := os.Stat(dst); os.IsNotExist(err) {
		// Open the source file
		srcFile, err := os.Open(src)
		if err != nil {
			return err
		}
		defer srcFile.Close()

		// Create the destination file
		dstFile, err := os.Create(dst)
		if err != nil {
			return err
		}
		defer dstFile.Close()

		// Copy the contents
		if _, err := io.Copy(dstFile, srcFile); err != nil {
			return err
		}

		log.Printf("Copied %s to %s", src, dst)
	} else if err != nil {
		return err
	} else {
		// log.Printf("%s already exists, skipping copy", dst)
	}
	return nil
}

// BuildCallGraphFromBC builds/fixes metadata and then generates a call-graph
// with WPA.  It first tries the full x.bc; on timeout it retries with the
// smaller x1.bc, x2.bc … that were produced by limitBCFileSize().
func BuildCallGraphFromBC(fuzzer string, workDir string) error {
	fuzzerBase := filepath.Base(fuzzer)
	fuzzerDir := filepath.Dir(fuzzer)
	fuzzerBc := fuzzer + ".bc"

	//----------------------------------------------------------------------
	// 0. ensure extapi.bc is available (same as before)
	//----------------------------------------------------------------------
	if err := CopyExtAPIFileIfNotExists(); err != nil {
		log.Printf("Warning ensuring extapi.bc: %v", err)
	}

	//----------------------------------------------------------------------
	// 1. run fundef-bc to generate <fuzzer>_function_metadata.json
	//----------------------------------------------------------------------
	fundefCmd := exec.Command("/app/strategyx/legacy_strategy/fundef-bc", fuzzerBc)
	fundefCmd.Dir = workDir

	// fmt.Printf("[DEBUG] fundef-bc cwd: %s\n", fundefCmd.Dir)
	// fmt.Printf("[DEBUG] fundef-bc cmd:  %s %s\n",
	// 	fundefCmd.Path, strings.Join(fundefCmd.Args[1:], " "))

	// capture output for troubleshooting
	var stdout, stderr bytes.Buffer
	fundefCmd.Stdout = &stdout
	fundefCmd.Stderr = &stderr

	runWithTimeout(fundefCmd, 15*time.Minute)

	// fmt.Printf("[DEBUG] fundef-bc stdout:\n%s\n", stdout.String())

	// verify that the metadata file is present
	metaFile := filepath.Join(workDir, "function_metadata.json")
	if !fileExists(metaFile) {
		fmt.Printf("[DEBUG] fundef-bc did not create %s\n", metaFile)
		fmt.Printf("[DEBUG fundefCmd] %v\n", fundefCmd)
		fmt.Printf("[DEBUG] fundef-bc stderr:\n%s\n", stderr.String())
		// entries, _ := os.ReadDir(workDir)
		// for _, e := range entries {
		// 	fmt.Printf("  found: %s\n", e.Name())
		// }
	}

	metaSrc := filepath.Join(workDir, "function_metadata.json")
	if fi, err := os.Stat(metaSrc); err != nil {
		return fmt.Errorf("no metadata produced; %v", err)
	} else if fi.Size() == 0 {
		return fmt.Errorf("no metadata produced; fundef-bc returned empty file")
	}

	metaDst := filepath.Join(fuzzerDir, fuzzerBase+"_function_metadata.json")
	if err := copyFile(metaSrc, metaDst); err != nil {
		log.Printf("Warning copying metadata: %v", err)
	}
	_ = os.Remove(metaSrc) // best-effort

	wpaSuccess := false
	log.Printf("Running type-based pointer analysis for %s", fuzzerBc)
	wpaTypeCmd := exec.Command("/app/strategyx/legacy_strategy/wpa", "-type", "-dump-callgraph", fuzzerBc)
	wpaTypeCmd.Dir = workDir
	if err := runWithTimeout(wpaTypeCmd, 10*time.Minute); err != nil {
		log.Printf("Warning: wpa analysis failed for %s: %v", fuzzerBc, err)

		//----------------------------------------------------------------------
		// 2. prepare list of candidate bit-code bundles
		//----------------------------------------------------------------------
		var bcBundles []string
		for i := 0; ; i++ {
			name := "x.bc"
			name = fmt.Sprintf("x%d.bc", i)
			path := filepath.Join(fuzzerDir, name)
			if _, err := os.Stat(path); err != nil {
				break // first missing file → stop
			}
			bcBundles = append(bcBundles, path)
		}

		if len(bcBundles) == 0 {
			return fmt.Errorf("no x*.bc files found in %s", fuzzerDir)
		}

		llvmLink := getValidLlvmLinkPath()

		fuzzerBc_x := filepath.Join(fuzzerDir, "bitcode-fuzzer", fuzzerBase+".bc")
		if _, err := os.Stat(fuzzerBc_x); err != nil {
			return fmt.Errorf("WPA failed because fuzzerBc_x does not exist: %s", fuzzerBc_x)
		}
		//----------------------------------------------------------------------
		// 3. iterate over bundles until WPA succeeds
		//----------------------------------------------------------------------
		for _, bundle := range bcBundles {
			log.Printf("Attempting WPA with %s …", filepath.Base(bundle))
			tmpBc := filepath.Join(workDir, "tmp.bc")
			linkArgs := []string{bundle, "--override", fuzzerBc_x, "-o", tmpBc}
			if err := exec.Command(llvmLink, linkArgs...).Run(); err != nil {
				log.Printf("link failed for %s: %v", bundle, err)
				continue
			}

			wpa := exec.Command("/app/strategyx/legacy_strategy/wpa", "-type", "-dump-callgraph", tmpBc)
			wpa.Dir = workDir
			if err := runWithTimeout(wpa, 5*time.Minute); err != nil {
				log.Printf("WPA timed-out/failed on %s: %v", bundle, err)
				continue // try the next (smaller) bc bundle
			}

			// success → move dot file and clean up
			wpaSuccess = true
			break
		}

	} else {
		wpaSuccess = true
	}

	if wpaSuccess {
		// Move callgraph_final.dot to fuzzer's directory with proper name
		fuzzerDotName := filepath.Join(fuzzerDir, fuzzerBase+".dot")
		srcDot := filepath.Join(workDir, "callgraph_final.dot")
		if err := copyFile(srcDot, fuzzerDotName); err != nil {
			return fmt.Errorf("Warning: Failed to copy callgraph for %s: %v", fuzzerBc, err)
		}
		os.Remove(srcDot)
		os.Remove(filepath.Join(workDir, "callgraph_initial.dot"))

		return nil
	} else {
		return fmt.Errorf("WPA failed on all candidate bit-code bundles for %s", fuzzerBase)
	}
}

// Helper function to run a command with timeout
func runWithTimeout(cmd *exec.Cmd, timeout time.Duration) error {
	if err := cmd.Start(); err != nil {
		return err
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		if err := cmd.Process.Kill(); err != nil {
			log.Printf("Failed to kill process: %v", err)
		}
		return fmt.Errorf("command timed out")
	}
}

type CompileCommand struct {
	Arguments []string `json:"arguments"`
	Directory string   `json:"directory"`
	File      string   `json:"file"`
}

var (
	CompileCommandDirectory = ""
	IncludeDirectories      sync.Map
)

// GenerateBitcodeFilesWithBearParallel processes compile_commands.json and generates bitcode files in parallel
func GenerateBitcodeFilesWithBearParallel(compileCommandsPath, projectDir, projectName string, cFuzzerSourceFiles, skippedFuzzerSourceFiles []string, cFilesToAnalyzeBearFail *[]string, bitcodeDir, bitcodeFuzzerDir string) error {
	// Parse the compile_commands.json
	data, err := os.ReadFile(compileCommandsPath)
	if err != nil {
		fmt.Printf("Error reading compile_commands.json: %v\n", err)
		return err
	}

	var compileCommands []CompileCommand

	if err := json.Unmarshal(data, &compileCommands); err != nil {
		fmt.Printf("Error parsing compile_commands.json: %v\n", err)
		return err
	}

	docker_image_bear := projectName + "-with-bear"
	fmt.Printf("Generating bitcode with %s in parallel...\n", docker_image_bear)

	// Define warning flag replacements
	warningReplacements := map[string]string{
		"-Wno-error=vla-cxx-extension": "-Wno-error=vla-extension",
		"-Werror=vla-cxx-extension":    "-Werror=vla-extension",
	}

	// Use a semaphore to limit concurrent Docker processes
	maxConcurrent := runtime.NumCPU() * 2 / 3 // Adjust based on your system capabilities
	if maxConcurrent < 2 {
		maxConcurrent = 1
	}

	semaphore := make(chan struct{}, maxConcurrent)

	// Use wait group to wait for all goroutines to complete
	var wg sync.WaitGroup

	// Mutex for thread-safe updates to shared variables
	var mu sync.Mutex
	regularCount := 0

	var filesToProcess []CompileCommand

	cFuzzerSourceFilesx := append(cFuzzerSourceFiles, skippedFuzzerSourceFiles...)

	for _, cmd := range compileCommands {
		srcFile := cmd.File

		// Skip non-C/C++ files
		if !strings.HasSuffix(srcFile, ".c") && !strings.HasSuffix(srcFile, ".cpp") &&
			!strings.HasSuffix(srcFile, ".cc") && !strings.HasSuffix(srcFile, ".cxx") {
			continue
		}

		if strings.Contains(srcFile, "test.c") || strings.Contains(srcFile, "test/") {
			continue
		}

		filesToProcess = append(filesToProcess, cmd)
	}

	if len(filesToProcess) == 0 {
		return fmt.Errorf("[likely bear error] found ZERO filesToProcess!")
	}

	fmt.Printf("Processing %d files in parallel using %d workers\n", len(filesToProcess), maxConcurrent)

	// Process each compile command in parallel
	alreadyProcessedFiles := make(map[string]bool)

	for _, cmd := range filesToProcess {
		wg.Add(1)
		go func(cmd CompileCommand) {
			defer wg.Done()

			// Acquire semaphore (blocks if maxConcurrent processes are already running)
			semaphore <- struct{}{}
			defer func() { <-semaphore }() // Release semaphore when done

			srcFile := cmd.File

			mu.Lock()
			if _, exists := alreadyProcessedFiles[srcFile]; exists {
				// Already processed or being processed by another goroutine, release lock and exit
				mu.Unlock()
				return
			}
			// Mark as processed *before* releasing the lock
			alreadyProcessedFiles[srcFile] = true
			mu.Unlock()

			// Create bitcode filename
			baseName := filepath.Base(srcFile)
			bcFileName := strings.TrimSuffix(baseName, filepath.Ext(baseName)) + ".bc"
			bcFilePath := filepath.Join(bitcodeDir, bcFileName)

			// Create modified compile command for bitcode generation
			modifiedArgs := make([]string, 0, len(cmd.Arguments))

			// Replace compiler with clang-17
			modifiedArgs = append(modifiedArgs, "clang-17")

			// Add -emit-llvm flag after the compiler
			modifiedArgs = append(modifiedArgs, "-emit-llvm")

			// Add all other arguments except the original compiler, output flag and file
			skipNext := false
			for i := 1; i < len(cmd.Arguments); i++ {
				if skipNext {
					skipNext = false
					continue
				}

				if cmd.Arguments[i] == "-o" {
					// Skip the original output file
					skipNext = true
					continue
				}

				arg := cmd.Arguments[i]

				//add include
				if strings.HasPrefix(arg, "-I") {
					IncludeDirectories.Store(arg, true)
				}
				// Handle problematic warning flags
				if replacement, exists := warningReplacements[arg]; exists {
					if replacement != "" {
						modifiedArgs = append(modifiedArgs, replacement)
					}
					continue
				}

				modifiedArgs = append(modifiedArgs, cmd.Arguments[i])
			}

			// Remove the original source file (it will be added at the end)
			modifiedArgs = modifiedArgs[:len(modifiedArgs)-1]

			// Set output to bitcode file
			modifiedArgs = append(modifiedArgs, "-o", "/out/"+bcFileName)

			// Add the source file
			modifiedArgs = append(modifiedArgs, srcFile)

			bitcodeDirx := bitcodeDir
			// Determine if this is a fuzzer file
			isFuzzer := false
			for _, fuzzerFile := range cFuzzerSourceFilesx {
				if strings.Contains(fuzzerFile, baseName) {
					isFuzzer = true
					break
				}
			}

			// Skip fuzzer files
			if isFuzzer {
				CompileCommandDirectory = cmd.Directory
				//store -I
				bitcodeDirx = bitcodeFuzzerDir
			}
			// Build the docker command
			dockerArgs := []string{
				"run",
				"--rm",
				"--privileged",
				"--shm-size=8g",
				"--platform", "linux/amd64",
				"-e", "FUZZING_ENGINE=libfuzzer",
				"-e", "ARCHITECTURE=x86_64",
				"-e", fmt.Sprintf("PROJECT_NAME=%s", projectName),
				"-e", "HELPER=True",
				"-v", fmt.Sprintf("%s:/src/%s", projectDir, projectName),
				"-v", fmt.Sprintf("%s:/out", bitcodeDirx),
				// "-v", "/usr/include:/usr/include",
				"-w", cmd.Directory,
				"-t", docker_image_bear,
				"bash", "-c", strings.Join(modifiedArgs, " "),
			}

			// Execute the docker command with reduced output
			dockerCmd := exec.Command("docker", dockerArgs...)

			// Redirect output to a buffer and a log file to reduce console spam
			var outputBuffer bytes.Buffer
			logFile := filepath.Join(os.TempDir(), fmt.Sprintf("docker_build_%s.log", bcFileName))
			logFileHandle, err := os.Create(logFile)

			if err == nil {
				dockerCmd.Stdout = io.MultiWriter(&outputBuffer, logFileHandle)
				dockerCmd.Stderr = io.MultiWriter(&outputBuffer, logFileHandle)
				defer logFileHandle.Close()
			} else {
				// If log file creation fails, just use buffer
				dockerCmd.Stdout = &outputBuffer
				dockerCmd.Stderr = &outputBuffer
			}

			// Use a mutex to avoid interleaved console output
			log.Printf("Generating bitcode for %s -> %s\n", srcFile, bcFilePath)

			if err := dockerCmd.Run(); err != nil {
				mu.Lock()
				// log.Printf("Error generating bitcode for %s: %v\ndockerArgs: %v\n", srcFile, err,dockerArgs)
				// Add to failed list
				if !isFuzzer {
					*cFilesToAnalyzeBearFail = append(*cFilesToAnalyzeBearFail, srcFile)
				}
				mu.Unlock()
			} else {
				mu.Lock()
				regularCount++
				mu.Unlock()
			}
		}(cmd)
	}

	// Wait for all goroutines to complete
	wg.Wait()

	fmt.Printf("Generated %d regular bitcode files in %s\n", regularCount, bitcodeDir)
	if len(*cFilesToAnalyzeBearFail) > 0 {
		fmt.Printf("Failed to generate %d files (added to fallback list)\n", len(*cFilesToAnalyzeBearFail))
	}

	return nil
}
func GenerateBitcodeFileInDocker(projectDir, projectName, srcFile, bitcodeDir string, includeDirSlice *[]string) error {

	docker_image_bear := projectName + "-with-bear"

	// Create bitcode filename
	baseName := filepath.Base(srcFile)
	bcFileName := strings.TrimSuffix(baseName, filepath.Ext(baseName)) + ".bc"
	bcFilePath := filepath.Join(bitcodeDir, bcFileName)

	modifiedArgs := []string{}
	// Replace compiler with clang-17
	modifiedArgs = append(modifiedArgs, "clang-17")
	modifiedArgs = append(modifiedArgs, "-emit-llvm")
	modifiedArgs = append(modifiedArgs, "-g")
	modifiedArgs = append(modifiedArgs, "-c")

	if len(CompileCommandDirectory) > 0 {
		modifiedArgs = append(modifiedArgs, "-I"+CompileCommandDirectory) //e.g.,/src/sqlite3/bld
	}
	if len(*includeDirSlice) > 0 {
		modifiedArgs = append(modifiedArgs, (*includeDirSlice)...)
	}
	// Set output to bitcode file
	modifiedArgs = append(modifiedArgs, "-o", "/out/"+bcFileName)

	// Add the source file
	relPath, err := filepath.Rel(projectDir, srcFile)
	if err != nil {
		// fallback to absolute host path if something goes wrong
		relPath = srcFile
	}
	// container paths always use forward-slashes
	containerSrc := filepath.ToSlash(filepath.Join("/src", projectName, relPath))
	modifiedArgs = append(modifiedArgs, containerSrc)

	// Build the docker command
	dockerArgs := []string{
		"run",
		"--rm",
		"--privileged",
		"--shm-size=8g",
		"--platform", "linux/amd64",
		"-e", "FUZZING_ENGINE=libfuzzer",
		"-e", "ARCHITECTURE=x86_64",
		"-e", fmt.Sprintf("PROJECT_NAME=%s", projectName),
		"-e", "HELPER=True",
		"-v", fmt.Sprintf("%s:/src/%s", projectDir, projectName),
		"-v", fmt.Sprintf("%s:/out", bitcodeDir),
		// "-v", "/usr/include:/usr/include",
		"-t", docker_image_bear,
		"bash", "-c", strings.Join(modifiedArgs, " "),
	}

	// Execute the docker command with reduced output
	dockerCmd := exec.Command("docker", dockerArgs...)

	// Redirect output to a buffer and a log file to reduce console spam
	var outputBuffer bytes.Buffer
	logFile := filepath.Join(os.TempDir(), fmt.Sprintf("docker_build_%s.log", bcFileName))
	logFileHandle, err := os.Create(logFile)

	if err == nil {
		dockerCmd.Stdout = io.MultiWriter(&outputBuffer, logFileHandle)
		dockerCmd.Stderr = io.MultiWriter(&outputBuffer, logFileHandle)
		defer logFileHandle.Close()
	} else {
		// If log file creation fails, just use buffer
		dockerCmd.Stdout = &outputBuffer
		dockerCmd.Stderr = &outputBuffer
	}

	fmt.Printf("Generating bitcode in docker for %s -> %s\n", srcFile, bcFilePath)

	if err := dockerCmd.Run(); err != nil {
		fmt.Printf("GenerateBitcodeFileInDocker Error generating bitcode for %s: %v\n", srcFile, err)
		fmt.Printf("Execute Docker command: docker %s\n", strings.Join(dockerArgs, " "))
		return err
	}

	return nil
}

var (
	LLVM_LINK_PATH  = "llvm-link-17"
	LLVM_LINK_PATH1 = "llvm17-link"
	CLANG_PATH      = "clang-17"
)

func commandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

// When you need to use the command
func getValidLlvmLinkPath() string {
	if commandExists(LLVM_LINK_PATH) {
		return LLVM_LINK_PATH
	}
	if commandExists(LLVM_LINK_PATH1) {
		fmt.Printf("Warning: %s not found, using %s instead\n", LLVM_LINK_PATH, LLVM_LINK_PATH1)
		return LLVM_LINK_PATH1
	}
	fmt.Printf("Error: Neither %s nor %s found in PATH\n", LLVM_LINK_PATH, LLVM_LINK_PATH1)
	return LLVM_LINK_PATH // Return the primary path anyway, the command will fail but with a clear error
}

func linkSubset(llvmLinkPath string, files []string, out string) error {
	args := []string{files[0]}
	for _, f := range files[1:] {
		args = append(args, "--override", f)
	}
	args = append(args, "-o", out)
	cmd := exec.Command(llvmLinkPath, args...)
	return cmd.Run()
}

func generateSubsetBCFiles(files []string, outDir, llvmLinkPath string) {
	subset := files
	idx := 1
	for len(subset) > 1 {
		subset = subset[:len(subset)/2] // halve
		out := filepath.Join(outDir, fmt.Sprintf("x%d.bc", idx))
		if err := linkSubset(llvmLinkPath, subset, out); err != nil {
			log.Printf("subset link failed (%s): %v", out, err)
			return
		}
		if fi, err := os.Stat(out); err == nil && fi.Size() < 25*1024*1024 {
			return // small enough, stop
		}
		idx++
	}
}
func limitBCFileSize(regularBcFiles []string, outputXBCFile, llvmLinkPath string) error {
	const maxFileMB = 50
	maxBytes := int64(maxFileMB * 1024 * 1024)

	fi, err := os.Stat(outputXBCFile)
	if err != nil {
		return err
	}
	if fi.Size() <= maxBytes {
		// still produce the smaller variants for later fallback
		generateSubsetBCFiles(regularBcFiles, filepath.Dir(outputXBCFile), llvmLinkPath)
		return nil
	}

	// -------- shrink x.bc to <= 100 MB --------
	factor := int(math.Ceil(float64(fi.Size()) / float64(maxBytes)))
	rand.Seed(time.Now().UnixNano())
	shuffled := append([]string(nil), regularBcFiles...)
	rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	subset := shuffled[:len(shuffled)/factor]

	if err := linkSubset(llvmLinkPath, subset, outputXBCFile); err != nil {
		return err
	}

	// emit the additional x1.bc, x2.bc, … for fallback
	generateSubsetBCFiles(subset, filepath.Dir(outputXBCFile), llvmLinkPath)
	return nil
}

func LinkOneFuzzerBitcodeFiles(fuzzerBc string, outputDir string) error {
	fuzzerBaseName := filepath.Base(fuzzerBc)
	outputFile := filepath.Join(outputDir, fuzzerBaseName)
	outputXBCFile := filepath.Join(outputDir, "x.bc")

	// Prepare llvm-link command arguments
	args := []string{}
	if fileExists(outputXBCFile) {
		// Add all regular bitcode files first
		args = append(args, outputXBCFile)
		args = append(args, "--override")
	}
	// Add the fuzzer bitcode file last
	args = append(args, fuzzerBc)

	// Add output file
	args = append(args, "-o", outputFile)

	// cmdStr := LLVM_LINK_PATH + " " + strings.Join(args, " ")
	// fmt.Printf("Executing command:\n%s\n", cmdStr)

	// Create and run the command
	cmd := exec.Command(LLVM_LINK_PATH, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	fmt.Printf("Linking fuzzer bitcode for %s -> %s\n",
		fuzzerBaseName, outputFile)

	err := cmd.Run()
	if err != nil {
		fmt.Printf("Error linking fuzzer bitcode for %s: %v\n", fuzzerBaseName, err)
		fmt.Printf("Stderr: %s\n", stderr.String())
		return fmt.Errorf("Error linking fuzzer bitcode for %s: %v\n", fuzzerBaseName, err)
	}
	return nil
}

// LinkRegularBCFiles links all “regular” *.bc files into a single x.bc,
// but does it in two stages so large projects don’t stall llvm-link:
//
//  1. Split the input list into small batches (default 10 files).
//     Each batch is linked in parallel, producing tmp_link/batch_<n>.bc.
//  2. Link the batch artefacts serially to obtain x.bc.
//
// The intermediate step keeps every individual llvm-link invocation fast and
// allows parallel CPU utilisation.  After x.bc is produced we still call
// limitBCFileSize so the existing size‐reduction logic remains intact.
func LinkRegularBCFiles(bitcodeDir string, outputDir string) error {
	// Discover bitcode inputs
	regularBcFiles, err := filepath.Glob(filepath.Join(bitcodeDir, "*.bc"))
	if err != nil {
		return fmt.Errorf("failed to list regular bitcode files: %v", err)
	}

	// ----------------------------------------------------------------
	// Filter-out single huge artefacts that blow up llvm-link and are
	// almost always useless for whole-program analysis (e.g. flex’s
	// scanner.bc).  Two heuristics:
	//   • name contains "scanner.bc"
	//   • file size ≥ 30 MB
	// ----------------------------------------------------------------
	if len(regularBcFiles) > 1 {
		const skipThreshold = int64(32 * 1024 * 1024) // 30 MB
		var filtered []string
		for _, f := range regularBcFiles {

			if st, err := os.Stat(f); err == nil && st.Size() >= skipThreshold { // 2️⃣
				fmt.Printf("Skip %s (%.1f MB > %d MB)\n",
					filepath.Base(f), float64(st.Size())/1024/1024,
					skipThreshold/1024/1024)
				continue
			}
			filtered = append(filtered, f)
		}

		regularBcFiles = filtered
		fmt.Printf("After filtering: %d bitcode files\n", len(regularBcFiles))
	}

	if len(regularBcFiles) == 0 {
		fmt.Println("No regular bitcode files to link.")
		return nil
	}

	const batchSize = 10 // tweak for your hardware
	llvmLinkPath := getValidLlvmLinkPath()
	tmpDir := filepath.Join(outputDir, "tmp_link")
	_ = os.MkdirAll(tmpDir, 0755)

	// --------------------------------------------------------------------
	// 1.  Link batches in parallel
	// --------------------------------------------------------------------
	var wg sync.WaitGroup
	var mu sync.Mutex
	var batchErr error
	var interFiles []string

	for i := 0; i < len(regularBcFiles); i += batchSize {
		end := i + batchSize
		if end > len(regularBcFiles) {
			end = len(regularBcFiles)
		}
		batch := regularBcFiles[i:end]
		out := filepath.Join(tmpDir, fmt.Sprintf("batch_%d.bc", i/batchSize))
		interFiles = append(interFiles, out)

		wg.Add(1)
		go func(files []string, output string) {
			defer wg.Done()
			if err := linkSubset(llvmLinkPath, files, output); err != nil {
				mu.Lock()
				if batchErr == nil {
					batchErr = err
				}
				mu.Unlock()
				fmt.Printf("linkSubset failed (%s): %v\n", output, err)
			}
		}(batch, out)
	}
	wg.Wait()
	if batchErr != nil {
		return batchErr
	}

	// --------------------------------------------------------------------
	// 2.  Final serial link of the intermediates
	// --------------------------------------------------------------------
	outputXBCFile := filepath.Join(outputDir, "x.bc")
	fmt.Printf("Linking %d intermediate BC files → %s\n", len(interFiles), outputXBCFile)
	if err := linkSubset(llvmLinkPath, interFiles, outputXBCFile); err != nil {
		return fmt.Errorf("final link failed: %w", err)
	}

	// --------------------------------------------------------------------
	// 3.  Optionally shrink / split if the result is very large
	// --------------------------------------------------------------------
	if err := limitBCFileSize(regularBcFiles, outputXBCFile, llvmLinkPath); err != nil {
		return err
	}

	return nil
}

func LinkRegularBCFiles0(bitcodeDir string, outputDir string) error {

	// Get list of all regular bitcode files
	regularBcFiles, err := filepath.Glob(filepath.Join(bitcodeDir, "*.bc"))
	if err != nil {
		return fmt.Errorf("failed to list regular bitcode files: %v", err)
	}

	fmt.Printf("Found %d regular bitcode files\n", len(regularBcFiles))

	if len(regularBcFiles) == 0 {
		fmt.Println("No regular bitcode files to link.")
		return nil
	}

	// Link all regularBcFiles to x.bc (serial, as it's a single file)
	var args []string
	args = append(args, regularBcFiles[0])
	if len(regularBcFiles) > 1 {
		for _, regularBc := range regularBcFiles[1:] {
			args = append(args, "--override")
			args = append(args, regularBc)
		}
	}
	outputXBCFile := filepath.Join(outputDir, "x.bc")
	args = append(args, "-o", outputXBCFile)

	llvmLinkPath := getValidLlvmLinkPath()
	// cmdStr := llvmLinkPath + " " + strings.Join(args, " ")
	// fmt.Printf("Executing command:\n%s\n", cmdStr)

	cmd := exec.Command(llvmLinkPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	fmt.Printf("Linking bitcode for %d regular BC files -> %s\n",
		len(regularBcFiles), outputXBCFile)

	err = cmd.Run()
	if err != nil {
		fmt.Printf("Error linking bitcode for %s: %v\n", outputXBCFile, err)
		return err
	}

	limitBCFileSize(regularBcFiles, outputXBCFile, llvmLinkPath)

	return nil
}

func collectMapKeys(m *sync.Map) []string {
	var keys []string
	m.Range(func(key, value interface{}) bool {
		keys = append(keys, key.(string))
		return true
	})
	return keys
}
func GenerateFuzzerBitcodeFilesAndLinkParallel(projectDir, projectName string, bitcodeDir string, cFuzzerSourceFiles []string, bitcodeFuzzerDir, fuzzerDir string) error {

	err := LinkRegularBCFiles(bitcodeDir, fuzzerDir)
	if err != nil {
		fmt.Printf("Error LinkRegularBCFiles %v\n", err)
	}

	outputDir := bitcodeFuzzerDir
	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		// Check if it's a permission error
		if os.IsPermission(err) {
			log.Printf("Permission denied when creating directory, trying with sudo: %s", outputDir)
			// Try using sudo to create the directory
			sudoCmd := exec.Command("sudo", "mkdir", "-p", outputDir)
			if sudoErr := sudoCmd.Run(); sudoErr != nil {
				return fmt.Errorf("failed to create output directory even with sudo %s: %v", outputDir, sudoErr)
			}
			// Change ownership to current user so we can write to it
			currentUser := os.Getenv("USER")
			if currentUser != "" {
				chownCmd := exec.Command("sudo", "chown", "-R", currentUser+":"+currentUser, outputDir)
				if chownErr := chownCmd.Run(); chownErr != nil {
					log.Printf("Warning: Failed to change ownership on directory: %v", chownErr)
				}
			}
			// Also set permissions with sudo
			chmodCmd := exec.Command("sudo", "chmod", "-R", "755", outputDir)
			if chmodErr := chmodCmd.Run(); chmodErr != nil {
				log.Printf("Warning: Failed to set permissions on directory: %v", chmodErr)
			}
			log.Printf("Successfully created directory with sudo: %s", outputDir)
		} else {
			// It's not a permission error, so return the original error
			return fmt.Errorf("failed to create output directory %s: %v", outputDir, err)
		}
	}

	// Try to find the include directories
	includeDirs := findIncludeDirs(projectDir)

	//TODO cp src/libpostal.h /usr/local/include/libpostal/
	includeLibFileSrc := filepath.Join(projectDir, "src", projectName+".h")
	includeLibDstDir := filepath.Join("/usr/local/include", projectName)
	includeLibFileDst := filepath.Join(includeLibDstDir, projectName+".h")
	if fileExists(includeLibFileSrc) && !fileExists(includeLibFileDst) {
		// Ensure the destination directory exists
		if err := os.MkdirAll(includeLibDstDir, 0755); err != nil {
			if os.IsPermission(err) {
				log.Printf("Permission denied creating %s, retrying with sudo", includeLibDstDir)
				_ = exec.Command("sudo", "mkdir", "-p", includeLibDstDir).Run()
			} else {
				log.Printf("Failed to create directory %s: %v", includeLibDstDir, err)
			}
		}
		// Copy the header, falling back to sudo on permission errors
		if err := copyFile(includeLibFileSrc, includeLibFileDst); err != nil {
			if os.IsPermission(err) {
				log.Printf("Permission denied copying %s, retrying with sudo", includeLibFileDst)
				_ = exec.Command("sudo", "cp", includeLibFileSrc, includeLibFileDst).Run()
			} else {
				log.Printf("Failed to copy %s: %v", includeLibFileSrc, err)
			}
		} else {
			log.Printf("Copied %s -> %s", includeLibFileSrc, includeLibFileDst)
		}
	}

	var includeDirSlice []string
	for _, includeDir := range collectMapKeys(&IncludeDirectories) {
		includeDirSlice = append(includeDirSlice, includeDir)
	}

	// Set up parallelism
	maxConcurrent := runtime.NumCPU() * 2 / 3 // Adjust based on your system capabilities
	if maxConcurrent < 2 {
		maxConcurrent = 1
	}
	semaphore := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup

	for _, sourceFile := range cFuzzerSourceFiles {
		wg.Add(1)
		go func(sourceFile string) {
			defer wg.Done()
			semaphore <- struct{}{} // acquire

			// Determine output filename
			baseName := filepath.Base(sourceFile)
			ext := filepath.Ext(baseName)
			baseNameWithoutExt := baseName[:len(baseName)-len(ext)]
			outputFile := filepath.Join(outputDir, baseNameWithoutExt+".bc")
			successFuzzerBC := true
			if fileExists(outputFile) {
				fmt.Printf("Fuzzer BC file already generated: %s\n", outputFile)
			} else {
				includeFlags := []string{"-emit-llvm", "-c", "-g", "-fms-extensions", "-Wno-error", "-I" + projectDir, "-I/usr/include", "-I/usr/local/include", "-I/app/include"}
				for _, dir := range includeDirs {
					includeFlags = append(includeFlags, "-I"+dir)
				}
				includeFlags = append(includeFlags, sourceFile, "-o", outputFile)

				// cmdStr := CLANG_PATH + " " + strings.Join(includeFlags, " ")
				// fmt.Printf("Executing command:\n%s\n", cmdStr)

				// Build clang command
				cmd := exec.Command(CLANG_PATH, includeFlags...)

				// Run command
				var stdout, stderr bytes.Buffer
				cmd.Stdout = &stdout
				cmd.Stderr = &stderr

				fmt.Printf("Generating bitcode for fuzzer %s -> %s\n", sourceFile, outputFile)
				err := cmd.Run()

				if err != nil {
					fmt.Printf("GenerateFuzzerBitcodeFilesAndLinkParallel Error generating bitcode for %s: %v\ncmd: %v", sourceFile, err, cmd)
					fmt.Printf("Stderr: %s\n", stderr.String())
					// Continue with next file despite error
					//trying in docker
					err := GenerateBitcodeFileInDocker(projectDir, projectName, sourceFile, outputDir, &includeDirSlice)
					if err != nil {
						successFuzzerBC = false
					} else {
						fmt.Printf("GenerateBitcodeFileInDocker successful for %s\n", outputFile)
					}
				}

			}
			if successFuzzerBC {
				LinkOneFuzzerBitcodeFiles(outputFile, fuzzerDir)
			}

			<-semaphore // release
		}(sourceFile)
	}

	wg.Wait()
	return nil
}

// GenerateBitcodeFilesParallel generates LLVM bitcode files from C/C++ source files in parallel
func GenerateBitcodeFilesParallel(projectDir string, sourceFiles []string, outputDir string) error {
	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		// Check if it's a permission error
		if os.IsPermission(err) {
			log.Printf("Permission denied when creating directory, trying with sudo: %s", outputDir)
			// Try using sudo to create the directory
			sudoCmd := exec.Command("sudo", "mkdir", "-p", outputDir)
			if sudoErr := sudoCmd.Run(); sudoErr != nil {
				return fmt.Errorf("failed to create output directory even with sudo %s: %v", outputDir, sudoErr)
			}
			// Change ownership to current user so we can write to it
			currentUser := os.Getenv("USER")
			if currentUser != "" {
				chownCmd := exec.Command("sudo", "chown", "-R", currentUser+":"+currentUser, outputDir)
				if chownErr := chownCmd.Run(); chownErr != nil {
					log.Printf("Warning: Failed to change ownership on directory: %v", chownErr)
				}
			}
			// Also set permissions with sudo
			chmodCmd := exec.Command("sudo", "chmod", "-R", "755", outputDir)
			if chmodErr := chmodCmd.Run(); chmodErr != nil {
				log.Printf("Warning: Failed to set permissions on directory: %v", chmodErr)
			}
			log.Printf("Successfully created directory with sudo: %s", outputDir)
		} else {
			// It's not a permission error, so return the original error
			return fmt.Errorf("failed to create output directory %s: %v", outputDir, err)
		}
	}

	// Try to find the include directories
	includeDirs := findIncludeDirs(projectDir)
	// Set up parallelism
	maxConcurrent := runtime.NumCPU() * 2 / 3 // Adjust based on your system capabilities
	if maxConcurrent < 2 {
		maxConcurrent = 1
	}
	semaphore := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup

	for _, sourceFile := range sourceFiles {
		wg.Add(1)
		go func(sourceFile string) {
			defer wg.Done()
			semaphore <- struct{}{} // acquire

			// Determine output filename
			baseName := filepath.Base(sourceFile)
			ext := filepath.Ext(baseName)
			baseNameWithoutExt := baseName[:len(baseName)-len(ext)]
			outputFile := filepath.Join(outputDir, baseNameWithoutExt+".bc")

			includeFlags := []string{"-emit-llvm", "-c", "-g", "-fms-extensions", "-Wno-error", "-I" + projectDir, "-I/usr/include", "-I/usr/local/include", "-I/app/include"}
			for _, dir := range includeDirs {
				includeFlags = append(includeFlags, "-I"+dir)
			}
			includeFlags = append(includeFlags, sourceFile, "-o", outputFile)

			// cmdStr := CLANG_PATH + " " + strings.Join(includeFlags, " ")
			// fmt.Printf("Executing command:\n%s\n", cmdStr)

			// Build clang command
			cmd := exec.Command(CLANG_PATH, includeFlags...)

			// Run command
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			fmt.Printf("Generating bitcode for %s -> %s\n", sourceFile, outputFile)
			err := cmd.Run()
			if err != nil {
				fmt.Printf("GenerateBitcodeFilesParallel Error generating bitcode for %s: %v\n", sourceFile, err)
				fmt.Printf("Stderr: %s\n", stderr.String())
				// Continue with next file despite error
			}

			<-semaphore // release
		}(sourceFile)
	}

	wg.Wait()

	return nil
}

// GenerateBitcodeFiles generates LLVM bitcode files from C/C++ source files
func GenerateBitcodeFiles(projectDir string, sourceFiles []string, outputDir string) error {
	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		// Check if it's a permission error
		if os.IsPermission(err) {
			log.Printf("Permission denied when creating directory, trying with sudo: %s", outputDir)

			// Try using sudo to create the directory
			sudoCmd := exec.Command("sudo", "mkdir", "-p", outputDir)
			if sudoErr := sudoCmd.Run(); sudoErr != nil {
				return fmt.Errorf("failed to create output directory even with sudo %s: %v", outputDir, sudoErr)
			}

			// Also set permissions with sudo
			chmodCmd := exec.Command("sudo", "chmod", "755", outputDir)
			if chmodErr := chmodCmd.Run(); chmodErr != nil {
				log.Printf("Warning: Failed to set permissions on directory: %v", chmodErr)
			}

			log.Printf("Successfully created directory with sudo: %s", outputDir)
		} else {
			// It's not a permission error, so return the original error
			return fmt.Errorf("failed to create output directory %s: %v", outputDir, err)
		}
	}

	// Try to find the include directories
	includeDirs := findIncludeDirs(projectDir)

	for _, sourceFile := range sourceFiles {
		// Determine output filename
		baseName := filepath.Base(sourceFile)
		ext := filepath.Ext(baseName)
		baseNameWithoutExt := baseName[:len(baseName)-len(ext)]
		outputFile := filepath.Join(outputDir, baseNameWithoutExt+".bc")

		includeFlags := []string{"-emit-llvm", "-c", "-g", "-fms-extensions", "-Wno-error", "-I" + projectDir, "-I/usr/include", "-I/usr/local/include", "-I/app/include"}
		for _, dir := range includeDirs {
			includeFlags = append(includeFlags, "-I"+dir)
		}
		includeFlags = append(includeFlags, sourceFile, "-o", outputFile)

		// cmdStr := CLANG_PATH + " " + strings.Join(includeFlags, " ")
		// fmt.Printf("Executing command:\n%s\n", cmdStr)

		// Build clang command
		cmd := exec.Command(CLANG_PATH, includeFlags...)

		// Run command
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		fmt.Printf("Generating bitcode for %s -> %s\n", sourceFile, outputFile)
		err := cmd.Run()
		if err != nil {

			fmt.Printf("GenerateBitcodeFiles Error generating bitcode for %s: %v\n", sourceFile, err)
			fmt.Printf("Stderr: %s\n", stderr.String())
			// Continue with next file despite error
			continue
		}
	}

	return nil
}

// findIncludeDirs searches for any directories named "include" under the projectDir
func findIncludeDirs(projectDir string) []string {
	var includeDirs []string

	// Walk through the project directory
	err := filepath.Walk(projectDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Printf("Error accessing path %s: %v\n", path, err)
			return nil // Continue despite errors
		}

		// Check if this is a directory named "include"
		if info.IsDir() && (info.Name() == "include" || info.Name() == "includes" || info.Name() == "lib" || info.Name() == "libs") {
			includeDirs = append(includeDirs, path)
			// fmt.Printf("Found include directory: %s\n", path)
		}

		return nil
	})

	if err != nil {
		fmt.Printf("Error walking directory tree: %v\n", err)
	}

	return includeDirs
}

// Function to find C files that are not fuzzers
func FindCFilesToAnalyze(rootDir string) ([]string, []string, error) {
	var cFilesToAnalyze []string
	var cFuzzerSourceFiles []string

	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		if isCCppFile(path) {
			isFuzzer, _, _ := isFuzzerFile(path, info)

			if isFuzzer {
				cFuzzerSourceFiles = append(cFuzzerSourceFiles, path)
			} else if strings.HasSuffix(path, ".c") && !shouldSkipFile(path) {
				cFilesToAnalyze = append(cFilesToAnalyze, path)
			}
		}

		return nil
	})

	return cFilesToAnalyze, cFuzzerSourceFiles, err
}

// Helper function to check if a file is a fuzzer based on content or name
func isFuzzerFile(path string, info os.FileInfo) (bool, bool, error) {
	// Check if file contains LLVMFuzzerTestOneInput
	hasLLVMFuzzer := false
	data, err := os.ReadFile(path)
	if err == nil && strings.Contains(string(data), "LLVMFuzzerTestOneInput") {
		hasLLVMFuzzer = true
	}

	// Check if file name indicates it's a fuzzer
	hasFuzzerName := strings.Contains(path, "_fuzzer") ||
		strings.Contains(path, "fuzz_") ||
		strings.Contains(path, "fuzz/") ||
		strings.Contains(strings.ToLower(info.Name()), "fuzz")

	return hasLLVMFuzzer || hasFuzzerName, hasLLVMFuzzer, err
}

// Helper function to check if file is a C/C++ file
func isCCppFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".c" || ext == ".cc" || ext == ".cpp"
}

// Function to find fuzzer files in a directory
func findFuzzerFiles(rootDir string, existingFuzzers []string) ([]string, error) {
	var fuzzerFiles []string

	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Printf("Error accessing path %s: %v\n", path, err)
			return nil // Continue walking despite the error
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Check if it's a C/C++ file
		if !isCCppFile(path) {
			return nil
		}

		// Check if it's a fuzzer
		isFuzzer, hasLLVMFuzzer, err := isFuzzerFile(path, info)
		if err != nil {
			fmt.Printf("Error reading file %s: %v\n", path, err)
		}

		if !isFuzzer {
			return nil
		}

		// Check for duplicates
		baseName := filepath.Base(path)
		for _, existingPath := range existingFuzzers {
			if filepath.Base(existingPath) == baseName {
				fmt.Printf("Skipping duplicate fuzzer: %s (already have %s)\n",
					path, existingPath)
				return nil
			}
		}
		// Add to list
		fuzzerFiles = append(fuzzerFiles, path)
		fmt.Printf("Found C fuzzer source: %s\n", path)
		if hasLLVMFuzzer {
			fmt.Printf("  ↳ Contains LLVMFuzzerTestOneInput\n")
		}

		return nil
	})

	return fuzzerFiles, err
}

func EngineMainCodeql(request models.AnalysisRequest) ([]models.CallPath, error) {

	// Check if project directory exists
	projectDir := request.ProjectSourceDir
	if projectDir == "" {
		return nil, fmt.Errorf("project source directory not specified")
	}

	// Create a directory with the fuzzer file
	fuzzerSourcePath := request.FuzzerSourcePath
	if fuzzerSourcePath == "" {
		return nil, fmt.Errorf("fuzzerSourcePath not specified")
	}
	// Use project name and fuzzer name as the temporary directory name
	projectName := filepath.Base(projectDir)
	fuzzerName := filepath.Base(fuzzerSourcePath)
	fuzzerName = strings.TrimSuffix(fuzzerName, filepath.Ext(fuzzerName))

	fuzzerDir := filepath.Dir(request.FuzzerSourcePath)
	taskDir := filepath.Dir(projectDir)
	taskID := request.TaskID

	// Determine if this is a Java project
	isJavaProject := false
	javaFileCount := 0

	err := filepath.Walk(projectDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and hidden files
		if info.IsDir() || strings.HasPrefix(filepath.Base(path), ".") {
			return nil
		}

		// Count Java files
		if strings.HasSuffix(strings.ToLower(path), ".java") {
			javaFileCount++
			if javaFileCount >= 5 { // Consider it a Java project if we find at least 5 Java files
				isJavaProject = true
				return filepath.SkipDir // Stop walking early
			}
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error scanning project directory: %v", err)
	}

	if !isJavaProject {
		return nil, fmt.Errorf("not a Java project or insufficient Java files found. CodeQL analysis requires Java projects")
	}

	// Extract target function information from the request
	var targetFunctions []models.TargetFunction
	for filePath, functions := range request.TargetFunctions {
		for _, funcInfo := range functions {
			targetFunctions = append(targetFunctions, models.TargetFunction{
				FilePath:     filePath,
				FunctionName: funcInfo.Name,
				StartLine:    funcInfo.StartLine,
			})
		}
	}

	// DEBUG only
	// if fuzzerName != "CompressSevenZFuzzer" {
	// 	return nil, fmt.Errorf("for debug skipping fuzzerName %s (only check CompressSevenZFuzzer)", fuzzerName)
	// }

	// Log task start
	log.Printf("Starting CodeQL analysis for project: %s fuzzerName %s", projectDir, fuzzerName)
	log.Printf("Analyzing %d target functions: %v", len(targetFunctions), targetFunctions)

	{
		tempProjectDir := filepath.Join(taskDir, projectName+"-temp")
		dirMu := getTempDirLock(tempProjectDir)
		dirMu.Lock()
		defer dirMu.Unlock()

		// Check if temporary directory already exists
		tempDirExists := false
		if _, err := os.Stat(tempProjectDir); err == nil {
			tempDirExists = true
			log.Printf("Found existing temporary directory at: %s", tempProjectDir)

			// Check if fuzzer file exists in temp directory
			targetFuzzerPath := filepath.Join(tempProjectDir, filepath.Base(fuzzerSourcePath))
			if _, err := os.Stat(targetFuzzerPath); err == nil {
				projectDir = tempProjectDir
				// Skip the rest of the copying logic
				goto SKIP_COPY
			} else {
				log.Printf("Existing temporary directory found but fuzzer file is missing, will recreate")
				tempDirExists = false
			}
		}

		// If temp directory doesn't exist or fuzzer is missing, create it
		if !tempDirExists {
			log.Printf("Creating a directory with project files and fuzzer files...")

			// Clean up any existing directory
			os.RemoveAll(tempProjectDir)

			// Create temporary directory
			if err := os.MkdirAll(tempProjectDir, 0755); err != nil {
				return nil, fmt.Errorf("failed to create temporary project directory: %v", err)
			}

			// Copy project files to temporary directory (using direct copy instead of symlinks)
			copyCmd := exec.Command("cp", "-r", projectDir+"/.", tempProjectDir)
			var copyOutput bytes.Buffer
			copyCmd.Stdout = &copyOutput
			copyCmd.Stderr = &copyOutput

			if err := copyCmd.Run(); err != nil {
				return nil, fmt.Errorf("failed to copy project files: %v", err)
			}

			// If the project has JAR files, try to extract source code
			jarFiles, _ := filepath.Glob(filepath.Join(tempProjectDir, "**/*.jar"))
			for _, jarFile := range jarFiles {
				// Check if it's a sources jar
				if strings.Contains(jarFile, "-sources") {
					extractCmd := exec.Command("jar", "xf", jarFile)
					extractCmd.Dir = tempProjectDir
					if extractErr := extractCmd.Run(); err != nil {
						log.Printf("Warning: Failed to extract sources from %s: %v", jarFile, extractErr)
					} else {
						log.Printf("Extracted sources from %s", jarFile)
					}
				}
			}

			// Check if fuzzer file exists
			_, fuzzerErr := os.Stat(fuzzerSourcePath)
			if fuzzerErr != nil {
				return nil, fmt.Errorf("fuzzer source file not found at: %s", fuzzerSourcePath)
			}

			// Copy fuzzer file to temp directory
			fuzzerFileName := filepath.Base(fuzzerSourcePath)
			targetFuzzerPath := filepath.Join(tempProjectDir, fuzzerFileName)

			// copyFuzzerCmd := exec.Command("cp", fuzzerSourcePath, targetFuzzerPath)
			copyFuzzerCmd := exec.Command("cp", "-r", fuzzerDir+"/.", tempProjectDir)
			if err := copyFuzzerCmd.Run(); err != nil {
				return nil, fmt.Errorf("failed to copy fuzzer file: %v", err)
			}

			log.Printf("Copied fuzzer file to: %s", targetFuzzerPath)

			// Use the new temporary directory as the source code root
			projectDir = tempProjectDir
			log.Printf("Using temporary project directory with fuzzer: %s", projectDir)
		}

	SKIP_COPY:
		// Continue with the rest of the code
	}

	// Create database directory in current working directory
	dbDir := taskDir + "/codeql_databases" // Create directly in current directory
	dbPath := filepath.Join(dbDir, projectName+"-temp-db-"+fuzzerName)

	log.Printf("DBPath: %s", dbPath)

	// Check if database already exists
	dbExists := false
	if _, err := os.Stat(dbPath); err == nil {
		dbExists = true
		log.Printf("Found existing CodeQL database at: %s", dbPath)
	}

	// If database doesn't exist or needs to be recreated
	if !dbExists {

		if err := os.MkdirAll(dbDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create databases directory: %v", err)
		}

		log.Printf("Creating new CodeQL database for %s...", projectName)

		// Build CodeQL database creation command
		cmdArgs := []string{
			"database", "create",
			dbPath,
			"--overwrite",
			"--language=java",
			"--source-root=" + projectDir,
			"--build-mode=none",
		}

		cmd := exec.Command("codeql", cmdArgs...)
		var output bytes.Buffer
		cmd.Stdout = &output
		cmd.Stderr = &output

		// Execute command
		if err := cmd.Run(); err != nil {
			log.Printf("CodeQL database creation output:\n%s", output.String())
			return nil, fmt.Errorf("failed to create CodeQL database: %v\nOutput: %s", err, output.String())
		}

		log.Printf("Successfully created CodeQL database at: %s", dbPath)
	} else {
		// Database already exists, use it directly
	}

	// Create temporary query directory under myqueries
	queriesDir := filepath.Join("/app/strategyx/legacy_strategy/my-queries", "temp-call-"+taskID+"-"+fuzzerName)
	if err := os.MkdirAll(queriesDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create temp queries directory: %v", err)
	}

	// Read query template
	templatePath := filepath.Join("/app/strategyx/legacy_strategy/my-queries", "callpath-template.ql")
	templateContent, err := os.ReadFile(templatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read query template: %v", err)
	}

	// Get fuzzer file name
	fuzzerFileName := filepath.Base(request.FuzzerSourcePath)

	var callPaths []models.CallPath

	// Create batch size
	batchSize := 1000

	// Process target functions in batches
	for i := 0; i < len(targetFunctions); i += batchSize {
		end := min(i+batchSize, len(targetFunctions))
		batch := targetFunctions[i:end]

		// Create combined query
		combinedQuery := createCombinedCodeQLQuery(templateContent, fuzzerFileName, batch)

		// Save the combined query
		queryFilePath := filepath.Join(queriesDir, fmt.Sprintf("combined_query_%d.ql", i/batchSize))
		if err := os.WriteFile(queryFilePath, []byte(combinedQuery), 0644); err != nil {
			log.Printf("Warning: Failed to write combined query file: %v", err)
			continue
		}

		// Execute combined query
		bqrsFilePath := filepath.Join(queriesDir, fmt.Sprintf("combined_result_%d.bqrs", i/batchSize))
		jsonFilePath := filepath.Join(queriesDir, fmt.Sprintf("combined_result_%d.json", i/batchSize))

		if false {

			// Execute query and get results
			queryCmd := exec.Command(
				"codeql", "query", "run",
				queryFilePath,
				"--database="+dbPath,
				"--output="+bqrsFilePath,
			)

			var queryOutput bytes.Buffer
			queryCmd.Stdout = &queryOutput
			queryCmd.Stderr = &queryOutput

			if err := queryCmd.Run(); err != nil {
				log.Printf("Combined query failed: %v\nOutput: %s", err, queryOutput.String())
				continue
			}
		} else {

			queryCmd := exec.Command(
				"codeql", "query", "run",
				"--timeout=120",
				"--threads=48",
				"--database="+dbPath,
				"--output="+bqrsFilePath,
				queryFilePath,
			)

			var queryOutput bytes.Buffer
			queryCmd.Stdout = &queryOutput
			queryCmd.Stderr = &queryOutput

			if err := queryCmd.Start(); err != nil {
				log.Printf("Failed to start combined query: %v", err)
				continue
			}

			done := make(chan error, 1)
			go func() { done <- queryCmd.Wait() }()

			timeout := time.After(2 * time.Minute)
			timedOut := false

			select {
			case err := <-done:
				// Query finished naturally (success or error)
				if err != nil {
					log.Printf("Combined query failed: %v\nOutput: %s", err, queryOutput.String())
					continue
				}

			case <-timeout:
				// Timeout: ask CodeQL to stop gracefully
				timedOut = true
				log.Printf("Combined query exceeded 2 minutes, sending SIGINT...")
				_ = queryCmd.Process.Signal(syscall.SIGINT)

				// Give CodeQL 30 s to flush .bqrs before killing it
				select {
				case err := <-done:
					if err != nil {
						log.Printf("Combined query (after SIGINT) returned error: %v", err)
					}
				case <-time.After(30 * time.Second):
					log.Printf("CodeQL still running; sending SIGKILL...")
					_ = queryCmd.Process.Kill()
					<-done
				}
			}

			if timedOut {
				log.Printf("Combined query timed out; partial results (if any) in %s", bqrsFilePath)
			}
		}

		if false {
			decodeCmd := exec.Command(
				"codeql", "bqrs", "decode",
				"--format=json",
				"--output="+jsonFilePath,
				bqrsFilePath,
			)

			if err := decodeCmd.Run(); err != nil {
				log.Printf("BQRS decode failed: %v", err)
				continue
			}
		} else {

			log.Printf("Codeql Decode: %s\n", bqrsFilePath)

			decodeCmd := exec.Command(
				"codeql", "bqrs", "decode",
				"--format=json",
				"--output="+jsonFilePath,
				bqrsFilePath,
			)

			var decodeOutput bytes.Buffer
			decodeCmd.Stdout = &decodeOutput
			decodeCmd.Stderr = &decodeOutput

			if err := decodeCmd.Start(); err != nil {
				log.Printf("Failed to start BQRS decode: %v", err)
				continue
			}

			decodeDone := make(chan error, 1)
			go func() { decodeDone <- decodeCmd.Wait() }()

			decodeTimeout := time.After(1 * time.Minute) // adjust if needed
			decodeTimedOut := false

			select {
			case err := <-decodeDone:
				if err != nil {
					log.Printf("BQRS decode failed: %v\nOutput: %s", err, decodeOutput.String())
					continue
				}

			case <-decodeTimeout:
				decodeTimedOut = true
				log.Printf("BQRS decode exceeded 1 minute, sending SIGINT...")
				_ = decodeCmd.Process.Signal(syscall.SIGINT)

				// give CodeQL a short grace period to finish flushing JSON
				select {
				case err := <-decodeDone:
					if err != nil {
						log.Printf("BQRS decode (after SIGINT) returned error: %v", err)
					}
				case <-time.After(15 * time.Second):
					log.Printf("BQRS decode still running; sending SIGKILL...")
					_ = decodeCmd.Process.Kill()
					<-decodeDone
				}
			}

			if decodeTimedOut {
				log.Printf("BQRS decode timed out; partial JSON (if any) left in %s", jsonFilePath)
			}

		}

		resultData, err := os.ReadFile(jsonFilePath)
		if err != nil {
			log.Printf("Failed to read query results: %v", err)
			continue
		}

		paths, err := parseCodeQLResults(resultData, projectDir, batch)
		if err != nil {
			log.Printf("Failed to parse results: %v", err)
			continue
		}

		callPaths = append(callPaths, paths...)
	}

	return callPaths, nil
}

func createCombinedCodeQLQuery(templateContent []byte, fuzzerFileName string, targetFunctions []models.TargetFunction) string {
	// Base query template
	baseQuery := string(templateContent)

	// Build target method conditions
	var targetConditions []string
	for _, tf := range targetFunctions {
		targetFileName := filepath.Base(tf.FilePath)
		if !strings.HasSuffix(targetFileName, ".java") {
			targetFileName += ".java"
		}

		condition := fmt.Sprintf(
			`(targetMethod.getName() = "%s" and targetMethod.getLocation().getFile().getBaseName() = "%s")`,
			tf.FunctionName,
			targetFileName,
		)
		targetConditions = append(targetConditions, condition)

		// if len(targetConditions) > 5 {
		// 	break
		// }
	}

	// Combine all target conditions with OR
	combinedTargetCondition := strings.Join(targetConditions, " or\n    ")

	// Replace placeholders in template
	modifiedQuery := strings.Replace(baseQuery,
		`targetMethod.getName() = "{{TARGET_METHOD}}" and`,
		"("+combinedTargetCondition+") and",
		-1)

	// Replace source file and method placeholders
	modifiedQuery = strings.Replace(modifiedQuery, "{{SOURCE_FILE}}", fuzzerFileName, -1)
	modifiedQuery = strings.Replace(modifiedQuery, "{{SOURCE_METHOD}}", "fuzzerTestOneInput", -1)

	return modifiedQuery
}

func parseCodeQLResults(resultData []byte, projectDir string, targetFunctions []models.TargetFunction) ([]models.CallPath, error) {
	var codeqlResult struct {
		Select struct {
			Columns []struct {
				Name string `json:"name"`
				Kind string `json:"kind"`
			} `json:"columns"`
			Tuples [][]interface{} `json:"tuples"`
		} `json:"#select"`
	}

	if err := json.Unmarshal(resultData, &codeqlResult); err != nil {
		return nil, fmt.Errorf("failed to parse query results: %v", err)
	}

	var callPaths []models.CallPath

	// Check if there are results
	if len(codeqlResult.Select.Tuples) == 0 {
		log.Printf("No call paths found for target functions")
		return nil, nil
	}

	log.Printf("Found %d call paths for target functions", len(codeqlResult.Select.Tuples))

	// Convert to CallPath format
	for _, tuple := range codeqlResult.Select.Tuples {
		if len(tuple) < 6 {
			log.Printf("Warning: Unexpected tuple format, expected at least 6 elements, got %d", len(tuple))
			continue
		}

		// Extract values from the tuple, note type conversions
		callPathStr, ok1 := tuple[0].(string)
		_, ok2 := tuple[1].(float64)
		locationsStr, ok3 := tuple[2].(string)
		sourceFile, ok4 := tuple[3].(string)
		sourceLine, ok5 := tuple[4].(float64)
		targetFile, ok6 := tuple[5].(string)
		targetLine, ok7 := tuple[6].(float64)

		if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 || !ok7 {
			log.Printf("Warning: Failed to extract values from tuple, skipping")
			continue
		}

		// Convert floats to integers
		sourceLineInt := int(sourceLine)
		targetLineInt := int(targetLine)
		// depth := int(depthFloat)
		// log.Printf("Found call path with depth %d: %s", depth, callPathStr)

		// Parse method names in the call path
		methodNames := strings.Split(callPathStr, " -> ")

		// Parse location information string
		locationParts := strings.Split(locationsStr, "|")
		methodLocations := make([]struct {
			FilePath string
			Line     int
		}, len(methodNames))

		// Ensure location info and method names count match
		if len(locationParts) != len(methodNames) {
			log.Printf("Warning: Location parts count (%d) doesn't match method names count (%d)",
				len(locationParts), len(methodNames))
			// Use default line numbers
			for i := range methodNames {
				if i == 0 {
					methodLocations[i] = struct {
						FilePath string
						Line     int
					}{sourceFile, sourceLineInt}
				} else if i == len(methodNames)-1 {
					methodLocations[i] = struct {
						FilePath string
						Line     int
					}{targetFile, targetLineInt}
				} else {
					methodLocations[i] = struct {
						FilePath string
						Line     int
					}{"Unknown", 0}
				}
			}
		} else {
			// Parse each method's location information
			for i, locPart := range locationParts {
				parts := strings.Split(locPart, ":")
				if len(parts) != 2 {
					continue
				}

				filePath := parts[0]
				line, err := strconv.Atoi(parts[1])
				if err != nil {
					line = 0
				}

				methodLocations[i] = struct {
					FilePath string
					Line     int
				}{filePath, line}
			}
		}

		// Create CallPath object
		callPath := models.CallPath{
			Target: filepath.Join(projectDir, targetFile),
			Nodes:  make([]models.CallPathNode, 0, len(methodNames)),
		}

		// Create nodes for each method
		for i, methodName := range methodNames {
			location := methodLocations[i]

			// Extract complete method source code
			var body string
			if location.FilePath != "Unknown" && location.Line > 0 {
				fullPath := filepath.Join(projectDir, location.FilePath)
				if fileExists(fullPath) {
					// log.Printf("File exists: %s", fullPath)

					// Read the entire file content
					fileContent, err := os.ReadFile(fullPath)
					if err == nil {
						// log.Printf("Successfully read file (%d bytes)", len(fileContent))
						// log.Printf("Method Name: %s", methodName)

						// Use more robust method to extract the complete method body
						// Using the same logic as JavaFunctionVisitor.EnterMethodDeclaration
						sourceLines := strings.Split(string(fileContent), "\n")
						methodStartLine := max(0, location.Line-1)                  // Position may have slight offset
						methodEndLine := min(len(sourceLines), methodStartLine+100) // Initial assumption: method under 100 lines

						// Find method start and end positions
						bracketCount := 0
						foundStart := false
						actualStartLine := methodStartLine
						actualEndLine := methodEndLine

						// Extract simple method name from fully qualified name
						simpleMethodName := methodName
						if strings.Contains(methodName, ".") {
							parts := strings.Split(methodName, ".")
							simpleMethodName = parts[len(parts)-1]
							// log.Printf("Using simple method name '%s' from fully qualified name '%s'",
							// 		simpleMethodName, methodName)
						}

						// Search downward from the potential start line to find the method body
						for i := methodStartLine; i < min(len(sourceLines), methodStartLine+20); i++ {
							if strings.Contains(sourceLines[i], simpleMethodName) &&
								(strings.Contains(sourceLines[i], "(") ||
									(i+1 < len(sourceLines) && strings.Contains(sourceLines[i+1], "("))) {
								actualStartLine = i
								foundStart = true
								// log.Printf("  Found method definition at line %d: %s", i+1, sourceLines[i])
								break
							}
						}

						if foundStart {
							// Find the end of the method body
							for i := actualStartLine; i < len(sourceLines); i++ {
								line := sourceLines[i]
								bracketCount += strings.Count(line, "{") - strings.Count(line, "}")

								if bracketCount <= 0 && strings.Contains(line, "}") {
									actualEndLine = i
									break
								}

								// Prevent excessively long methods
								if i > actualStartLine+500 {
									actualEndLine = i
									break
								}
							}

							// Extract the method body
							if actualEndLine >= actualStartLine {
								methodBody := sourceLines[actualStartLine : actualEndLine+1]
								body = strings.Join(methodBody, "\n")

								// Print the full method body (limit to first 1000 chars if too long)
								// if len(body) > 1000 {
								// 	log.Printf("DEBUG: Extracted method body for %s (truncated):\n%s...\n[Total: %d chars]",
								// 	simpleMethodName, body[:1000], len(body))
								// } else {
								// 	log.Printf("DEBUG: Extracted method body for %s:\n%s", simpleMethodName, body)
								// }
							}
						}
					}
				}
			}

			// Create node
			node := models.CallPathNode{
				Function:   methodName,
				File:       location.FilePath,
				Line:       fmt.Sprintf("%d", location.Line),
				Body:       body,
				IsModified: i == len(methodNames)-1, // Mark target method as modified
			}

			callPath.Nodes = append(callPath.Nodes, node)
		}

		// Add to result list
		callPaths = append(callPaths, callPath)
	}

	// // If we have enough paths, stop analyzing other target functions
	// if len(callPaths) >= 20 {
	// 	break
	// }

	if len(callPaths) == 0 {
		log.Printf("No call paths found for any target functions")
	} else {
		log.Printf("Analysis complete. Found %d call paths across all target functions", len(callPaths))
	}

	return callPaths, nil
}

// Generate all possible paths
func EngineMainAnalysisCodeql(taskDetail models.TaskDetail, taskDir, projectDir, fuzzerDir0 string, fuzzerFiles []string) (models.CodeqlAnalysisResults, error) {
	// Initialize the result structure
	results := models.CodeqlAnalysisResults{
		Functions:          make(map[string]*models.FunctionDefinition),
		ReachableFunctions: make(map[string][]string),
		Paths:              make(map[string]map[string][][]string),
	}

	log.Printf("Project directory: %s", projectDir)
	// fuzzerDir contains all the Fuzzer Java source files
	// log.Printf("Fuzzer source directory: %s", fuzzerDir)
	log.Printf("Taskdir directory: %s", taskDir)

	taskID := taskDetail.TaskID.String()

	// Extract the base name from the project directory path to use as the output file name
	projectBase := filepath.Base(projectDir)
	outputJson0 := filepath.Join(taskDir, fmt.Sprintf("%s.json", projectBase))
	outputJson := filepath.Join(taskDir, fmt.Sprintf("%s_qx.json", projectBase))
	// Check if existing analysis results exist
	if fileExists(outputJson) {
		// Attempt to load existing results
		log.Printf("Found existing analysis results at %s, loading...", outputJson)
		fileData, err := os.ReadFile(outputJson)
		if err == nil {
			err = json.Unmarshal(fileData, &results)
			if err == nil {
				log.Printf("Successfully loaded existing Codeql analysis results with %d functions and %d target paths",
					len(results.Functions), len(results.Paths))

				if results.Functions == nil {
					results.Functions = make(map[string]*models.FunctionDefinition)
				}
				if results.Paths == nil {
					results.Paths = make(map[string]map[string][][]string)
				}

				return results, nil
			}
			log.Printf("Warning: Failed to parse existing results file: %v", err)
		} else {
			log.Printf("Warning: Failed to read existing results file: %v", err)
		}
		log.Printf("Proceeding with fresh analysis due to loading errors")
	} else {
		log.Printf("No existing analysis results found at %s, performing fresh analysis", outputJson)
	}

	log.Printf("Output JSON will be saved to %s", outputJson)

	// Record the start time
	startTime := time.Now()

	// =============================================
	// Add custom analysis logic here
	// =============================================

	if projectDir == "" {
		return results, fmt.Errorf("project source directory is empty")
	}

	if !dirExists(projectDir) {
		log.Printf("WARNING: Project directory does not exist: %s", projectDir)
		return results, fmt.Errorf("project directory does not exist: %s", projectDir)
	}

	log.Printf("Starting CodeQL analysis for project: %s", projectDir)

	tempProjectDir := filepath.Join(taskDir, projectBase+"-temp")
	log.Printf("Creating temporary project directory: %s", tempProjectDir)

	tempDirExists := dirExists(tempProjectDir)
	if !tempDirExists {
		if err := os.MkdirAll(tempProjectDir, 0755); err != nil {
			return results, fmt.Errorf("failed to create temporary project directory: %v", err)
		}

		log.Printf("Copying project files from %s to %s", projectDir, tempProjectDir)
		copyCmd := exec.Command("cp", "-r", projectDir+"/.", tempProjectDir)
		var copyOutput bytes.Buffer
		copyCmd.Stdout = &copyOutput
		copyCmd.Stderr = &copyOutput

		if err := copyCmd.Run(); err != nil {
			log.Printf("Copy command output:\n%s", copyOutput.String())
			return results, fmt.Errorf("failed to copy project files: %v\nOutput: %s", err, copyOutput.String())
		}
		log.Printf("Successfully copied project files to temporary directory")

		{
			fuzzerTempDir := filepath.Join(tempProjectDir, "fuzzers")
			log.Printf("Creating fuzzer directory: %s", fuzzerTempDir)
			if err := os.MkdirAll(fuzzerTempDir, 0755); err != nil {
				log.Printf("WARNING: Failed to create fuzzer temp directory: %v", err)
			} else {
				log.Printf("Copying fuzzer files to %s", fuzzerTempDir)

				for _, fuzzerFile := range fuzzerFiles {
					srcPath := fuzzerFile
					dstPath := filepath.Join(fuzzerTempDir, filepath.Base(fuzzerFile))
					if errCopy := copyFile(srcPath, dstPath); errCopy != nil {
						log.Printf("WARNING: Failed to copy from %s to %s: %v", srcPath, dstPath, err)
					} else {
						log.Printf("Copied %s to %s", srcPath, dstPath)
					}
				}
			}
		}
	} else {
		log.Printf("Using existing temporary project directory: %s", tempProjectDir)
	}

	projectName := filepath.Base(tempProjectDir)
	dbDir := taskDir + "/codeql_databases"
	masterDbPath := filepath.Join(dbDir, projectName+"-db")

	log.Printf("MasterDBPath: %s", masterDbPath)

	if err := os.MkdirAll(dbDir, 0755); err != nil {
		return results, fmt.Errorf("failed to create databases directory: %v", err)
	}

	dbExists := false
	if _, err := os.Stat(masterDbPath); err == nil {
		dbExists = true
		log.Printf("Found existing CodeQL database at: %s", masterDbPath)
	}

	jvmOpts := "-Xmx48G -XX:MaxDirectMemorySize=128G"
	os.Setenv("CODEQL_JAVA_OPTS", jvmOpts)

	if !dbExists {
		log.Printf("Creating new CodeQL database for %s...", projectName)

		// 构建CodeQL数据库创建命令
		cmdArgs := []string{
			"database", "create",
			masterDbPath,
			"--overwrite",
			"--language=java",
			"--source-root=" + tempProjectDir,
			"--build-mode=none",
		}

		cmd := exec.Command("codeql", cmdArgs...)
		cmd.Env = append(os.Environ(), fmt.Sprintf("CODEQL_JAVA_OPTS=%s", jvmOpts))

		var output bytes.Buffer
		cmd.Stdout = &output
		cmd.Stderr = &output

		if err := cmd.Run(); err != nil {
			log.Printf("CodeQL database creation output:\n%s", output.String())
			return results, fmt.Errorf("failed to create CodeQL database: %v\nOutput: %s", err, output.String())
		}

		log.Printf("Successfully created CodeQL database at: %s", masterDbPath)
	}

	log.Printf("Found %d fuzzer files", len(fuzzerFiles))

	numFuzzers := len(fuzzerFiles)
	log.Printf("Preparing to create %d copies of the master database...", numFuzzers)
	dbCopyPaths := make([]string, numFuzzers) // Store paths to the copies

	for i, fuzzerSourcePath := range fuzzerFiles {
		fuzzerName := filepath.Base(fuzzerSourcePath)
		fuzzerName = strings.TrimSuffix(fuzzerName, filepath.Ext(fuzzerName))
		// Handle potential empty fuzzer names if paths are weird
		if fuzzerName == "" {
			log.Printf("Warning: Could not derive fuzzer name from path '%s' for DB copy, skipping index %d", fuzzerSourcePath, i)
			// Mark this path as invalid or handle differently? For now, skip creation.
			dbCopyPaths[i] = "" // Mark as invalid or empty
			continue
		}

		// Define the path for this specific copy
		dbCopyPaths[i] = fmt.Sprintf("%s-%s", masterDbPath, fuzzerName)

		log.Printf("Copying master database to: %s (for fuzzer '%s')", dbCopyPaths[i], fuzzerName)

		// Remove any existing old copy first
		_ = os.RemoveAll(dbCopyPaths[i]) // Ignore error if it doesn't exist

		// Use 'cp -r' for robust directory copying
		copyCmd := exec.Command("cp", "-r", masterDbPath, dbCopyPaths[i])
		var copyOutput bytes.Buffer
		copyCmd.Stdout = &copyOutput
		copyCmd.Stderr = &copyOutput

		copyStartTime := time.Now()
		if err := copyCmd.Run(); err != nil {
			log.Printf("Failed to copy database for fuzzer %d to %s after %v. Output:\n%s", i, dbCopyPaths[i], time.Since(copyStartTime), copyOutput.String())
			// Decide if you want to return an error or just log and skip this fuzzer
			// For now, let's return an error as processing might fail later
			// Clean up already created copies before returning? Optional.
			for j := 0; j < i; j++ { // Clean up successful copies before this one
				os.RemoveAll(dbCopyPaths[j])
			}
			return results, fmt.Errorf("failed to copy database for index %d: %v", i, err)
		}
		log.Printf("Successfully copied database for fuzzer %d (took %v)", i, time.Since(copyStartTime))
	}
	log.Printf("Finished creating %d database copies.", numFuzzers)
	// --- End Database Copying ---

	// Read the template file
	templatePath := filepath.Join("/app/strategyx/legacy_strategy/my-queries", "call-template.ql")
	templateContent, err := os.ReadFile(templatePath)
	if err != nil {
		return results, fmt.Errorf("failed to read template file: %v", err)
	}

	var wg sync.WaitGroup // Use WaitGroup to wait for all goroutines
	var resultsMutex sync.Mutex
	// Generate and execute a query for each fuzzer file
	for i, fuzzerPath := range fuzzerFiles {

		currentDbPath := dbCopyPaths[i]
		if currentDbPath == "" {
			log.Printf("Skipping fuzzer '%s' due to previous DB copy naming/creation issue.", fuzzerPath)
			continue // Skip this iteration if DB path is invalid
		}

		wg.Add(1) // Increment counter before launching goroutine

		go func(fuzzerIdx int, currentFuzzerPath string, currentDbPath string) {
			defer wg.Done() // Decrement counter when goroutine finishes

			fuzzerName := filepath.Base(fuzzerPath)
			fuzzerName = strings.TrimSuffix(fuzzerName, ".java")

			log.Printf("Processing fuzzer: %s", fuzzerName)

			// Create the query directory
			queriesDir := filepath.Join("/app/strategyx/legacy_strategy/my-queries", "temp-call-"+taskID+"-"+fuzzerName)
			if err := os.MkdirAll(queriesDir, 0755); err != nil {
				log.Printf("failed to create queries directory: %v", err)
				return
			}

			query := string(templateContent)
			query = strings.ReplaceAll(query, "FUZZER_CLASS_NAME", fuzzerName)

			queryFilePath := filepath.Join(queriesDir, fmt.Sprintf("query_%s.ql", fuzzerName))
			if err := os.WriteFile(queryFilePath, []byte(query), 0644); err != nil {
				log.Printf("Warning: Failed to write query file for %s: %v", fuzzerName, err)
				return
			}

			bqrsFilePath := filepath.Join(queriesDir, fmt.Sprintf("result_%s.bqrs", fuzzerName))
			jsonFilePath := filepath.Join(queriesDir, fmt.Sprintf("result_%s.json", fuzzerName))

			log.Printf("Executing CodeQL query for %s...", fuzzerName)
			queryCmd := exec.Command(
				"codeql", "query", "run",
				queryFilePath,
				"--database="+currentDbPath,
				"--output="+bqrsFilePath,
			)
			queryCmd.Env = append(os.Environ(), fmt.Sprintf("CODEQL_JAVA_OPTS=%s", jvmOpts))

			var queryOutput bytes.Buffer
			queryCmd.Stdout = &queryOutput
			queryCmd.Stderr = &queryOutput

			if err := queryCmd.Run(); err != nil {
				log.Printf("Query failed for %s: %v\nOutput: %s", fuzzerName, err, queryOutput.String())
				return
			}

			if _, err := os.Stat(bqrsFilePath); os.IsNotExist(err) {
				log.Printf("Query did not produce BQRS results for %s", fuzzerName)
				return
			}

			decodeCmd := exec.Command(
				"codeql", "bqrs", "decode",
				"--format=json",
				"--output="+jsonFilePath,
				bqrsFilePath,
			)
			decodeCmd.Env = append(os.Environ(), fmt.Sprintf("CODEQL_JAVA_OPTS=%s", jvmOpts))

			var decodeOutput bytes.Buffer
			decodeCmd.Stdout = &decodeOutput
			decodeCmd.Stderr = &decodeOutput

			if err := decodeCmd.Run(); err != nil {
				log.Printf("BQRS decode failed for %s: %v\nOutput: %s", fuzzerName, err, decodeOutput.String())
				return
			}

			if _, err := os.Stat(jsonFilePath); os.IsNotExist(err) {
				log.Printf("BQRS decode did not produce JSON file for %s", fuzzerName)
				return
			}

			log.Printf("Successfully processed results for fuzzer: %s", fuzzerName)

			log.Printf("Now finding code paths for fuzzer %s...", fuzzerName)

			processFuzzerFile(fuzzerIdx, fuzzerPath, fuzzerFiles, queriesDir, &results, &resultsMutex, taskDetail, projectDir)

		}(i, fuzzerPath, currentDbPath) // Pass index and specific DB path

	}

	wg.Wait()
	// log.Printf("Finished processing all %d fuzzer files.", len(fuzzerFiles))

	// log.Printf("Now finding code paths for %d fuzzers in parallel...", len(fuzzerFiles))

	// for fuzzerIndex, fuzzerPath := range fuzzerFiles {
	// 	processFuzzerFile(fuzzerIndex, fuzzerPath, fuzzerFiles, queriesDir, &results, taskDetail, projectDir)
	// }

	log.Printf("Completed analysis of all %d fuzzer files", len(fuzzerFiles))

	// =============================================
	if fileExists(outputJson0) {
		// Post-process: copy SourceCode (and line information) from the
		// “full” analysis results into the QX-only result we have just
		// produced.  This avoids empty SourceCode fields in the API.
		var prev struct {
			Functions map[string]*models.FunctionDefinition `json:"functions"`
		}
		if raw, err := os.ReadFile(outputJson0); err == nil {
			if err := json.Unmarshal(raw, &prev); err == nil {
				// Build reverse index keyed by "<fileBase>:<Name>"
				lookup := make(map[string]*models.FunctionDefinition)
				for _, pf := range prev.Functions {
					if pf != nil && pf.SourceCode != "" {
						key := filepath.Base(pf.FilePath) + ":" + pf.Name
						lookup[key] = pf
					}
				}

				filled := 0
				for _, fn := range results.Functions {
					if fn == nil || fn.SourceCode != "" {
						continue
					}

					key := filepath.Base(fn.FilePath) + ":" + fn.Name
					src := lookup[key]

					// Fallback: same name and path-suffix match
					if src == nil {
						for _, pf := range lookup {
							if pf.Name == fn.Name &&
								(strings.HasSuffix(pf.FilePath, fn.FilePath) ||
									strings.HasSuffix(fn.FilePath, pf.FilePath)) {
								src = pf
								break
							}
						}
					}

					if src != nil {
						fn.SourceCode = src.SourceCode
						fn.StartLine = src.StartLine
						fn.EndLine = src.EndLine
						if fn.FilePath == "" {
							fn.FilePath = src.FilePath
						}
						filled++
					}
				}

				if filled > 0 {
					log.Printf("Enriched %d function definitions with source from %s", filled, outputJson0)
				}
			} else {
				log.Printf("WARNING: cannot parse %s: %v", outputJson0, err)
			}
		} else {
			log.Printf("WARNING: cannot read %s: %v", outputJson0, err)
		}
	}

	// Calculate the analysis duration
	elapsedTime := time.Since(startTime)
	// log.Printf("CodeQL Analysis completed in %v", elapsedTime)

	// Save the result statistics
	// log.Printf("Analysis results: %d functions, %d paths",
	// len(results.Functions), len(results.Paths))

	// log.Printf("Saving results to %s", outputJson)
	// log.Printf("POST-PROCESS map address: %p", results.Functions)
	jsonData, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		log.Printf("Error marshaling JSON: %v", err)
	} else {
		err = os.WriteFile(outputJson, jsonData, 0644)
		if err != nil {
			log.Printf("Error writing JSON file: %v", err)
		} else {
			log.Printf("[CodeQL] Analysis completed in %v. Results written to %s",
				elapsedTime, outputJson)
		}
	}

	return results, nil
}

func processFuzzerFile(
	fuzzerIndex int,
	fuzzerPath string,
	fuzzerFiles []string,
	queriesDir string,
	results *models.CodeqlAnalysisResults,
	resultsMutex *sync.Mutex,
	taskDetail models.TaskDetail,
	projectDir string,
) {
	fuzzerName := filepath.Base(fuzzerPath)
	fuzzerName = strings.TrimSuffix(fuzzerName, ".java")

	log.Printf("Processing fuzzer %d/%d: %s", fuzzerIndex+1, len(fuzzerFiles), fuzzerName)

	var fuzzerTargetFunctions []models.TargetFunction
	fuzzerCollectedFuncMap := make(map[string]bool)

	jsonFilePath := filepath.Join(queriesDir, fmt.Sprintf("result_%s.json", fuzzerName))

	if !fileExists(jsonFilePath) {
		log.Printf("No JSON results file found for %s, skipping path analysis", fuzzerName)
		return
	}

	data, err := os.ReadFile(jsonFilePath)
	if err != nil {
		log.Printf("Failed to read JSON results for %s: %v", fuzzerName, err)
		return
	}

	var codeqlResult struct {
		Select struct {
			Columns []struct {
				Name string `json:"name"`
				Kind string `json:"kind"`
			} `json:"columns"`
			Tuples [][]interface{} `json:"tuples"`
		} `json:"#select"`
	}

	if err := json.Unmarshal(data, &codeqlResult); err != nil {
		log.Printf("Failed to parse JSON results for %s: %v", fuzzerName, err)
		return
	}

	if len(codeqlResult.Select.Tuples) == 0 {
		log.Printf("No function call results found for %s", fuzzerName)
		return
	}

	log.Printf("Found %d function call results for %s", len(codeqlResult.Select.Tuples), fuzzerName)

	for _, tuple := range codeqlResult.Select.Tuples {
		if len(tuple) < 2 {
			continue
		}

		functionName, ok := tuple[0].(string)
		if !ok {
			continue
		}

		var filePath string
		if msg, ok := tuple[1].(string); ok {
			if strings.Contains(msg, "in file:") {
				parts := strings.Split(msg, "in file:")
				if len(parts) > 1 {
					filePath = strings.TrimSpace(parts[1])
				}
			}
		}

		functionName = strings.ReplaceAll(functionName, "<", "_of_")
		functionName = strings.ReplaceAll(functionName, ">", "")

		// add Reachable
		resultsMutex.Lock()
		if results.ReachableFunctions == nil {
			results.ReachableFunctions = make(map[string][]string)
		}

		if _, exists := results.ReachableFunctions[fuzzerName]; !exists {
			results.ReachableFunctions[fuzzerName] = make([]string, 0)
		}
		results.ReachableFunctions[fuzzerName] = append(results.ReachableFunctions[fuzzerName], functionName)
		resultsMutex.Unlock()

		if strings.HasSuffix(filePath, ".class") {
			log.Printf("Skipping class file: %s for function: %s", filePath, functionName)
			continue
		}

		simpleFuncName := functionName
		if lastDotIndex := strings.LastIndex(functionName, "."); lastDotIndex != -1 {
			simpleFuncName = functionName[lastDotIndex+1:]
		}

		funcKey := filePath + ":" + simpleFuncName
		if !fuzzerCollectedFuncMap[funcKey] {
			fuzzerCollectedFuncMap[funcKey] = true

			fuzzerTargetFunctions = append(fuzzerTargetFunctions, models.TargetFunction{
				FilePath:     filePath,
				FunctionName: simpleFuncName,
				StartLine:    1,
			})

			qualifiedFuncName := functionName
			resultsMutex.Lock()
			if _, exists := results.Functions[qualifiedFuncName]; !exists {
				results.Functions[qualifiedFuncName] = &models.FunctionDefinition{
					Name:       simpleFuncName,
					FilePath:   filePath,
					StartLine:  1,
					EndLine:    1,
					SourceCode: "",
				}
			}
			resultsMutex.Unlock()
		}
	}

	log.Printf("Collected %d unique target functions for fuzzer %s", len(fuzzerTargetFunctions), fuzzerName)

	if results.Paths[fuzzerName] == nil {
		results.Paths[fuzzerName] = make(map[string][][]string)
	}

	fuzzerTargetFunctionsMap := make(map[string][]models.FunctionInfo)
	for _, tf := range fuzzerTargetFunctions {
		fuzzerTargetFunctionsMap[tf.FilePath] = append(fuzzerTargetFunctionsMap[tf.FilePath], models.FunctionInfo{
			Name:      tf.FunctionName,
			StartLine: tf.StartLine,
		})
	}

	if len(fuzzerTargetFunctionsMap) == 0 {
		log.Printf("No target functions for fuzzer %s, skipping path analysis", fuzzerName)
		return
	}

	codeqlRequest := models.AnalysisRequest{
		TaskID:           taskDetail.TaskID.String(),
		Focus:            taskDetail.Focus,
		ProjectSourceDir: projectDir,
		FuzzerSourcePath: fuzzerPath,
		TargetFunctions:  fuzzerTargetFunctionsMap,
	}

	log.Printf("Calling EngineMainCodeql for fuzzer %s with %d target files",
		fuzzerName, len(fuzzerTargetFunctionsMap))

	// Call EngineMainCodeql to perform path analysis
	callPaths, err := EngineMainCodeql(codeqlRequest)
	if err != nil {
		log.Printf("Error from EngineMainCodeql for fuzzer %s: %v", fuzzerName, err)
		return
	}

	log.Printf("Found %d call paths for fuzzer %s", len(callPaths), fuzzerName)

	// Process the returned call paths
	for _, path := range callPaths {
		targetPath := path.Target

		if len(path.Nodes) == 0 {
			continue
		}

		var pathNodes []string
		lastNode := path.Nodes[len(path.Nodes)-1]
		targetFunc := lastNode.Function

		for _, node := range path.Nodes {
			pathNodes = append(pathNodes, node.Function)
		}

		pathComponents := strings.Split(targetPath, "/")
		fileName := pathComponents[len(pathComponents)-1]
		fileName = strings.TrimSuffix(fileName, ".java")

		var qualifiedName string
		if strings.Contains(targetFunc, ".") {
			qualifiedName = targetFunc
		} else {
			packageName := ""
			for i := 0; i < len(pathComponents)-1; i++ {
				if packageName != "" {
					packageName += "."
				}
				packageName += pathComponents[i]
			}
			if packageName != "" {
				qualifiedName = packageName + "." + fileName + "." + targetFunc
			} else {
				qualifiedName = fileName + "." + targetFunc
			}
		}

		qualifiedName = strings.ReplaceAll(qualifiedName, "<", "_of_")
		qualifiedName = strings.ReplaceAll(qualifiedName, ">", "")

		resultsMutex.Lock()
		if _, exists := results.Functions[qualifiedName]; exists {
			if lastNode.Body != "" && results.Functions[qualifiedName].SourceCode == "" {
				results.Functions[qualifiedName].SourceCode = lastNode.Body
			}

			if lineStr := lastNode.Line; lineStr != "" && results.Functions[qualifiedName].StartLine <= 1 {
				if lineNum, err := strconv.Atoi(lineStr); err == nil {
					results.Functions[qualifiedName].StartLine = lineNum
					lineCount := strings.Count(lastNode.Body, "\n") + 1
					results.Functions[qualifiedName].EndLine = lineNum + lineCount
				}
			}
		} else {
			lineNum := 1
			if lineStr := lastNode.Line; lineStr != "" {
				if n, err := strconv.Atoi(lineStr); err == nil {
					lineNum = n
				}
			}

			results.Functions[qualifiedName] = &models.FunctionDefinition{
				Name:       targetFunc,
				FilePath:   lastNode.File,
				StartLine:  lineNum,
				EndLine:    lineNum + strings.Count(lastNode.Body, "\n") + 1,
				SourceCode: lastNode.Body,
			}
		}
		resultsMutex.Unlock()

		if len(pathNodes) > 0 {
			if results.Paths[fuzzerName][qualifiedName] == nil {
				results.Paths[fuzzerName][qualifiedName] = make([][]string, 0)
			}

			pathStr := strings.Join(pathNodes, "|")
			isDuplicate := false
			for _, existingPath := range results.Paths[fuzzerName][qualifiedName] {
				if strings.Join(existingPath, "|") == pathStr {
					isDuplicate = true
					break
				}
			}

			if !isDuplicate {
				results.Paths[fuzzerName][qualifiedName] = append(
					results.Paths[fuzzerName][qualifiedName], pathNodes)
			}
		}
	}

	log.Printf("Completed analysis for fuzzer %d/%d: %s",
		fuzzerIndex+1, len(fuzzerFiles), fuzzerName)
}

func normaliseAnalysisPath(fp string) string {

	// fmt.Println("normaliseAnalysisPath:", fp)

	// Remove leading WORK_DIR + “/”.
	rel := strings.TrimPrefix(fp, filepath.Clean(WORK_DIR))
	rel = strings.TrimPrefix(rel, string(filepath.Separator)) // drop leading “/”

	// expected layout now:  <taskdir>/<rest‑of‑path>
	parts := strings.SplitN(rel, string(filepath.Separator), 2)
	if len(parts) != 2 {
		// unexpected, give up
		fmt.Println("unexpected, give up:", fp)
		return fp
	}
	taskDirRaw, rest := parts[0], parts[1]

	// Convert  <uuid>-YYYYMMDD-HHMMSS  →  <uuid>
	uuidPart := taskDirRaw
	if segments := strings.Split(taskDirRaw, "-"); len(segments) > 5 {
		// a UUID is exactly 5 dash‑separated segments;
		// anything after that is the date‑time suffix
		uuidPart = strings.Join(segments[:5], "-")
	}
	// Build the corrected path.
	corrected := filepath.Join(WORK_DIR, uuidPart, rest)

	if !fileExists(corrected) {
		var tryPath string
		if strings.Contains(corrected, "-memory") {
			tryPath = strings.Replace(corrected, "-memory/", "-address/", 1)
		} else if strings.Contains(corrected, "-undefined") {
			tryPath = strings.Replace(corrected, "-undefined/", "-address/", 1)
		}
		if tryPath != "" && fileExists(tryPath) {
			corrected = tryPath
		}
	}

	// fmt.Println("Corrected AnalysisPath:", corrected)
	return corrected
}

func EngineMainFunMeta(request models.FunMetaRequest, results *models.AnalysisResults) (map[string]models.FunctionMetaInfo, error) {
	funMeta := make(map[string]models.FunctionMetaInfo)

	for _, target := range request.TargetFunctions {
		// Split "file_path:function_name"
		parts := strings.SplitN(target, ":", 2)
		if len(parts) != 2 {
			continue
		}
		filePath := parts[0]
		functionName := parts[1]
		fileName := filepath.Base(filePath)
		fmt.Printf("[DEBUG] EngineMainFunMeta filePath: %s fileName: %s functionName: %s\n", filePath, fileName, functionName)

		// Try to find the function by matching both file path and function name
		var def *models.FunctionDefinition
		for _, candidate := range results.Functions {
			// fmt.Printf("[DEBUG] candidate.FilePath: %s candidate.Name: %s\n", candidate.FilePath, candidate.Name)

			if candidate == nil {
				continue
			}
			// Match function name and file path (allowing for relative path match)
			if candidate.Name == functionName {
				//if filePath is empty, we may get a wrong function
				if filePath == "MISSING" || filePath == "unknown.c" || filePath == "Unknown.java" || strings.HasSuffix(candidate.FilePath, fileName) {
					def = candidate
					break
				} else {
					// fmt.Printf("[DEBUG] DOES NOT MATCH candidate.FilePath: %s candidate.Name: %s\n", candidate.FilePath, candidate.Name)
				}
			}
		}

		if def == nil {
			// Not found, skip or log
			fmt.Printf("[WARN] Function not found for filePath: %s functionName: %s\n", filePath, functionName)
			continue
		}

		filePath_x := def.FilePath
		//fix filePath
		{
			focus := request.Focus
			focusAddress := request.Focus + "-address"
			idx := strings.Index(filePath_x, focusAddress)
			if idx >= 0 {
				filePath_x = filePath_x[idx+len(focusAddress)+1:]
			} else {
				idx = strings.Index(filePath_x, focus)
				if idx >= 0 {
					filePath_x = filePath_x[idx+len(focus)+1:]
				}
			} //TODO extract anything after
			fmt.Printf("[DEBUG] def.FilePath: %s\n", def.FilePath)
			fmt.Printf("[DEBUG] filePath_x: %s\n", filePath_x)
		}

		meta := models.FunctionMetaInfo{
			Name:       def.Name,
			StartLine:  def.StartLine,
			EndLine:    def.EndLine,
			FilePath:   filePath_x,
			SourceCode: def.SourceCode,
		}
		funMeta[functionName] = meta
	}

	// Debug summary before returning
	fmt.Printf("[DEBUG] Successfully processed %d functions in EngineMainFunMeta:\n", len(funMeta))
	for funcName, meta := range funMeta {
		fmt.Printf("[DEBUG]   - %s in %s (lines %d-%d)\n",
			funcName,
			meta.FilePath,
			meta.StartLine,
			meta.EndLine)
	}

	return funMeta, nil
}
func EngineMainReachableQX(request models.AnalysisRequest, results *models.CodeqlAnalysisResults) ([]models.FunctionDefinition, error) {

	fuzzerSourcePath := normaliseAnalysisPath(request.FuzzerSourcePath)

	var entryPoint string
	if strings.HasSuffix(fuzzerSourcePath, ".java") {
		entryPoint = fuzzerSourcePath + "." + "fuzzerTestOneInput"
	} else {
		entryPoint = fuzzerSourcePath + "." + "LLVMFuzzerTestOneInput"
	}
	maxDepth := 6
	targetFuncs, err := findPotentiallyVulnerableReachableFunctionsQX(results, entryPoint, maxDepth)

	/* ---------- DEBUG: print counts ---------- */
	if err == nil {
		numFuncs := len(targetFuncs)
		totalWords := 0
		for _, fd := range targetFuncs {
			totalWords += len(strings.Fields(fd.SourceCode))
		}
		fmt.Printf("[DEBUG] EngineMainReachableQX reachable functions: %d  |  total words: %d\n", numFuncs, totalWords)
	}
	/* ----------------------------------------- */

	return targetFuncs, err
}
func EngineMainReachable(request models.AnalysisRequest, results *models.AnalysisResults) ([]models.FunctionDefinition, error) {
	fmt.Printf("[DEBUG] EngineMainReachable request.FuzzerSourcePath: %s\n", request.FuzzerSourcePath)
	fuzzerSourcePath := normaliseAnalysisPath(request.FuzzerSourcePath)

	var entryPoint string
	if strings.HasSuffix(fuzzerSourcePath, ".java") {
		entryPoint = fuzzerSourcePath + "." + "fuzzerTestOneInput"
	} else {
		entryPoint = fuzzerSourcePath + "." + "LLVMFuzzerTestOneInput"
	}
	maxDepth := 6
	targetFuncs, err := findPotentiallyVulnerableReachableFunctions(results, entryPoint, maxDepth)

	/* ---------- DEBUG: print counts ---------- */
	if err == nil {
		numFuncs := len(targetFuncs)
		totalWords := 0
		for _, fd := range targetFuncs {
			totalWords += len(strings.Fields(fd.SourceCode))
		}
		fmt.Printf("[DEBUG] EngineMainReachable reachable functions: %d  |  total words: %d  entryPoint %s\n", numFuncs, totalWords, entryPoint)
	}
	/* ----------------------------------------- */

	return targetFuncs, err
}
func findPotentiallyVulnerableReachableFunctionsQX(results *models.CodeqlAnalysisResults, entryPoint string, maxDepth int) ([]models.FunctionDefinition, error) {

	fmt.Printf("[DEBUG] findPotentiallyVulnerableReachableFunctionsQX entryPoint: %s\n", entryPoint)

	if results.ReachableFunctions == nil {
		results.ReachableFunctions = make(map[string][]string)
	}

	if len(results.ReachableFunctions) == 0 && len(results.Paths) > 0 {
		for fuzzerName, pathsListMap := range results.Paths {
			// fmt.Println("tf.FunctionName:", tf.FunctionName)
			var reachable []string
			for fullTargetFunction, _ := range pathsListMap {
				// fmt.Println("fullTargetFunction:", fullTargetFunction)
				reachable = append(reachable, fullTargetFunction)
			}
			//save to reachable functions
			results.ReachableFunctions[fuzzerName] = reachable
		}
	}

	var out []models.FunctionDefinition

	fuzzerName, err := extractFuzzerName(entryPoint)
	if err != nil {
		fmt.Println("Error:", err)
		return out, err
	}

	// 1. Get the reachable function names.
	reachableNames := results.ReachableFunctions[fuzzerName]
	// 2. Build the output slice, making sure we don’t duplicate entries.
	seen := make(map[string]struct{}, len(reachableNames))

	for _, name := range reachableNames {
		if _, ok := seen[name]; ok {
			continue // already added
		}
		seen[name] = struct{}{}

		if def, ok := results.Functions[name]; ok && def != nil {
			// We have a full definition: add a *copy* (not the pointer)
			def.Name = name
			out = append(out, *def)
			continue
		}

		// If the fully‑qualified name is not present, try a best‑effort
		// match on the simple name (last path component). This is useful for
		// Java when we only have simple names in the call‑graph.
		simple := name
		if idx := strings.LastIndex(simple, "."); idx != -1 {
			simple = simple[idx+1:]
		}

		found := false
		for fn, def := range results.Functions {
			if def != nil && strings.HasSuffix(fn, "."+simple) {
				def.Name = name
				out = append(out, *def)
				found = true
				break
			}
		}

		fmt.Println("ReachableFunction QX:", name, "No FunctionDefinition")

		// it's possible the reachable function not in results.Functions duo to BC errors
		if !found {
			def := &models.FunctionDefinition{
				Name:       name,
				FilePath:   "",
				StartLine:  0,
				EndLine:    0,
				SourceCode: "",
			}
			out = append(out, *def)
		}
	}

	return out, nil
}
func findPotentiallyVulnerableReachableFunctions(results *models.AnalysisResults, entryPoint string, maxDepth int) ([]models.FunctionDefinition, error) {

	fmt.Printf("[DEBUG] findPotentiallyVulnerableReachableFunctions entryPoint: %s\n", entryPoint)

	if results.ReachableFunctions == nil {
		results.ReachableFunctions = make(map[string][]string)
	}
	// 1. Get the reachable function names.
	reachableNames := results.ReachableFunctions[entryPoint]
	// 2. Build the output slice, making sure we don’t duplicate entries.
	seen := make(map[string]struct{}, len(reachableNames))
	var out []models.FunctionDefinition

	for _, name := range reachableNames {
		if _, ok := seen[name]; ok {
			continue // already added
		}
		seen[name] = struct{}{}

		if def, ok := results.Functions[name]; ok && def != nil {
			// We have a full definition: add a *copy* (not the pointer)
			out = append(out, *def)
			continue
		}

		// If the fully‑qualified name is not present, try a best‑effort
		// match on the simple name (last path component). This is useful for
		// Java when we only have simple names in the call‑graph.
		simple := name
		if idx := strings.LastIndex(simple, "."); idx != -1 {
			simple = simple[idx+1:]
		}
		found := false
		for fn, def := range results.Functions {
			if def != nil && strings.HasSuffix(fn, "."+simple) {
				out = append(out, *def)
				found = true
				break
			}
		}

		// if !strings.HasPrefix(name, "llvm.") && !strings.HasPrefix(name, "__sanitizer") && !strings.HasPrefix(name, "__asan_")  &&
		// 	// Common C standard library functions
		// 	name != "abort" &&
		// 	name != "memcmp" &&
		// 	name != "memcpy" &&
		// 	name != "memmove" &&
		// 	name != "memset" &&
		// 	name != "longjmp" &&
		// 	name != "setjmp" &&
		// 	name != "malloc" &&
		// 	name != "calloc" &&
		// 	name != "realloc" &&
		// 	name != "free" &&
		// 	name != "strlen" &&
		// 	name != "pow" {
		// 	fmt.Println("ReachableFunction:", name, "No FunctionDefinition")
		// }
		// it's possible the reachable function not in results.Functions duo to BC errors
		if !found {
			def := &models.FunctionDefinition{
				Name:       name,
				FilePath:   "",
				StartLine:  0,
				EndLine:    0,
				SourceCode: "",
			}
			out = append(out, *def)
		}
	}

	return out, nil
}
func extractFuzzerName(entryPoint string) (string, error) {
	base := filepath.Base(entryPoint) // e.g., "DataTreeFuzzer.java.fuzzerTestOneInput"
	parts := strings.SplitN(base, ".", 2)
	if len(parts) < 1 || parts[0] == "" {
		return "", fmt.Errorf("could not extract fuzzer name from entryPoint: %s", entryPoint)
	}
	return parts[0], nil
}
func getPathsForTargetFunctionsQX(entryPoint, projectDir string, results *models.CodeqlAnalysisResults, targetFunctions *[]models.TargetFunction) []models.CallPath {

	var finalPaths []models.CallPath

	fuzzerName, err := extractFuzzerName(entryPoint)
	if err != nil {
		fmt.Println("Error:", err)
		return finalPaths
	} else {
		fmt.Println("Fuzzer name:", fuzzerName)
	}

	// fmt.Println("Available fuzzer names:", reflect.ValueOf(results.Paths).MapKeys())

	// fmt.Printf("entryPoint: '%s'\n", entryPoint)
	for _, tf := range *targetFunctions {
		// fmt.Println("tf.FunctionName:", tf.FunctionName)
		pathsListMap := results.Paths[fuzzerName]
		var reachable []string

		for fullTargetFunction, pathsList := range pathsListMap {
			// fmt.Println("fullTargetFunction:", fullTargetFunction)
			reachable = append(reachable, fullTargetFunction)

			if fullTargetFunction == tf.FunctionName || strings.HasSuffix(fullTargetFunction, "."+tf.FunctionName) {
				// fmt.Printf("pathsList: '%v'\n", pathsList)
				for _, path := range pathsList {
					callPath := models.CallPath{
						Target: fullTargetFunction,
						Nodes:  make([]models.CallPathNode, 0, len(path)),
					}
					// Populate the nodes in the call path
					for _, funcName := range path {
						// Get function details from our analysis results
						funcDef, exists := results.Functions[funcName]
						if !exists {
							continue
						}

						isModified := false
						// If the function is in our target list
						if funcName == fullTargetFunction {
							isModified = true
						}

						// Extract the source code for this function
						body := funcDef.SourceCode
						if body == "" {
							// Try to read the source file to get the function body
							filePath := funcDef.FilePath
							if filePath != "" && fileExists(filePath) {
								body = extractFunctionBodyFromFile(filePath, funcDef.StartLine, funcDef.EndLine)
							}
						}

						// Create the node with all available information
						node := models.CallPathNode{
							Function:   funcDef.Name,
							File:       funcDef.FilePath,
							Line:       fmt.Sprintf("%d", funcDef.StartLine),
							Body:       body,
							IsModified: isModified,
						}
						callPath.Nodes = append(callPath.Nodes, node)
					}
					// Only add non-empty paths
					if len(callPath.Nodes) > 0 {
						finalPaths = append(finalPaths, callPath)
						// limit to 20 paths
						if len(finalPaths) > 20 {
							break
						}
					}

				}
			}
		}

		//save to reachable functions
		results.ReachableFunctions[fuzzerName] = reachable

	}

	fmt.Printf("QX Returning %d call paths. Target: %v\n", len(finalPaths), *targetFunctions)
	// fmt.Printf("%v \n", finalPaths)
	return finalPaths
}

func EngineMainQueryQX(request models.AnalysisRequest, results *models.CodeqlAnalysisResults) ([]models.CallPath, error) {
	var targetFunctions []models.TargetFunction
	// Extract all target functions with their start lines
	for filePath, functions := range request.TargetFunctions {
		for _, funcInfo := range functions {
			targetFunctions = append(targetFunctions, models.TargetFunction{
				FilePath:     filePath,
				FunctionName: funcInfo.Name,
				StartLine:    funcInfo.StartLine,
			})
		}
	}
	projectDir := path.Join(WORK_DIR, request.TaskID, request.Focus)
	projectDir = request.ProjectSourceDir
	fuzzerSourcePath := normaliseAnalysisPath(request.FuzzerSourcePath)

	var entryPoint string
	if strings.HasSuffix(fuzzerSourcePath, ".java") {
		entryPoint = fuzzerSourcePath + "." + "fuzzerTestOneInput"
	} else {
		entryPoint = fuzzerSourcePath + "." + "LLVMFuzzerTestOneInput"
	}
	finalPaths := getPathsForTargetFunctionsQX(entryPoint, projectDir, results, &targetFunctions)
	return finalPaths, nil
}

func EngineMainQuery(request models.AnalysisRequest, results *models.AnalysisResults) ([]models.CallPath, error) {

	if results == nil || len(results.Paths) == 0 {
		return EngineMain(request)
	} else {
		var targetFunctions []models.TargetFunction
		// Extract all target functions with their start lines
		for filePath, functions := range request.TargetFunctions {
			for _, funcInfo := range functions {
				targetFunctions = append(targetFunctions, models.TargetFunction{
					FilePath:     filePath,
					FunctionName: funcInfo.Name,
					StartLine:    funcInfo.StartLine,
				})
			}
		}
		projectDir := path.Join(WORK_DIR, request.TaskID, request.Focus)
		projectDir = request.ProjectSourceDir

		fuzzerSourcePath := normaliseAnalysisPath(request.FuzzerSourcePath)

		var entryPoint string
		if strings.HasSuffix(fuzzerSourcePath, ".java") {
			entryPoint = fuzzerSourcePath + "." + "fuzzerTestOneInput"
		} else {
			entryPoint = fuzzerSourcePath + "." + "LLVMFuzzerTestOneInput"
		}
		finalPaths := getPathsForTargetFunctions(entryPoint, projectDir, results, &targetFunctions)
		return finalPaths, nil
	}
}

func EngineMain(request models.AnalysisRequest) ([]models.CallPath, error) {
	var targetFunctions []models.TargetFunction
	var targetFunctionNames []string
	// Extract all target functions with their start lines
	for filePath, functions := range request.TargetFunctions {
		for _, funcInfo := range functions {
			targetFunctions = append(targetFunctions, models.TargetFunction{
				FilePath:     filePath,
				FunctionName: funcInfo.Name,
				StartLine:    funcInfo.StartLine,
			})
			targetFunctionNames = append(targetFunctionNames, funcInfo.Name)
		}
	}
	// normalize request.ProjectSourceDir
	if strings.HasSuffix(request.ProjectSourceDir, "-undefined") || strings.HasSuffix(request.ProjectSourceDir, "-memory") {
		request.ProjectSourceDir = request.ProjectSourceDir[:strings.LastIndex(request.ProjectSourceDir, "-")] + "-address"
	}

	projectDir := request.ProjectSourceDir
	fuzzerSourcePath := request.FuzzerSourcePath
	projectFocusName := filepath.Base(projectDir)
	taskDir := filepath.Dir(projectDir)
	uuidWithTimestamp := filepath.Base(taskDir)

	timestampRegex := regexp.MustCompile(`-\d{8}-\d{6}$`)
	uuidPart := timestampRegex.ReplaceAllString(uuidWithTimestamp, "")
	taskID := request.TaskID
	if uuidPart != "" && os.Getuid() == 0 {
		// on the real crs-analysis node
		taskDir = path.Join(WORK_DIR, taskID)
		projectDir = path.Join(WORK_DIR, taskID, projectFocusName)

		fuzzerSourcePath = normaliseAnalysisPath(request.FuzzerSourcePath)

		if !fileExists(request.Fuzzer) {
			request.Fuzzer = normaliseAnalysisPath(request.Fuzzer)
		}
	}

	outputJson := path.Join(taskDir, fmt.Sprintf("%s.json", projectFocusName))
	fmt.Println("Analysis outputJson:", outputJson) // For debugging

	var language string
	var entryPoint string

	if strings.Contains(fuzzerSourcePath, ".java") {
		language = "java"
		callPaths, err := EngineMainCodeql(request)
		if err == nil {
			return callPaths, err
		}
	} else {
		language = "c"
		//if request.Fuzzer.dot exist
		callGraph_dot := fmt.Sprintf("%s.dot", request.Fuzzer)
		if fileExists(callGraph_dot) {
			return GetCCallPaths(projectDir, request.Fuzzer, callGraph_dot, targetFunctionNames)
		} else {
			fmt.Println("request.Fuzzer callgraph does not exist:", callGraph_dot) // For debugging
		}
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
		err := filepath.Walk(projectDir, func(path string, info os.FileInfo, err error) error {
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
			var finalCCallPaths []models.CallPath
			return finalCCallPaths, err
		}
	}

	fmt.Printf("Found %d C/C++ files and %d Java files to analyze\n",
		len(cFilesToAnalyze), len(javaFilesToAnalyze))

	// Initialize results
	results := models.AnalysisResults{
		Functions:          make(map[string]*models.FunctionDefinition),
		CallGraph:          &models.CallGraph{Calls: []models.MethodCall{}},
		ReachableFunctions: make(map[string][]string),
		Paths:              make(map[string][][]string),
	}

	numWorkers := runtime.NumCPU()
	startTime := time.Now()
	fmt.Printf("Starting analysis with %d workers...\n", numWorkers)

	// Process files based on language
	if language == "c" {
		processCFiles(&results, cFilesToAnalyze, numWorkers)
	} else {
		buildJavaCallGraph(&results, javaFilesToAnalyze, numWorkers)
	}

	maxDepth := 6

	// Find all paths from entry point
	if len(targetFunctions) > 0 {
		fmt.Printf("Finding paths from %s (max depth: %d)...\n",
			entryPoint, maxDepth)

		for _, targetFunc := range targetFunctions {
			targetFuncName := targetFunc.FunctionName // Use the simple function name
			targetFunc := fmt.Sprintf("%s/%s.%s", projectDir, targetFunc.FilePath, targetFuncName)

			// The findAllPaths function should handle resolving simple names to qualified names
			// fmt.Printf("Finding paths to target: %s", targetFunc)

			paths := findAllPaths(&results, entryPoint, targetFunc, maxDepth)

			// Store paths keyed by the simple function name for now
			// You might want a more robust key later (e.g., combining file and function)
			if len(paths) > 0 {

				compositeKey := fmt.Sprintf("%s-%s", entryPoint, targetFuncName)
				results.Paths[compositeKey] = paths
				// fmt.Printf("Found %d paths to target function %s", len(paths), targetFunc)

				// Print a few example paths for this target
				fmt.Println("  Example paths:")
				for i := 0; i < min(3, len(paths)); i++ {
					fmt.Printf("    Path %d: %s", i+1, strings.Join(paths[i], " -> "))
				}
			}
		}

	} else {
		// If no target specified, find reachable functions from entry point
		reachable := findReachableFunctions(&results, entryPoint, maxDepth)
		fmt.Printf("Found %d reachable functions from entry point %s\n", len(reachable), entryPoint)

		/* ───── C: save the reachable list ───── */
		if results.ReachableFunctions == nil {
			results.ReachableFunctions = make(map[string][]string)
		}
		results.ReachableFunctions[entryPoint] = reachable

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
					paths := findAllPaths(&results, entryPoint, funcName, maxDepth)
					pathInfo := "  (no path found)"
					if len(paths) > 0 {
						pathInfo = fmt.Sprintf("  (example path: %s)", strings.Join(paths[0], " -> "))
					}
					fmt.Printf("  - %s%s\n", funcName, pathInfo)
				}
			}

			fmt.Println("\n=== END REACHABLE FUNCTIONS ===")

		}
		// Store paths for each reachable function
		for _, func_ := range reachable {
			paths := findAllPaths(&results, entryPoint, func_, maxDepth)
			if len(paths) > 0 {
				compositeKey := fmt.Sprintf("%s-%s", entryPoint, func_)
				results.Paths[compositeKey] = paths
			}
		}
	}

	// Write results to JSON file
	jsonData, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling JSON: %v\n", err)
		os.Exit(1)
	}

	err = os.WriteFile(outputJson, jsonData, 0644)
	if err != nil {
		fmt.Printf("Error writing JSON file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Analysis completed in %v. Results written to %s\n",
		time.Since(startTime), outputJson)

	finalPaths := getPathsForTargetFunctions(entryPoint, projectDir, &results, &targetFunctions)
	return finalPaths, nil
}

type FunctionInfo struct {
	Name        string      `json:"name"`
	MangledName string      `json:"mangledName"`
	File        string      `json:"file"`
	Line        json.Number `json:"line"`      // Use json.Number for all numeric fields
	StartLine   json.Number `json:"startLine"` // This allows parsing both strings and numbers
	ScopeLine   json.Number `json:"scopeLine"`
	EndLine     json.Number `json:"endLine"`
}
type FunctionMetadata struct {
	Functions      []FunctionInfo `json:"functions"`
	TotalFunctions int            `json:"totalFunctions"`
	InputFiles     []string       `json:"inputFiles"`
}

// GetCCallPathsParallel processes call paths for multiple target functions in parallel.
func GetCCallPathsParallel(projectDir, fuzzerPath, callGraph_dot string, entryPoint string, targetFunctionNames []string, results *models.AnalysisResults, resultsMu *sync.Mutex) error {

	fuzzerDir := filepath.Dir(fuzzerPath)
	fuzzerBase := filepath.Base(fuzzerPath)
	// Load the function metadata
	functionMetadataFile := filepath.Join(fuzzerDir, fuzzerBase+"_function_metadata.json")
	functionMetadataData, err := os.ReadFile(functionMetadataFile)
	if err != nil {
		return fmt.Errorf("Failed to read function metadata file %s: %v", functionMetadataFile, err)
	}
	// Unmarshal into our carefully designed struct
	var functionMetadata FunctionMetadata
	decoder := json.NewDecoder(bytes.NewReader(functionMetadataData))
	decoder.UseNumber() // This is important to handle numbers as json.Number
	if err := decoder.Decode(&functionMetadata); err != nil {
		return fmt.Errorf("Failed to parse function metadata JSON %s: %v", functionMetadataFile, err)
	}

	// Build functionMap with robust file path resolution
	functionMap := make(map[string]FunctionInfo)
	filePathCache := make(map[string]string) // Cache for resolved file paths [basename -> fullpath]
	for _, funcInfo := range functionMetadata.Functions {
		startLineInt, _ := funcInfo.StartLine.Int64()
		if startLineInt == 0 {
			lineInt, _ := funcInfo.Line.Int64()
			funcInfo.StartLine = json.Number(strconv.FormatInt(lineInt, 10))
		}
		originalFile := funcInfo.File
		if !fileExists(funcInfo.File) {
			fullPath := filepath.Join(projectDir, funcInfo.File)
			if fileExists(fullPath) {
				funcInfo.File = fullPath
			} else {
				baseName := filepath.Base(originalFile)
				cachedPath, foundInCache := filePathCache[baseName]
				if foundInCache {
					if cachedPath != "" { // Found a valid path previously
						funcInfo.File = cachedPath
						// fmt.Printf("[DEBUG] GetCCallPathsParallel Found cached path for %s: %s\n", baseName, cachedPath)
					} else {
						// Cached as not found, keep funcInfo.File as is (original relative/invalid path)
						fmt.Printf("[DEBUG] GetCCallPathsParallel Path for %s previously not found (cached).\n", baseName)
					}
				} else {
					// Search recursively under projectDir for a file with the same basename
					var foundPath string
					_ = filepath.Walk(projectDir, func(path string, info os.FileInfo, err error) error {
						if err != nil {
							return err
						}
						// ../test/shell.c can be funcInfo.File due to bear compile
						if !info.IsDir() && (info.Name() == funcInfo.File || info.Name() == baseName) {
							foundPath = path
							filePathCache[baseName] = foundPath
							return filepath.SkipDir // Stop searching once found
						}
						return nil
					})
					if foundPath != "" {
						funcInfo.File = foundPath
						// fmt.Printf("[DEBUG] GetCCallPathsParallel Found full path for %s: %s\n", originalFile, foundPath)
					}
				}
			}
		}
		functionMap[funcInfo.MangledName] = funcInfo
		if strings.HasPrefix(funcInfo.MangledName, "OSS_FUZZ_") {
			simpleName := funcInfo.MangledName[9:]
			functionMap[simpleName] = funcInfo
		}
	}

	if origN := len(targetFunctionNames); origN > 1000 {
		rand.Seed(time.Now().UnixNano())
		rand.Shuffle(origN, func(i, j int) {
			targetFunctionNames[i], targetFunctionNames[j] =
				targetFunctionNames[j], targetFunctionNames[i]
		})
		targetFunctionNames = targetFunctionNames[:1000]
		log.Printf("[GetCCallPathsParallel] Down-sampled functions from %d to %d",
			origN, len(targetFunctionNames))
	}

	maxConcurrent := runtime.NumCPU() * 2 / 3 // Adjust based on your system capabilities
	if maxConcurrent < 2 {
		maxConcurrent = 1
	}

	log.Printf("[GetCCallPathsParallel] maxConcurrent: %d #targetFunctions %d", maxConcurrent, len(targetFunctionNames))

	semaphore := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup

	for _, targetFuncName := range targetFunctionNames {
		wg.Add(1)
		go func(targetFuncName string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			var stdout, stderr bytes.Buffer
			testCmd := exec.Command("python3", "/app/strategyx/legacy_strategy/parse_callgraph.py", callGraph_dot, targetFuncName)
			testCmd.Stdout = &stdout
			testCmd.Stderr = &stderr

			// Run the command
			if err := runWithTimeout(testCmd, 5*time.Minute); err != nil {
				log.Printf("Python script error: %v", err)
				log.Printf("Python script stdout: %s", stdout.String())
				log.Printf("Python script stderr: %s", stderr.String())
				fmt.Printf("Warning: parse_callgraph.py failed for %s: %v\n", callGraph_dot, err)
				return
			} else {
				// log.Printf("Successfully ran call path analysis for fuzzer: %s targetFuncName: %s", fuzzerPath, targetFuncName)
				// load json from fuzzerDir/targetFuncName_callpaths.json
				callPathsFile := filepath.Join(fuzzerDir, targetFuncName+"_callpaths.json")
				callPathsData, err := os.ReadFile(callPathsFile)
				if err != nil {
					return
				}
				// Parse the call paths JSON
				var callPathsResults struct {
					StartFunction string     `json:"start_function"`
					EndFunction   string     `json:"end_function"`
					MaxDepth      int        `json:"max_depth"`
					NumPaths      int        `json:"num_paths"`
					Paths         [][]string `json:"paths"`
				}

				if err := json.Unmarshal(callPathsData, &callPathsResults); err != nil {
					fmt.Printf("Failed to parse call paths JSON %s: %v", callPathsFile, err)
					return
				}

				var targetCCallPaths []models.CallPath

				// Process each path
				for _, path := range callPathsResults.Paths {
					callPath := models.CallPath{
						Target: targetFuncName,
						Nodes:  make([]models.CallPathNode, 0, len(path)),
					}
					// Populate the nodes in the call path
					for _, funcName := range path {
						funcInfo, exists := functionMap[funcName]
						if !exists {
							// fmt.Printf("Skip functions we don't have info for funcName %s targetFuncName: %s\n", funcName, targetFuncName)
							continue
						}
						isModified := (funcName == targetFuncName)
						body := ""
						if funcInfo.File != "" && fileExists(funcInfo.File) {
							startLineInt, _ := funcInfo.StartLine.Int64()
							endLineInt, _ := funcInfo.EndLine.Int64()
							body = extractFunctionBodyFromFile(funcInfo.File, int(startLineInt), int(endLineInt))
						} else {
							fmt.Printf("[DEBUG] GetCCallPathsParallel File missing or does not exist for function %s: %s\n", funcName, funcInfo.File)
						}
						node := models.CallPathNode{
							Function:   funcName,
							File:       funcInfo.File,
							Line:       funcInfo.Line.String(),
							StartLine:  funcInfo.StartLine.String(),
							EndLine:    funcInfo.EndLine.String(),
							Body:       body,
							IsModified: isModified,
						}
						callPath.Nodes = append(callPath.Nodes, node)
					}
					// Only add non-empty paths
					if len(callPath.Nodes) > 0 {
						targetCCallPaths = append(targetCCallPaths, callPath)
						// Limit to 20 paths if needed
						if len(targetCCallPaths) > 20 {
							break
						}
					}
				}

				// Convert to [][]string and merge FunctionDefinitions into results
				paths := extractPaths(results, resultsMu, targetCCallPaths)

				compositeKey := fmt.Sprintf("%s-%s", entryPoint, targetFuncName)
				resultsMu.Lock()
				results.Paths[compositeKey] = paths
				resultsMu.Unlock()
			}
		}(targetFuncName)
	}

	wg.Wait()

	return nil
}

func GetCCallPaths(projectDir, fuzzerPath string, callGraph_dot string, targetFunctionNames []string) ([]models.CallPath, error) {
	var finalCCallPaths []models.CallPath

	fuzzerDir := filepath.Dir(fuzzerPath)
	fuzzerBase := filepath.Base(fuzzerPath)
	// Load the function metadata
	functionMetadataFile := filepath.Join(fuzzerDir, fuzzerBase+"_function_metadata.json")
	functionMetadataData, err := os.ReadFile(functionMetadataFile)
	if err != nil {
		return finalCCallPaths, fmt.Errorf("Failed to read function metadata file %s: %v", functionMetadataFile, err)
	}
	// Unmarshal into our carefully designed struct
	var functionMetadata FunctionMetadata
	decoder := json.NewDecoder(bytes.NewReader(functionMetadataData))
	decoder.UseNumber() // This is important to handle numbers as json.Number
	if err := decoder.Decode(&functionMetadata); err != nil {
		return finalCCallPaths, fmt.Errorf("Failed to parse function metadata JSON %s: %v", functionMetadataFile, err)
	}

	// Then use functionMetadataWrapper.Functions instead of functionMetadata
	functionMap := make(map[string]FunctionInfo)
	for _, funcInfo := range functionMetadata.Functions {
		startLineInt, _ := funcInfo.StartLine.Int64()
		if startLineInt == 0 {
			lineInt, _ := funcInfo.Line.Int64()
			funcInfo.StartLine = json.Number(strconv.FormatInt(lineInt, 10))
		}
		if !fileExists(funcInfo.File) {
			fullPath := filepath.Join(projectDir, funcInfo.File)
			if fileExists(fullPath) {
				funcInfo.File = fullPath
			} else {
				// Search recursively under projectDir for a file with the same basename
				var foundPath string
				err := filepath.Walk(projectDir, func(path string, info os.FileInfo, err error) error {
					if err != nil {
						return err
					}
					if !info.IsDir() && info.Name() == funcInfo.File {
						foundPath = path
						return filepath.SkipDir // Stop searching once found
					}
					return nil
				})
				if err != nil {
					fmt.Printf("[DEBUG] Error searching for %s: %v\n", funcInfo.File, err)
				}
				if foundPath != "" {
					funcInfo.File = foundPath
					// fmt.Printf("[DEBUG] GetCCallPaths Found full path for %s: %s\n", funcInfo.File, foundPath)
				} else {
					// if !strings.HasPrefix(funcInfo.Name,"asan.") && !strings.HasPrefix(funcInfo.Name,"sancov.") && !strings.HasPrefix(funcInfo.Name,"__clang_") && !strings.HasPrefix(funcInfo.Name,"strtod") {
					// 	fmt.Printf("[DEBUG] Could not find file for function %s: %s\n", funcInfo.Name, funcInfo.File)
					// }
				}
			}
		}

		functionMap[funcInfo.MangledName] = funcInfo
		if strings.HasPrefix(funcInfo.MangledName, "OSS_FUZZ_") {
			simpleName := funcInfo.MangledName[9:]
			functionMap[simpleName] = funcInfo
		}
	}

	for _, targetFuncName := range targetFunctionNames {
		var stdout, stderr bytes.Buffer

		testCmd := exec.Command("python3", "/app/strategyx/legacy_strategy/parse_callgraph.py", callGraph_dot, targetFuncName)
		testCmd.Stdout = &stdout
		testCmd.Stderr = &stderr

		// Run the command
		if err := runWithTimeout(testCmd, 5*time.Minute); err != nil {
			log.Printf("Python script error: %v", err)
			log.Printf("Python script stdout: %s", stdout.String())
			log.Printf("Python script stderr: %s", stderr.String())
			fmt.Printf("Warning: parse_callgraph.py failed for %s: %v\n", callGraph_dot, err)
		} else {
			log.Printf("Successfully ran call path analysis for fuzzer: %s targetFuncName: %s", fuzzerPath, targetFuncName)
			// log.Printf("Python script stdout: %s", stdout.String())
			//load json from fuzzerDir/targetFuncName_callpaths.json
			callPathsFile := filepath.Join(fuzzerDir, targetFuncName+"_callpaths.json")
			callPathsData, err := os.ReadFile(callPathsFile)
			if err != nil {
				// fmt.Printf("Failed to read call paths file %s: %v", callPathsFile, err)
				continue
			}
			// Parse the call paths JSON
			var callPathsResults struct {
				StartFunction string     `json:"start_function"`
				EndFunction   string     `json:"end_function"`
				MaxDepth      int        `json:"max_depth"`
				NumPaths      int        `json:"num_paths"`
				Paths         [][]string `json:"paths"`
			}

			if err := json.Unmarshal(callPathsData, &callPathsResults); err != nil {
				fmt.Printf("Failed to parse call paths JSON %s: %v", callPathsFile, err)
				continue
			}

			// Process each path
			for _, path := range callPathsResults.Paths {
				// fmt.Printf("[DEBUG] Processing path: %v\n", path)

				callPath := models.CallPath{
					Target: targetFuncName,
					Nodes:  make([]models.CallPathNode, 0, len(path)),
				}
				// Populate the nodes in the call path
				for _, funcName := range path {
					funcInfo, exists := functionMap[funcName]
					if !exists {
						// Skip functions we don't have info for
						fmt.Printf("Skip functions we don't have info for funcName %s targetFuncName: %s\n", funcName, targetFuncName)
						continue
					}

					isModified := (funcName == targetFuncName)

					// Extract the source code for this function
					body := ""
					if funcInfo.File != "" && fileExists(funcInfo.File) {
						startLineInt, _ := funcInfo.StartLine.Int64()
						endLineInt, _ := funcInfo.EndLine.Int64()
						body = extractFunctionBodyFromFile(funcInfo.File, int(startLineInt), int(endLineInt))
					} else {
						fmt.Printf("[DEBUG] GetCCallPaths File missing or does not exist for function %s: %s\n", funcName, funcInfo.File)
					}

					// Create the node with all available information
					node := models.CallPathNode{
						Function:   funcName,
						File:       funcInfo.File,
						Line:       funcInfo.Line.String(),
						StartLine:  funcInfo.StartLine.String(),
						EndLine:    funcInfo.EndLine.String(),
						Body:       body,
						IsModified: isModified,
					}
					callPath.Nodes = append(callPath.Nodes, node)
				}

				// Only add non-empty paths
				if len(callPath.Nodes) > 0 {
					finalCCallPaths = append(finalCCallPaths, callPath)
					// limit to 20 paths
					if len(finalCCallPaths) >= 20 {
						break
					}
				}
			}
		}

	}

	return finalCCallPaths, nil
}

func getPathsForTargetFunctions(entryPoint, projectDir string, results *models.AnalysisResults, targetFunctions *[]models.TargetFunction) []models.CallPath {

	var finalPaths []models.CallPath
	// fmt.Printf("entryPoint: '%s'\n", entryPoint)
	for _, tf := range *targetFunctions {

		// Use only the simple method name (last token after '.')
		simpleName := tf.FunctionName
		if idx := strings.LastIndex(simpleName, "."); idx != -1 {
			simpleName = simpleName[idx+1:]
		}

		targetFullPath := fmt.Sprintf("%s/%s.%s", projectDir, tf.FilePath, simpleName)
		// fmt.Printf("tf.FunctionName: '%s'\n", tf.FunctionName)
		// fmt.Printf("targetFullPath: '%s'\n", targetFullPath)
		compositeKey := fmt.Sprintf("%s-%s", entryPoint, simpleName)
		// fmt.Printf("compositeKey: '%v'\n", compositeKey)
		pathsList := results.Paths[compositeKey]
		// fmt.Printf("pathsList: '%v'\n", pathsList)
		for _, path := range pathsList {
			callPath := models.CallPath{
				Target: targetFullPath,
				Nodes:  make([]models.CallPathNode, 0, len(path)),
			}
			// Populate the nodes in the call path
			for _, funcName := range path {
				// Get function details from our analysis results
				funcDef, exists := results.Functions[funcName]
				if !exists {
					continue
				}

				isModified := false
				// If the function is in our target list
				if funcName == targetFullPath {
					isModified = true
				}

				// Extract the source code for this function
				body := funcDef.SourceCode
				if body == "" {
					// Try to read the source file to get the function body
					filePath := funcDef.FilePath
					if filePath != "" && fileExists(filePath) {
						body = extractFunctionBodyFromFile(filePath, funcDef.StartLine, funcDef.EndLine)
					}
				}

				// Create the node with all available information
				node := models.CallPathNode{
					Function:   funcDef.Name,
					File:       funcDef.FilePath,
					Line:       fmt.Sprintf("%d", funcDef.StartLine),
					Body:       body,
					IsModified: isModified,
				}
				callPath.Nodes = append(callPath.Nodes, node)
			}
			// Only add non-empty paths
			if len(callPath.Nodes) > 0 {
				finalPaths = append(finalPaths, callPath)
				// limit to 20 paths
				if len(finalPaths) > 20 {
					break
				}
			}

		}
	}

	fmt.Printf("Returning %d call paths. Target: %v\n", len(finalPaths), *targetFunctions)
	// fmt.Printf("%v \n", finalPaths)
	return finalPaths
}
func getSimpleFunctionName(fullName string) string {
	if strings.Contains(fullName, ".") {
		parts := strings.Split(fullName, ".")
		return parts[len(parts)-1]
	}
	return fullName
}

func extractFunctionBodyFromFile(filePath string, startLine, endLine int) string {

	if startLine <= 0 || endLine <= 0 || endLine < startLine {
		return ""
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		return ""
	}

	lines := strings.Split(string(content), "\n")
	if startLine > len(lines) {
		return ""
	}

	// Adjust for 0-based indexing
	startLine = max(0, startLine-1)
	endLine = min(len(lines), endLine)

	return strings.Join(lines[startLine:endLine], "\n")
}

// processCFiles processes C/C++ files in parallel
func processCFiles(results *models.AnalysisResults, files []string, numWorkers int) {
	var wg sync.WaitGroup
	fileChan := make(chan string, len(files))
	resultChan := make(chan map[string]*models.FunctionDefinition, len(files))

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
			// fmt.Printf("name %s: %v\n", name, def)
			results.Functions[name] = def
		}
	}

	// Build call graph for C functions
	buildCCallGraph(results)
	// printCallGraph(results.CallGraph)
}

// processJavaFile processes a Java file and returns functions and method calls
func processJavaFile(filePath string) (map[string]*models.FunctionDefinition, []models.MethodCall, error) {
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

// buildCCallGraph builds a call graph for C functions by analyzing function bodies
func buildCCallGraph(results *models.AnalysisResults) {
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
						results.CallGraph.Calls = append(results.CallGraph.Calls, models.MethodCall{
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

func buildJavaCallGraph(results *models.AnalysisResults, javaFiles []string, numWorkers int) {
	// Process all Java files to extract functions and initial calls
	var wg sync.WaitGroup
	fileChan := make(chan string, len(javaFiles))
	resultChan := make(chan struct {
		functions map[string]*models.FunctionDefinition
		calls     []models.MethodCall
	}, len(javaFiles))

	// Start worker goroutines to process files in parallel
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for filePath := range fileChan {

				// fmt.Printf("processJavaFile: %s", filePath)

				functions, calls, err := processJavaFile(filePath)
				if err != nil {
					fmt.Printf("Error processing %s: %v\n", filePath, err)
					continue
				}
				resultChan <- struct {
					functions map[string]*models.FunctionDefinition
					calls     []models.MethodCall
				}{functions, calls}
			}
		}()
	}

	// Send files to workers
	for _, file := range javaFiles {
		fileChan <- file
	}
	close(fileChan)

	// Wait for all workers to finish
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect initial function definitions and calls
	for result := range resultChan {
		for name, def := range result.functions {
			// fmt.Printf("name: %s def %v\n", name, def)
			results.Functions[name] = def
		}
		results.CallGraph.Calls = append(results.CallGraph.Calls, result.calls...)
	}

	// Deduplicate Caller→Callee pairs
	callSeen := make(map[string]struct{}, len(results.CallGraph.Calls))
	unique := make([]models.MethodCall, 0, len(results.CallGraph.Calls))

	for _, c := range results.CallGraph.Calls {
		// Skip set/get for Java
		if strings.HasPrefix(c.Callee, "set") || strings.HasPrefix(c.Callee, "get") {
			continue
		}
		key := c.Caller + "->" + c.Callee
		if _, ok := callSeen[key]; !ok {
			callSeen[key] = struct{}{}
			unique = append(unique, c)
		}
	}
	results.CallGraph.Calls = unique

	// After collecting all functions, enhance the call graph with more detailed analysis
	enhanceJavaCallGraph(results)

	fmt.Printf("Built Java call graph with %d calls\n", len(results.CallGraph.Calls))
}

func enhanceJavaCallGraph(results *models.AnalysisResults) {
	// Use a map to track unique calls to avoid duplicates
	uniqueCalls := make(map[string]bool)

	// Add all existing calls to the unique calls map
	for _, call := range results.CallGraph.Calls {
		callKey := call.Caller + " -> " + call.Callee
		uniqueCalls[callKey] = true
	}

	// Regular expressions to find method calls
	directMethodCallPattern := regexp.MustCompile(`\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(`)
	objectMethodCallPattern := regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)\s*\.\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\(`)

	// Scan all function bodies to find potential method calls
	for callerName, callerDef := range results.Functions {
		// Skip non-Java functions or functions without source code
		if !strings.HasSuffix(callerDef.FilePath, ".java") || callerDef.SourceCode == "" {
			continue
		}

		// Clean up the source code by removing comments
		cleanedContent := stripComments(callerDef.SourceCode)

		// Track unique callees for this caller
		callerCallees := make(map[string]bool)

		// Process direct method calls (no object prefix)
		directMatches := directMethodCallPattern.FindAllStringSubmatch(cleanedContent, -1)
		for _, match := range directMatches {
			if len(match) > 1 {
				methodName := match[1]

				// Skip if it's a common keyword or the caller itself
				if isCommonJavaKeyword(methodName) || methodName == callerName {
					continue
				}
				// Skip set/get for Java
				if strings.HasPrefix(methodName, "set") || strings.HasPrefix(methodName, "get") {
					continue
				}

				// Add as a potential callee
				calleeName := methodName
				if strings.HasSuffix(calleeName, "LLVMFuzzerTestOneInput") || strings.HasSuffix(calleeName, "fuzzerTestOneInput") {
					continue
				}

				callKey := callerName + " -> " + calleeName

				if !callerCallees[calleeName] && !uniqueCalls[callKey] {
					callerCallees[calleeName] = true
					uniqueCalls[callKey] = true
					results.CallGraph.Calls = append(results.CallGraph.Calls, models.MethodCall{
						Caller: callerName,
						Callee: calleeName,
					})
				}
			}
		}

		// Process object method calls (object.method)
		objectMatches := objectMethodCallPattern.FindAllStringSubmatch(cleanedContent, -1)
		for _, match := range objectMatches {
			if len(match) > 2 {
				objectPath := match[1] // Can be simple or complex: "x" or "a.b.c"
				methodName := match[2]

				// Skip common Java keywords and constructs
				if isCommonJavaKeyword(methodName) {
					continue
				}

				// Handle enum constants: Direction.RECEIVED should not be seen as a method call
				isEnumAccess := false
				enumPattern := regexp.MustCompile(`[A-Z][A-Z_0-9]*\.[A-Z][A-Z_0-9]*`)
				if enumPattern.MatchString(objectPath + "." + methodName) {
					isEnumAccess = true
				}

				if !isEnumAccess {
					// Try to resolve qualified method name
					for funcName := range results.Functions {
						if strings.HasSuffix(funcName, "."+methodName) {
							calleeName := funcName

							// Skip if calling itself
							if calleeName == callerName {
								continue
							}

							if strings.HasSuffix(calleeName, "LLVMFuzzerTestOneInput") || strings.HasSuffix(calleeName, "fuzzerTestOneInput") {
								continue
							}

							callKey := callerName + " -> " + calleeName
							if !callerCallees[calleeName] && !uniqueCalls[callKey] {
								callerCallees[calleeName] = true
								uniqueCalls[callKey] = true
								results.CallGraph.Calls = append(results.CallGraph.Calls, models.MethodCall{
									Caller: callerName,
									Callee: calleeName,
								})
							}
						}
					}

					// Also add the simple method name as a fallback
					calleeName := methodName
					callKey := callerName + " -> " + calleeName

					if !callerCallees[calleeName] && !uniqueCalls[callKey] {
						callerCallees[calleeName] = true
						uniqueCalls[callKey] = true
						results.CallGraph.Calls = append(results.CallGraph.Calls, models.MethodCall{
							Caller: callerName,
							Callee: calleeName,
						})
					}
				}
			}
		}
	}
}

// isCommonJavaKeyword checks if a string is a common Java keyword or construct
func isCommonJavaKeyword(word string) bool {
	keywords := map[string]bool{
		"if":        true,
		"else":      true,
		"for":       true,
		"while":     true,
		"do":        true,
		"switch":    true,
		"case":      true,
		"break":     true,
		"continue":  true,
		"return":    true,
		"new":       true,
		"this":      true,
		"super":     true,
		"class":     true,
		"interface": true,
		"enum":      true,
		"import":    true,
		"package":   true,
		"public":    true,
		"private":   true,
		"protected": true,
		"static":    true,
		"final":     true,
		"abstract":  true,
		"try":       true,
		"catch":     true,
		"finally":   true,
		"throw":     true,
		"throws":    true,
		"true":      true,
		"false":     true,
		"null":      true,
		"void":      true,
		"int":       true,
		"long":      true,
		"float":     true,
		"double":    true,
		"boolean":   true,
		"char":      true,
		"byte":      true,
		"short":     true,
		"String":    true,
		"System":    true, // Common class
		"out":       true, // System.out is common
		"err":       true, // System.err is common
		"in":        true, // System.in is common
		"equals":    true, // System.in is common
	}
	return keywords[word]
}

// findAllPaths finds all paths from source to target in the call graph
func findAllPaths0(results *models.AnalysisResults, fullyQualifiedSource, target string, maxDepth int) [][]string {
	graph := results.CallGraph

	fmt.Printf("\nDEBUG: Finding paths from '%s' to '%s' (max depth: %d)\n", fullyQualifiedSource, target, maxDepth)

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
			fmt.Printf("should never be there funcName: '%s'\n", funcName)
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

	// Map to track unique paths (as strings) to eliminate duplicates
	uniquePaths := make(map[string]bool)

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
				// Create a copy of the path
				pathCopy := make([]string, len(path))
				copy(pathCopy, path)

				// Convert path to a string representation for uniqueness check
				pathStr := strings.Join(pathCopy, "|")

				// Only add the path if it's not a duplicate
				if !uniquePaths[pathStr] {
					uniquePaths[pathStr] = true
					paths = append(paths, pathCopy)
				}
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

	// Add a secondary DFS from potential alternative source names if no paths found
	// if len(paths) == 0 && strings.Contains(fullyQualifiedSource, ".") {
	// 	// Try with other qualified sources that have the same simple name
	// 	simpleName := qualifiedToSimple[fullyQualifiedSource]
	// 	for _, alternativeSource := range simpleToQualified[simpleName] {
	// 		if alternativeSource != fullyQualifiedSource && !visited[alternativeSource] {
	// 			fmt.Printf("DEBUG: Trying alternative source: %s\n", alternativeSource)
	// 			dfs(alternativeSource, []string{alternativeSource}, 0)
	// 		}
	// 	}
	// }

	// Apply additional deduplication based on function sequence
	// This handles cases where equivalent paths may have slight differences in naming
	dedupedPaths := deduplicateFunctionallyIdenticalPaths(paths, qualifiedToSimple)

	// Print the paths for debugging
	// if len(dedupedPaths) > 0 {
	// 	fmt.Printf("DEBUG: Found %d unique paths\n", len(dedupedPaths))
	// 	for i, path := range dedupedPaths {
	// 		// Limit to first 10 paths to avoid excessive output
	// 		if i >= 10 {
	// 			fmt.Printf("DEBUG: ... and %d more paths\n", len(dedupedPaths)-10)
	// 			break
	// 		}
	// 		fmt.Printf("DEBUG: Path %d: %s\n", i+1, strings.Join(path, " -> "))
	// 	}
	// } else {
	// 	fmt.Println("DEBUG: No paths found")
	// }

	return dedupedPaths
}

// findAllPaths finds all paths from source to target (≤ maxDepth) in the call-graph.
// It is memoised and therefore much faster than the original naïve DFS.
func findAllPaths(results *models.AnalysisResults, fullyQualifiedSource, target string, maxDepth int) [][]string {
	// ----------------------------------------------------------------------
	// 0.  Pre-compute adjacency list once per call-graph and cache it
	// ----------------------------------------------------------------------
	if results.CallGraphAdj == nil { // lazy build
		adj := make(map[string][]string)
		for _, call := range results.CallGraph.Calls {
			adj[call.Caller] = append(adj[call.Caller], call.Callee)
		}
		results.CallGraphAdj = adj
	}
	adjList := results.CallGraphAdj

	// ----------------------------------------------------------------------
	// 1.  Map simple → fully-qualified names (built once per invocation)
	// ----------------------------------------------------------------------
	simpleToQualified := make(map[string][]string, len(results.Functions))
	for fn := range results.Functions {
		parts := strings.Split(fn, ".")
		simple := parts[len(parts)-1]
		simpleToQualified[simple] = append(simpleToQualified[simple], fn)
	}

	targets := []string{target}
	if !strings.Contains(target, ".") {
		targets = simpleToQualified[target]
	}

	targetSet := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		targetSet[t] = struct{}{}
	}

	// ----------------------------------------------------------------------
	// 2.  DFS with memoisation                       memo[node][depth-left]
	// ----------------------------------------------------------------------
	type memoKey struct {
		node  string
		depth int
	}
	memo := make(map[memoKey][][]string)

	var dfs func(node string, depth int, path []string, seen map[string]struct{}) [][]string
	dfs = func(node string, depth int, path []string, seen map[string]struct{}) [][]string {
		if depth < 0 {
			return nil
		}
		if _, ok := targetSet[node]; ok {
			// Return a fresh slice so callers can append safely
			cp := append([]string(nil), path...)
			return [][]string{cp}
		}

		key := memoKey{node, depth}
		if cached, ok := memo[key]; ok {
			// prepend current partial path to cached suffixes
			out := make([][]string, 0, len(cached))
			for _, suf := range cached {
				// suf[0] is 'node', so skip it to avoid duplication
				combined := append(append([]string(nil), path...), suf[1:]...)
				out = append(out, combined)
			}
			return out
		}

		var all [][]string
		seen[node] = struct{}{}

		for _, neigh := range adjList[node] {
			if _, dup := seen[neigh]; dup {
				continue // avoid cycles
			}
			path = append(path, neigh)
			all = append(all, dfs(neigh, depth-1, path, seen)...)
			path = path[:len(path)-1]
		}
		delete(seen, node)

		// cache full suffix paths (each starts with ‘node’)
		memoSuffixes := make([][]string, len(all))
		prefixIdx := len(path) - 1 // index of current node within each full path
		for i, full := range all {
			memoSuffixes[i] = append([]string(nil), full[prefixIdx:]...)
		}
		memo[key] = memoSuffixes
		return all
	}

	paths := dfs(fullyQualifiedSource, maxDepth, []string{fullyQualifiedSource}, map[string]struct{}{})
	return paths
}

// deduplicateFunctionallyIdenticalPaths removes paths that are functionally identical
// by comparing their simple function name sequences
func deduplicateFunctionallyIdenticalPaths(paths [][]string, qualifiedToSimple map[string]string) [][]string {
	if len(paths) <= 1 {
		return paths
	}

	// Create a map to track functionally unique paths
	uniqueSimplePaths := make(map[string]int) // Maps simple path string to index in original paths
	var result [][]string

	for i, path := range paths {
		// Convert path to simple names
		simplePath := make([]string, len(path))
		for j, node := range path {
			if simple, exists := qualifiedToSimple[node]; exists {
				simplePath[j] = simple
			} else {
				// If no mapping exists, use the original (likely already simple)
				simplePath[j] = node
			}
		}

		// Convert to string for uniqueness check
		simplePathStr := strings.Join(simplePath, "|")

		// Check if we've seen this simple path before
		if existingIndex, exists := uniqueSimplePaths[simplePathStr]; exists {
			// We've seen this path before, check if we should prefer this one
			// Preference criteria: shorter fully qualified names are better
			// (they're usually more direct and readable)

			// Sum the length of all node names in both paths
			existingPathLength := 0
			for _, node := range paths[existingIndex] {
				existingPathLength += len(node)
			}

			currentPathLength := 0
			for _, node := range path {
				currentPathLength += len(node)
			}

			// If current path has shorter names overall, replace the existing one
			if currentPathLength < existingPathLength {
				// Remove the existing path from results (will be replaced)
				for resultIdx, resultPath := range result {
					if reflect.DeepEqual(resultPath, paths[existingIndex]) {
						// Remove by replacing with the last element and truncating
						result[resultIdx] = result[len(result)-1]
						result = result[:len(result)-1]
						break
					}
				}

				// Update the index for this simple path
				uniqueSimplePaths[simplePathStr] = i
				result = append(result, path)
			}
			// Otherwise keep the existing path (do nothing)
		} else {
			// First time seeing this path
			uniqueSimplePaths[simplePathStr] = i
			result = append(result, path)
		}
	}

	// fmt.Printf("DEBUG: Deduplicated from %d to %d paths\n", len(paths), len(result))
	return result
}

// printCallGraph prints all the calls in the call graph for debugging
func printCallGraph(graph *models.CallGraph) {
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
	fmt.Println("===================")
}

func findReachableFunctions(results *models.AnalysisResults, fullyQualifiedSource string, maxDepth int) []string {
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

	}

	// BFS to find reachable functions
	visited := make(map[string]bool)
	queue := []struct {
		node  string
		depth int
	}{{fullyQualifiedSource, 0}}

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

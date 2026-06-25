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
	"static-analysis/internal/parser/java"
	java_parser "static-analysis/internal/parser/java/grammar"
	"strings"
	"sync"
	"time"
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
	v.Functions[v.CurrentFunc] = &FunctionDefinition{
		Name:       v.CurrentFunc,
		FilePath:   v.CurrentFile,
		StartLine:  startLine,
		EndLine:    endLine,
		SourceCode: sourceCode,
	}

	fmt.Printf("Found function: %s (lines %d-%d)\n", v.CurrentFunc, startLine, endLine)

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

	v.Functions[v.CurrentFunc] = &FunctionDefinition{
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

	// // Preprocess the source to handle line continuations
	// preprocessedSource := PreprocessCSource(string(content))
	// sourceLines := strings.Split(preprocessedSource, "\n")

	// // Create a simple line map that maps each line to itself
	// lineMap := make(map[int]c.LineInfo)
	// for i := range sourceLines {
	//     lineMap[i+1] = c.LineInfo{
	//         File: filePath,
	//         Line: i+1,
	//     }
	// }

	// // Create input stream for ANTLR
	// input := antlr.NewInputStream(preprocessedSource)

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

// PreprocessCSource handles line continuations and other preprocessing
func PreprocessCSource(source string) string {
	// Handle line continuations (backslash at end of line)
	lineContinuationPattern := regexp.MustCompile(`\\\r?\n`)
	preprocessed := lineContinuationPattern.ReplaceAllString(source, " ")

	return preprocessed
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
			Caller: v.CurrentFunc,
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

	fmt.Printf("Found method: %s lines [%d-%d]\n", methodName, startLine, endLine)

	// Extract source code
	sourceCode := ""
	if startLine <= endLine && startLine <= len(v.SourceLines) {
		sourceLines := v.SourceLines[startLine-1 : min(endLine, len(v.SourceLines))]
		sourceCode = strings.Join(sourceLines, "\n")
	}

	// Add to function definitions
	v.Functions[methodName] = &FunctionDefinition{
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
		fmt.Printf("Found class: %s\n", v.CurrentClass)
	} else {
		fmt.Println("Could not find class name")
	}
}

// Add this method to reset class name when exiting a class
func (v *JavaFunctionVisitor) ExitClassDeclaration(ctx *java_parser.ClassDeclarationContext) {
	v.CurrentClass = ""
}

func main() {
	// Parse command-line arguments
	rootDir := flag.String("dir", ".", "Root directory to analyze")
	outputPath := flag.String("output", "function_definitions.txt", "Output file path")
	jsonPath := flag.String("json", "analysis_results.json", "JSON output file path")
	funcNameFlag := flag.String("func", "", "Specific function name to find")
	fuzzerClassFlag := flag.String("fuzzer", "", "Path to fuzzer class file")
	fuzzerPathsFlag := flag.String("fuzzer-paths", "", "Comma-separated list of fuzzer class files")
	fuzzerDirFlag := flag.String("fuzzer-dir", "", "Directory containing fuzzer class files")
	targetFuncFlag := flag.String("target", "", "Target function to find paths to")
	numWorkers := flag.Int("workers", runtime.NumCPU(), "Number of parallel workers")
	forceFlag := flag.Bool("force", false, "Force recomputation even if JSON exists")
	flag.Parse()

	// Process fuzzer paths
	var fuzzerPaths []string

	// Add single fuzzer if specified
	if *fuzzerClassFlag != "" {
		fuzzerPaths = append(fuzzerPaths, *fuzzerClassFlag)
	}

	// Add comma-separated list of fuzzers if specified
	if *fuzzerPathsFlag != "" {
		additionalPaths := strings.Split(*fuzzerPathsFlag, ",")
		fuzzerPaths = append(fuzzerPaths, additionalPaths...)
	}

	// Add all Java files from fuzzer directory if specified
	if *fuzzerDirFlag != "" {
		files, err := os.ReadDir(*fuzzerDirFlag)
		if err != nil {
			fmt.Printf("Error reading fuzzer directory %s: %v\n", *fuzzerDirFlag, err)
		} else {
			for _, file := range files {
				if !file.IsDir() && strings.HasSuffix(strings.ToLower(file.Name()), ".java") {
					fuzzerPath := filepath.Join(*fuzzerDirFlag, file.Name())
					fuzzerPaths = append(fuzzerPaths, fuzzerPath)
				}
			}
			fmt.Printf("Added %d fuzzer files from directory %s\n", len(fuzzerPaths), *fuzzerDirFlag)
		}
	}

	// Initialize empty results
	var results AnalysisResults
	var needFunctions, needCallGraph, needPaths bool

	// Check if results already exist
	if !*forceFlag && fileExists(*jsonPath) {
		jsonData, err := os.ReadFile(*jsonPath)
		if err == nil {
			if err := json.Unmarshal(jsonData, &results); err == nil {
				fmt.Printf("Loaded existing analysis results from %s\n", *jsonPath)

				// Check what needs to be computed
				needFunctions = len(results.Functions) == 0
				needCallGraph = results.CallGraph == nil || len(results.CallGraph.Calls) == 0
				needPaths = *fuzzerClassFlag != "" && *targetFuncFlag != "" &&
					(results.Paths == nil || len(results.Paths[*targetFuncFlag]) == 0)

				if !needFunctions && !needCallGraph && !needPaths {
					// Everything we need is already computed
					writeResultsToTextFile(&results, *outputPath, *funcNameFlag, *fuzzerClassFlag, *targetFuncFlag)
					fmt.Printf("Results written to %s\n", *outputPath)
					return
				}

				fmt.Printf("Partial results found. Need to compute: functions=%v, callGraph=%v, paths=%v\n",
					needFunctions, needCallGraph, needPaths)
			} else {
				fmt.Printf("Error parsing existing JSON: %v, will recompute everything\n", err)
				needFunctions = true
				needCallGraph = true
				needPaths = *fuzzerClassFlag != "" && *targetFuncFlag != ""
				results = AnalysisResults{
					Functions: make(map[string]*FunctionDefinition),
					CallGraph: &CallGraph{Calls: []MethodCall{}},
					Paths:     make(map[string][][]string),
				}
			}
		} else {
			fmt.Printf("Error reading JSON file: %v, will recompute everything\n", err)
			needFunctions = true
			needCallGraph = true
			needPaths = *fuzzerClassFlag != "" && *targetFuncFlag != ""
			results = AnalysisResults{
				Functions: make(map[string]*FunctionDefinition),
				CallGraph: &CallGraph{Calls: []MethodCall{}},
				Paths:     make(map[string][][]string),
			}
		}
	} else {
		// Force recomputation or JSON doesn't exist
		needFunctions = true
		needCallGraph = true
		needPaths = *fuzzerClassFlag != "" && *targetFuncFlag != ""
		results = AnalysisResults{
			Functions: make(map[string]*FunctionDefinition),
			CallGraph: &CallGraph{Calls: []MethodCall{}},
			Paths:     make(map[string][][]string),
		}
	}

	// If we need to compute functions or call graph, analyze the files
	if needFunctions || needCallGraph {

		// Find all C/C++ and Java files to analyze
		var cFilesToAnalyze []string
		var javaFilesToAnalyze []string

		// Add all fuzzer paths to Java files to analyze
		for _, fuzzerPath := range fuzzerPaths {

			// Skip files in certain directories
			if shouldSkipFile(fuzzerPath) {
				continue
			}
			if strings.HasSuffix(fuzzerPath, ".c") || strings.HasSuffix(fuzzerPath, ".cc") || strings.HasSuffix(fuzzerPath, ".cpp") {
				cFilesToAnalyze = append(cFilesToAnalyze, fuzzerPath)
			} else if strings.HasSuffix(fuzzerPath, ".java") {
				javaFilesToAnalyze = append(javaFilesToAnalyze, fuzzerPath)
				fmt.Printf("Added fuzzer class: %s\n", fuzzerPath)
			} else {
				fmt.Printf("Warning: Fuzzer class %s is not a C or Java file\n", fuzzerPath)
			}
		}

		err := filepath.Walk(*rootDir, func(path string, info os.FileInfo, err error) error {
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
					cFilesToAnalyze = append(cFilesToAnalyze, path)
				} else if ext == ".java" {
					javaFilesToAnalyze = append(javaFilesToAnalyze, path)
				}
			}

			return nil
		})

		if err != nil {
			fmt.Printf("Error finding files: %v\n", err)
			os.Exit(1)
		}

		// Map to store all function definitions
		allFunctionsMutex := sync.Mutex{}
		allFunctions := make(map[string]*FunctionDefinition)

		// Global call graph with mutex for thread safety
		callGraphMutex := sync.Mutex{}
		globalCallGraph := &CallGraph{Calls: []MethodCall{}}

		// Process C/C++ files if needed
		if needFunctions {
			// Process C/C++ files
			fmt.Printf("Found %d C/C++ files to analyze\n", len(cFilesToAnalyze))
			// Create a worker pool
			var wg sync.WaitGroup
			cFilesChan := make(chan string, len(cFilesToAnalyze))

			// Start worker goroutines
			for i := 0; i < *numWorkers; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()

					for filePath := range cFilesChan {
						fmt.Printf("Analyzing C/C++ file: %s...\n", filePath)

						// Process the C/C++ file and extract functions
						functions, err := processCFile(filePath)
						if err != nil {
							fmt.Printf("Error processing file %s: %v\n", filePath, err)
							continue
						}

						// Add functions to the global map with mutex lock
						if len(functions) > 0 {
							allFunctionsMutex.Lock()
							for name, funcDef := range functions {
								allFunctions[name] = funcDef
							}
							allFunctionsMutex.Unlock()
							fmt.Printf("Found %d functions in %s\n", len(functions), filePath)
						} else {
							fmt.Printf("No functions found in %s\n", filePath)
						}
					}
				}()
			}

			// Send files to workers
			for _, filePath := range cFilesToAnalyze {
				cFilesChan <- filePath
			}
			close(cFilesChan)

			// Wait for all C/C++ files to be processed
			wg.Wait()
		}

		// Process Java files if needed
		if needFunctions || needCallGraph {
			// Process Java files
			fmt.Printf("Found %d Java files to analyze\n", len(javaFilesToAnalyze))
			var wg sync.WaitGroup
			// Create a worker pool for Java files
			javaFilesChan := make(chan string, len(javaFilesToAnalyze))

			// Start worker goroutines
			for i := 0; i < *numWorkers; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()

					for filePath := range javaFilesChan {
						fmt.Printf("Analyzing Java file: %s...\n", filePath)

						// Read the file content
						content, err := os.ReadFile(filePath)
						if err != nil {
							fmt.Printf("Error reading file %s: %v\n", filePath, err)
							continue
						}

						sourceLines := strings.Split(string(content), "\n")
						// Parse Java file
						tree, err := java.Parse(string(content))
						if err != nil {
							fmt.Printf("Error parsing file %s: %v\n", filePath, err)
							continue
						}
						// Visit parse tree to find function definitions
						v := NewJavaFunctionVisitor(filePath, sourceLines)

						// Use ParseTreeWalker
						walker := antlr.NewParseTreeWalker()
						walker.Walk(v, tree)

						// Add functions to the global map with mutex lock
						allFunctionsMutex.Lock()
						for name, funcDef := range v.Functions {
							allFunctions[name] = funcDef
						}
						allFunctionsMutex.Unlock()

						// Add calls to the global call graph with mutex lock
						callGraphMutex.Lock()
						globalCallGraph.Calls = append(globalCallGraph.Calls, v.CallGraph.Calls...)
						callGraphMutex.Unlock()
					}
				}()
			}

			// Send files to workers
			for _, filePath := range javaFilesToAnalyze {
				javaFilesChan <- filePath
			}
			close(javaFilesChan)

			// Wait for all Java files to be processed
			wg.Wait()
		}

		// Update results with computed data
		if needFunctions {
			results.Functions = allFunctions
		}
		if needCallGraph {
			results.CallGraph = globalCallGraph
		}

	}

	// Create output file
	outputFile, err := os.Create(*outputPath)
	if err != nil {
		fmt.Printf("Error creating output file: %v\n", err)
		os.Exit(1)
	}
	defer outputFile.Close()

	// Compute paths if needed
	if needPaths {
		// Extract fuzzer class name from path
		fuzzerClassName := filepath.Base(*fuzzerClassFlag)
		fuzzerClassName = strings.TrimSuffix(fuzzerClassName, ".java")

		// The entry point is typically fuzzerTestOneInput in the fuzzer class
		entryPoint := fuzzerClassName + ".fuzzerTestOneInput"

		// Find all paths from entry point to target
		paths := findAllPaths(results.CallGraph, entryPoint, *targetFuncFlag)

		// Initialize paths map if needed
		if results.Paths == nil {
			results.Paths = make(map[string][][]string)
		}

		results.Paths[*targetFuncFlag] = paths
		fmt.Printf("Computed %d paths from %s to %s\n", len(paths), entryPoint, *targetFuncFlag)
	}

	// Save results to JSON
	jsonData, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Printf("Error creating JSON: %v\n", err)
	} else {
		if err := os.WriteFile(*jsonPath, jsonData, 0644); err != nil {
			fmt.Printf("Error writing JSON file: %v\n", err)
		} else {
			fmt.Printf("Analysis results saved to %s\n", *jsonPath)
		}
	}

	// Write results to text output file
	// writeResultsToTextFile(&results, *outputPath, *funcNameFlag, *fuzzerClassFlag, *targetFuncFlag)
	// fmt.Printf("Results written to %s\n", *outputPath)
}

// writeResultsToTextFile writes the analysis results to a text file
func writeResultsToTextFile(results *AnalysisResults, outputPath, funcNameFlag, fuzzerClassFlag, targetFuncFlag string) {
	// Create output file
	outputFile, err := os.Create(outputPath)
	if err != nil {
		fmt.Printf("Error creating output file: %v\n", err)
		return
	}
	defer outputFile.Close()

	// If a specific function was requested
	if funcNameFlag != "" {
		if funcDef, found := results.Functions[funcNameFlag]; found {
			fmt.Fprintf(outputFile, "Function: %s\n", funcDef.Name)
			fmt.Fprintf(outputFile, "File: %s\n", funcDef.FilePath)
			fmt.Fprintf(outputFile, "Lines: %d-%d\n", funcDef.StartLine, funcDef.EndLine)
			fmt.Fprintf(outputFile, "Source Code:\n%s\n", funcDef.SourceCode)
		} else {
			fmt.Fprintf(outputFile, "Function '%s' not found\n", funcNameFlag)
		}
	} else {
		// Print all functions
		fmt.Fprintf(outputFile, "Found %d function definitions\n", len(results.Functions))

		// Sort functions by name for consistent output
		var functionNames []string
		for name := range results.Functions {
			functionNames = append(functionNames, name)
		}
		sort.Strings(functionNames)

		for _, name := range functionNames {
			funcDef := results.Functions[name]
			fmt.Fprintf(outputFile, "\n-------------------------------------------\n")
			fmt.Fprintf(outputFile, "Function: %s\n", funcDef.Name)
			fmt.Fprintf(outputFile, "File: %s\n", funcDef.FilePath)
			fmt.Fprintf(outputFile, "Lines: %d-%d\n", funcDef.StartLine, funcDef.EndLine)
			fmt.Fprintf(outputFile, "Source Code:\n%s\n", funcDef.SourceCode)
		}
	}

	// Add call graph information
	fmt.Fprintf(outputFile, "\n\n--- CALL GRAPH ---\n\n")
	for _, call := range results.CallGraph.Calls {
		fmt.Fprintf(outputFile, "%s -> %s\n", call.Caller, call.Callee)
	}

	// Add path analysis if available
	if fuzzerClassFlag != "" && targetFuncFlag != "" {
		// Extract fuzzer class name from path
		fuzzerClassName := filepath.Base(fuzzerClassFlag)
		fuzzerClassName = strings.TrimSuffix(fuzzerClassName, ".java")

		// The entry point is typically fuzzerTestOneInput in the fuzzer class
		entryPoint := fuzzerClassName + ".fuzzerTestOneInput"

		fmt.Fprintf(outputFile, "\n\n--- PATHS FROM FUZZER TO TARGET ---\n\n")
		fmt.Fprintf(outputFile, "Fuzzer entry point: %s\n", entryPoint)
		fmt.Fprintf(outputFile, "Target function: %s\n\n", targetFuncFlag)

		paths, ok := results.Paths[targetFuncFlag]
		if !ok || len(paths) == 0 {
			fmt.Fprintf(outputFile, "No paths found from %s to %s\n", entryPoint, targetFuncFlag)
		} else {
			fmt.Fprintf(outputFile, "Found %d paths:\n\n", len(paths))

			for i, path := range paths {
				fmt.Fprintf(outputFile, "Path %d:\n", i+1)
				for j, node := range path {
					if j < len(path)-1 {
						fmt.Fprintf(outputFile, "  %s ->\n", node)
					} else {
						fmt.Fprintf(outputFile, "  %s\n", node)
					}
				}
				fmt.Fprintf(outputFile, "\n")
			}
		}
	}
}

// findAllPaths finds all paths from start to end in the call graph
func findAllPaths(graph *CallGraph, start, targetFunc string) [][]string {
	// Create a map for faster lookup of edges
	edgeMap := make(map[string][]string)
	for _, call := range graph.Calls {
		edgeMap[call.Caller] = append(edgeMap[call.Caller], call.Callee)
	}

	// Find all target methods that match the target function name
	targetMethods := []string{}
	for _, call := range graph.Calls {
		if getSimpleName(call.Callee) == targetFunc {
			targetMethods = append(targetMethods, call.Callee)
		}
	}
	targetMethods = uniqueStrings(targetMethods)

	fmt.Printf("Found %d potential target methods matching '%s': %v\n",
		len(targetMethods), targetFunc, targetMethods)

	// If no target methods found, try to find callers that call methods with this name
	if len(targetMethods) == 0 {
		fmt.Printf("No direct matches found for '%s', looking for callers...\n", targetFunc)
		for _, call := range graph.Calls {
			if getSimpleName(call.Callee) == targetFunc {
				fmt.Printf("Found method call: %s -> %s\n", call.Caller, call.Callee)
			}
		}

		// Try to find a chain of calls that might lead to the target
		fmt.Printf("Looking for potential call chains to '%s'...\n", targetFunc)
		findPotentialCallChains(graph, targetFunc, 3) // Look for chains up to 3 calls long
	}

	// If we still don't have target methods, we can't proceed
	if len(targetMethods) == 0 {
		fmt.Printf("No paths can be found without identified target methods\n")
		return [][]string{}
	}

	// Find all possible start methods
	var startMethods []string
	if strings.Contains(start, ".") {
		startMethods = []string{start}
	} else {
		// Find all methods with this name
		for _, call := range graph.Calls {
			if getSimpleName(call.Caller) == start {
				startMethods = append(startMethods, call.Caller)
			}
		}
		startMethods = uniqueStrings(startMethods)
	}

	if len(startMethods) == 0 {
		startMethods = []string{start} // Use the original name if no matches
	}

	fmt.Printf("Found %d potential start methods matching '%s': %v\n",
		len(startMethods), start, startMethods)

	// Set up BFS parameters
	maxDepth := 20 // Reasonable depth limit

	// Find paths using BFS from each start method to each target method
	allPaths := [][]string{}

	for _, startMethod := range startMethods {
		for _, targetMethod := range targetMethods {
			fmt.Printf("Searching for paths from %s to %s (max depth: %d)...\n",
				startMethod, targetMethod, maxDepth)

			paths := findPathsBFS(edgeMap, startMethod, targetMethod, maxDepth)
			allPaths = append(allPaths, paths...)

			fmt.Printf("Found %d paths from %s to %s\n",
				len(paths), startMethod, targetMethod)
		}
	}

	return allPaths
}

// findPathsBFS finds paths from start to target using BFS with a depth limit
func findPathsBFS(edgeMap map[string][]string, start, target string, maxDepth int) [][]string {
	// Queue for BFS
	type QueueItem struct {
		node  string
		path  []string
		depth int
	}

	queue := []QueueItem{{node: start, path: []string{start}, depth: 0}}
	visited := make(map[string]bool)
	var paths [][]string

	startTime := time.Now()
	nodesVisited := 0
	progressInterval := 5 * time.Second
	lastProgressTime := startTime

	for len(queue) > 0 {
		// Get the next item from the queue
		item := queue[0]
		queue = queue[1:]

		// Skip if we've reached max depth
		if item.depth >= maxDepth {
			continue
		}

		// Update progress
		nodesVisited++
		now := time.Now()
		if now.Sub(lastProgressTime) > progressInterval {
			elapsed := now.Sub(startTime).Seconds()
			fmt.Printf("BFS Progress: visited %d nodes, queue size %d, current depth %d, elapsed %.1f seconds\n",
				nodesVisited, len(queue), item.depth, elapsed)
			lastProgressTime = now
		}

		// Check if we've reached the target
		if item.node == target {
			paths = append(paths, item.path)
			fmt.Printf("Found path: %v (length: %d)\n", item.path, len(item.path))
			continue
		}

		// Mark as visited
		visited[item.node] = true

		// Add neighbors to the queue
		for _, neighbor := range edgeMap[item.node] {
			if !visited[neighbor] {
				newPath := make([]string, len(item.path))
				copy(newPath, item.path)
				newPath = append(newPath, neighbor)

				queue = append(queue, QueueItem{
					node:  neighbor,
					path:  newPath,
					depth: item.depth + 1,
				})
			}
		}
	}

	return uniquePaths(paths)
}
func uniquePaths(paths [][]string) [][]string {
	// Create a map to track unique paths
	uniquePathMap := make(map[string][]string)

	for _, path := range paths {
		// Convert path to string for map key
		pathKey := strings.Join(path, "|")
		uniquePathMap[pathKey] = path
	}

	// Convert back to slice
	result := make([][]string, 0, len(uniquePathMap))
	for _, path := range uniquePathMap {
		result = append(result, path)
	}

	return result
}

// findPotentialCallChains looks for chains of calls that might lead to the target
func findPotentialCallChains(graph *CallGraph, targetFunc string, maxDepth int) {
	// Build a reverse map from callee to callers
	reverseMap := make(map[string][]string)
	for _, call := range graph.Calls {
		reverseMap[call.Callee] = append(reverseMap[call.Callee], call.Caller)
	}

	// Find methods that directly call methods with the target name
	directCallers := []string{}
	for _, call := range graph.Calls {
		if getSimpleName(call.Callee) == targetFunc {
			directCallers = append(directCallers, call.Caller)
		}
	}
	directCallers = uniqueStrings(directCallers)

	if len(directCallers) > 0 {
		fmt.Printf("Found %d methods that directly call '%s':\n", len(directCallers), targetFunc)
		for _, caller := range directCallers {
			fmt.Printf("  %s\n", caller)
		}

		// For each direct caller, find what calls it
		for _, caller := range directCallers {
			findCallerChain(graph, caller, 1, maxDepth)
		}
	}
}

// findCallerChain recursively finds chains of callers
func findCallerChain(graph *CallGraph, method string, depth, maxDepth int) {
	if depth >= maxDepth {
		return
	}

	// Find methods that call this method
	callers := []string{}
	for _, call := range graph.Calls {
		if call.Callee == method {
			callers = append(callers, call.Caller)
		}
	}

	for _, caller := range callers {
		indent := strings.Repeat("  ", depth)
		fmt.Printf("%s%s -> %s\n", indent, caller, method)
		findCallerChain(graph, caller, depth+1, maxDepth)
	}
}

// getSimpleName extracts the simple method name from a fully qualified name
func getSimpleName(fullMethodName string) string {
	parts := strings.Split(fullMethodName, ".")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullMethodName
}

// isMethodMatch checks if a fully qualified method name matches the target function
func isMethodMatch(fullMethodName, targetFunc string) bool {
	// If the full method name exactly matches the target, return true
	if fullMethodName == targetFunc {
		return true
	}

	// Check if the method name part matches the target
	return getSimpleName(fullMethodName) == targetFunc
}

// uniqueStrings removes duplicates from a slice of strings
func uniqueStrings(slice []string) []string {
	keys := make(map[string]bool)
	var list []string
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

// Helper function to check if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// shouldSkipFile returns true if the file should be skipped
func shouldSkipFile(filePath string) bool {
	// List of directories to exclude
	excludeDirs := []string{
		"contrib",      // All contrib code (often has platform dependencies)
		"libpng_build", // Build artifacts
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

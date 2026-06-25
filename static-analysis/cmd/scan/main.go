// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/antlr4-go/antlr/v4"
	"github.com/joho/godotenv"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
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

// FileStats represents statistics for a source file
type FileStats struct {
	FilePath    string `json:"filePath"`
	Language    string `json:"language"`
	LineCount   int    `json:"lineCount"`
	TokenCount  int    `json:"tokenCount"`
	CleanedSize int    `json:"cleanedSize"` // Size in bytes after comment removal
}

// SuspiciousFile holds data if an LLM suspects vulnerabilities
type SuspiciousFile struct {
	FilePath      string `json:"filePath"`
	Model         string `json:"model"`
	Snippet       string `json:"snippet"`
	LLMRawMessage string `json:"llmRawMessage"`
}

func main() {
	// Parse command-line arguments
	rootDir := flag.String("dir", "", "Root directory to analyze")
	numWorkers := flag.Int("workers", runtime.NumCPU(), "Number of parallel workers")
	statsPath := flag.String("stats", "file_stats.json", "Statistics output file path")
	suspectPath := flag.String("suspect", "suspected_vulns.json", "Suspicious files output (based on LLM)")
	incremental := flag.Bool("incremental", false, "Save results incrementally as vulnerabilities are found")
	flag.Parse()

	// Ensure root directory is provided
	if *rootDir == "" {
		fmt.Fprintf(os.Stderr, "Error: Root directory (-dir) is required\n")
		flag.Usage()
		os.Exit(1)
	}

	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		fmt.Printf("Warning: .env file not found, using environment variables")
	}

	// Find all source files
	fmt.Printf("Finding source files in %s...\n", *rootDir)
	sourceFiles, err := findSourceFiles(*rootDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding source files: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Found %d source files\n", len(sourceFiles))

	// Process files and collect statistics
	fmt.Printf("Processing files with %d workers...\n", *numWorkers)
	fileStats, suspected, err := processSourceFilesWithLLM(sourceFiles, *rootDir, *numWorkers, *suspectPath, *incremental)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error processing source files: %v\n", err)
		os.Exit(1)
	}

	// Print summary statistics
	printStatsSummary(fileStats, *statsPath)

	// Write statistics to file
	if err := writeFileStats(fileStats, *statsPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing file statistics: %v\n", err)
		os.Exit(1)
	}

	// Only write the final file if we're not in incremental mode
	if !*incremental {
		// Write suspected vulnerabilities to JSON
		if err := writeSuspectedFiles(suspected, *suspectPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing suspicious files: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Printf("Processed %d source files. Found %d suspicious chunks (saved incrementally).\n",
			len(fileStats), len(suspected))
	}

	fmt.Printf("Processed %d source files. Statistics written to %s\n", len(fileStats), *statsPath)
}

var (
	fileMutex sync.Mutex
)

// processSourceFilesWithLLM is similar to processSourceFiles, but also calls LLMs
func processSourceFilesWithLLM(sourceFiles []string, projectDir string, numWorkers int, outputPath string, incremental bool) ([]FileStats, []SuspiciousFile, error) {
	fileStats := make([]FileStats, 0, len(sourceFiles))
	suspected := make([]SuspiciousFile, 0)
	var mu sync.Mutex

	var wg sync.WaitGroup
	fileChan := make(chan string, len(sourceFiles))

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for filePath := range fileChan {
				stats, suspicious, err := processSourceFileWithLLM(projectDir, filePath)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error processing %s: %v\n", filePath, err)
					continue
				}

				mu.Lock()
				fileStats = append(fileStats, stats)
				// If we found suspicious files and incremental mode is on
				if len(suspicious) > 0 && incremental {
					// Save each suspicious file immediately
					for _, susp := range suspicious {
						// Append to the global list
						suspected = append(suspected, susp)

						// Save to file immediately
						if err := appendSuspectedFile(susp, outputPath); err != nil {
							fmt.Fprintf(os.Stderr, "Error saving suspicious file: %v\n", err)
						} else {
							fmt.Printf("✅ Immediately saved suspicious file to %s: %s\n", outputPath, susp.FilePath)
						}
					}
				} else {
					// In non-incremental mode, just add to the list
					suspected = append(suspected, suspicious...)
				}
				mu.Unlock()
			}
		}()
	}

	for _, filePath := range sourceFiles {
		fileChan <- filePath
	}
	close(fileChan)
	wg.Wait()

	return fileStats, suspected, nil
}

// New function to append a single suspicious file to the JSON file
func appendSuspectedFile(suspicious SuspiciousFile, outputPath string) error {
	fileMutex.Lock()
	defer fileMutex.Unlock()

	// Read existing data
	var existingSuspicious []SuspiciousFile

	// Check if file exists
	if _, err := os.Stat(outputPath); err == nil {
		// File exists, read it
		data, err := os.ReadFile(outputPath)
		if err != nil {
			return fmt.Errorf("error reading existing file: %v", err)
		}

		// Unmarshal existing data
		if err := json.Unmarshal(data, &existingSuspicious); err != nil {
			// If file is corrupted or empty, start fresh
			existingSuspicious = []SuspiciousFile{}
		}
	} else {
		// File doesn't exist, start with empty array
		existingSuspicious = []SuspiciousFile{}
	}

	// Append new suspicious file
	existingSuspicious = append(existingSuspicious, suspicious)

	// Marshal to JSON
	jsonData, err := json.MarshalIndent(existingSuspicious, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling JSON: %v", err)
	}

	// Write to file
	if err := os.WriteFile(outputPath, jsonData, 0644); err != nil {
		return fmt.Errorf("error writing to file: %v", err)
	}

	return nil
}

var (
	// LLM model list
	models = []string{
		CLAUDE_MODEL,
		OPENAI_MODEL,
		GEMINI_MODEL_PRO_25,
		GEMINI_MODEL,
	}
)

// 3. Configuration
const maxChunkLines = 1000
const maxChunkTokens = 10000
const bigFunctionThreshold = 2000 // lines

func analyzeFunctionWithLLM(functions map[string]*FunctionDefinition, language string, filePath, relativeFilePath string) []SuspiciousFile {
	var suspicious []SuspiciousFile

	// 1. Extract all function definitions into a slice so we can sort them.
	var functionDefs []*FunctionDefinition
	for _, fdef := range functions {
		functionDefs = append(functionDefs, fdef)
	}

	// 2. Sort them by start line to preserve code order
	sort.Slice(functionDefs, func(i, j int) bool {
		return functionDefs[i].StartLine < functionDefs[j].StartLine
	})

	var linesBuffer []string
	var currentTokens int
	var mergedChunks [][]string

	for _, funcDef := range functionDefs {
		numLines := funcDef.EndLine - funcDef.StartLine
		if numLines <= 0 {
			continue
		}

		// Split function into lines so we can count or split if it's too large
		funcLines := strings.Split(funcDef.SourceCode, "\n")

		// 3a. If function itself exceeds 1000 lines, we must chunk *within* that function.
		if numLines > bigFunctionThreshold {
			// Break this single function into up-to-500-line sub-chunks
			startIdx := 0
			for startIdx < len(funcLines) {
				endIdx := startIdx + maxChunkLines
				if endIdx > len(funcLines) {
					endIdx = len(funcLines)
				}
				subFuncLines := funcLines[startIdx:endIdx]
				subTokenCount := countTokens(strings.Join(subFuncLines, "\n"))

				// Check if adding these lines to our current chunk exceeds chunk limits
				if len(linesBuffer)+len(subFuncLines) > maxChunkLines ||
					currentTokens+subTokenCount > maxChunkTokens {

					// Finalize the current chunk
					if len(linesBuffer) > 0 {
						mergedChunks = append(mergedChunks, linesBuffer)
					}
					linesBuffer = nil
					currentTokens = 0
				}

				// Start (or continue) a new chunk with the sub-chunk
				linesBuffer = append(linesBuffer, subFuncLines...)
				currentTokens += subTokenCount

				// Move on to the next segment of this large function
				startIdx = endIdx
			}
		} else {
			// 3b. Function <= 1000 lines. Keep it intact if it fits, otherwise finalize current chunk first.

			// Count tokens for the entire function
			funcTokenCount := countTokens(funcDef.SourceCode)

			// Check if adding this entire function would exceed the chunk limits
			if len(linesBuffer)+len(funcLines) > maxChunkLines ||
				currentTokens+funcTokenCount > maxChunkTokens {

				// finalize the current chunk
				if len(linesBuffer) > 0 {
					mergedChunks = append(mergedChunks, linesBuffer)
				}
				linesBuffer = nil
				currentTokens = 0
			}

			// Then either start or continue with a new chunk containing this whole function
			linesBuffer = append(linesBuffer, funcLines...)
			currentTokens += funcTokenCount
		}
	}

	// 3c. If the buffer still has lines after processing all functions, finalize it
	if len(linesBuffer) > 0 {
		mergedChunks = append(mergedChunks, linesBuffer)
	}

	// 4. Now each merged chunk is at most 500 lines or 5000 tokens (and no small function was split).
	//    Perform the LLM security check on each chunk.
	for _, chunkLines := range mergedChunks {
		chunkContent := strings.Join(chunkLines, "\n")
		voteCount := 0
		var rawMessages []string
		var flaggedBy []string

		for _, model := range models {
			hasVuln, raw := callLLMForSecurityCheck(model, filePath, relativeFilePath, chunkContent, language)
			if hasVuln {
				voteCount++
				rawMessages = append(rawMessages, fmt.Sprintf("[%s] %s", model, raw))
				flaggedBy = append(flaggedBy, model)
			}

			// Optional early exit if we hit required votes
			if voteCount >= 2 {
				break
			}
		}

		// If 2 or more models flagged the snippet as vulnerable, mark it suspicious
		if voteCount >= 2 {
			suspicious = append(suspicious, SuspiciousFile{
				FilePath:      relativeFilePath,
				Model:         strings.Join(flaggedBy, ", "),
				Snippet:       chunkContent,
				LLMRawMessage: strings.Join(rawMessages, "\n\n"),
			})
			fmt.Printf("✅ flagged %s as suspicious by %s\n", filePath, flaggedBy)
		}
	}

	return suspicious
}

func analyzeFunctionWithLLM0(functions map[string]*FunctionDefinition, language string, filePath, relativeFilePath string) []SuspiciousFile {

	var suspicious []SuspiciousFile

	for _, funcDef := range functions {

		line_start := funcDef.StartLine
		line_end := funcDef.EndLine
		num_lines := line_end - line_start
		if num_lines <= 0 {
			continue
		}
		content := funcDef.SourceCode
		tokenCount := countTokens(content)
		lines := strings.Split(content, "\n")
		// Split into chunks
		chunks := splitIntoChunks(lines, 500, 5000, tokenCount)

		for _, chunk := range chunks {
			chunkContent := strings.Join(chunk, "\n")
			voteCount := 0
			var rawMessages []string
			var flaggedBy []string

			for _, model := range models {
				// fmt.Printf("🔍 callLLMForSecurityCheck | model=%-20s | file=%s\n", model, filePath)
				hasVuln, raw := callLLMForSecurityCheck(model, filePath, relativeFilePath, chunkContent, language)

				if hasVuln {
					voteCount++
					rawMessages = append(rawMessages, fmt.Sprintf("[%s] %s", model, raw))
					flaggedBy = append(flaggedBy, model)
				}

				// Optional early exit if we hit required votes
				if voteCount >= 2 {
					break
				}
			}

			if voteCount >= 2 {
				suspicious = append(suspicious, SuspiciousFile{
					FilePath:      relativeFilePath,
					Model:         strings.Join(flaggedBy, ", "),
					Snippet:       chunkContent,
					LLMRawMessage: strings.Join(rawMessages, "\n\n"),
				})

				fmt.Printf("✅ flagged %s as suspicious by %s\n", filePath, flaggedBy)
			}
		}
	}
	return suspicious
}
func processSourceFileWithLLM(projectDir string, filePath string) (FileStats, []SuspiciousFile, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return FileStats{}, nil, fmt.Errorf("error reading file: %v", err)
	}

	var suspicious []SuspiciousFile

	// Strip the project directory from the file path to make it relative
	relativeFilePath := filePath
	if strings.HasPrefix(filePath, projectDir) {
		// Add 1 to include the trailing slash if it exists
		relativeFilePath = filePath[len(projectDir):]
		// Remove leading slash if present
		relativeFilePath = strings.TrimPrefix(relativeFilePath, "/")
	}

	// Determine language based on file extension
	ext := strings.ToLower(filepath.Ext(filePath))
	language := "unknown"
	if ext == ".java" {
		language = "java"
		// fmt.Printf("Analyzing Java file: %s...\n", filePath)
		// Read the file content
		content, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Printf("Error reading file %s: %v\n", filePath, err)
		}

		sourceLines := strings.Split(string(content), "\n")
		// Parse Java file
		tree, err := java.Parse(string(content))
		if err != nil {
			fmt.Printf("Error parsing file %s: %v\n", filePath, err)
		}
		// Visit parse tree to find function definitions
		v := NewJavaFunctionVisitor(filePath, sourceLines)
		// Use ParseTreeWalker
		walker := antlr.NewParseTreeWalker()
		walker.Walk(v, tree)

		suspicious_f := analyzeFunctionWithLLM(v.Functions, language, filePath, relativeFilePath)
		suspicious = append(suspicious, suspicious_f...)

	} else if ext == ".c" || ext == ".cpp" || ext == ".h" || ext == ".hpp" {
		language = "c"
		// fmt.Printf("Analyzing C/C++ file: %s...\n", filePath)

		functions, err := processCFile(filePath)
		if err != nil {
			fmt.Printf("Error processing file %s: %v\n", filePath, err)
		} else {
			suspicious_f := analyzeFunctionWithLLM(functions, language, filePath, relativeFilePath)
			suspicious = append(suspicious, suspicious_f...)
		}
	}

	// Strip comments
	cleanedContent := stripComments(string(content), language)

	// Count lines and tokens
	lines := strings.Split(cleanedContent, "\n")
	lineCount := len(lines)
	tokenCount := countTokens(cleanedContent)

	stats := FileStats{
		FilePath:    filePath,
		Language:    language,
		LineCount:   lineCount,
		TokenCount:  tokenCount,
		CleanedSize: len(cleanedContent),
	}

	return stats, suspicious, nil
}

// splitIntoChunks splits the file lines to ensure each chunk is at most maxLines lines
// and at most maxTokens tokens. For simplicity, we *only* consider line size here, but
// you could do a more refined approach that also tracks tokens in each chunk.
func splitIntoChunks(lines []string, maxLines, maxTokens, totalTokens int) [][]string {
	if len(lines) <= maxLines && totalTokens <= maxTokens {
		return [][]string{lines}
	}

	var chunks [][]string
	start := 0
	for start < len(lines) {
		end := start + maxLines
		if end > len(lines) {
			end = len(lines)
		}
		chunk := lines[start:end]
		chunks = append(chunks, chunk)
		start = end
	}

	return chunks
}

func callLLMForSecurityCheck(modelName, filePath, relativeFilePath string, snippet string, language string) (bool, string) {

	// Create language-specific prompts
	var prompt string

	switch language {
	case "c":
		prompt = fmt.Sprintf(`You are a security expert specializing in C/C++ code analysis. Carefully analyze the following code snippet and determine whether it contains any *clear and significant* security vulnerabilities.

Only respond with "YES VULNERABLE" if you are highly confident that the code introduces a real or likely exploitable vulnerability. Do not guess. If there is uncertainty or the issue is minor, respond with "NO SAFE".

Pay special attention to these common C/C++ vulnerabilities:
- Out-of-Bounds Read/Write (CWE-125 / CWE-787)
- Integer Overflow/Underflow (CWE-190)
- Use After Free (CWE-416)
- NULL Pointer Dereference (CWE-476)
- Buffer Overflow (CWE-120)
- Double Free (CWE-415)
- Format String Vulnerabilities (CWE-134)
- Improper Input Validation (CWE-20)

After your answer, briefly explain your reasoning with specific reference to the vulnerability type if found.

## File:
%s

## Functions:
%s`, relativeFilePath, snippet)

	case "java":
		prompt = fmt.Sprintf(`You are a security expert specializing in Java code analysis. Carefully analyze the following code snippet and determine whether it contains any *clear and significant* security vulnerabilities.

Only respond with "YES VULNERABLE" if you are highly confident that the code introduces a real or likely exploitable vulnerability. Do not guess. If there is uncertainty or the issue is minor, respond with "NO SAFE".

Pay special attention to these common Java vulnerabilities:
- Path Traversal (CWE-22)
- Command Injection (CWE-77, CWE-78)
- Unsafe Deserialization (CWE-502)
- Server-Side Request Forgery (SSRF) (CWE-918)
- XML External Entity (XXE) Processing (CWE-611)
- SQL Injection (CWE-89)
- Cross-Site Scripting (XSS) (CWE-79)
- Insecure Cryptography (CWE-327)
- Improper Authentication (CWE-287)
- Improper Access Control (CWE-284)

After your answer, briefly explain your reasoning with specific reference to the vulnerability type if found.

## File:
%s

## Functions:
%s`, relativeFilePath, snippet)
	default:
		// Generic prompt for other languages
		prompt = fmt.Sprintf(`You are a security expert. Carefully analyze the following code snippet and determine whether it contains any *clear and significant* security vulnerabilities.

Only respond with "YES VULNERABLE" if you are highly confident that the code introduces a real or likely exploitable vulnerability. Do not guess. If there is uncertainty or the issue is minor, respond with "NO SAFE".

After your answer, briefly explain your reasoning.

## File:
%s

## Functions:
%s`, relativeFilePath, snippet)
	}
	var client = &http.Client{}
	var body []byte
	var req *http.Request
	var resp *http.Response
	var err error

	lowerName := strings.ToLower(modelName)

	// Prepare request body based on the model
	switch {
	case strings.HasPrefix(lowerName, "chatgpt-"):
		apiKey := os.Getenv("OPENAI_API_KEY")
		if apiKey == "" {
			return false, "Missing OPENAI_API_KEY"
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
			return false, "Missing ANTHROPIC_API_KEY"
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
			return false, "Missing GEMINI_API_KEY"
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
		return false, "Unsupported model: " + modelName
	}

	if err != nil {
		return false, "Failed to create request: " + err.Error()
	}

	// Retry logic (up to 3 times)
	var respBody []byte
	for attempt := 1; attempt <= 3; attempt++ {
		resp, err = client.Do(req)
		if err != nil {
			if attempt == 3 {
				return false, fmt.Sprintf("HTTP request failed after 3 attempts: %v", err)
			}
			time.Sleep(time.Duration(attempt) * time.Second)
			continue
		}
		defer resp.Body.Close()

		respBody, err = io.ReadAll(resp.Body)
		if err != nil {
			if attempt == 3 {
				return false, fmt.Sprintf("Failed to read response after 3 attempts: %v", err)
			}
			time.Sleep(time.Duration(attempt) * time.Second)
			continue
		}

		// Retry if HTTP status indicates rate limiting or server error
		if resp.StatusCode >= 500 || resp.StatusCode == 429 {
			if attempt == 3 {
				return false, fmt.Sprintf("LLM returned error after 3 retries (status %d): %s", resp.StatusCode, string(respBody))
			}
			time.Sleep(time.Duration(attempt) * time.Second)
			continue
		}

		break // success
	}

	respStr := string(respBody)
	// if 	strings.HasPrefix(modelName, "claude-") {
	// fmt.Println(prompt)
	// fmt.Println(respStr)
	// }

	// Extract the actual text content based on model type
	var responseText string

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

	if strings.Contains(strings.ToUpper(respStr), "YES VULNERABLE") {
		return true, responseText
	}

	return false, responseText
}

// printStatsSummary prints a summary of file statistics to the terminal
func printStatsSummary(stats []FileStats, statsPath string) {
	// Count files by language
	languageCounts := make(map[string]int)
	totalLines := 0
	totalTokens := 0

	for _, stat := range stats {
		languageCounts[stat.Language]++
		totalLines += stat.LineCount
		totalTokens += stat.TokenCount
	}

	// Print summary
	fmt.Println("\n=== Source Code Statistics ===")
	fmt.Printf("Total files: %d\n", len(stats))
	fmt.Printf("Total lines: %d\n", totalLines)
	fmt.Printf("Total tokens: %d\n", totalTokens)

	fmt.Println("\nFiles by language:")
	for lang, count := range languageCounts {
		fmt.Printf("  %s: %d files\n", lang, count)
	}

	// Print top 10 largest files by line count
	fmt.Println("\nTop 10 largest files (by line count):")

	// Create a copy of stats to sort
	sortedStats := make([]FileStats, len(stats))
	copy(sortedStats, stats)

	// Sort by line count in descending order
	sort.Slice(sortedStats, func(i, j int) bool {
		return sortedStats[i].LineCount > sortedStats[j].LineCount
	})

	// Print top 10 or fewer if less than 10 files
	limit := 10
	if len(sortedStats) < limit {
		limit = len(sortedStats)
	}

	for i := 0; i < limit; i++ {
		stat := sortedStats[i]
		fmt.Printf("  %s: %d lines, %d tokens\n", stat.FilePath, stat.LineCount, stat.TokenCount)
	}

	fmt.Println("\nDetailed statistics written to", statsPath)
}

// shouldSkipFile returns true if the file should be skipped
func shouldSkipFile(filePath string) bool {
	// List of directories to exclude
	excludeDirs := []string{
		"contrib", // All contrib code (often has platform dependencies)
		"build",   // Build artifacts
		".deps/",
		"test/",            // Test code
		"tests/",           // Test code
		"/scripts/",        // Test code
		"/Test",            // Test code
		"/test",            // Test code
		"scripts",          // Build scripts
		"arm",              // ARM-specific code
		"intel",            // Intel-specific code
		"mips",             // MIPS-specific code
		"powerpc",          // PowerPC-specific code
		"loongarch",        // LoongArch-specific code
		"include/asic_reg", // Very large header files with register definitions
		"drivers/gpu",      // GPU drivers often have large auto-generated files
		"drivers/",         // Most drivers are unlikely to be fuzzed
		"Documentation/",   // Documentation
		"tools/",           // Tools
		"samples/",         // Sample code
		"package-info",
	}

	// Check if the file is in an excluded directory
	for _, dir := range excludeDirs {
		if strings.Contains(filePath, dir) {
			return true
		}
	}

	// Skip header files that are likely to be just type definitions
	// but keep those that might contain inline functions
	if strings.HasSuffix(filePath, ".h") || strings.HasSuffix(filePath, ".hpp") {
		// Skip headers with these patterns in their names
		skipPatterns := []string{
			"_sh_mask", "_offset", "_reg", "_def",
			"types", "config", "compat", "const",
			"generated", "autogen", "auto-gen",
		}

		for _, pattern := range skipPatterns {
			if strings.Contains(strings.ToLower(filePath), pattern) {
				return true
			}
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

// findSourceFiles recursively finds all .c, .cpp, .h, .hpp, and .java files in the given directory
func findSourceFiles(rootDir string) ([]string, error) {
	var sourceFiles []string

	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Check file extension
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".c" || ext == ".cpp" || ext == ".h" || ext == ".hpp" || ext == ".java" {
			// Check if we should skip this file
			if !shouldSkipFile(path) {
				sourceFiles = append(sourceFiles, path)
			}
		}

		return nil
	})

	return sourceFiles, err
}

// processSourceFiles processes all source files and collects statistics
func processSourceFiles(sourceFiles []string, numWorkers int) ([]FileStats, error) {
	fileStats := make([]FileStats, 0, len(sourceFiles))
	var mu sync.Mutex

	// Create a worker pool
	var wg sync.WaitGroup
	fileChan := make(chan string, len(sourceFiles))

	// Start workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for filePath := range fileChan {
				// Process the file
				stats, err := processSourceFile(filePath)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error processing %s: %v\n", filePath, err)
					continue
				}

				// Add stats to the result
				mu.Lock()
				fileStats = append(fileStats, stats)
				mu.Unlock()
			}
		}()
	}
	// Send files to workers
	for _, filePath := range sourceFiles {
		fileChan <- filePath
	}
	close(fileChan)

	// Wait for all workers to finish
	wg.Wait()

	return fileStats, nil
}

// processSourceFile processes a single source file and returns its statistics
func processSourceFile(filePath string) (FileStats, error) {
	// Read the file
	content, err := os.ReadFile(filePath)
	if err != nil {
		return FileStats{}, fmt.Errorf("error reading file: %v", err)
	}

	// Determine language based on file extension
	ext := strings.ToLower(filepath.Ext(filePath))
	language := "unknown"
	if ext == ".java" {
		language = "java"
	} else if ext == ".c" || ext == ".cpp" || ext == ".h" || ext == ".hpp" {
		language = "c"
	}

	// Strip comments
	cleanedContent := stripComments(string(content), language)

	// Count lines and tokens
	lines := strings.Split(cleanedContent, "\n")
	lineCount := len(lines)

	// Count tokens (words) by splitting on whitespace and punctuation
	tokenCount := countTokens(cleanedContent)

	return FileStats{
		FilePath:    filePath,
		Language:    language,
		LineCount:   lineCount,
		TokenCount:  tokenCount,
		CleanedSize: len(cleanedContent),
	}, nil
}

// stripComments removes comments from source code
func stripComments(source string, language string) string {
	// For both C/C++ and Java
	// Remove block comments (/* ... */)
	blockCommentPattern := regexp.MustCompile(`/\*[\s\S]*?\*/`)
	result := blockCommentPattern.ReplaceAllString(source, "")

	// Remove line comments (// ...)
	lineCommentPattern := regexp.MustCompile(`//.*`)
	result = lineCommentPattern.ReplaceAllString(result, "")

	return result
}

// countTokens counts the number of tokens (words) in the source code
func countTokens(source string) int {
	// Replace all punctuation with spaces
	punctuationPattern := regexp.MustCompile(`[^\w\s]`)
	normalized := punctuationPattern.ReplaceAllString(source, " ")

	// Split on whitespace and count non-empty tokens
	tokens := strings.Fields(normalized)
	return len(tokens)
}

// writeFileStats writes file statistics to a JSON file
func writeFileStats(stats []FileStats, outputPath string) error {
	// Sort stats by file path for consistency
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].FilePath < stats[j].FilePath
	})

	// Marshal to JSON
	jsonData, err := json.MarshalIndent(stats, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling JSON: %v", err)
	}

	// Write to file
	if err := os.WriteFile(outputPath, jsonData, 0644); err != nil {
		return fmt.Errorf("error writing to file: %v", err)
	}

	return nil
}

// writeSuspectedFiles writes suspicious files (based on LLM responses) to a JSON file.
func writeSuspectedFiles(suspected []SuspiciousFile, outputPath string) error {
	if len(suspected) == 0 {
		fmt.Println("No suspicious files detected by LLMs.")
		return nil
	}

	jsonData, err := json.MarshalIndent(suspected, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling JSON: %v", err)
	}

	if err := os.WriteFile(outputPath, jsonData, 0644); err != nil {
		return fmt.Errorf("error writing to file: %v", err)
	}

	fmt.Printf("Wrote %d suspicious file entries to %s\n", len(suspected), outputPath)
	return nil
}

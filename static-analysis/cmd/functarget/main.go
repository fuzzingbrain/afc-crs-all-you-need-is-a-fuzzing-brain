// SPDX-License-Identifier: Apache-2.0
package main

import (
	"regexp"
	"flag"
	"fmt"
	"encoding/json"
	"os"
	"strings"
    // "strconv"
    // "runtime"
    "path/filepath"
	"github.com/antlr4-go/antlr/v4"
	"static-analysis/internal/parser/c"
	c_parser "static-analysis/internal/parser/c/grammar"
	"static-analysis/internal/parser/java"
	java_parser "static-analysis/internal/parser/java/grammar"
)
// FunctionDefinition represents a function definition with its source code
type FunctionDefinition struct {
    File string
    Function string
    Class string
	StartLine  int
	EndLine    int
	SourceCode string
}


// CFunctionVisitor for C/C++ files
type CFunctionVisitor struct {
    *c_parser.BaseCListener // Use pointer to BaseCListener
    Functions     map[string][]*FunctionDefinition  // Changed to slice of pointers
    CurrentFile   string
    LineMap       map[int]c.LineInfo
    SourceLines   []string
    CurrentFunc   string
    CurrentStart  int
    InFunctionDef bool
}

func NewCFunctionVisitor(filePath string, lineMap map[int]c.LineInfo, sourceLines []string) *CFunctionVisitor {
    return &CFunctionVisitor{
        BaseCListener: new(c_parser.BaseCListener), // Use new() to create a pointer
        Functions:     make(map[string][]*FunctionDefinition),  // Changed to slice of pointers
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
    funcDef := &FunctionDefinition{
        File: v.CurrentFile,
        Function: v.CurrentFunc,
        StartLine:  startLine,
        EndLine:    endLine,
        SourceCode: sourceCode,
    }
    
    // Append to the slice for this function name
    v.Functions[v.CurrentFunc] = append(v.Functions[v.CurrentFunc], funcDef)
    
    
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
    v.InFunctionDef = false
}

// processCFile processes a C/C++ file and returns the functions found
func processCFile(filePath string, content []byte) (map[string][]*FunctionDefinition, error) {
	    // Skip preprocessing and use the original source directly
		sourceContent := string(content)
		sourceLines := strings.Split(sourceContent, "\n")
		
		// Create a simple line map that maps each line to itself
		lineMap := make(map[int]c.LineInfo)
		for i := range sourceLines {
			lineMap[i+1] = c.LineInfo{
				File: filePath,
				Line: i+1,
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


// JavaFunctionVisitor for Java files
type JavaFunctionVisitor struct {
    *java_parser.BaseJavaParserListener // Embed the base listener
    Functions     map[string][]*FunctionDefinition  // Changed to slice of pointers
    CurrentFile   string
    SourceLines   []string
    CurrentClass  string
    CurrentFunc   string
    CurrentStart  int
    InFunctionDef bool
}

func NewJavaFunctionVisitor(filePath string, sourceLines []string) *JavaFunctionVisitor {
    return &JavaFunctionVisitor{
        BaseJavaParserListener: &java_parser.BaseJavaParserListener{},
        Functions:             make(map[string][]*FunctionDefinition),  // Changed to slice of pointers
        CurrentFile:           filePath,
        SourceLines:           sourceLines,
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
    
    methodName0:= methodName
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
    
    // Create function definition
    funcDef := &FunctionDefinition{
        File: v.CurrentFile,
        Function: v.CurrentFunc,
        Class: v.CurrentClass,
        StartLine:  startLine,
        EndLine:    endLine,
        SourceCode: sourceCode,
    }
    
    // Append to the slice for this method name
    v.Functions[methodName] = append(v.Functions[methodName], funcDef)
  
    
    // Set current function info
    v.CurrentFunc = methodName0
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

// processFileSection processes a single file section from the diff
func processFileSection(section string, changedFunctions map[string][]ChangedFunction) {
	lines := strings.Split(section, "\n")
	if len(lines) < 3 {
		return
	}
	
	// Extract file path
	// The format is typically "a/path/to/file.c b/path/to/file.c"
	filePathLine := lines[0]
	parts := strings.Fields(filePathLine)
	if len(parts) < 2 {
		return
	}
	
	// Get the file path (remove the a/ or b/ prefix)
	filePath := ""
	for _, part := range parts {
		if strings.HasPrefix(part, "b/") {
			filePath = strings.TrimPrefix(part, "b/")
			break
		}
	}
	
	if filePath == "" {
		return
	}
	
	// Track which functions we've found in this file
	foundFunctions := make(map[string]bool)
	
	// Find the @@ lines which indicate changed hunks
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		
		// Parse hunk headers to get line numbers
		if strings.HasPrefix(line, "@@") {
			// Format: @@ -oldStart,oldCount +newStart,newCount @@
			// Look for function names in the context
			contextIndex := strings.LastIndex(line, "@@")
			if contextIndex >= 0 && contextIndex+2 < len(line) {
				context := strings.TrimSpace(line[contextIndex+2:])
				
				// Extract function name from context
				// Common formats:
				// 1. "function_name(...)" - C/C++ style
				// 2. "void function_name(...)" - with return type
				// 3. "class::function_name(...)" - C++ class method
				// 4. "function_name" - just the name
				
				funcNameMatch := regexp.MustCompile(`(?:[\w\*&]+\s+)?(\w+(?:::\w+)*)(?:\s*\(|$)`).FindStringSubmatch(context)
				if len(funcNameMatch) > 1 {
					funcName := funcNameMatch[1]
					
					// Skip if it's a keyword
					if !isKeyword(funcName) && !foundFunctions[funcName] {
						// Create a ChangedFunction entry
						changedFunc := ChangedFunction{
							Name: funcName,
							// We're not setting StartLine and EndLine as requested
						}
						
						// Add to our map
						if _, exists := changedFunctions[filePath]; !exists {
							changedFunctions[filePath] = []ChangedFunction{}
						}
						changedFunctions[filePath] = append(changedFunctions[filePath], changedFunc)
						
						// Mark as found
						foundFunctions[funcName] = true
					}
				}
			}
			
			// Now scan the actual changed lines for function definitions
			for j := i + 1; j < len(lines); j++ {
				hunkLine := lines[j]
				
				// If we hit another hunk header or end of file section, break
				if strings.HasPrefix(hunkLine, "@@") || strings.HasPrefix(hunkLine, "diff --git") {
					break
				}
				
				// Look for function definitions in added lines
				if strings.HasPrefix(hunkLine, "+") {
					codeLine := hunkLine[1:] // Remove the + prefix
					
					// Skip comments
					if isCommentLine(codeLine) {
						continue
					}
					
					// Look for function definitions
					// C/C++ style: return_type function_name(params)
					// Java style: [modifiers] return_type function_name(params)
					funcDefMatch := regexp.MustCompile(`(?:[\w\s\*&]+\s+)?(\w+)\s*\([^)]*\)\s*(?:\{|$)`).FindStringSubmatch(codeLine)
					if len(funcDefMatch) > 1 {
						funcName := funcDefMatch[1]
						
						// Skip keywords
						if !isKeyword(funcName) && !foundFunctions[funcName] {
							// Create a ChangedFunction entry
							changedFunc := ChangedFunction{
								Name: funcName,
								// We're not setting StartLine and EndLine as requested
							}
							
							// Add to our map
							if _, exists := changedFunctions[filePath]; !exists {
								changedFunctions[filePath] = []ChangedFunction{}
							}
							changedFunctions[filePath] = append(changedFunctions[filePath], changedFunc)
							
							// Mark as found
							foundFunctions[funcName] = true
						}
					}
					
					// Also look for function calls in added lines
					// This helps identify which functions are affected by the changes
					funcCallMatches := regexp.MustCompile(`\b(\w+)\s*\(`).FindAllStringSubmatch(codeLine, -1)
					for _, match := range funcCallMatches {
						if len(match) > 1 {
							funcName := match[1]
							
							// Skip keywords and already found functions
							if !isKeyword(funcName) && !foundFunctions[funcName] {
								// Create a ChangedFunction entry
								changedFunc := ChangedFunction{
									Name: funcName,
									// We're not setting StartLine and EndLine as requested
								}
								
								// Add to our map
								if _, exists := changedFunctions[filePath]; !exists {
									changedFunctions[filePath] = []ChangedFunction{}
								}
								changedFunctions[filePath] = append(changedFunctions[filePath], changedFunc)
								
								// Mark as found
								foundFunctions[funcName] = true
							}
						}
					}
				}
			}
		}
	}
	
	// If we didn't find any functions but there are changes, add a placeholder
	if len(foundFunctions) == 0 {
		// Use the filename as a fallback
		baseName := filepath.Base(filePath)
		fileFunc := strings.TrimSuffix(baseName, filepath.Ext(baseName))
		
		changedFunc := ChangedFunction{
			Name: fileFunc,
			// We're not setting StartLine and EndLine as requested
		}
		
		// Add to our map
		if _, exists := changedFunctions[filePath]; !exists {
			changedFunctions[filePath] = []ChangedFunction{}
		}
		changedFunctions[filePath] = append(changedFunctions[filePath], changedFunc)
	}
}




    // ChangedFunction represents a function that was changed in the diff
type ChangedFunction struct {
	Name      string `json:"name"`
	StartLine int    `json:"startLine"`
	EndLine   int    `json:"endLine,omitempty"`
}

// countFunctions counts the total number of functions across all files
func countFunctions(changedFunctions map[string][]ChangedFunction) int {
	count := 0
	for _, functions := range changedFunctions {
		count += len(functions)
	}
	return count
}

    
// parseDiff parses a unified diff format and extracts changed functions
func parseDiff(diffText string) map[string][]ChangedFunction {
	changedFunctions := make(map[string][]ChangedFunction)
	
	// Split diff into file sections
	fileSections := strings.Split(diffText, "diff --git ")
	
	// Skip the first empty section if it exists
	startIdx := 0
	if len(fileSections) > 0 && fileSections[0] == "" {
		startIdx = 1
	}
	
	for i := startIdx; i < len(fileSections); i++ {
		section := fileSections[i]
		if section == "" {
			continue
		}
		
		// Process each file section
		processFileSection(section, changedFunctions)
	}
	
	return changedFunctions
}


// isCommentLine checks if a line is a comment
func isCommentLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "//") || 
	       strings.HasPrefix(trimmed, "/*") || 
	       strings.HasPrefix(trimmed, "*")
}
// isKeyword checks if a string is a common programming keyword
func isKeyword(word string) bool {
	keywords := map[string]bool{
		"if":      true,
		"else":    true,
		"for":     true,
		"while":   true,
		"switch":  true,
		"case":    true,
		"return":  true,
		"break":   true,
		"continue": true,
		"goto":    true,
		"typedef": true,
		"struct":  true,
		"enum":    true,
		"union":   true,
	}
	return keywords[word]
}

// countChar counts occurrences of a character in a string
func countChar(s string, c byte) int {
	count := 0
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			count++
		}
	}
	return count
}
func main() {
	// Parse command-line arguments
	projectDir := flag.String("dir", "", "Project directory to analyze")
	// numWorkers := flag.Int("workers", runtime.NumCPU(), "Number of parallel workers")
    diffPath := flag.String("diff", "diff/ref.diff", "The diff commit file")
	outputFileFlag := flag.String("output", "diff_functions.json", "output json file path")
	flag.Parse()
	
	outputFile := *outputFileFlag

	// Ensure root directory is provided
	if *projectDir == "" {
		fmt.Fprintf(os.Stderr, "Error: Project directory (-dir) is required\n")
		flag.Usage()
		os.Exit(1)
	}


	// Find diff file
	diffFilePath := *diffPath
	if _, err := os.Stat(diffFilePath); os.IsNotExist(err) {
		// Try to find diff file relative to project directory
		altPath := filepath.Join(*projectDir, "..", *diffPath)
		if _, err := os.Stat(altPath); err == nil {
			diffFilePath = altPath
		} else {
			fmt.Fprintf(os.Stderr, "Error: Diff file not found at %s or %s\n", *diffPath, altPath)
			os.Exit(1)
		}
	}

	// Load diff file content
	diffText, err := os.ReadFile(diffFilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading diff file: %v\n", err)
		os.Exit(1)
	}
	// Parse diff to find changed files and functions
	changedFunctions := parseDiff(string(diffText))

	fmt.Printf("Found %d changed functions across %d files\n", 
		countFunctions(changedFunctions), len(changedFunctions))

    
        for filePath, functions := range changedFunctions {
            fmt.Printf("filePath: %s changedFunctions: %v\n", filePath,functions)
        }

	var matchingFunctions []*FunctionDefinition

    for filePath, xfunctions := range changedFunctions {
		fullFilePath := filepath.Join(*projectDir, filePath)

		if strings.HasSuffix(filePath, ".java") {
			fmt.Printf("Analyzing Java file: %s...\n", fullFilePath)
			// Read the file content
			content, err := os.ReadFile(fullFilePath)
			if err != nil {
				fmt.Printf("Error reading file %s: %v\n", fullFilePath, err)
				continue
			}

			sourceLines := strings.Split(string(content), "\n")
			// Parse Java file
			tree, err := java.Parse(string(content))
			if err != nil {
				fmt.Printf("Error parsing file %s: %v\n", fullFilePath, err)
				continue
			}
			// Visit parse tree to find function definitions
			v := NewJavaFunctionVisitor(fullFilePath, sourceLines)
			// Use ParseTreeWalker
			walker := antlr.NewParseTreeWalker()
			walker.Walk(v, tree)

			for _,changedFunc := range xfunctions {
				targetFunc:= changedFunc.Name
				// Find matching functions
				if targetFunc != "" {
					for name, funcDef := range v.Functions {
						// For Java, check both simple name and class.method name
						if name == targetFunc || strings.HasSuffix(name, "."+targetFunc) {
							matchingFunctions = append(matchingFunctions, funcDef...)
						}
					}
				} else {
					// If no target function specified, return all functions
					for _, funcDef := range v.Functions {
						matchingFunctions = append(matchingFunctions, funcDef...)
					}
				}
			} 
			
		} else if strings.HasSuffix(filePath, ".c") || strings.HasSuffix(filePath, ".cpp") || strings.HasSuffix(filePath, ".h") || strings.HasSuffix(filePath, ".hpp") {
			fmt.Printf("Analyzing C/C++ file: %s...\n", fullFilePath)
				// Read the file
				content, err := os.ReadFile(fullFilePath)
				if err != nil {
					fmt.Printf("error reading file: %v", err)
					continue
				}

			functions, err := processCFile(fullFilePath,content)
			if err != nil {
				fmt.Printf("Error processing file %s: %v\n", fullFilePath, err)
				os.Exit(1)
			}
			
			for _,changedFunc := range xfunctions {
				targetFunc:= changedFunc.Name
				// Find matching functions
				if targetFunc != "" {
					for name, funcDef := range functions {
						if name == targetFunc {
							matchingFunctions = append(matchingFunctions, funcDef...)
						}
					}
				} else {
					// If no target function specified, return all functions
					for _, funcDef := range functions {
						matchingFunctions = append(matchingFunctions, funcDef...)
					}
				}
			}
		} else {
			fmt.Printf("Warnning: %s is not a supported file type (C, C++, or Java)\n", fullFilePath)
		}
    }

    if len(matchingFunctions) == 0 {
		fmt.Println("No matching functions found.")
		os.Exit(1)
    }
	// Create the JSON output
	type FunctionOutput struct {
        File string    `json:"file"`
        Class string    `json:"class"`
        Function string    `json:"function"`
		StartLine int    `json:"start_line"`
		EndLine   int    `json:"end_line"`
		Content   string `json:"content"`
	}

	var result []FunctionOutput
	for _, funcDef := range matchingFunctions {
		result = append(result, FunctionOutput{
            File: funcDef.File,
            Class: funcDef.Class,
            Function: funcDef.Function,
			StartLine: funcDef.StartLine,
			EndLine:   funcDef.EndLine,
			Content:   funcDef.SourceCode,
		})
	}
	// Output the result as JSON
	jsonOutput, err := json.MarshalIndent(result, "", "    ")
	if err != nil {
		fmt.Printf("Error creating JSON output: %v\n", err)
		os.Exit(1)
	}
	
	// Get the absolute path to show the full path
	absPath, err := filepath.Abs(outputFile)
	if err != nil {
		// If we can't get the absolute path, just use the original path
		absPath = outputFile
	}
		
	// Write to output file
	err = os.WriteFile(outputFile, jsonOutput, 0644)
	if err != nil {
		fmt.Printf("Funtarget Error writing to output file %s: %v\n", outputFile, err)
		fmt.Printf("absPath: %s\n", absPath)
		os.Exit(1)
	}
	
	// Also print to stdout
	fmt.Println(string(jsonOutput))

    fmt.Printf("Results saved to %s\n", absPath)	

}

// Helper function for Java visitor
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
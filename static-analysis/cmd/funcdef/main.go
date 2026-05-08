// SPDX-License-Identifier: Apache-2.0
package main

import (
	"path/filepath"
	"regexp"
	"flag"
	"fmt"
	"encoding/json"
	"os"
	"strings"
	"github.com/antlr4-go/antlr/v4"
	"static-analysis/internal/parser/c"
	c_parser "static-analysis/internal/parser/c/grammar"
	"static-analysis/internal/parser/java"
	java_parser "static-analysis/internal/parser/java/grammar"
)
// FunctionDefinition represents a function definition with its source code
type FunctionDefinition struct {
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
    
    if false {
        // Use regex to extract the function name
        namePattern := regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)\s*\(`)
        matches := namePattern.FindStringSubmatch(funcText)
        
        if len(matches) > 1 {
            v.CurrentFunc = matches[1]
        } else {
            // Fallback to a simpler approach
            v.CurrentFunc = fmt.Sprintf("func_%d", ctx.GetStart().GetLine())
        }
    } else {
        // 1. Cut everything after the first '(' – we only care about the left side
        if idx := strings.IndexByte(funcText, '('); idx != -1 {
            funcText = funcText[:idx]
        }
        // 2. Split on anything that is not a letter, digit or underscore
        tokens := regexp.MustCompile(`[^a-zA-Z0-9_]+`).Split(funcText, -1)
        if len(tokens) > 0 {
            v.CurrentFunc = tokens[len(tokens)-1] // last identifier before '('
        }
        if v.CurrentFunc == "" {
            // absolute fallback – should almost never happen
            v.CurrentFunc = fmt.Sprintf("func_%d", ctx.GetStart().GetLine())
        }
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
func processCFile(filePath string) (map[string][]*FunctionDefinition, error) {
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
    
    if true {
    // Fallback: regex scan for functions the formal parser missed
    // ------------------------------------------------------------------
   // Any identifier followed by '(' … ')' and an opening brace on the same
   // line is treated as a potential definition.
   reFunc := regexp.MustCompile(`(?m)^[\pL\pN_][\pL\pN_\s\*\(\)]+\s+([\pL\pN_]+)\s*\([^;{]*\)\s*\{`)
   for _, m := range reFunc.FindAllStringSubmatchIndex(sourceContent, -1) {
       name := sourceContent[m[2]:m[3]]
       if _, already := visitor.Functions[name]; already {
           continue // parser already found it
       }

       // Determine start / end byte positions
       startByte := m[0]
       braceDepth, endByte := 0, len(sourceContent)
       for i := startByte; i < len(sourceContent); i++ {
           switch sourceContent[i] {
           case '{':
               braceDepth++
           case '}':
               braceDepth--
               if braceDepth == 0 {
                   endByte = i + 1
                   i       = len(sourceContent) // break outer loop
               }
           }
       }

       startLine := 1 + strings.Count(sourceContent[:startByte], "\n")
       endLine   := startLine + strings.Count(sourceContent[startByte:endByte], "\n")
       code      := sourceContent[startByte:endByte]

       fd := &FunctionDefinition{
           StartLine:  startLine,
           EndLine:    endLine,
           SourceCode: code,
       }
       visitor.Functions[name] = []*FunctionDefinition{fd}
   }

    }
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

func (v *JavaFunctionVisitor) EnterConstructorDeclaration(ctx *java_parser.ConstructorDeclarationContext) {
    // The constructor name is always the class name
    constructorName := v.CurrentClass

    startLine := ctx.GetStart().GetLine()
    endLine := ctx.GetStop().GetLine()

    fmt.Printf("Found constructor: %s lines [%d-%d]\n", constructorName, startLine, endLine)

    // Extract source code
    sourceCode := ""
    if startLine <= endLine && startLine <= len(v.SourceLines) {
        sourceLines := v.SourceLines[startLine-1 : min(endLine, len(v.SourceLines))]
        sourceCode = strings.Join(sourceLines, "\n")
    }

    funcDef := &FunctionDefinition{
        StartLine:  startLine,
        EndLine:    endLine,
        SourceCode: sourceCode,
    }

    // Record as <init> and ClassName.<init>
    v.Functions["<init>"] = append(v.Functions["<init>"], funcDef)
    v.Functions[constructorName+".<init>"] = append(v.Functions[constructorName+".<init>"], funcDef)
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

	fmt.Printf("Found method: %s lines [%d-%d]\n", methodName,startLine,endLine)

    // Extract source code
    sourceCode := ""
    if startLine <= endLine && startLine <= len(v.SourceLines) {
        sourceLines := v.SourceLines[startLine-1 : min(endLine, len(v.SourceLines))]
        sourceCode = strings.Join(sourceLines, "\n")
    }
    
    // Create function definition
    funcDef := &FunctionDefinition{
        StartLine:  startLine,
        EndLine:    endLine,
        SourceCode: sourceCode,
    }

    // Append to the slice for this method name
    v.Functions[methodName] = append(v.Functions[methodName], funcDef)
  
    
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
	targetFuncFlag := flag.String("func", "", "function name to find")
	targetFileFlag := flag.String("file", "", "file path")
	outputFileFlag := flag.String("output", "", "output file path (default: <func>.json)")
	flag.Parse()
	
	filePath := *targetFileFlag
	targetFunc := *targetFuncFlag
	outputFile := *outputFileFlag

	if filePath == "" {
		fmt.Println("Error: file path is required")
		flag.Usage()
		os.Exit(1)
	}
	// Set default output file if not specified
	if outputFile == "" {
		if targetFunc == "" {
			outputFile = "all_functions.json"
		} else {
			outputFile = targetFunc + ".json"
		}
	}
	// Ensure output file has .json extension
	if !strings.HasSuffix(outputFile, ".json") {
		outputFile += ".json"
	}
	var matchingFunctions []*FunctionDefinition

	if strings.HasSuffix(filePath, ".java") {
		fmt.Printf("Analyzing Java file: %s...\n", filePath)
		// Read the file content
		content, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Printf("Error reading file %s: %v\n", filePath, err)
			os.Exit(1)
		}

		sourceLines := strings.Split(string(content), "\n")
		// Parse Java file
		tree, err := java.Parse(string(content))
		if err != nil {
			fmt.Printf("Error parsing file %s: %v\n", filePath, err)
			os.Exit(1)
		}
		// Visit parse tree to find function definitions
		v := NewJavaFunctionVisitor(filePath, sourceLines)
		// Use ParseTreeWalker
		walker := antlr.NewParseTreeWalker()
		walker.Walk(v, tree)

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
	} else if strings.HasSuffix(filePath, ".c") || strings.HasSuffix(filePath, ".cpp") || strings.HasSuffix(filePath, ".in") || strings.HasSuffix(filePath, ".h") || strings.HasSuffix(filePath, ".hpp") {
		fmt.Printf("Analyzing C/C++ file: %s...\n", filePath)

		functions, err := processCFile(filePath)
		if err != nil {
			fmt.Printf("Error processing file %s: %v\n", filePath, err)
			os.Exit(1)
		}
		
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
	} else {
		fmt.Printf("Error: %s is not a supported file type (C, C++, or Java)\n", filePath)
		os.Exit(1)
	}

    if len(matchingFunctions) == 0 {
		fmt.Println("No matching functions found.")
		os.Exit(1)
    }

	// Create the JSON output
	type FunctionOutput struct {
		StartLine int    `json:"start_line"`
		EndLine   int    `json:"end_line"`
		Content   string `json:"content"`
	}

	var result []FunctionOutput
	for _, funcDef := range matchingFunctions {
		result = append(result, FunctionOutput{
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
		fmt.Printf("Fundep Error writing to output file %s: %v\n", outputFile, err)
		fmt.Printf("absPath: %s\n", absPath)
		os.Exit(1)
	}
	
	fmt.Printf("Results saved to %s\n", outputFile)
	
	// Also print to stdout
	fmt.Println(string(jsonOutput))
}

// Helper function for Java visitor
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
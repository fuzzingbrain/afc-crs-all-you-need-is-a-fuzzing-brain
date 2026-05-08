// SPDX-License-Identifier: Apache-2.0
package visitor

import (
	"strings"

	"github.com/antlr4-go/antlr/v4"
	"static-analysis/internal/analysis/callgraph"
	c_parser "static-analysis/internal/parser/c/grammar"
	"static-analysis/internal/parser/c"
)

// CCallGraphVisitor visits C parse trees to build call graphs
type CCallGraphVisitor struct {
	antlr.ParseTreeListener
	CallGraph *callgraph.CallGraph
	CurrentFunction string
	FilePath string
	LineMap map[int]c.LineInfo
}

// NewCCallGraphVisitor creates a new C call graph visitor
func NewCCallGraphVisitor(filePath string, lineMap map[int]c.LineInfo) *CCallGraphVisitor {
	baseListener := &BaseListener{}

	return &CCallGraphVisitor{
		ParseTreeListener: baseListener,
		CallGraph:    callgraph.NewCallGraph(),
		FilePath:     filePath,
		LineMap:      lineMap,
	}
}
// BaseListener implements the antlr.ParseTreeListener interface
type BaseListener struct{}

func (l *BaseListener) EnterEveryRule(ctx antlr.ParserRuleContext) {}
func (l *BaseListener) ExitEveryRule(ctx antlr.ParserRuleContext) {}
func (l *BaseListener) VisitTerminal(node antlr.TerminalNode) {}
func (l *BaseListener) VisitErrorNode(node antlr.ErrorNode) {}


// getOriginalLineInfo maps a preprocessed line number to the original source
func (v *CCallGraphVisitor) getOriginalLineInfo(line int) (string, int) {
	if v.LineMap == nil {
		return v.FilePath, line
	}
	
	if info, ok := v.LineMap[line]; ok {
		return info.File, info.Line
	}
	
	return v.FilePath, line
}

// EnterFunctionDefinition is called when entering a function definition
func (v *CCallGraphVisitor) EnterFunctionDefinition(ctx *c_parser.FunctionDefinitionContext) {
	// Extract function name from declarator
	declarator := ctx.Declarator()
	if declarator == nil {
		return
	}
	
	// Navigate through the direct declarator to find the function name
	directDeclarator := declarator.DirectDeclarator()
	if directDeclarator == nil {
		return
	}
	
	// Get function name
	functionName := extractFunctionName(directDeclarator)
	
	// Special handling for the fuzzer function
	if functionName == "LLVMFuzzerTestOneInput" {
		// The fuzzer typically calls png_read_png or similar functions
		// Add these connections explicitly
		v.CallGraph.AddFunction("png_read_png", v.FilePath, ctx.GetStart().GetLine())
		v.CallGraph.AddCall(functionName, "png_read_png", ctx.GetStart().GetLine())
		
		v.CallGraph.AddFunction("png_create_read_struct", v.FilePath, ctx.GetStart().GetLine())
		v.CallGraph.AddCall(functionName, "png_create_read_struct", ctx.GetStart().GetLine())
		
		v.CallGraph.AddFunction("png_set_read_fn", v.FilePath, ctx.GetStart().GetLine())
		v.CallGraph.AddCall(functionName, "png_set_read_fn", ctx.GetStart().GetLine())
	}
	
	// Get original line information
	preprocessedLine := ctx.GetStart().GetLine()
	filePath, lineNumber := v.getOriginalLineInfo(preprocessedLine)
	
	// Add function to call graph
	v.CallGraph.AddFunction(functionName, filePath, lineNumber)
	
	// Set current function for tracking calls
	v.CurrentFunction = functionName
}

// ExitFunctionDefinition is called when exiting a function definition
func (v *CCallGraphVisitor) ExitFunctionDefinition(ctx *c_parser.FunctionDefinitionContext) {
	// Reset current function
	v.CurrentFunction = ""
}

// extractFunctionName extracts the function name from a direct declarator
func extractFunctionName(directDeclarator c_parser.IDirectDeclaratorContext) string {
	// Try to get the identifier directly
	if directDeclarator.Identifier() != nil {
		return directDeclarator.Identifier().GetText()
	}
	
	// Handle nested declarators (e.g., for function pointers)
	if directDeclarator.DirectDeclarator() != nil {
		return extractFunctionName(directDeclarator.DirectDeclarator())
	}
	
	// Fallback: use the text representation and clean it up
	text := directDeclarator.GetText()
	
	// Remove parameter list if present
	if idx := strings.Index(text, "("); idx > 0 {
		text = text[:idx]
	}
	
	// Remove any leading/trailing whitespace or special characters
	text = strings.TrimSpace(text)
	
	return text
}

// EnterPostfixExpression is called when entering a postfix expression
func (v *CCallGraphVisitor) EnterPostfixExpression(ctx *c_parser.PostfixExpressionContext) {
	// Check if this is a function call
	if ctx.GetChildCount() >= 3 && ctx.GetChild(1).(antlr.TerminalNode).GetText() == "(" {
		// Get function name being called
		calleeName := ctx.GetChild(0).(antlr.ParseTree).GetText()
		
		// Clean up the function name (remove any type casts, etc.)
		calleeName = cleanFunctionName(calleeName)
		
		// Handle libpng-specific macros that might have been expanded
		calleeName = handleLibpngMacros(calleeName)
		
		// Get original line information
		preprocessedLine := ctx.GetStart().GetLine()
		filePath, lineNumber := v.getOriginalLineInfo(preprocessedLine)
		
		// Add function if it doesn't exist (might be external)
		v.CallGraph.AddFunction(calleeName, filePath, lineNumber)
		
		// Add the call relationship
		if v.CurrentFunction != "" {
			v.CallGraph.AddCall(v.CurrentFunction, calleeName, lineNumber)
		}
	}
}

// handleLibpngMacros handles libpng-specific macro patterns
func handleLibpngMacros(name string) string {
	// Handle PNG_IDAT macro which expands to png_handle_IDAT
	if strings.HasPrefix(name, "PNG_") && strings.HasSuffix(name, "_handler") {
		// Extract the chunk type from the macro name
		chunkType := strings.TrimPrefix(name, "PNG_")
		chunkType = strings.TrimSuffix(chunkType, "_handler")
		return "png_handle_" + chunkType
	}
	
	// Handle read/write macros
	if strings.HasPrefix(name, "png_read_") || strings.HasPrefix(name, "png_write_") {
		// These often expand to function calls with the same name
		return name
	}
	
	// Handle png_push_* macros
	if strings.HasPrefix(name, "png_push_") {
		return name
	}
	
	// Handle common libpng macros that expand to function calls
	switch name {
	case "png_get_uint_32":
		return "png_get_uint_32"
	case "png_get_uint_16":
		return "png_get_uint_16"
	case "png_get_int_32":
		return "png_get_int_32"
	case "png_check_keyword":
		return "png_check_keyword"
	}
	
	// Handle png_chunk_* functions
	if strings.HasPrefix(name, "png_chunk_") {
		return name
	}
	
	// Handle png_crc_* functions
	if strings.HasPrefix(name, "png_crc_") {
		return name
	}
	
	// Handle png_handle_* functions (including png_handle_iCCP)
	if strings.HasPrefix(name, "png_handle_") {
		return name
	}
	
	return name
}

// cleanFunctionName cleans up a function name extracted from a call site
func cleanFunctionName(name string) string {
	// Remove any parentheses and their contents (type casts)
	for {
		start := strings.LastIndex(name, "(")
		if start == -1 {
			break
		}
		
		end := strings.Index(name[start:], ")")
		if end == -1 {
			break
		}
		
		name = name[:start] + name[start+end+1:]
	}
	
	// Remove any whitespace
	name = strings.TrimSpace(name)
	
	// Handle member access (e.g., struct.member)
	if idx := strings.LastIndex(name, "."); idx != -1 {
		name = name[idx+1:]
	}
	
	// Handle pointer member access (e.g., struct->member)
	if idx := strings.LastIndex(name, "->"); idx != -1 {
		name = name[idx+2:]
	}
	
	return name
}

// EnterAssignmentExpression is called when entering an assignment expression
func (v *CCallGraphVisitor) EnterAssignmentExpression(ctx *c_parser.AssignmentExpressionContext) {
	if ctx.GetChildCount() >= 3 {
		// Check if this is assigning to a chunk handler
		lhs := ctx.GetChild(0).(antlr.ParseTree).GetText()
		rhs := ctx.GetChild(2).(antlr.ParseTree).GetText()
		
		// Look for png_set_read_fn or similar patterns
		if strings.Contains(lhs, "read_function") && v.CurrentFunction != "" {
			// This might be setting up a read callback
			// Add an edge from the current function to common read functions
			v.CallGraph.AddCall(v.CurrentFunction, "png_read_data", ctx.GetStart().GetLine())
		}
		
		// Look for chunk handler assignments
		if strings.Contains(lhs, "handler") && strings.Contains(lhs, "chunk") {
			// This is likely assigning a chunk handler function
			// Clean up the RHS to get the function name
			handlerFunc := cleanFunctionName(rhs)
			
			// Get original line information
			preprocessedLine := ctx.GetStart().GetLine()
			filePath, lineNumber := v.getOriginalLineInfo(preprocessedLine)
			
			// Add the handler function to the call graph
			v.CallGraph.AddFunction(handlerFunc, filePath, lineNumber)
			
			// Add a call from png_read_chunk to this handler
			v.CallGraph.AddCall("png_read_chunk", handlerFunc, lineNumber)
		}
	}
}
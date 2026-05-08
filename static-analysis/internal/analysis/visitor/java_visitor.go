// SPDX-License-Identifier: Apache-2.0
package visitor

import (
	"github.com/antlr4-go/antlr/v4"
	"static-analysis/internal/analysis/callgraph"
	java_parser "static-analysis/internal/parser/java/grammar"
)

// JavaCallGraphVisitor visits Java parse trees to build call graphs
type JavaCallGraphVisitor struct {
	antlr.ParseTreeListener // Use the ANTLR interface instead of a specific implementation
	CallGraph *callgraph.CallGraph
	CurrentFunction string
	FilePath string
}


// NewJavaCallGraphVisitor creates a new Java call graph visitor
func NewJavaCallGraphVisitor(filePath string) *JavaCallGraphVisitor {
	// Create a base listener that implements the ParseTreeListener interface
	baseListener := &JavaBaseListener{}
	
	return &JavaCallGraphVisitor{
		ParseTreeListener: baseListener,
		CallGraph:    callgraph.NewCallGraph(),
		FilePath:     filePath,
	}
}

// JavaBaseListener implements the antlr.ParseTreeListener interface
type JavaBaseListener struct{}

func (l *JavaBaseListener) EnterEveryRule(ctx antlr.ParserRuleContext) {}
func (l *JavaBaseListener) ExitEveryRule(ctx antlr.ParserRuleContext) {}
func (l *JavaBaseListener) VisitTerminal(node antlr.TerminalNode) {}
func (l *JavaBaseListener) VisitErrorNode(node antlr.ErrorNode) {}

// EnterMethodDeclaration is called when entering a method declaration
func (v *JavaCallGraphVisitor) EnterMethodDeclaration(ctx *java_parser.MethodDeclarationContext) {
	// Get method name
	methodHeader := ctx.MethodHeader()
	if methodHeader == nil {
		return
	}
	
	methodDeclarator := methodHeader.MethodDeclarator()
	if methodDeclarator == nil {
		return
	}
	
	identifier := methodDeclarator.Identifier()
	if identifier == nil {
		return
	}
	
	methodName := identifier.GetText()
	lineNumber := ctx.GetStart().GetLine()
	
	// Add method to call graph
	v.CallGraph.AddFunction(methodName, v.FilePath, lineNumber)
	
	// Set current method for tracking calls
	v.CurrentFunction = methodName
}

// ExitMethodDeclaration is called when exiting a method declaration
func (v *JavaCallGraphVisitor) ExitMethodDeclaration(ctx *java_parser.MethodDeclarationContext) {
	// Reset current function
	v.CurrentFunction = ""
}


// EnterMethodInvocation is called when entering a method invocation
func (v *JavaCallGraphVisitor) EnterMethodInvocation(ctx *java_parser.MethodInvocationContext) {
	// Get method name being called
	var calleeName string
	
	// Handle different forms of method invocation
	if ctx.Identifier() != nil {
		// Direct method call: methodName()
		calleeName = ctx.Identifier().GetText()
	} else if ctx.MethodName() != nil {
		// Method call with explicit name: obj.methodName()
		calleeName = ctx.MethodName().GetText()
	} else if ctx.TypeName() != nil && ctx.Identifier() != nil {
		// Static method call: TypeName.methodName()
		calleeName = ctx.TypeName().GetText() + "." + ctx.Identifier().GetText()
	} else {
		// Handle other cases or use a default
		calleeName = ctx.GetText()
	}
	
	lineNumber := ctx.GetStart().GetLine()
	
	// Add method if it doesn't exist (might be external)
	v.CallGraph.AddFunction(calleeName, v.FilePath, lineNumber)
	
	// Add the call relationship
	if v.CurrentFunction != "" {
		v.CallGraph.AddCall(v.CurrentFunction, calleeName, lineNumber)
	}
}
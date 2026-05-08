// SPDX-License-Identifier: Apache-2.0
package c

import (
	"github.com/antlr4-go/antlr/v4"
	c_parser "static-analysis/internal/parser/c/grammar"
)

// Parse parses C code and returns the parse tree
func Parse(input string) (antlr.Tree, error) {
	// Create the input stream
	inputStream := antlr.NewInputStream(input)
	
	// Create the lexer
	lexer := c_parser.NewCLexer(inputStream)
	
	// Create the token stream
	tokenStream := antlr.NewCommonTokenStream(lexer, antlr.TokenDefaultChannel)
	
	// Create the parser
	parser := c_parser.NewCParser(tokenStream)
	
	// Set error handling
	parser.RemoveErrorListeners()
	errorListener := antlr.NewDiagnosticErrorListener(true)
	parser.AddErrorListener(errorListener)
	
	// Parse the input
	return parser.CompilationUnit(), nil
}
// SPDX-License-Identifier: Apache-2.0
package java

import (
	"github.com/antlr4-go/antlr/v4"
	java_parser "static-analysis/internal/parser/java/grammar"
)

// Parse parses Java code and returns the parse tree
func Parse(input string) (antlr.Tree, error) {
	// Create the input stream
	inputStream := antlr.NewInputStream(input)

	// Create the lexer
	lexer := java_parser.NewJavaLexer(inputStream)

	// Create the token stream
	tokenStream := antlr.NewCommonTokenStream(lexer, antlr.TokenDefaultChannel)

	// Create the parser
	parser := java_parser.NewJavaParser(tokenStream)

	// Set error handling
	parser.RemoveErrorListeners()
	errorListener := antlr.NewDiagnosticErrorListener(true)
	parser.AddErrorListener(errorListener)

	// Parse the input
	return parser.CompilationUnit(), nil
}

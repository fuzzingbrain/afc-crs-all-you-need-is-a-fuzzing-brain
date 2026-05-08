// SPDX-License-Identifier: Apache-2.0
package callgraph

import (
	"fmt"
	"os"
	"path/filepath"
)

// GenerateDOTFile creates a DOT file representation of the call graph
func (cg *CallGraph) GenerateDOTFile(outputPath string) error {
	dotFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("error creating DOT file: %v", err)
	}
	defer dotFile.Close()
	
	// Write DOT file header
	fmt.Fprintf(dotFile, "digraph CallGraph {\n")
	fmt.Fprintf(dotFile, "  node [shape=box, style=filled, fillcolor=lightblue];\n")
	
	// Write nodes
	for _, function := range cg.Functions {
		fmt.Fprintf(dotFile, "  \"%s\" [label=\"%s\\n%s:%d\"];\n", 
			function.Name, function.Name, filepath.Base(function.FilePath), function.LineNumber)
	}
	
	// Write edges
	for _, function := range cg.Functions {
		for _, call := range function.Calls {
			fmt.Fprintf(dotFile, "  \"%s\" -> \"%s\" [label=\"line %d\"];\n",
				call.Caller.Name, call.Callee.Name, call.LineNumber)
		}
	}
	
	// Write DOT file footer
	fmt.Fprintf(dotFile, "}\n")
	
	return nil
}

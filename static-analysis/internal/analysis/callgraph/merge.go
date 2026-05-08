// SPDX-License-Identifier: Apache-2.0
package callgraph

// Fix unused variable warning
func MergeCallGraphs(graphs ...*CallGraph) *CallGraph {
	merged := NewCallGraph()
	
	for _, graph := range graphs {
		for name, function := range graph.Functions {
			// Add function if it doesn't exist in merged graph
			_ = merged.AddFunction(name, function.FilePath, function.LineNumber)
			
			// Add all calls
			for _, call := range function.Calls {
				calleeName := call.Callee.Name
				// Make sure callee exists in merged graph
				merged.AddFunction(calleeName, call.Callee.FilePath, call.Callee.LineNumber)
				// Add the call
				merged.AddCall(name, calleeName, call.LineNumber)
			}
		}
	}
	
	return merged
}
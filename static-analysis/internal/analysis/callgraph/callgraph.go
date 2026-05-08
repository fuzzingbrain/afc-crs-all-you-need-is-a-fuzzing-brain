// SPDX-License-Identifier: Apache-2.0
package callgraph

// Function represents a function in the call graph
type Function struct {
	Name       string
	FilePath   string
	LineNumber int
	Calls      []*Call
}

// Call represents a function call
type Call struct {
	Caller    *Function
	Callee    *Function
	LineNumber int
}

// CallGraph represents the entire call graph
type CallGraph struct {
	Functions map[string]*Function
}

// NewCallGraph creates a new call graph
func NewCallGraph() *CallGraph {
	return &CallGraph{
		Functions: make(map[string]*Function),
	}
}

// AddFunction adds a function to the call graph
func (cg *CallGraph) AddFunction(name string, filePath string, lineNumber int) *Function {
	if f, exists := cg.Functions[name]; exists {
		return f
	}
	
	f := &Function{
		Name:       name,
		FilePath:   filePath,
		LineNumber: lineNumber,
		Calls:      make([]*Call, 0),
	}
	
	cg.Functions[name] = f
	return f
}

// AddCall adds a call from caller to callee
func (cg *CallGraph) AddCall(callerName, calleeName string, lineNumber int) {
	caller := cg.Functions[callerName]
	callee := cg.Functions[calleeName]
	
	if caller == nil || callee == nil {
		return
	}
	
	call := &Call{
		Caller:     caller,
		Callee:     callee,
		LineNumber: lineNumber,
	}
	
	caller.Calls = append(caller.Calls, call)
}

package database

// ReachableFunction represents a function that can be reached from the fuzzer entry point
// This structure is used to parse the reachable_functions.jsonl file
type ReachableFunction struct {
	// Required fields
	FunctionName string   `json:"function_name"` // Name of the function
	FilePath     string   `json:"file_path"`     // Relative path from project root
	StartLine    int      `json:"start_line"`    // Function start line number
	EndLine      int      `json:"end_line"`      // Function end line number

	// Optional fields
	CallPath     []string `json:"call_path,omitempty"`     // Call chain from entry point, e.g. ["main", "process", "parse"]
	Signature    string   `json:"signature,omitempty"`     // Function signature, e.g. "int parse(char* buf, size_t len)"
	FunctionBody string   `json:"function_body,omitempty"` // Complete function source code
	Complexity   int      `json:"complexity,omitempty"`    // Cyclomatic complexity
	LOC          int      `json:"loc,omitempty"`           // Lines of code
}

// Example JSONL format:
// {"function_name": "parse_header", "file_path": "src/parser.c", "start_line": 145, "end_line": 203, "call_path": ["main", "process_request", "parse_header"], "signature": "int parse_header(char* buf, size_t len)"}
// {"function_name": "validate_input", "file_path": "src/validator.c", "start_line": 89, "end_line": 120, "call_path": ["main", "validate_input"], "signature": "bool validate_input(const char* input)"}

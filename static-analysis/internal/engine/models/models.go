// SPDX-License-Identifier: Apache-2.0
package models

import (
    "github.com/google/uuid"
)
// TargetFunction represents a function to analyze
type TargetFunction struct {
	FilePath     string
	FunctionName string
	StartLine    int
}

type FunctionInfo struct {
    Name      string `json:"name"`
    StartLine int    `json:"start_line"`
}
// AnalysisRequest represents the request payload format
type AnalysisRequest struct {
    TaskID string `json:"task_id"`
    Focus string `json:"focus"`
	ProjectSourceDir      string              `json:"project_src_dir"`
    Fuzzer      string              `json:"fuzzer_path"`
	FuzzerSourcePath      string              `json:"fuzzer_source_path"`
    TargetFunctions   map[string][]FunctionInfo `json:"target_functions"`
}

type FunMetaRequest struct {
    TaskID string `json:"task_id"`
    Focus string `json:"focus"`
	ProjectSourceDir      string              `json:"project_src_dir"`
    TargetFunctions   []string `json:"target_functions"`
}


// CallNode represents a node in the call path
type CallPathNode struct {
	File        string `json:"file"`
	Function    string `json:"function"`
	Line        string `json:"line"`
    StartLine        string `json:"start_line"`
	EndLine        string `json:"end_line"`
	Body        string `json:"body"`
	IsModified  bool   `json:"is_modified"`
}

// CallPath represents a node in the call path
type CallPath struct {
	Target string `json:"target"`
	Nodes        []CallPathNode  `json:"nodes,omitempty"`
}
// AnalysisResponse is the response format
type AnalysisResponse struct {
	Status    string      `json:"status"`
	Message   string      `json:"message,omitempty"`
	CallPaths []CallPath `json:"call_paths,omitempty"`
}


type ReachableResponse struct {
    Status    string      `json:"status"`
	Message   string      `json:"message,omitempty"`
	ReachableFunctions []FunctionDefinition `json:"reachable,omitempty"`
}


type FunctionMetaInfo struct {
    Name      string `json:"name"`
    StartLine int    `json:"start_line"`
	FilePath  string `json:"file_path,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
	SourceCode string `json:"content,omitempty"`
}
type FunMetaResponse struct {
    Status    string      `json:"status"`
	Message   string      `json:"message,omitempty"`
	FunctionsMetaData map[string]FunctionMetaInfo `json:"funmeta,omitempty"`
}
// Task types
type TaskType string
const (
    TaskTypeFull  TaskType = "full"
    TaskTypeDelta TaskType = "delta"
)

// Source types
type SourceType string
const (
    SourceTypeRepo        SourceType = "repo"
    SourceTypeFuzzTooling SourceType = "fuzz-tooling"
    SourceTypeDiff        SourceType = "diff"
)

type Task struct {
    MessageID   uuid.UUID    `json:"message_id"`
    MessageTime int64        `json:"message_time"`
    Tasks       []TaskDetail `json:"tasks"`
}

type TaskState string

const (
    TaskStatePending   TaskState = "pending"
    TaskStateRunning   TaskState = "running"
    TaskStateSucceeded TaskState = "succeeded"
    TaskStateErrored   TaskState = "errored"
    TaskStateCanceled  TaskState = "canceled"
)

type TaskDetail struct {
    TaskID      uuid.UUID     `json:"task_id"`
    Type        TaskType      `json:"type"`
    HarnessesIncluded   bool  `json:"harnesses_included"`
    Deadline    int64         `json:"deadline"`
    Focus       string        `json:"focus"`
    ProjectName string        `json:"project_name"`
    Language    string        `json:"language,omitempty"`
    Source      []SourceDetail `json:"source"`
    Metadata    map[string]string `json:"metadata"`
    State       TaskState     `json:"state"`
}

type SourceDetail struct {
    Type   SourceType `json:"type"`
    URL    string     `json:"url"`
    SHA256 string     `json:"sha256"`
}


type AnalysisResults struct {
	Functions          map[string]*FunctionDefinition `json:"functions"`
	CallGraph          *CallGraph                     `json:"callGraph"`
	ReachableFunctions map[string][]string            `json:"reachable"`
	Paths              map[string][][]string          `json:"paths"` // Map from target to paths

	// Cached adjacency list (caller → callees) built once and reused by findAllPaths.
	CallGraphAdj map[string][]string `json:"-"` // not marshalled
}

type CodeqlAnalysisResults struct {
	Functions map[string]*FunctionDefinition `json:"functions"`
    ReachableFunctions map[string][]string `json:"reachable"`
	Paths     map[string]map[string][][]string         `json:"paths"` // Map from fuzzer to target to paths
}

// FunctionDefinition represents a function definition with its source code
type FunctionDefinition struct {
	Name       string
	FilePath   string
	StartLine  int
	EndLine    int
	SourceCode string
}

type MethodCall struct {
    Caller string
    Callee string
}

// CallGraph represents a directed graph of method calls
type CallGraph struct {
    Calls []MethodCall
}

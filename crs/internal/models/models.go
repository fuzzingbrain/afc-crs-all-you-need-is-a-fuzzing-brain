// SPDX-License-Identifier: Apache-2.0
package models

import (
    "github.com/google/uuid"
)

// Status represents the CRS status
type Status struct {
    Ready   bool         `json:"ready"`
    Since   int64        `json:"since"`
    State   StatusState  `json:"state"`
    Version string       `json:"version"`
    Details interface{}  `json:"details,omitempty"`
    GitRef  string      `json:"gitRef"` 
}

type StatusState struct {
    Tasks StatusTasksState `json:"tasks"`
}

type StatusTasksState struct {
    Pending    int `json:"pending"`
    Processing int `json:"processing"`
    Waiting    int `json:"waiting"`
    Succeeded  int `json:"succeeded"`
    Failed     int `json:"failed"`
    Errored    int `json:"errored"`
    Canceled   int `json:"canceled"`
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

type WorkerTask struct {
    MessageID   uuid.UUID              `json:"message_id"`
    MessageTime int64              `json:"message_time"`
    Tasks       []TaskDetail `json:"tasks"`
    Fuzzer      string              `json:"fuzzer"` // The specific fuzzer this worker should run
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
    Deadline    int64         `json:"deadline"`
    Focus       string        `json:"focus"`
    HarnessesIncluded   bool  `json:"harnesses_included"`
    ProjectName string        `json:"project_name"`
    Source      []SourceDetail `json:"source"`
    Metadata    map[string]string `json:"metadata"`
    State       TaskState     `json:"state"`
}

type SourceDetail struct {
    Type   SourceType `json:"type"`
    URL    string     `json:"url"`
    SHA256 string     `json:"sha256"`
}

// SARIF broadcast types
type SARIFBroadcast struct {
    MessageID   uuid.UUID              `json:"message_id"`
    MessageTime int64                  `json:"message_time"`
    Broadcasts  []SARIFBroadcastDetail `json:"broadcasts"`
}

type SARIFBroadcastDetail struct {
    TaskID    uuid.UUID         `json:"task_id"`
    SarifID   uuid.UUID         `json:"sarif_id"`
    SARIF     interface{}       `json:"sarif"` // SARIF Report v2.1.0
    Metadata  map[string]string `json:"metadata"`
}

type SARIFBroadcastDetailWorker struct {
    Broadcast SARIFBroadcastDetail `json:"broadcast"`
    Fuzzer string `json:"fuzzer"`
}

type Architecture string
const (
    ArchitectureX8664 Architecture = "x86_64"
)

type POVSubmission struct {
    TaskID string `json:"task_id,omitempty"`
    POVID string `json:"pov_id,omitempty"`
    Architecture Architecture `json:"architecture"`
    Engine       string       `json:"engine"`       
    FuzzerName   string       `json:"fuzzer_name"`
    Sanitizer    string       `json:"sanitizer"`
    Testcase     string       `json:"testcase"` 
    CrashTrace   string `json:"crash_trace"` 
    Signature    string `json:"signature"`
}

type TaskValidPOVsResponse struct {
    TaskID string         `json:"task_id"`
    POVs   []POVSubmission `json:"povs"`
    Count  int            `json:"count"`
}

type SarifValidResponse struct {
    SarifID string         `json:"sarif_id"`
    IsValid  bool            `json:"is_valid"`
}
type SarifInValidResponse struct {
    SarifID string         `json:"sarif_id"`
    IsInvalid  int            `json:"is_invalid"`
}

type POVSubmissionResponse struct {
    Status string `json:"status"`
    POVID  string `json:"pov_id"`
}

type POVStatsResponse struct {
    TaskID string         `json:"task_id"`
    Count  int            `json:"count"`
    PatchCount  int            `json:"patch_count"`
}
// Patch submission types for competition API
type PatchSubmission struct {
    Patch string `json:"patch"` // base64 encoded
}

type PatchSubmissionResponse struct {
    PatchID                  string `json:"patch_id"`
    Status                   string `json:"status"`
    FunctionalityTestsPassing *bool  `json:"functionality_tests_passing,omitempty"`
}


type CodeContext struct {
    File string
    Func string
    Snip string
}

// Vulnerability represents a security vulnerability found in the code
type Vulnerability struct {
    RuleID      string
    Description string
    Severity    string
    Location    struct {
        FilePath  string
        StartLine int
        EndLine   int
        StartCol  int
        EndCol    int
    }
    CodeFlows []CodeFlow
}

// CodeFlow represents a sequence of code locations that demonstrate the vulnerability
type CodeFlow struct {
    ThreadFlows []ThreadFlow
}

// ThreadFlow represents a sequence of code locations in a single thread
type ThreadFlow struct {
    Locations []ThreadFlowLocation
}

// ThreadFlowLocation represents a single location in a thread flow
type ThreadFlowLocation struct {
    FilePath  string
    StartLine int
    EndLine   int
    StartCol  int
    EndCol    int
    Message   string
}

// Patch represents a generated fix for a vulnerability
type Patch struct {
    OriginalCode string
    PatchedCode  string
    Description  string
}
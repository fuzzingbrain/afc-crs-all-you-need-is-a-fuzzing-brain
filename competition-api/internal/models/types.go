// SPDX-License-Identifier: Apache-2.0
package models

import "encoding/json"
import (
    "github.com/google/uuid"
)

type Architecture string
const (
    ArchitectureX8664 Architecture = "x86_64"
)

type Assessment string
const (
    AssessmentCorrect   Assessment = "correct"
    AssessmentIncorrect Assessment = "incorrect"
)

type SubmissionStatus string
const (
    SubmissionStatusAccepted          SubmissionStatus = "accepted"
    SubmissionStatusPassed            SubmissionStatus = "passed"
    SubmissionStatusFailed            SubmissionStatus = "failed"
    SubmissionStatusDeadlineExceeded  SubmissionStatus = "deadline_exceeded"
    SubmissionStatusErrored           SubmissionStatus = "errored"
    SubmissionStatusInConclusive           SubmissionStatus = "inconclusive"
)

type Error struct {
    Message string            `json:"message"`
    Fields  map[string]string `json:"fields,omitempty"`
}

type POVSubmission struct {
    TaskID string `json:"task_id,omitempty"`
    POVID string `json:"pov_id,omitempty"`
    Architecture Architecture `json:"architecture"`
    Engine       string       `json:"engine"`       
    FuzzerName   string       `json:"fuzzer_name"`
    FuzzerFile   string       `json:"fuzzer_file,omitempty"`
    FuzzerSource string       `json:"fuzzer_source,omitempty"`
    // BuildScriptFile  string       `json:"build_script_file,omitempty"`
    // BuildScriptSource  string       `json:"build_script_source,omitempty"`
    Sanitizer    string       `json:"sanitizer"`
    Testcase     string       `json:"testcase"` 
    CrashTrace   string `json:"crash_trace"` 
    Signature    string `json:"signature"`
    Strategy string `json:"strategy"`
}

type TaskValidPOVsResponse struct {
    TaskID string         `json:"task_id"`
    POVs   []POVSubmission `json:"povs"`
    Count  int            `json:"count"`
}
type POVSubmissionResponse struct {
    Status SubmissionStatus `json:"status"`
    POVID  string           `json:"pov_id"`
}
type FreeformSubmissionResponse struct {
    Status SubmissionStatus `json:"status"`
    FreeformID  string           `json:"freeform_id"`
}

// Patch related types
type PatchSubmission struct {
    PatchID                 string           `json:"patch_id"`
    PoVSignature string `json:"pov_signature"`
    SarifID string `json:"sarif_id,omitempty"`
    PatchDiff                 string           `json:"diff"`
    Patch string `json:"patch"` // base64 encoded
}

type PatchSubmissionResponse struct {
    PatchID                 string           `json:"patch_id"`
    Status                  SubmissionStatus `json:"status"`
    FunctionalityTestsPassing *bool           `json:"functionality_tests_passing,omitempty"`
}
// PatchStatusResponse represents the response from the patch status endpoint
type PatchStatusResponse struct {
    PatchID                   string `json:"patch_id"`
    Status                    string `json:"status"`
    FunctionalityTestsPassing *bool  `json:"functionality_tests_passing"`
}
// Freeform related types
type FreeformSubmission struct {
    Submission string `json:"submission"` // base64 encoded
}

type FreeformResponse struct {
    Status     SubmissionStatus `json:"status"`
    FreeformID string           `json:"freeform_id"`
}

// SARIF related types
type SARIFSubmission struct {
    SARIF json.RawMessage `json:"sarif"`
}

type SARIFSubmissionResponse struct {
    Status           SubmissionStatus `json:"status"`
    SubmittedSarifID string           `json:"submitted_sarif_id"`
}

type SarifAssessmentSubmission struct {
    Assessment  Assessment `json:"assessment"`
    Description string     `json:"description"`
}

type SarifAssessmentResponse struct {
    Status SubmissionStatus `json:"status"`
}

// Bundle related types
type BundleSubmission struct {
    BroadcastSarifID string `json:"broadcast_sarif_id,omitempty"`
    Description      string `json:"description,omitempty"`
    FreeformID       string `json:"freeform_id,omitempty"`  // New field
    PatchID          string `json:"patch_id,omitempty"`
    POVID            string `json:"pov_id,omitempty"`
    SubmittedSarifID string `json:"submitted_sarif_id,omitempty"`
}

type BundleSubmissionResponse struct {
    BundleID string           `json:"bundle_id"`
    Status   SubmissionStatus `json:"status"`
}

type BundleSubmissionResponseVerbose struct {
    BundleSubmissionResponse
    BroadcastSarifID string `json:"broadcast_sarif_id,omitempty"`
    Description      string `json:"description,omitempty"`
    FreeformID       string `json:"freeform_id,omitempty"`  // New field
    PatchID          string `json:"patch_id,omitempty"`
    POVID            string `json:"pov_id,omitempty"`
    SubmittedSarifID string `json:"submitted_sarif_id,omitempty"`
}

// Ping related types
type PingResponse struct {
    Status string `json:"status"`
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

type SarifValidResponse struct {
    SarifID string         `json:"sarif_id"`
    IsValid  bool            `json:"is_valid"`
}
type SarifInValidResponse struct {
    SarifID string         `json:"sarif_id"`
    IsInvalid  int            `json:"is_invalid"`
}

type POVStatsResponse struct {
    TaskID string         `json:"task_id"`
    Count  int            `json:"count"`
    PatchCount  int            `json:"patch_count"`
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
    Deadline    int64         `json:"deadline"`
    Focus       string        `json:"focus"`
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
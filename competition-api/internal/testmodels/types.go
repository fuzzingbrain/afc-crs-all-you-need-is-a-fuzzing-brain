// SPDX-License-Identifier: Apache-2.0
package testmodels

import (
    "github.com/google/uuid"
)

// Source types
type SourceType string
const (
    SourceTypeRepo        SourceType = "repo"
    SourceTypeFuzzTooling SourceType = "fuzz-tooling"
    SourceTypeDiff        SourceType = "diff"
)

// Task types
type TaskType string
const (
    TaskTypeFull  TaskType = "full"
    TaskTypeDelta TaskType = "delta"
)

type SourceDetail struct {
    SHA256 string     `json:"sha256"`
    Type   SourceType `json:"type"`
    URL    string     `json:"url"`
}

type TaskDetail struct {
    Deadline int64         `json:"deadline"`
    Source   []SourceDetail `json:"source"`
    TaskID   string        `json:"task_id"`
    Type     TaskType      `json:"type"`
}

type Task struct {
    MessageID   string       `json:"message_id"`
    MessageTime int64        `json:"message_time"`
    Tasks       []TaskDetail `json:"tasks"`
}

type VulnBroadcast struct {
    MessageID   uuid.UUID    `json:"message_id"`
    MessageTime int64        `json:"message_time"`
    Vulns       []VulnDetail `json:"vulns"`
}

type VulnDetail struct {
    TaskID  uuid.UUID   `json:"task_id"`
    VulnID  uuid.UUID   `json:"vuln_id"`
    SARIF   interface{} `json:"sarif"`
}

// SPDX-License-Identifier: Apache-2.0
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "time"
    "github.com/google/uuid"
)

// Define the same models as CRS
type SourceType string
const (
    SourceTypeRepo        SourceType = "repo"
    SourceTypeFuzzTooling SourceType = "fuzz-tooling"
    SourceTypeDiff        SourceType = "diff"
)

type TaskType string
const (
    TaskTypeFull  TaskType = "full"
    TaskTypeDelta TaskType = "delta"
)

type Task struct {
    MessageID   uuid.UUID    `json:"message_id"`
    MessageTime int64        `json:"message_time"`
    Tasks       []TaskDetail `json:"tasks"`
}

type TaskDetail struct {
    TaskID   uuid.UUID      `json:"task_id"`
    Type     TaskType       `json:"type"`
    Deadline int64          `json:"deadline"`
    Source   []SourceDetail `json:"source"`
}

type SourceDetail struct {
    Type   SourceType `json:"type"`
    URL    string     `json:"url"`
    SHA256 string     `json:"sha256"`
}

func main() {
    // Create a libpng task
    task := Task{
        MessageID:   uuid.New(),
        MessageTime: time.Now().Unix(),
        Tasks: []TaskDetail{
            {
                TaskID:   uuid.New(),
                Type:     TaskTypeFull,
                Deadline: time.Now().Add(24 * time.Hour).Unix(),
                Source: []SourceDetail{
                    {
                        Type:   SourceTypeRepo,
                        URL:    "https://github.com/glennrp/libpng",
                        SHA256: "e120ec1b07752dae225489aae99c6ef8c52c4edc6910d24c2a5ba1c68f03d70f",
                    },
                    {
                        Type:   SourceTypeFuzzTooling,
                        URL:    "https://github.com/google/oss-fuzz/tree/master/projects/libpng",
                        SHA256: "b3687b9d68a8b8ed6c2e7384b5b3f498fc0a3c2527e3d249dbef11ad3a147fcd",
                    },
                },
            },
        },
    }

    // Convert to JSON
    jsonData, err := json.Marshal(task)
    if err != nil {
        panic(err)
    }

    // Print the JSON being sent
    fmt.Printf("Sending JSON: %s\n", string(jsonData))

    // Send to CRS
    req, err := http.NewRequest("POST", "http://localhost:8080/v1/task/", bytes.NewBuffer(jsonData))
    if err != nil {
        panic(err)
    }

    req.Header.Set("Content-Type", "application/json")
    req.SetBasicAuth("username", "password")

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()

    // Read and print response body
    body, _ := io.ReadAll(resp.Body)
    fmt.Printf("Response: %s\n", string(body))

    fmt.Printf("Task submitted with status: %d\n", resp.StatusCode)
    fmt.Printf("Task ID: %s\n", task.Tasks[0].TaskID)
}
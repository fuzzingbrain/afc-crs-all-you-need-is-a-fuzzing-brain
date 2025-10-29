package handlers

import (
    "encoding/json"
    "log"
    "net/http"
    "github.com/gin-gonic/gin"
    "crs/internal/models"
    "crs/internal/services"
    "bytes"
    "io"
    "os"
    "path/filepath"
    "time"
    "fmt"
    "strings"
    "context"
    "crs/internal/telemetry"
    "go.opentelemetry.io/otel/attribute"
)

type Handler struct {
    crs services.CRSService
    startTime int64
    analysisService string
    submissionService string
}

func NewHandler(crs services.CRSService, analysisService, submissionService string) *Handler {
    return &Handler{
        crs: crs,
        analysisService: analysisService,
        submissionService: submissionService,
        startTime: time.Now().Unix(),
    }
}


func (h *Handler) GetStatus(c *gin.Context) {
    status := h.crs.GetStatus()
    // Add the since field from handler
    status.Since = h.startTime
    c.JSON(http.StatusOK, status)
}

func (h *Handler) ResetStatus(c *gin.Context) {
    // Reset the start time
    h.startTime = time.Now().Unix()
    // Reset the service status if needed
    // h.crs.ResetStatus()
    c.Status(http.StatusOK)
}

func (h *Handler) SubmitWorkerSarif(c *gin.Context) {
    
        // Read the raw request body first
        rawBody, err := io.ReadAll(c.Request.Body)
        if err != nil {
            log.Printf("Error reading request body: %v", err)
            c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
            return
        }
        
        // Restore the body for binding
        c.Request.Body = io.NopCloser(bytes.NewBuffer(rawBody))
        
        // Print the raw request body
        log.Printf("Raw SARIF broadcast detail data: %s", string(rawBody))

    var broadcastWorker models.SARIFBroadcastDetailWorker
    if err := c.ShouldBindJSON(&broadcastWorker); err != nil {
        log.Printf("Error parsing SARIF broadcast detail: %v", err)
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }


    if err := h.crs.HandleSarifBroadcastWorker(broadcastWorker); err != nil {
        log.Printf("Worker error processing SARIF broadcast: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    c.Status(http.StatusOK)
}


func (h *Handler) SubmitSarif(c *gin.Context) {
    // Read the raw request body first
    rawBody, err := io.ReadAll(c.Request.Body)
    if err != nil {
        log.Printf("Error reading request body: %v", err)
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    
    // Restore the body for binding
    c.Request.Body = io.NopCloser(bytes.NewBuffer(rawBody))
    
    // Print the raw request body
    log.Printf("Raw SARIF broadcast data: %s", string(rawBody))
    
    // Save the raw data to a file
    sarifDir := filepath.Join(h.crs.GetWorkDir(), "sarif_reports")
    if err := os.MkdirAll(sarifDir, 0755); err != nil {
        log.Printf("Error creating SARIF reports directory: %v", err)
    } else {
        timestamp := time.Now().Format("20060102-150405")
        filename := filepath.Join(sarifDir, fmt.Sprintf("sarif_raw_%s.json", timestamp))
        if err := os.WriteFile(filename, rawBody, 0644); err != nil {
            log.Printf("Error saving raw SARIF data to file: %v", err)
        } else {
            log.Printf("Raw SARIF data saved to %s", filename)
        }
    }

    var sarifBroadcast models.SARIFBroadcast
    if err := c.ShouldBindJSON(&sarifBroadcast); err != nil {
        log.Printf("Error parsing SARIF broadcast: %v", err)
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    
    // Log the received SARIF broadcast details
    log.Printf("Received SARIF broadcast: MessageID=%s, MessageTime=%d, Broadcasts=%d",
        sarifBroadcast.MessageID,
        sarifBroadcast.MessageTime,
        len(sarifBroadcast.Broadcasts))
    
    if err := h.crs.SubmitSarif(sarifBroadcast); err != nil {
        log.Printf("Error processing SARIF broadcast: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    
    c.Status(http.StatusOK)
}

func (h *Handler) SubmitWorkerTask(c *gin.Context) {
    var task models.WorkerTask
    if err := c.ShouldBindJSON(&task); err != nil {
        log.Printf("Error binding JSON: %v", err)
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    if err := h.crs.SubmitWorkerTask(task); err != nil {

        if strings.Contains(err.Error(), "worker is busy") {
            // Return 429 Too Many Requests for busy worker
            c.JSON(http.StatusTooManyRequests, gin.H{
                "error": err.Error(),
                "status": "busy",
            })
            return
        }

        log.Printf("Error processing task: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    c.Status(http.StatusAccepted)
}

func (h *Handler) SubmitLocalTask(taskPath string) {
    log.Printf("SubmitLocalTask taskPath: %v", taskPath)

    if os.Getenv("ANALYSIS_SERVICE_TEST") != "" || os.Getenv("LOCAL_TEST") != "" {
        h.analysisService = "http://localhost:7082"
    }
    if os.Getenv("SUBMISSION_SERVICE_TEST") != "" || os.Getenv("LOCAL_TEST") != "" {
        h.submissionService = "http://localhost:7081"
    }

    h.crs.SubmitLocalTask(taskPath)

}

func (h *Handler) SubmitTask(c *gin.Context) {
    var task models.Task
    if err := c.ShouldBindJSON(&task); err != nil {
        log.Printf("Error binding JSON: %v", err)
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    log.Printf("Received task request with %d tasks", len(task.Tasks))

    log.Printf("Received task details:")
    log.Printf("  MessageID: %s", task.MessageID)
    log.Printf("  MessageTime: %d", task.MessageTime)
    log.Printf("  Number of Tasks: %d", len(task.Tasks))
    
    for i, t := range task.Tasks {
        log.Printf("  Task[%d]:", i)
        log.Printf("    TaskID: %s", t.TaskID)
        log.Printf("    Type: %s", t.Type)
        log.Printf("    HarnessesIncluded: %t", t.HarnessesIncluded)
        log.Printf("    Deadline: %d", t.Deadline)
        deadlineTime := time.Unix(t.Deadline/1000, 0) // Convert milliseconds to seconds
        hoursRemaining := time.Until(deadlineTime).Hours()
        log.Printf("    Hours until deadline: %.2f", hoursRemaining)
        log.Printf("    Focus: %s", t.Focus)
        log.Printf("    ProjectName: %s", t.ProjectName)
        log.Printf("    Sources:")
        for j, src := range t.Source {
            log.Printf("      Source[%d]:", j)
            log.Printf("        Type: %s", src.Type)
            log.Printf("        URL: %s", src.URL)
            log.Printf("        SHA256: %s", src.SHA256)
        }
    }
    
    if os.Getenv("ANALYSIS_SERVICE_TEST") != "" || os.Getenv("LOCAL_TEST") != "" {
        h.analysisService = "http://localhost:7082"
    }
    if os.Getenv("SUBMISSION_SERVICE_TEST") != "" || os.Getenv("LOCAL_TEST") != "" {
        h.submissionService = "http://localhost:7081"
    }

    if true {
        // Make a copy of task if needed (to avoid race conditions)
        taskCopy := task
    
        go func() {
            taskJSON, err := json.Marshal(taskCopy)
            if err != nil {
                log.Printf("Error processing taskJSON: %v", err)
                return
            }

            // Create a new request with the proper method, URL, and body
req, err := http.NewRequest("POST", fmt.Sprintf("%s/v1/task", h.analysisService), bytes.NewBuffer(taskJSON))
if err != nil {
    log.Printf("Error creating request: %v", err)
    return
}

// Set content type
req.Header.Set("Content-Type", "application/json")

// Add Basic Authentication from environment variables
apiKeyID := os.Getenv("COMPETITION_API_KEY_ID")
apiToken := os.Getenv("COMPETITION_API_KEY_TOKEN")
if apiKeyID != "" && apiToken != "" {
    req.SetBasicAuth(apiKeyID, apiToken)
} else {
    log.Printf("Warning: API credentials not found in environment variables")
}

// Create an HTTP client and send the request
client := &http.Client{}
resp, err := client.Do(req)
if err != nil {
    log.Printf("Error sending request: %v", err)
    return
}
defer resp.Body.Close()
    
            // Read response
            respBody, err := io.ReadAll(resp.Body)
            if err != nil {
                log.Printf("Error reading response: %v", err)
                return
            }
    
            // Print response
            fmt.Printf("\nResponse from analysis server (status %d):\n", resp.StatusCode)
    
            // Format JSON response if possible
            var prettyJSON bytes.Buffer
            err = json.Indent(&prettyJSON, respBody, "", "  ")
            if err != nil {
                // Not valid JSON, print as-is
                fmt.Println(string(respBody))
            } else {
                fmt.Println(prettyJSON.String())
            }
    
            log.Printf("Successfully forwarded to the analysis server: %s", taskCopy.MessageID)
        }()

        go func() {
            taskJSON, err := json.Marshal(taskCopy)
            if err != nil {
                log.Printf("Error processing taskJSON: %v", err)
                return
            }
// Create a new request with the proper method, URL, and body
req, err := http.NewRequest("POST", fmt.Sprintf("%s/v1/task", h.submissionService), bytes.NewBuffer(taskJSON))
if err != nil {
    log.Printf("Error creating request: %v", err)
    return
}

// Set content type
req.Header.Set("Content-Type", "application/json")

// Add Basic Authentication from environment variables
apiKeyID := os.Getenv("COMPETITION_API_KEY_ID")
apiToken := os.Getenv("COMPETITION_API_KEY_TOKEN")
if apiKeyID != "" && apiToken != "" {
    req.SetBasicAuth(apiKeyID, apiToken)
} else {
    log.Printf("Warning: API credentials not found in environment variables")
}

// Create an HTTP client and send the request
client := &http.Client{}
resp, err := client.Do(req)
if err != nil {
    log.Printf("Error sending request: %v", err)
    return
}
defer resp.Body.Close()
    
            // Read response
            respBody, err := io.ReadAll(resp.Body)
            if err != nil {
                log.Printf("Error reading response: %v", err)
                return
            }
    
            // Print response
            fmt.Printf("\nResponse from submission server (status %d):\n", resp.StatusCode)
    
            // Format JSON response if possible
            var prettyJSON bytes.Buffer
            err = json.Indent(&prettyJSON, respBody, "", "  ")
            if err != nil {
                // Not valid JSON, print as-is
                fmt.Println(string(respBody))
            } else {
                fmt.Println(prettyJSON.String())
            }
    
            log.Printf("Successfully forwarded to the submission server: %s", taskCopy.MessageID)
        }()
        // The main thread continues immediately here
    }
    
    if err := h.crs.SubmitTask(task); err != nil {
        log.Printf("Error processing task: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    
    //send task detail to telemetry server 
    for i, t := range task.Tasks {
        ctx := context.Background()
        ctx, span := telemetry.StartSpan(ctx, "task_detail")
        defer span.End()
        for key, value := range t.Metadata {
            span.SetAttributes(attribute.String(key, value))
        }
        span.SetAttributes(
            attribute.String("task", fmt.Sprint(i)),
            attribute.String("task_id", t.TaskID.String()),
            attribute.String("task_type", string(t.Type)),
            attribute.Int64("deadline", t.Deadline),
            attribute.String("project_name", t.ProjectName),
            attribute.String("focus", t.Focus),
        )
    }

    log.Printf("Successfully processed SubmitTask MessageID: %s", task.MessageID)
    c.Status(http.StatusAccepted)
}

func (h *Handler) CancelTask(c *gin.Context) {
    taskID := c.Param("task_id")
    err := h.crs.CancelTask(taskID)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    c.Status(http.StatusOK)
}

func (h *Handler) CancelAllTasks(c *gin.Context) {
    err := h.crs.CancelAllTasks()
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    c.Status(http.StatusOK)
}
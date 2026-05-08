// SPDX-License-Identifier: Apache-2.0
package handlers

import (
    "reflect"
    "os/exec"
    "strconv"
    "path/filepath"
    "os"
    "strings"
    "encoding/json"
    "bytes"
    "io"
    "log"
    "fmt"
    "sync"
    "time"
    "crypto/sha256"
    "encoding/hex"
    "regexp"
    "github.com/agnivade/levenshtein"
    "github.com/gin-gonic/gin"
    "github.com/google/uuid"
    "net"
    "net/http"
    "context"
    "encoding/base64"
    "competition-api/internal/models"
    "competition-api/internal/telemetry"
    "go.opentelemetry.io/otel/attribute"
    "google.golang.org/genai"
)

type Handler struct {
    tasks                sync.Map // map[string]map[string]interface{}
    receivedPovSubmissions sync.Map // map[string][]models.POVSubmission
    povSubmissions       sync.Map // map[string]models.POVSubmission
    freeformSubmissions  sync.Map // map[string]models.FreeformSubmission
    sarifs               sync.Map // map[string][]models.SARIFBroadcastDetail
    processedSarifs      sync.Map // map[string]bool

    // Signature-to-group mapping, per task.
    // taskID → *sync.Map(signature string → canonicalGroupSig string)
    povSignatureGroups     sync.Map
    
    // One patch per canonical group.
    // taskID → *sync.Map(groupSig string → patchID string)    
    patchByGroup           sync.Map

    bundleByGroup sync.Map // taskID → *sync.Map(canonicalSig → bundleID)
    patchFingerprintByGroup sync.Map
    lastPatchTime sync.Map
    hostAPIBaseURL string   
}

type patchSubmitInfo struct {
    Time time.Time
    PatchID string
}

func normaliseDiff(diff string) string {
    // strip CR/LF noise and compress whitespace
    s := strings.ReplaceAll(diff, "\r", "")
    s = regexp.MustCompile(`\s+`).ReplaceAllString(s, " ")
    return s
}

func sha256Hex(s string) string {
    h := sha256.Sum256([]byte(s))
    return hex.EncodeToString(h[:])
}

func similar(a, b string) bool {
    // very cheap similarity metric (distance ≤ 10 chars)
    distance := levenshtein.ComputeDistance(a, b)
    return distance <= 10
    // return levenshtein.Distance(a, b, nil) <= 10
}

func NewHandler() *Handler {
    return &Handler{
        hostAPIBaseURL: "https://api.tail7e9b4c.ts.net", // Default value
        //FOR TESTING ONLY
        // hostAPIBaseURL: "https://test-synthetic-dawn-api.tail7e9b4c.ts.net",
    }
}

// Add a method to set the host API base URL
func (h *Handler) SetHostAPIBaseURL(url string) {
    h.hostAPIBaseURL = url
}

type SimplifiedPOVSubmission struct {
    Architecture string `json:"architecture"`
    Engine       string `json:"engine"`
    FuzzerName   string `json:"fuzzer_name"`
    Sanitizer    string `json:"sanitizer"`
    Testcase     string `json:"testcase"`
}
type SimplifiedPatchSubmission struct {
    Patch string `json:"patch"`
}

func (h *Handler) GetPOVStats(c *gin.Context) {
    taskID := c.Param("task_id")
    if taskID == "" {
        c.JSON(http.StatusBadRequest, models.Error{Message: "invalid task_id"})
        return
    }

    var count int
    var patch_count int
    if taskMapAny, ok := h.tasks.Load(taskID); ok {
        taskMap := taskMapAny.(*sync.Map)
        taskMap.Range(func(_, vAny interface{}) bool {
            // if _, ok := vAny.(models.POVSubmissionResponse); ok {
            //     count++
            // } else  if _, ok := vAny.(models.PatchSubmissionResponse); ok {
            //     patch_count++
            // }
            switch vAny.(type) {
            case models.POVSubmissionResponse, *models.POVSubmissionResponse:
                count++
            case models.PatchSubmissionResponse, *models.PatchSubmissionResponse,
                models.PatchStatusResponse, *models.PatchStatusResponse:
                patch_count++
            }
            return true
        })
    }

    log.Printf("GetPOVStats: task %s has %d POV submissions. PatchCount: %d", taskID, count, patch_count)
    c.JSON(http.StatusOK, models.POVStatsResponse{
        TaskID: taskID,
        Count:  count,
        PatchCount:  patch_count,
    })
}

func (h *Handler) SubmitFreeformPOV(c *gin.Context) {
    taskID := c.Param("task_id")
    // Create a context for telemetry
    ctx, span := telemetry.StartSpan(c.Request.Context(), "SubmitFreeformPOV")
    defer span.End()

    // Add initial context
    telemetry.AddSpanAttributes(ctx,
        attribute.String("crs.action.category", "non_scoring_submission"),
        attribute.String("crs.action.name", "SubmitFreeformPOV"),
    )
    // Validate taskID
    if taskID == "" {
        log.Printf("Error: empty task_id in submission")
        telemetry.AddSpanEvent(ctx, "error", attribute.String("error", "empty task_id"))
        c.JSON(http.StatusBadRequest, models.Error{Message: "invalid task_id"})
        return
    }
    telemetry.AddSpanAttributes(ctx, attribute.String("task.id", taskID))

    // Read and log the raw request body
    rawData, err := io.ReadAll(c.Request.Body)
    if err != nil {
        log.Printf("Error reading request body for task %s: %v", taskID, err)
        telemetry.AddSpanError(ctx, err)
        c.JSON(http.StatusBadRequest, models.Error{Message: "failed to read request body"})
        return
    }

    encoded := base64.StdEncoding.EncodeToString(rawData)
    submission_x := models.FreeformSubmission{
            Submission: encoded,
    }

    // Log the raw JSON data (truncated for telemetry)
    truncatedData := string(rawData)
    if len(truncatedData) > 10000 {
        truncatedData = truncatedData[:5000] + "... [truncated] ..." + truncatedData[len(truncatedData)-5000:]
    }
    log.Printf("Received Freeform POV submission for task %s: %s", taskID, truncatedData)
    
    // Send raw data to telemetry
    telemetry.AddSpanEvent(ctx, "freeform_pov_submission_received", 
        attribute.String("raw_data", truncatedData),
        attribute.Int("data_size", len(rawData)))

    // Restore the request body for binding
    c.Request.Body = io.NopCloser(bytes.NewBuffer(rawData))
        
    var submission models.POVSubmission
    if err := c.ShouldBindJSON(&submission); err != nil {
        log.Printf("Error: failed to parse submission for task %s: %v", taskID, err)
        telemetry.AddSpanError(ctx, err)
        c.JSON(http.StatusBadRequest, models.Error{Message: err.Error()})
        return
    }

    // Skip submissions where signature starts with "MEMORY:generic:" and crash_trace contains "NOTE: fuzzing was not performed"
    if strings.HasPrefix(submission.Signature, "MEMORY:generic:") && 
        strings.Contains(submission.CrashTrace, "NOTE: fuzzing was not performed") {
            log.Printf("Skipping MEMORY submission with 'fuzzing was not performed' for task %s", taskID)
            c.JSON(http.StatusOK, models.FreeformSubmissionResponse{
                FreeformID:  "skipped_false_positive",
                Status: "skipped",
            })
            return
    }


    submission.TaskID = taskID

    // Log the received submission details
    log.Printf("Freeform POV submission details: TaskID=%s, Architecture=%s, Engine=%s, FuzzerName=%s, Signature=%s,  Sanitizer=%s, FuzzerFile=%s, FuzzerSourceSize=%d, TestcaseSize=%d",
        submission.TaskID,
        submission.Architecture,
        submission.Engine,
        submission.FuzzerName,
        submission.Signature,
        submission.Sanitizer,
        submission.FuzzerFile,
        len(submission.FuzzerSource),
        len(submission.Testcase))

    // Add submission details to telemetry
    telemetry.AddSpanAttributes(ctx,
        attribute.String("architecture", string(submission.Architecture)),
        attribute.String("engine", submission.Engine),
        attribute.String("fuzzer_name", submission.FuzzerName),
        attribute.String("sanitizer", submission.Sanitizer),
        attribute.Int("testcase_size", len(submission.Testcase)))

    h.submitFreeform(c, ctx, submission_x, taskID)
}

func (h *Handler) SubmitFreeformPatch(c *gin.Context) {

    taskID := c.Param("task_id")
    // Create a context for telemetry
    ctx, span := telemetry.StartSpan(c.Request.Context(), "SubmitFreeformPatch")
    defer span.End()

    // Add initial context
    telemetry.AddSpanAttributes(ctx,
        attribute.String("crs.action.category", "non_scoring_submission"),
        attribute.String("crs.action.name", "SubmitFreeformPatch"),
    )
    // Validate taskID
    if taskID == "" {
        log.Printf("Error: empty task_id in submission")
        telemetry.AddSpanEvent(ctx, "error", attribute.String("error", "empty task_id"))
        c.JSON(http.StatusBadRequest, models.Error{Message: "invalid task_id"})
        return
    }
    telemetry.AddSpanAttributes(ctx, attribute.String("task.id", taskID))

    // Read and log the raw request body
    rawData, err := io.ReadAll(c.Request.Body)
    if err != nil {
        log.Printf("Error reading request body for task %s: %v", taskID, err)
        telemetry.AddSpanError(ctx, err)
        c.JSON(http.StatusBadRequest, models.Error{Message: "failed to read request body"})
        return
    }

    encoded := base64.StdEncoding.EncodeToString(rawData)
    submission_x := models.FreeformSubmission{
            Submission: encoded,
    }

    // Log the raw JSON data (truncated for telemetry)
    truncatedData := string(rawData)
    if len(truncatedData) > 10000 {
        truncatedData = truncatedData[:5000] + "... [truncated] ..." + truncatedData[len(truncatedData)-5000:]
    }
    log.Printf("Received Freeform patch submission for task %s: %s", taskID, truncatedData)
    
    // Send raw data to telemetry
    telemetry.AddSpanEvent(ctx, "freeform_patch_submission_received", 
        attribute.String("raw_data", truncatedData),
        attribute.Int("data_size", len(rawData)))

    // Restore the request body for binding
    c.Request.Body = io.NopCloser(bytes.NewBuffer(rawData))
        
    var submission models.PatchSubmission
    if err := c.ShouldBindJSON(&submission); err != nil {
        log.Printf("Error: failed to parse submission for task %s: %v", taskID, err)
        telemetry.AddSpanError(ctx, err)
        c.JSON(http.StatusBadRequest, models.Error{Message: err.Error()})
        return
    }
    h.submitFreeform(c, ctx, submission_x, taskID)
}

func (h *Handler) submitFreeform(c *gin.Context, ctx context.Context, submission models.FreeformSubmission, taskID string) {

    // Forward to host API
    hostAPIURL := fmt.Sprintf("%s/v1/task/%s/freeform/", h.hostAPIBaseURL, taskID)
        
    simplifiedData, err := json.Marshal(submission)
    if err != nil {
        telemetry.AddSpanError(ctx, err)
        log.Printf("Error marshaling simplified submission: %v", err)
        c.JSON(http.StatusInternalServerError, models.Error{Message: "failed to process submission"})
        return
    }
    hostReq, err := http.NewRequest("POST", hostAPIURL, bytes.NewBuffer(simplifiedData))
    if err != nil {
        telemetry.AddSpanError(ctx, err)
        log.Printf("Error creating request to host API: %v", err)
        c.JSON(http.StatusInternalServerError, models.Error{Message: "failed to forward request"})
        return
    }
    
    // Copy headers from original request
    hostReq.Header = c.Request.Header
    
    // Use a client with configured timeouts
    client := &http.Client{
        Timeout: 60*time.Second,  // Slightly shorter than context timeout
        Transport: &http.Transport{
            MaxIdleConns:        100,
            MaxIdleConnsPerHost: 100,
            IdleConnTimeout:     90 * time.Second,
            DialContext: (&net.Dialer{
                Timeout:   5 * time.Second,
                KeepAlive: 30 * time.Second,
            }).DialContext,
            TLSHandshakeTimeout:   5 * time.Second,
            ResponseHeaderTimeout: 10 * time.Second,
        },
    }

    // Improve error handling for host API response
    resp, err := client.Do(hostReq)
    if err != nil {
        telemetry.AddSpanError(ctx, err)
        log.Printf("Error sending request to host API: %v", err)
        if os.IsTimeout(err) || strings.Contains(err.Error(), "connection refused") {
            telemetry.AddSpanEvent(ctx, "host_api_error",
                attribute.String("error_type", "connection"),
                attribute.String("error", err.Error()))
            c.JSON(http.StatusServiceUnavailable, models.Error{
                Message: "host API temporarily unavailable, please retry",
            })
        } else {
            telemetry.AddSpanEvent(ctx, "host_api_error",
                attribute.String("error_type", "request"),
                attribute.String("error", err.Error()))
            c.JSON(http.StatusInternalServerError, models.Error{
                Message: "failed to forward request",
            })
        }
        return
    }
    
    defer resp.Body.Close()

    // Read response body
    respBody, err := io.ReadAll(resp.Body)
    if err != nil {
        telemetry.AddSpanError(ctx, err)
        telemetry.AddSpanEvent(ctx, "response_error",
            attribute.String("error_type", "read"),
            attribute.String("error", err.Error()))
        log.Printf("Error reading response from host API: %v", err)
        c.JSON(http.StatusInternalServerError, models.Error{Message: "failed to read response"})
        return
    }

    // Add response to telemetry (truncated) - do this for ALL responses
    truncatedResp := string(respBody)
    if len(truncatedResp) > 1000 {
        truncatedResp = truncatedResp[:1000] + "..."
    }
    telemetry.AddSpanEvent(ctx, "host_api_response", 
        attribute.String("response_body", truncatedResp),
        attribute.Int("status_code", resp.StatusCode),
        attribute.Int("response_size", len(respBody)))


    // Handle non-200 responses
    if resp.StatusCode != http.StatusOK {
        log.Printf("Host API returned non-200 status: %d, body: %s", resp.StatusCode, truncatedResp)
        telemetry.AddSpanEvent(ctx, "host_api_error",
            attribute.Int("status_code", resp.StatusCode),
            attribute.String("error_type", "status"),
            attribute.String("response_body", truncatedResp))
        
        // Try to parse error response
        var errorResp models.Error
        if err := json.Unmarshal(respBody, &errorResp); err != nil {
            // If can't parse error response, use generic error
            errorResp = models.Error{
                Message: fmt.Sprintf("host API returned status %d", resp.StatusCode),
            }
        }
        
        c.JSON(resp.StatusCode, errorResp)
        return
    }

    // Continue with normal response handling...
    var response models.FreeformSubmissionResponse
    if err := json.Unmarshal(respBody, &response); err != nil {
        telemetry.AddSpanError(ctx, err)
        telemetry.AddSpanEvent(ctx, "parse_error",
            attribute.String("error_type", "unmarshal"),
            attribute.String("error", err.Error()))
        log.Printf("Error parsing response from host API: %v", err)
        c.JSON(http.StatusInternalServerError, models.Error{Message: "failed to parse response"})
        return
    }

    // Add successful response details to telemetry
    telemetry.AddSpanAttributes(ctx, 
        attribute.String("freeform_id", response.FreeformID),
        attribute.String("status", string(response.Status)))
    
    h.freeformSubmissions.Store(response.FreeformID, submission)

    log.Printf("Freeform submission forwarded and accepted: TaskID=%s, FreeformID=%s, Status=%s",
        taskID, response.FreeformID, response.Status)

    c.JSON(resp.StatusCode, response)
}


func (h *Handler) SubmitPOV(c *gin.Context) {

    taskID := c.Param("task_id")
    // Create a context for telemetry
    ctx, span := telemetry.StartSpan(c.Request.Context(), "SubmitPOV")
    defer span.End()

    // Add initial context
    telemetry.AddSpanAttributes(ctx,
        attribute.String("crs.action.category", "scoring_submission"),
        attribute.String("crs.action.name", "SubmitPOV"),
    )


    // Validate taskID
    if taskID == "" {
        log.Printf("Error: empty task_id in submission")
        telemetry.AddSpanEvent(ctx, "error", attribute.String("error", "empty task_id"))
        c.JSON(http.StatusBadRequest, models.Error{Message: "invalid task_id"})
        return
    }
    telemetry.AddSpanAttributes(ctx, attribute.String("task.id", taskID))

    // Read and log the raw request body
    rawData, err := io.ReadAll(c.Request.Body)
    if err != nil {
        log.Printf("Error reading request body for task %s: %v", taskID, err)
        telemetry.AddSpanError(ctx, err)
        c.JSON(http.StatusBadRequest, models.Error{Message: "failed to read request body"})
        return
    }
    
    // Log the raw JSON data (truncated for telemetry)
    truncatedData := string(rawData)
    if len(truncatedData) > 10000 {
        truncatedData = truncatedData[:5000] + "... [truncated] ..." + truncatedData[len(truncatedData)-5000:]
    }
    log.Printf("Received POV submission for task %s: %s", taskID, truncatedData)
    
    // Send raw data to telemetry
    telemetry.AddSpanEvent(ctx, "pov_submission_received", 
        attribute.String("raw_data", truncatedData),
        attribute.Int("data_size", len(rawData)))

    // Restore the request body for binding
    c.Request.Body = io.NopCloser(bytes.NewBuffer(rawData))
        
    var submission models.POVSubmission
    if err := c.ShouldBindJSON(&submission); err != nil {
        log.Printf("Error: failed to parse submission for task %s: %v", taskID, err)
        telemetry.AddSpanError(ctx, err)
        c.JSON(http.StatusBadRequest, models.Error{Message: err.Error()})
        return
    }

    // Skip submissions where signature starts with "MEMORY:generic:" and crash_trace contains "NOTE: fuzzing was not performed"
    if strings.HasPrefix(submission.Signature, "MEMORY:generic:") && 
        strings.Contains(submission.CrashTrace, "NOTE: fuzzing was not performed") {
            log.Printf("Skipping MEMORY submission with 'fuzzing was not performed' for task %s", taskID)
            c.JSON(http.StatusOK, models.POVSubmissionResponse{
                POVID:  "skipped_false_positive",
                Status: "skipped",
            })
            return
    }


    submission.TaskID = taskID

    // Log the received submission details
    log.Printf("POV submission details: TaskID=%s, Architecture=%s, Engine=%s, FuzzerName=%s, Sanitizer=%s, TestcaseSize=%d",
        submission.TaskID,
        submission.Architecture,
        submission.Engine,
        submission.FuzzerName,
        submission.Sanitizer,
        len(submission.Testcase))

    // Add submission details to telemetry
    telemetry.AddSpanAttributes(ctx,
        attribute.String("architecture", string(submission.Architecture)),
        attribute.String("engine", submission.Engine),
        attribute.String("fuzzer_name", submission.FuzzerName),
        attribute.String("sanitizer", submission.Sanitizer),
        attribute.Int("testcase_size", len(submission.Testcase)))

    // tasks: ensure map exists, then store
    taskMapAny, _ := h.tasks.LoadOrStore(taskID, &sync.Map{})
    taskMap := taskMapAny.(*sync.Map)


    groupMapAny, _ := h.povSignatureGroups.LoadOrStore(taskID, &sync.Map{})
    groupMap := groupMapAny.(*sync.Map)
    canonicalSig := submission.Signature

    // Check for duplicate vulnerabilities
    newCrashTrace := submission.CrashTrace
    if newCrashTrace != "" {
        ctxCompare, spanCompare := telemetry.StartSpan(ctx, "dedup_pov")
        defer spanCompare.End()
        duplicateFound := false
        if true {
            if povSliceAny, ok := h.receivedPovSubmissions.Load(taskID); ok {
                povSlice := povSliceAny.([]models.POVSubmission)
                for _, storedSubmission := range povSlice {
                        // Compare signatures first
                        if storedSubmission.Signature != "" && submission.Signature != "" && 
                            storedSubmission.Signature == submission.Signature {
                            telemetry.AddSpanEvent(ctxCompare, "duplicate_detected_by_signature", 
                                attribute.String("signature", submission.Signature))
                            log.Printf("Duplicate POV detected for task %s: Signature: %s", 
                            taskID, submission.Signature)
                            duplicate_resp := models.POVSubmissionResponse{
                                POVID:  storedSubmission.POVID,
                                Status: "duplicate",
                            }     
                            c.JSON(http.StatusOK, duplicate_resp)
                            duplicateFound = true
                            // re-use the first matching storedSubmission.Signature
                            canonicalSig = storedSubmission.Signature
                            
                            break
                        }
                        // Compare crash traces if signatures don't match
                        if storedSubmission.CrashTrace != "" {
                            telemetry.AddSpanEvent(ctxCompare, "comparing_crash_traces", 
                                attribute.String("signature", storedSubmission.Signature))
                            isDuplicate, err := h.compareCrashTraces(storedSubmission.CrashTrace, newCrashTrace)
                            if err != nil {
                                telemetry.AddSpanError(ctxCompare, err)
                                log.Printf("Error comparing crash traces: %v", err)
                            } else if isDuplicate {
                                telemetry.AddSpanEvent(ctxCompare, "duplicate_detected", 
                                    attribute.String("duplicate_pov_signature", submission.Signature))
                                log.Printf("Duplicate POV detected by llm for task %s: Signature: %s", 
                                taskID, submission.Signature)
                                duplicate_resp := models.POVSubmissionResponse{
                                    POVID:  storedSubmission.POVID,
                                    Status: "duplicate",
                                }
                                c.JSON(http.StatusOK, duplicate_resp)
                                duplicateFound = true
                                // re-use the first matching storedSubmission.Signature
                                canonicalSig = storedSubmission.Signature
                                break
                            }
                        }
                }
            }
        }
        log.Printf("SubmitPOV: after duplicate check, duplicate found: %v", duplicateFound)
        if duplicateFound {
            groupMap.Store(submission.Signature, canonicalSig)
            return
        }        
    } else {
        log.Printf("SubmitPOV: No crash trace present, skipping duplicate check")
    }

    groupMap.Store(submission.Signature, canonicalSig)

    // receivedPovSubmissions: append safely
    povSliceAny, _ := h.receivedPovSubmissions.LoadOrStore(taskID, []models.POVSubmission{})
    povSlice := povSliceAny.([]models.POVSubmission)
    povSlice = append(povSlice, submission)
    h.receivedPovSubmissions.Store(taskID, povSlice)

    // Create simplified submission for forwarding
    simplifiedSubmission := SimplifiedPOVSubmission{
        Architecture: string(submission.Architecture),
        Engine:      submission.Engine,
        FuzzerName:  submission.FuzzerName,
        Sanitizer:   submission.Sanitizer,
        Testcase:    submission.Testcase,
    }
    
    simplifiedData, err := json.Marshal(simplifiedSubmission)
    if err != nil {
        telemetry.AddSpanError(ctx, err)
        log.Printf("Error marshaling simplified submission: %v", err)
        c.JSON(http.StatusInternalServerError, models.Error{Message: "failed to process submission"})
        return
    }

    // Forward to host API
    hostAPIURL := fmt.Sprintf("%s/v1/task/%s/pov/", h.hostAPIBaseURL, taskID)
    
    telemetry.AddSpanAttributes(ctx, attribute.String("host_api_url", hostAPIURL))
    
    hostReq, err := http.NewRequest("POST", hostAPIURL, bytes.NewBuffer(simplifiedData))
    if err != nil {
        telemetry.AddSpanError(ctx, err)
        log.Printf("Error creating request to host API: %v", err)
        c.JSON(http.StatusInternalServerError, models.Error{Message: "failed to forward request"})
        return
    }
    
    // Copy headers from original request
    hostReq.Header = c.Request.Header
    
    // Use a client with configured timeouts
    client := &http.Client{
        Timeout: 60*time.Second,  // Slightly shorter than context timeout
        Transport: &http.Transport{
            MaxIdleConns:        100,
            MaxIdleConnsPerHost: 100,
            IdleConnTimeout:     90 * time.Second,
            DialContext: (&net.Dialer{
                Timeout:   5 * time.Second,
                KeepAlive: 30 * time.Second,
            }).DialContext,
            TLSHandshakeTimeout:   5 * time.Second,
            ResponseHeaderTimeout: 10 * time.Second,
        },
    }

    // Improve error handling for host API response
    resp, err := client.Do(hostReq)
    if err != nil {
        telemetry.AddSpanError(ctx, err)
        log.Printf("Error sending request to host API: %v", err)
        if os.IsTimeout(err) || strings.Contains(err.Error(), "connection refused") {
            telemetry.AddSpanEvent(ctx, "host_api_error",
                attribute.String("error_type", "connection"),
                attribute.String("error", err.Error()))
            c.JSON(http.StatusServiceUnavailable, models.Error{
                Message: "host API temporarily unavailable, please retry",
            })
        } else {
            telemetry.AddSpanEvent(ctx, "host_api_error",
                attribute.String("error_type", "request"),
                attribute.String("error", err.Error()))
            c.JSON(http.StatusInternalServerError, models.Error{
                Message: "failed to forward request",
            })
        }
        return
    }
    
    defer resp.Body.Close()

    // Read response body
    respBody, err := io.ReadAll(resp.Body)
    if err != nil {
        telemetry.AddSpanError(ctx, err)
        telemetry.AddSpanEvent(ctx, "response_error",
            attribute.String("error_type", "read"),
            attribute.String("error", err.Error()))
        log.Printf("Error reading response from host API: %v", err)
        c.JSON(http.StatusInternalServerError, models.Error{Message: "failed to read response"})
        return
    }

    // Add response to telemetry (truncated) - do this for ALL responses
    truncatedResp := string(respBody)
    if len(truncatedResp) > 1000 {
        truncatedResp = truncatedResp[:1000] + "..."
    }
    telemetry.AddSpanEvent(ctx, "host_api_response", 
        attribute.String("response_body", truncatedResp),
        attribute.Int("status_code", resp.StatusCode),
        attribute.Int("response_size", len(respBody)))


    // Handle non-200 responses
    if resp.StatusCode != http.StatusOK {
        log.Printf("Host API returned non-200 status: %d, body: %s", resp.StatusCode, truncatedResp)
        telemetry.AddSpanEvent(ctx, "host_api_error",
            attribute.Int("status_code", resp.StatusCode),
            attribute.String("error_type", "status"),
            attribute.String("response_body", truncatedResp))
        
        // Try to parse error response
        var errorResp models.Error
        if err := json.Unmarshal(respBody, &errorResp); err != nil {
            // If can't parse error response, use generic error
            errorResp = models.Error{
                Message: fmt.Sprintf("host API returned status %d", resp.StatusCode),
            }
        }
        
        c.JSON(resp.StatusCode, errorResp)
        return
    }

    // Continue with normal response handling...
    var response models.POVSubmissionResponse
    if err := json.Unmarshal(respBody, &response); err != nil {
        telemetry.AddSpanError(ctx, err)
        telemetry.AddSpanEvent(ctx, "parse_error",
            attribute.String("error_type", "unmarshal"),
            attribute.String("error", err.Error()))
        log.Printf("Error parsing response from host API: %v", err)
        c.JSON(http.StatusInternalServerError, models.Error{Message: "failed to parse response"})
        return
    }

    // Add successful response details to telemetry
    telemetry.AddSpanAttributes(ctx, 
        attribute.String("pov_id", response.POVID),
        attribute.String("status", string(response.Status)))
    
    // Store the response and submission
    taskMap.Store(response.POVID, response)
    submission.POVID = response.POVID
    h.povSubmissions.Store(response.POVID, submission)

    log.Printf("POV submission forwarded and accepted: TaskID=%s, POVID=%s, Status=%s",
        taskID, response.POVID, response.Status)

    
    // Run the SARIF check in a separate goroutine
    go func() {
        sarifID := ""
        // Get SARIFs for this task
        sarifsAny, ok := h.sarifs.Load(taskID)
        if ok {
            sarifs := sarifsAny.([]models.SARIFBroadcastDetail)
            if len(sarifs) > 0 {
                log.Printf("Found %d SARIF broadcasts to check for task %s response.POVID %s", len(sarifs), taskID, response.POVID)
                validSarifIDs := h.checkAndProcessSARIFsForPOV(context.Background(), taskID, response.POVID, submission, sarifs, c)
                if len(validSarifIDs) > 1 {
                    log.Printf("SOMETHING COULD BE WRONG! Found more than one validSarifIDs: %v\n",
                    validSarifIDs)
                }
                if len(validSarifIDs) > 0 {
                    sarifID = validSarifIDs[0].String()
                }
            }
        }
        // Try to create bundle in a separate goroutine
        h.tryCreateBundle(taskID, response.POVID, sarifID, "", "", c)
    }()

    c.JSON(resp.StatusCode, response)
}

func (h *Handler) checkAndProcessSARIFsForPOV(ctx context.Context, taskID, povID string, submission models.POVSubmission, sarifs []models.SARIFBroadcastDetail, c *gin.Context) []uuid.UUID {
    log.Printf("Checking SARIF broadcasts for POV %s on task %s", povID, taskID)

    var validSarifIDs []uuid.UUID

    // Get POV status from host API
    povStatus, err := h.getPOVStatus(ctx, taskID, povID, c.Request.Header)
    if err != nil {
        log.Printf("Error checking POV status for task %s, POVID %s: %v", taskID, povID, err)
        return validSarifIDs
    }

    if povStatus == nil || (povStatus.Status != models.SubmissionStatusPassed && povStatus.Status != models.SubmissionStatusAccepted) {
        statusText := "unknown"
        if povStatus != nil {
            statusText = string(povStatus.Status)
        }
        log.Printf("POV %s not passed for task %s: status=%s", povID, taskID, statusText)
        return validSarifIDs
    }

    log.Printf("POV %s has passed for task %s, checking against SARIF broadcasts", povID, taskID)

    // Check each SARIF against the POV
    for _, broadcast := range sarifs {
        isAccurate, err := h.CheckPOVDescriptionAccuracy(submission, broadcast)
        if err != nil {
            log.Printf("Error checking accuracy of SARIF %s against POV %s: %v", 
                broadcast.SarifID, povID, err)
            continue
        }

        if isAccurate {
            log.Printf("SARIF %s correctly describes POV %s for task %s", 
                broadcast.SarifID, povID, taskID)

            // Submit assessment to the competition API
            err := h.submitSarifAssessment(ctx, taskID, broadcast.SarifID.String(), povID,"", true, c.Request.Header)
            if err != nil {
                log.Printf("Error submitting SARIF assessment: %v", err)
            } else {
                log.Printf("Successfully submitted valid SARIF assessment for task %s (SARIF %s, POV %s)", 
                    taskID, broadcast.SarifID, povID)
                validSarifIDs = append(validSarifIDs, broadcast.SarifID)
            }
        } else {
            log.Printf("SARIF %s does not accurately describe POV %s for task %s", 
                broadcast.SarifID, povID, taskID)
        }
    }

    // Remove processed SARIFs
    if len(validSarifIDs) > 0 {
        h.removeSarifBroadcasts(taskID, validSarifIDs)
    }

    return validSarifIDs
}

func (h *Handler) removeSarifBroadcasts(taskID string, sarifIDs []uuid.UUID) {
    sarifsAny, ok := h.sarifs.Load(taskID)
    if !ok {
        return
    }
    sarifs := sarifsAny.([]models.SARIFBroadcastDetail)

    // Create a set of SARIF IDs to remove
    toRemove := make(map[uuid.UUID]bool)
    for _, id := range sarifIDs {
        toRemove[id] = true
    }

    // Keep only SARIFs not in the removal set
    var newSarifs []models.SARIFBroadcastDetail
    for _, sarif := range sarifs {
        if !toRemove[sarif.SarifID] {
            newSarifs = append(newSarifs, sarif)
        }
    }

    // Update the map with filtered list
    h.sarifs.Store(taskID, newSarifs)

    // update processedSarifs
    for _, id := range sarifIDs {
        h.processedSarifs.Store(id.String(), true)
    }

    log.Printf("Removed %d processed SARIF broadcasts for task %s, %d remaining", 
        len(sarifIDs), taskID, len(newSarifs))
}

// submitSarifAssessment submits an assessment of a SARIF broadcast to the competition API
func (h *Handler) submitSarifAssessment(ctx context.Context, taskID, sarifID, povID string, patchID string, isValid bool,  validHeader http.Header) error {
    hostAPIURL := fmt.Sprintf("%s/v1/task/%s/broadcast-sarif-assessment/%s/", 
        h.hostAPIBaseURL, taskID, sarifID)
    
    var description string
    if povID == "" && patchID == "" {
        if isValid {
            description = fmt.Sprintf("The SARIF vulnerability is determined by multiple AI models as True Positive.")
        } else {
            description = fmt.Sprintf("The SARIF vulnerability is determined by multiple AI models as False Positive.")
        }
    } else if povID != ""  {
        description = fmt.Sprintf("SARIF accurately describes vulnerability in POV %s", povID)
    } else if patchID != ""  {
        description = fmt.Sprintf("SARIF accurately describes a vulnerability patched by patchID: %s", patchID)
    }

    assessment := models.SarifAssessmentSubmission{
        Assessment: models.AssessmentCorrect,
        Description: description,
    }
    
    if !isValid {
        assessment.Assessment = models.AssessmentIncorrect
        assessment.Description = fmt.Sprintf("SARIF is false positive. No matches with any POV.")
    }
    
    reqBody, err := json.Marshal(assessment)
    if err != nil {
        return fmt.Errorf("error marshaling assessment: %v", err)
    }
    
    req, err := http.NewRequestWithContext(ctx, "POST", hostAPIURL, bytes.NewBuffer(reqBody))
    if err != nil {
        return fmt.Errorf("error creating request: %v", err)
    }
    
    req.Header = validHeader
    
    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return fmt.Errorf("error sending assessment: %v", err)
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        return fmt.Errorf("non-200 response: %d, body: %s", resp.StatusCode, body)
    }
    
    return nil
}




func analyzeSarifVulnerabilities(sarifData map[string]interface{}) ([]models.Vulnerability, error) {
    var vulnerabilities []models.Vulnerability
    
    // Extract the runs from the SARIF data
    runs, ok := sarifData["runs"].([]interface{})
    if !ok || len(runs) == 0 {
        return nil, fmt.Errorf("no runs found in SARIF data")
    }
    
    // Process each run
    for _, runInterface := range runs {
        run, ok := runInterface.(map[string]interface{})
        if !ok {
            continue
        }
        
        // Extract results from the run
        resultsInterface, ok := run["results"].([]interface{})
        if !ok {
            continue
        }
        
        // Process each result
        for _, resultInterface := range resultsInterface {
            result, ok := resultInterface.(map[string]interface{})
            if !ok {
                continue
            }
            
            // Create a vulnerability from the result
            vuln, err := createVulnerabilityFromResult(result, run)
            if err != nil {
                log.Printf("Error parsing sarif vulnerability: %v", err)
                continue
            }
            
            vulnerabilities = append(vulnerabilities, vuln)
        }
    }
    
    return vulnerabilities, nil
}


func getIntFromInterface(val interface{}) int {
	switch v := val.(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		i, _ := strconv.Atoi(v)
		return i
	default:
		return 0
	}
}

// createVulnerabilityFromResult creates a Vulnerability object from a SARIF result
func createVulnerabilityFromResult(result map[string]interface{}, run map[string]interface{}) (models.Vulnerability, error) {
	var vuln models.Vulnerability

	// Extract rule ID
	if ruleID, ok := result["ruleId"].(string); ok {
		vuln.RuleID = ruleID
	} else {
		return vuln, fmt.Errorf("missing ruleId in result")
	}

	// Extract message
	if messageObj, ok := result["message"].(map[string]interface{}); ok {
		if text, ok := messageObj["text"].(string); ok {
			vuln.Description = text
		}
	}

	// Extract severity level
	if level, ok := result["level"].(string); ok {
		vuln.Severity = level
	}

	// Extract location information
	if locationsInterface, ok := result["locations"].([]interface{}); ok && len(locationsInterface) > 0 {
		if locationObj, ok := locationsInterface[0].(map[string]interface{}); ok {
			if physicalLocation, ok := locationObj["physicalLocation"].(map[string]interface{}); ok {
				// Extract artifact location
				if artifactLocation, ok := physicalLocation["artifactLocation"].(map[string]interface{}); ok {
					if uri, ok := artifactLocation["uri"].(string); ok {
						vuln.Location.FilePath = uri
					}
				}
				// Extract region information
				if region, ok := physicalLocation["region"].(map[string]interface{}); ok {
					startLine := getIntFromInterface(region["startLine"])
					endLine := getIntFromInterface(region["endLine"])
					startCol := getIntFromInterface(region["startColumn"])
					endCol := getIntFromInterface(region["endColumn"])
					if endLine == 0 {
						endLine = startLine
					}
					if endCol == 0 {
						endCol = startCol
					}
					vuln.Location.StartLine = startLine
					vuln.Location.EndLine = endLine
					vuln.Location.StartCol = startCol
					vuln.Location.EndCol = endCol
				}
			}
		}
	}

	// Extract code flows if available
	if codeFlowsInterface, ok := result["codeFlows"].([]interface{}); ok {
		for _, cfInterface := range codeFlowsInterface {
			cf, ok := cfInterface.(map[string]interface{})
			if !ok {
				continue
			}
			var codeFlow models.CodeFlow
			if threadFlowsInterface, ok := cf["threadFlows"].([]interface{}); ok {
				for _, tfInterface := range threadFlowsInterface {
					tf, ok := tfInterface.(map[string]interface{})
					if !ok {
						continue
					}
					var threadFlow models.ThreadFlow
					if locationsInterface, ok := tf["locations"].([]interface{}); ok {
						for _, locInterface := range locationsInterface {
							loc, ok := locInterface.(map[string]interface{})
							if !ok {
								continue
							}
							var tfloc models.ThreadFlowLocation
							if location, ok := loc["location"].(map[string]interface{}); ok {
								if physicalLocation, ok := location["physicalLocation"].(map[string]interface{}); ok {
									if artifactLocation, ok := physicalLocation["artifactLocation"].(map[string]interface{}); ok {
										if uri, ok := artifactLocation["uri"].(string); ok {
											tfloc.FilePath = uri
										}
									}
									if region, ok := physicalLocation["region"].(map[string]interface{}); ok {
										startLine := getIntFromInterface(region["startLine"])
										endLine := getIntFromInterface(region["endLine"])
										startCol := getIntFromInterface(region["startColumn"])
										endCol := getIntFromInterface(region["endColumn"])
										if endLine == 0 {
											endLine = startLine
										}
										if endCol == 0 {
											endCol = startCol
										}
										tfloc.StartLine = startLine
										tfloc.EndLine = endLine
										tfloc.StartCol = startCol
										tfloc.EndCol = endCol
									}
								}
							}
							if messageObj, ok := loc["message"].(map[string]interface{}); ok {
								if text, ok := messageObj["text"].(string); ok {
									tfloc.Message = text
								}
							}
							threadFlow.Locations = append(threadFlow.Locations, tfloc)
						}
					}
					codeFlow.ThreadFlows = append(codeFlow.ThreadFlows, threadFlow)
				}
			}
			vuln.CodeFlows = append(vuln.CodeFlows, codeFlow)
		}
	}

	return vuln, nil
}

// CheckPOVDescriptionAccuracy checks if a SARIF broadcast accurately describes a POV
func (h *Handler) CheckPOVDescriptionAccuracy(pov models.POVSubmission, broadcast models.SARIFBroadcastDetail) (bool, error) {
    // This would be a complex implementation that compares SARIF rules and results 
    // against the actual vulnerability in the POV
    
    // log.Printf("Sarif CheckPOVDescriptionAccuracy pov: %v\nbroadcast: %v\n",pov,broadcast) 

    // Extract SARIF data - handle different types that might be in the interface{}
    var sarifData map[string]interface{}
    
    switch v := broadcast.SARIF.(type) {
    case map[string]interface{}:
        sarifData = v
    case string:
        if err := json.Unmarshal([]byte(v), &sarifData); err != nil {
            return false, fmt.Errorf("error parsing SARIF JSON string: %v", err)
        }
    default:
        jsonBytes, err := json.Marshal(broadcast.SARIF)
        if err != nil {
            return false, fmt.Errorf("error marshaling SARIF data: %v", err)
        }
        if err := json.Unmarshal(jsonBytes, &sarifData); err != nil {
            return false, fmt.Errorf("error unmarshaling SARIF data: %v", err)
        }
    }
    
    // Get results from SARIF
    resultsArr, ok := sarifData["runs"].([]interface{})
    if !ok || len(resultsArr) == 0 {
        return false, fmt.Errorf("invalid SARIF format: missing or empty 'runs' array")
    }

    vulnerabilities, err := analyzeSarifVulnerabilities(sarifData)
    if err != nil {
        fmt.Printf("Error in analyzeSarifVulnerabilities: %v\n", err)
        return false, err
    }
    sarif_vul_desc := extractVulnerabilityDetailDescription(vulnerabilities)
    fmt.Printf("SARIF VULNERABILITY DETAIL:\n%v\n", sarif_vul_desc)
    
    // For basic implementation, check if the SARIF mentions the signature or fuzzer name
    for _, run := range resultsArr {
        runMap, ok := run.(map[string]interface{})
        if !ok {
            continue
        }
        
        results, ok := runMap["results"].([]interface{})
        if !ok {
            continue
        }
        
        for _, result := range results {
            resultMap, ok := result.(map[string]interface{})
            if !ok {
                continue
            }
            
            // Check if this result matches the POV signature
            if matchesPOV(resultMap, sarif_vul_desc, pov) {
                return true, nil
            }
        }
    }
    
    return false, nil
}

func extractVulnerabilityDetailDescription(vulnerabilities []models.Vulnerability) string {
    var sb strings.Builder

    for _, vuln := range vulnerabilities {
        sb.WriteString(fmt.Sprintf("  - Rule ID: %s\n", vuln.RuleID))
        sb.WriteString(fmt.Sprintf("  - Description: %s\n", vuln.Description))
        sb.WriteString(fmt.Sprintf("  - Severity: %s\n", vuln.Severity))

        if vuln.Location.StartLine > 0 || vuln.Location.EndLine > 0 || vuln.Location.StartCol > 0 || vuln.Location.EndCol > 0 {
            sb.WriteString(fmt.Sprintf("  - Location: %s (lines %d-%d, columns %d-%d)\n",
                vuln.Location.FilePath,
                vuln.Location.StartLine,
                vuln.Location.EndLine,
                vuln.Location.StartCol,
                vuln.Location.EndCol,
            ))
        } else {
            sb.WriteString(fmt.Sprintf("  - Location: %s\n", vuln.Location.FilePath))
        }

        // Code flows if available
        if len(vuln.CodeFlows) > 0 {
            sb.WriteString("  - Code Flows:\n")
            for i, flow := range vuln.CodeFlows {
                sb.WriteString(fmt.Sprintf("    - Flow #%d:\n", i+1))
                for j, threadFlow := range flow.ThreadFlows {
                    sb.WriteString(fmt.Sprintf("      - Thread Flow #%d:\n", j+1))
                    for k, loc := range threadFlow.Locations {
                        sb.WriteString(fmt.Sprintf("        - Step %d: %s (lines %d-%d) - %s\n",
                            k+1,
                            loc.FilePath,
                            loc.StartLine,
                            loc.EndLine,
                            loc.Message,
                        ))
                    }
                }
            }
        }
        sb.WriteString("  -----------------------------\n")
    }

    return sb.String()
}

// TODO improve matchesPOV checks if a SARIF result matches a POV's characteristics
// 1. match file path and error location
// 2. match error type
// 3. ask LLM to confirm 
// if all YES, then return "true". otherwise, uncertain
func matchesPOV(result map[string]interface{}, sarif_vul_desc string, pov models.POVSubmission) bool {

    fileMatched := false
    locationExactMatched := false
    // 1. Check locations for file references
    locations, ok := result["locations"].([]interface{})
    if ok {
        for _, loc := range locations {
            locMap, ok := loc.(map[string]interface{})
            if !ok {
                continue
            }
            
            physicalLoc, ok := locMap["physicalLocation"].(map[string]interface{})
            if !ok {
                continue
            }
            
            artifactLocation, ok := physicalLoc["artifactLocation"].(map[string]interface{})
            if !ok {
                continue
            }
            var fileName string
            var startLine string
            var endLine string
            var startColumn string
            {
                uri, ok := artifactLocation["uri"].(string)
                if ok {
                    log.Printf("TODO: matchesPOV uri: %s",uri) 
                    fileName := filepath.Base(uri)
                    if strings.Contains(pov.CrashTrace, fileName) {
                        log.Printf("CrashTrace contains uri: %s",uri) 
                        log.Printf("fileMatched: %v", fileMatched)
                        fileMatched = true
                    }

                }
            }
            region, ok := physicalLoc["region"].(map[string]interface{})
            if ok {
                startLine = getRegionValue(region, "startLine")
                log.Printf("TODO: matchesPOV startLine: %s", startLine)
                endLine = getRegionValue(region, "endLine")
                log.Printf("TODO: matchesPOV endLine: %s", endLine)
                startColumn = getRegionValue(region, "startColumn")
                log.Printf("TODO: matchesPOV startColumn: %s", startColumn)
                
                try_signature_1 := fmt.Sprintf("%s:%s:%s", fileName,startLine,startColumn)
                try_signature_2 := fmt.Sprintf("%s:%s:%s", fileName,endLine,startColumn)
                if strings.Contains(pov.CrashTrace, try_signature_1) {
                    locationExactMatched = true
                    break
                } else if strings.Contains(pov.CrashTrace, try_signature_2) {
                    locationExactMatched = true
                    break
                }
            }

        }
    }

    log.Printf("locationExactMatched: %v", locationExactMatched)


    if locationExactMatched || (fileMatched && pov.Strategy == "sarif") {
        return true
    }

    if fileMatched && CheckSarifValidityWithLLM(sarif_vul_desc, pov) {
        return true
    }

    //OTHERS
    {
        // Check rule ID against signature
        ruleID, _ := result["ruleId"].(string)
        // if ruleID != "" && strings.Contains(pov.Signature, ruleID) {
        //     return true
        // }
        log.Printf("TODO: matchesPOV ruleID: %s",ruleID) 
    
        // Check message text for fuzzer name or signature
        message, ok := result["message"].(map[string]interface{})
        if ok {
            if text, ok := message["text"].(string); ok {
                log.Printf("TODO: matchesPOV message text: %s",text) 
            }
        }    
    }

    return false
}

func UpdateLLModels() {
    switch {
        case reflect.DeepEqual(TRY_MODELS,TRY_MODELS_BACKUP1):
            TRY_MODELS = TRY_MODELS_BACKUP2
        case reflect.DeepEqual(TRY_MODELS,TRY_MODELS_BACKUP2):
            TRY_MODELS = TRY_MODELS_BACKUP1  
        default:
            TRY_MODELS = TRY_MODELS_BACKUP1  
    }

    log.Printf("UpdateLLModels: %v",TRY_MODELS) 

}

func CheckSarifValidityWithLLM(sarif_vul_desc string, pov models.POVSubmission) bool {

    prompt := fmt.Sprintf(`
    You are a top expert on software code security. Your task is to determine if the SARIF vulnerability report accurately describes the provided crash (POV).
    
    Instructions:
    - Carefully compare the SARIF vulnerability description and details with the full POV information below.
    - Consider the type of vulnerability, file and line numbers, function names, error messages, sanitizer, fuzzer name, and any other relevant details.
    - If the SARIF report matches the root cause, location, and type of the crash in the POV, it is a true positive.
    - If the SARIF report does not match the crash log, or describes a different issue, it is a false positive.
    
    Respond with exactly "YES VALID SARIF" if the SARIF report is a true positive for this POV.
    Otherwise, explain briefly why it is not a valid match.
    
    SARIF Vulnerability Description:
    %s
    
    POV Submission:
    Architecture: %s
    Engine: %s
    Fuzzer Name: %s
    Sanitizer: %s
    Crash Trace:
    %s
    `, sarif_vul_desc, pov.Architecture, pov.Engine, pov.FuzzerName, pov.Sanitizer, pov.CrashTrace)

    voteCount := 0
    errCount := 0

    var rawMessages []string
	var flaggedBy []string

    for _, model := range TRY_MODELS {
        isValid, raw := callLLMAndCheckSignature(model, prompt, "YES VALID SARIF")
        if isValid {
            voteCount++
            rawMessages = append(rawMessages, fmt.Sprintf("[%s] %s", model, raw))
            flaggedBy = append(flaggedBy, model)
        } else {
            if strings.HasPrefix(raw, "[ERROR]") {
                errCount++
                fmt.Printf(raw)
            } else {
                fmt.Printf("Invalid. raw: %s\n", raw)
            }
        }

        // Optional early exit if we hit required votes
        if voteCount >= 2 {
            break
        }
    }

    // If 2 or more models flagged valid, mark it valid
    if voteCount >= 2 {
        fmt.Printf("Flagged as VALID by %s\n", flaggedBy)
        fmt.Printf("RawMessages: %v\n", rawMessages)
        return true
    }
    if errCount >= 2 {
        //likely we have used all API credits, change TRY_MODELS
        UpdateLLModels()
    }
    return false
}

func extractSarifData(sarifInterface interface{}) (map[string]interface{}, error) {
    sarifData, ok := sarifInterface.(map[string]interface{})
    if !ok {
        return nil, fmt.Errorf("invalid SARIF data format")
    }
    
    return sarifData, nil
}

func buildSarifFalsePositivePrompt(
    sarifDesc string,
    ctxs *[]models.CodeContext,
) string {
    var sb strings.Builder

    sb.WriteString(`
You are a top expert on software code security.

Task
----
Determine whether the SARIF vulnerability report below is a FALSE-POSITIVE
with respect to the referenced source code.  A false-positive means the
SARIF report describes a bug that does NOT actually exist at the cited
location in the code.

How to decide
-------------
1. Read the “SARIF Vulnerability” section.
2. Read the “Relevant Source Code” section(s).
3. Compare:
   • Vulnerability type (e.g. buffer overflow, use-after-free, etc.).
   • File path, function name, line / column numbers.
   • Any stack traces or error messages.
4. If the SARIF details truly match a real bug in the code, the report is
   a TRUE positive.
5. Pay attention to SARIF details, such as the cited bug type and bug location. If the SARIF details do NOT match the code (wrong location, wrong bug
   type, no bug visible, etc.), the report is a FALSE positive.

Response format
---------------
•  If the SARIF report is a FALSE positive, respond with EXACTLY:
   YES INVALID SARIF
•  Otherwise, briefly explain why it may not a false positive.

SARIF Vulnerability
-------------------
` + sarifDesc + "\n\n")

    sb.WriteString("Relevant Source Code\n--------------------\n")
    for i, c := range *ctxs {
        sb.WriteString(fmt.Sprintf("Snippet %d\n", i+1))
        sb.WriteString(fmt.Sprintf("File: %s\n", c.File))
        if c.Func != "" {
            sb.WriteString(fmt.Sprintf("Function: %s\n", c.Func))
        }
        sb.WriteString("-------------------- CODE --------------------\n")
        sb.WriteString(c.Snip)
        sb.WriteString("\n----------------------------------------------\n\n")
    }
    return sb.String()
}


func CheckSarifFalsePositive(taskID string, ctxs *[]models.CodeContext, broadcast *models.SARIFBroadcastDetail) (int, error) {

    //return code
    //0: error
    //1: false positive
    //2: true positive
    sarifData, err := extractSarifData(broadcast.SARIF)
    if err != nil {
        return 0, fmt.Errorf("failed to extract SARIF data: %w", err)
    }

    vulnerabilities, err := analyzeSarifVulnerabilities(sarifData)
    if err != nil {
        fmt.Printf("Error in analyzeSarifVulnerabilities: %v\n", err)
        return 0, err
    }
    sarifDesc := extractVulnerabilityDetailDescription(vulnerabilities)
    fmt.Printf("SARIF VULNERABILITY DETAIL:\n%v\n", sarifDesc)

    prompt := buildSarifFalsePositivePrompt(sarifDesc, ctxs)
    fmt.Printf("callLLMAndCheckSignature TRY_MODELS: %v, prompt: %v\n",TRY_MODELS, prompt)

    // Channel to signal if any model says the SARIF is potentially valid
    // validFound := make(chan struct {
    //     model string
    //     raw   string
    // }, 1)
    
    // Wait group to track when all goroutines are finished
    var wg sync.WaitGroup
    validCount := 0 
    invalidCount :=0
    errCount := 0
    // Run all checks in parallel
    for _, model := range TRY_MODELS {
        wg.Add(1)
        go func(m string) {
            defer wg.Done()
            
            isInvalid, raw := callLLMAndCheckSignature(m, prompt, "YES INVALID SARIF")
            log.Printf("Model %s result: %v %s", m, isInvalid, raw)
            if strings.HasPrefix(raw,"[ERROR]") {
                errCount = errCount + 1
                log.Printf("Skipping model %s due to error: %s", m, raw)
                return
            } else if isInvalid == false {
                validCount = validCount +1
                //the sarif is true positive
                // Try to send non-blocking (we only need one "valid" result)
                // select {
                //     case validFound <- struct {
                //         model string
                //         raw   string
                //     }{m, raw}:
                //     default:
                //         // Channel already has a message, that's fine
                //     }
            } else {
                invalidCount = invalidCount + 1
                //yes, the sarif is false positive
            }
        }(model)
    }
    
    wg.Wait() 
    {
        // Some model found it potentially valid
        if validCount + errCount == len(TRY_MODELS) && validCount > 1{
            //valid sarif!
            fmt.Printf("True Positive SARIF determined by all models!\n")
            return 2, nil
        } else {
            fmt.Printf("Potentially Valid. validCount: %d invalidCount: %d errCount: %d\n", validCount, invalidCount, errCount)
            return 0, nil
        } 
        if errCount >=2 {
            UpdateLLModels()
        }
    }

    // No model found it valid (all said it's invalid)
    fmt.Printf("False Positive SARIF flagged by multiple models: %d\n",invalidCount)
    return 1, nil
}

var (
    CLAUDE_OPUS_MODEL          = "claude-opus-4-20250514"
    CLAUDE_SONNET_4_MODEL          = "claude-sonnet-4-20250514"
	CLAUDE_MODEL          = "claude-3-7-sonnet-20250219"
	OPENAI_MODEL          = "chatgpt-4o-latest"
	GEMINI_MODEL_PRO_25   = "gemini-2.5-pro"
    GEMINI_MODEL_FLASH   = "gemini-2.5-flash"
    OPENAI_MODEL_O3 = "o3"
    GROK_MODEL = "grok-3-beta"

)
var (
	// LLM model list
	TRY_MODELS = []string{
        OPENAI_MODEL_O3,
        GEMINI_MODEL_PRO_25,
        CLAUDE_OPUS_MODEL,
	}

    TRY_MODELS_BACKUP1 = []string{
        OPENAI_MODEL_O3,
		OPENAI_MODEL,
		GEMINI_MODEL_PRO_25,
	}

    TRY_MODELS_BACKUP2 = []string{
        GEMINI_MODEL_PRO_25,
		GEMINI_MODEL_FLASH,
        GROK_MODEL,
	}
)

func callGeminiAPI(prompt, modelName, apiKey, signature0 string)  (bool, string) {

    // Create a new Gemini API client
    ctx := context.Background()
    client, err := genai.NewClient(ctx, &genai.ClientConfig{
        APIKey:  apiKey,
        Backend: genai.BackendGeminiAPI,
    })
    if err != nil {
        errMsg := fmt.Sprintf("[ERROR] creating client: %v", err)
        fmt.Println(errMsg)
        return false, errMsg
    }

    // Generate text using the gemini-2.0-flash model
    response, err := client.Models.GenerateContent(ctx, modelName, []*genai.Content{{Parts: []*genai.Part{{Text: prompt}}}}, nil)
    if err != nil {
        errMsg := fmt.Sprintf("[ERROR] generating content: %v", err)
        fmt.Println(errMsg)
        return false, errMsg
    }

    responseText := response.Text()
    // Print the generated text
    fmt.Println(responseText)

    if strings.Contains(strings.ToUpper(responseText), signature0) {
		return true, responseText
	}

	return false, responseText
}
func callLLMAndCheckSignature(modelName,prompt string, signature0 string) (bool, string) {

	var client = &http.Client{}
	var body []byte
	var req *http.Request
	var resp *http.Response
	var err error
    
	lowerName := strings.ToLower(modelName)

	// Prepare request body based on the model
	switch {
	case strings.HasPrefix(lowerName, "chatgpt-") || strings.HasPrefix(lowerName, "o"):
		apiKey := os.Getenv("OPENAI_API_KEY")
		if apiKey == "" {
			return false, "Missing OPENAI_API_KEY"
		}
		payload := map[string]interface{}{
			"model": modelName,
			"messages": []map[string]string{
				{"role": "user", "content": prompt},
			},
		}
		body, _ = json.Marshal(payload)
		req, err = http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+apiKey)

	case strings.HasPrefix(lowerName, "claude-"):
		apiKey := os.Getenv("ANTHROPIC_API_KEY")
		if apiKey == "" {
			return false, "Missing ANTHROPIC_API_KEY"
		}
		payload := map[string]interface{}{
			"model":      modelName,
            "max_tokens": 1024,
            "messages": []map[string]string{
                {"role": "user", "content": prompt},
            },
		}
		body, _ = json.Marshal(payload)
        req, err = http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-api-key", apiKey)
		req.Header.Set("anthropic-version", "2023-06-01")

	case strings.HasPrefix(lowerName, "grok-"):
		apiKey := os.Getenv("XAI_API_KEY")
		if apiKey == "" {
			return false, "Missing XAI_API_KEY"
		}
		payload := map[string]interface{}{
			"model":      modelName,
            "max_tokens": 1024,
            "messages": []map[string]string{
                {"role": "user", "content": prompt},
            },
		}
		body, _ = json.Marshal(payload)
        req, err = http.NewRequest("POST", "https://api.x.ai/v1/messages", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-api-key", apiKey)

	case strings.HasPrefix(lowerName, "gemini-"):
		apiKey := os.Getenv("GEMINI_API_KEY")
		if apiKey == "" {
			return false, "Missing GEMINI_API_KEY"
		}
        if true {
            return callGeminiAPI(prompt, modelName, apiKey, signature0)
        }
		url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s",modelName, apiKey)
		payload := map[string]interface{}{
			"contents": []map[string]interface{}{
				{
					"parts": []map[string]string{
						{"text": prompt},
					},
				},
			},
		}
		body, _ = json.Marshal(payload)
		req, err = http.NewRequest("POST", url, bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")

	default:
		return false, "[ERROR] Unsupported model: " + modelName
	}

	if err != nil {
		return false, "[ERROR] Failed to create request: " + err.Error()
	}

	// Retry logic (up to 3 times)
	var respBody []byte
	for attempt := 1; attempt <= 3; attempt++ {
		resp, err = client.Do(req)
		if err != nil {
			if attempt == 3 {
				return false, fmt.Sprintf("[ERROR] HTTP request failed after 3 attempts: %v", err)
			}
			time.Sleep(time.Duration(attempt) * time.Second)
			continue
		}
		defer resp.Body.Close()

		respBody, err = io.ReadAll(resp.Body)
		if err != nil {
			if attempt == 3 {
				return false, fmt.Sprintf("[ERROR] Failed to read response after 3 attempts: %v", err)
			}
			time.Sleep(time.Duration(attempt) * time.Second)
			continue
		}

		// Retry if HTTP status indicates rate limiting or server error
		if resp.StatusCode >= 500 || resp.StatusCode == 429 {
			if attempt == 3 {
				return false, fmt.Sprintf("[ERROR] LLM returned error after 3 retries (status %d): %s", resp.StatusCode, string(respBody))
			}
			time.Sleep(time.Duration(attempt) * time.Second)
			continue
		}

		break // success
	}

	respStr := string(respBody)
    response_error := false

    // if 	strings.HasPrefix(modelName, "grok-") {
	// fmt.Println(prompt)
	// fmt.Println(respStr)
	// }

    // Extract the actual text content based on model type
    var responseText string

	switch {
	case strings.HasPrefix(lowerName, "chatgpt-") || strings.HasPrefix(lowerName, "o"):
		// Parse OpenAI response format
		var openaiResp struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		}
		if err := json.Unmarshal(respBody, &openaiResp); err == nil && len(openaiResp.Choices) > 0 {
			responseText = openaiResp.Choices[0].Message.Content
		} else {
            response_error = true
			responseText = respStr // Fallback to raw response
		}
	
	case strings.HasPrefix(lowerName, "claude-"):
		// Parse Anthropic response format
		var anthropicResp struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		}
		if err := json.Unmarshal(respBody, &anthropicResp); err == nil && len(anthropicResp.Content) > 0 {
			responseText = anthropicResp.Content[0].Text
		} else {
            response_error = true
            responseText = respStr // Fallback to raw response
		}
        // fmt.Printf("model %s responseText %s: respStr: %q", lowerName, responseText, respStr)
	
	case strings.HasPrefix(lowerName, "grok-"):
		// Parse Anthropic response format
		var grokResp struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		}
		if err := json.Unmarshal(respBody, &grokResp); err == nil && len(grokResp.Content) > 0 {
			responseText = grokResp.Content[0].Text
		} else {
            response_error = true
            responseText = respStr // Fallback to raw response
		}
        // fmt.Printf("model %s responseText %s: respStr: %q", lowerName, responseText, respStr)

    case strings.HasPrefix(lowerName, "gemini-"):
        // Parse Gemini response format
        var geminiResp struct {
            Candidates []struct {
                Content struct {
                    Parts []struct {
                        Text string `json:"text"`
                    } `json:"parts"`
                } `json:"content"`
            } `json:"candidates"`
        }
        if err := json.Unmarshal(respBody, &geminiResp); err == nil && 
        len(geminiResp.Candidates) > 0 && 
        len(geminiResp.Candidates[0].Content.Parts) > 0 {
            responseText = geminiResp.Candidates[0].Content.Parts[0].Text
        } else {
            response_error = true
            responseText = respStr // Fallback to raw response
        }

    default:
        responseText = respStr
    }


	if strings.Contains(strings.ToUpper(respStr), signature0) {
		return true, responseText
	}
    if response_error {
        responseText = "[ERROR] "+ responseText
    }
	return false, responseText
}


func getRegionValue(region map[string]interface{}, key string) string {
    if v, ok := region[key]; ok {
        switch val := v.(type) {
        case string:
            return val
        case float64:
            return fmt.Sprintf("%.0f", val)
        case int:
            return fmt.Sprintf("%d", val)
        }
    }
    return ""
}


const (
	redundantMarker = "YES REDUNDANT"
	differentMarker = "DIFFERENT"
	maxLLMAttempts  = 2              // hard-stop even if TRY_MODELS is longer
)

func (h *Handler) compareCrashTraces(trace1, trace2 string) (bool, error) {
	// Normalise the traces to avoid trivial LLM mismatches
	norm := func(s string) string {
		return strings.TrimSpace(strings.ReplaceAll(s, "\r\n", "\n"))
	}

	prompt := fmt.Sprintf(
		`You are a top expert on software code security and OSS-Fuzz.
Please decide whether the two crash reports describe the SAME underlying vulnerability.
If they do, reply with exactly %q (without extra words).
Otherwise reply with exactly %q.

===== CRASH REPORT 1 =====
%s


===== CRASH REPORT 2 =====
%s
`, redundantMarker, differentMarker, norm(trace1), norm(trace2))

	attempts := 0
    errCount := 0
	for _, model := range TRY_MODELS {
		isRedundant, raw := callLLMAndCheckSignature(model, prompt, redundantMarker)
		
        if strings.HasPrefix(raw,"[ERROR]"){
            errCount++
            continue
        } 

        attempts++
        if attempts >= maxLLMAttempts {
			break
		}
        rawLower := strings.ToLower(raw)

		switch {
		case isRedundant:
			return true, nil

		case strings.Contains(rawLower, strings.ToLower(differentMarker)):
			return false, nil

		// Retry on well-known transient errors
		case strings.Contains(rawLower, "rate limit"),
            strings.Contains(rawLower, "usage limit"),
			strings.Contains(rawLower, "too many requests"),
			strings.Contains(rawLower, "overloaded"),
            strings.Contains(raw, "Bad Request"),
            strings.Contains(raw, "RESOURCE_EXHAUSTED"):
            
			continue

		default:
			// Any other unexpected reply → treat as "different" but return an error so caller can decide.
			return false, fmt.Errorf("unexpected LLM response from %s: %q", model, raw)
		}
	}

    if errCount >= 2 {
        UpdateLLModels()
    }

	// All attempts exhausted without a clear YES/DIFFERENT
	return false, fmt.Errorf("could not determine redundancy after %d attempts", attempts)
}

// compareCrashTraces uses Claude 3.7 to determine if two crash traces represent the same vulnerability
func (h *Handler) compareCrashTraces0(trace1, trace2 string) (bool, error) {
    // Get API key from environment
    apiKey := os.Getenv("ANTHROPIC_API_KEY")
    if apiKey == "" {
        return false, fmt.Errorf("ANTHROPIC_API_KEY not set")
    }

    // Prepare the request to Claude API
    type Message struct {
        Role    string `json:"role"`
        Content string `json:"content"`
    }

    type Request struct {
        Model     string    `json:"model"`
        Messages  []Message `json:"messages"`
        MaxTokens int       `json:"max_tokens"`
    }

    prompt := fmt.Sprintf(`do the following two sanitizer reports indicate the same underlying vulnerability? if yes, return "YES". otherwise, return "NO".

======CRASH LOG1=========
%s

======CRASH LOG2=========
%s`, trace1, trace2)

    reqBody := Request{
        Model: "claude-3-7-sonnet-latest",
        Messages: []Message{
            {
                Role:    "user",
                Content: prompt,
            },
        },
        MaxTokens: 100,
    }

    reqJSON, err := json.Marshal(reqBody)
    if err != nil {
        return false, fmt.Errorf("error marshaling request: %v", err)
    }

    // Log the request for debugging (pretty-printed)
reqJSONPretty, _ := json.MarshalIndent(reqBody, "", "  ")
log.Printf("Request to Claude API:\n%s", string(reqJSONPretty))


    // Send request to Claude API
    req, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewBuffer(reqJSON))
    if err != nil {
        return false, fmt.Errorf("error creating request: %v", err)
    }

    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("x-api-key", apiKey)
    req.Header.Set("anthropic-version", "2023-06-01")

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        return false, fmt.Errorf("error sending request: %v", err)
    }
    defer resp.Body.Close()

    {
        // Log response status
// log.Printf("Response status: %s", resp.Status)

// Read the response body
respBody, err := io.ReadAll(resp.Body)
if err != nil {
    return false, fmt.Errorf("error reading response: %v", err)
}

// Pretty print the JSON response for debugging
var prettyJSON bytes.Buffer
if err := json.Indent(&prettyJSON, respBody, "", "  "); err != nil {
    log.Printf("Raw response (not valid JSON): %s", string(respBody))
} else {
    // log.Printf("Response from Claude API:\n%s", prettyJSON.String())
}

// Restore the response body for further processing
resp.Body = io.NopCloser(bytes.NewBuffer(respBody))

    }
    // Parse response
    type Content struct {
        Type  string `json:"type"`
        Text  string `json:"text"`
    }

    type Response struct {
        Content []Content `json:"content"`
    }

    var result map[string]interface{}
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return false, fmt.Errorf("error decoding response: %v", err)
    }

    // Extract the response text
    contentList, ok := result["content"].([]interface{})
    if !ok || len(contentList) == 0 {
        return false, fmt.Errorf("unexpected response format")
    }

    content, ok := contentList[0].(map[string]interface{})
    if !ok {
        return false, fmt.Errorf("unexpected content format")
    }

    text, ok := content["text"].(string)
    if !ok {
        return false, fmt.Errorf("text not found in response")
    }

    // Check if the response indicates the traces are the same
    return strings.Contains(text, "YES"), nil
}

func (h *Handler) CheckSarifValidity(c *gin.Context) {
    taskID := c.Param("task_id")
    sarifID := c.Param("broadcast_sarif_id")

    log.Printf("Checking validity of SARIF %s for task %s", sarifID, taskID)

    // Parse the SARIF broadcast from the request body
    var broadcast models.SARIFBroadcastDetail
    if err := c.ShouldBindJSON(&broadcast); err != nil {
        log.Printf("Error parsing SARIF broadcast: %v", err)
        c.JSON(http.StatusBadRequest, models.Error{Message: fmt.Sprintf("Invalid request format: %v", err)})
        return
    }

    // Verify the SARIF ID in URL matches the one in the request body
    if broadcast.SarifID.String() != sarifID {
        log.Printf("SARIF ID mismatch: URL=%s, Body=%s", sarifID, broadcast.SarifID)
        c.JSON(http.StatusBadRequest, models.Error{Message: "SARIF ID in URL doesn't match the one in request body"})
        return
    }

    isValid := false

    // FOR TESTING ONLY
    if os.Getenv("SARIF_VALIDITY_TEST") != "" {
        if povSliceAny, ok := h.receivedPovSubmissions.Load(taskID); ok {
            povSlice := povSliceAny.([]models.POVSubmission)
            for _, submission := range povSlice {
                isAccurate, err := h.CheckPOVDescriptionAccuracy(submission, broadcast)
                if err != nil {
                    log.Printf("Error checking accuracy of SARIF %s against POV %s: %v", sarifID, submission.POVID, err)
                } else {
                    log.Printf("isAccurate: %v", isAccurate)
                }
            }
        }
    }

    // Check if we've already processed this SARIF
    if val, ok := h.processedSarifs.Load(sarifID); ok && val.(bool) {
        isValid = true
        log.Printf("SARIF %s was previously validated for task %s", sarifID, taskID)
    } else {
        ctx := c.Request.Context()

        // Check each POV for this task
        if taskMapAny, ok := h.tasks.Load(taskID); ok {
            taskMap := taskMapAny.(*sync.Map)
            var foundPOVID string
            taskMap.Range(func(_, vAny interface{}) bool {
                if resp, ok := vAny.(models.POVSubmissionResponse); ok {
                    foundPOVID = resp.POVID
                    // Skip if no POV ID
                    if foundPOVID == "" {
                        return true // continue
                    }
                    // Get POV status from host API
                    povStatus, err := h.getPOVStatus(ctx, taskID, foundPOVID, c.Request.Header)
                    if err != nil {
                        log.Printf("Error checking POV status for task %s, POV %s: %v", taskID, foundPOVID, err)
                        return true // continue
                    }
                    // Only consider POVs in "passed" or "accept" state
                    if povStatus != nil && (povStatus.Status == models.SubmissionStatusPassed || povStatus.Status == models.SubmissionStatusAccepted) {
                        log.Printf("Checking SARIF against passed/accepted POV %s", foundPOVID)
                        // Get POV details from h.povSubmissions map
                        if submissionAny, exists := h.povSubmissions.Load(foundPOVID); exists {
                            submission := submissionAny.(models.POVSubmission)
                            isAccurate, err := h.CheckPOVDescriptionAccuracy(submission, broadcast)
                            if err != nil {
                                log.Printf("Error checking accuracy of SARIF %s against POV %s: %v", sarifID, foundPOVID, err)
                                return true // continue
                            }
                            if isAccurate {
                                log.Printf("SARIF %s accurately describes POV %s", sarifID, foundPOVID)
                                
                                if done, ok := h.processedSarifs.Load(sarifID); ok && done.(bool) {
                                    log.Printf("SARIF %s already processed!", sarifID)
                                } else {
                                    // Submit SARIF assessment asynchronously
                                    go func(taskID, sarifID, povID string) {
                                        maxRetries := 3
                                        for attempt := 0; attempt < maxRetries; attempt++ {
                                            err := h.submitSarifAssessment(context.Background(), taskID, sarifID, povID,"", true, c.Request.Header)
                                            if err == nil {
                                                log.Printf("Successfully submitted valid SARIF assessment for task %s (SARIF %s, POV %s)", taskID, sarifID, povID)
                                                break
                                            }
                                            log.Printf("Error submitting SARIF assessment (attempt %d/%d): %v", attempt+1, maxRetries, err)
                                            if attempt < maxRetries-1 {
                                                time.Sleep(2 * time.Second)
                                            }
                                        }
                                    }(taskID, sarifID, foundPOVID)
                                }
                                // valid sarif found! let's create bundle for (povID,sarifID)
                                go h.tryCreateBundle(taskID, foundPOVID, sarifID, "", "", c)
                                isValid = true
                                h.processedSarifs.Store(sarifID, true)
                                return false // break
                            }
                        } else {
                            log.Printf("Warning: POV %s passed/accepted but no submission details found", foundPOVID)
                        }
                    } else {
                        statusText := "unknown"
                        if povStatus != nil {
                            statusText = string(povStatus.Status)
                        }
                        log.Printf("POV %s not passed for task %s: status=%s", foundPOVID, taskID, statusText)
                    }
                }
                return true // continue
            })
        }
    }

    // Prepare response
    response := models.SarifValidResponse{
        SarifID: sarifID,
        IsValid: isValid,
    }

    log.Printf("Sarif validity results: %v", response)
    c.JSON(http.StatusOK, response)
}

func (h *Handler) CheckSarifInValidity(c *gin.Context) {
    taskID := c.Param("task_id")
    sarifID := c.Param("broadcast_sarif_id")

    log.Printf("Checking invalidity of SARIF %s for task %s", sarifID, taskID)

    // Create a struct to parse both broadcast and contexts
    var payload struct {
        Broadcast models.SARIFBroadcastDetail `json:"broadcast"`
        Contexts  []models.CodeContext        `json:"contexts"`
    }

    // Parse the payload from the request body
    if err := c.ShouldBindJSON(&payload); err != nil {
        log.Printf("Error parsing payload: %v", err)
        c.JSON(http.StatusBadRequest, models.Error{Message: fmt.Sprintf("Invalid request format: %v", err)})
        return
    }

    // Extract the broadcast and contexts
    broadcast := payload.Broadcast
    ctxs := payload.Contexts

    isInvalid := 0
    // Check if we've already processed this SARIF
    if val, ok := h.processedSarifs.Load(sarifID); ok && val.(bool) {
        log.Printf("SARIF %s was previously invalidated for task %s", sarifID, taskID)
    } else {
        // Check if SARIF accurately describes the POV
        isTrueOrFalsePositive, err := CheckSarifFalsePositive(taskID, &ctxs, &broadcast)
        if err != nil {
            log.Printf("Error CheckSarifFalsePositive of SARIF %s: %v", sarifID, err)
        }
        if isTrueOrFalsePositive > 0 {
            isInvalid = isTrueOrFalsePositive
            var isValidSarif bool 
            if isTrueOrFalsePositive == 1 {
                isValidSarif = false
                log.Printf("SARIF %s is determined by all LLMs to be a false positive!", sarifID)
            } else {
                isValidSarif = true
                log.Printf("SARIF %s is determined by all LLMs to be a true positive!", sarifID)
            }
            // Submit SARIF assessment asynchronously
            go func(taskID, sarifID string) {
                maxRetries := 3
                for attempt := 0; attempt < maxRetries; attempt++ {
                    err := h.submitSarifAssessment(context.Background(), taskID, sarifID, "", "", isValidSarif, c.Request.Header)
                    if err == nil {
                        log.Printf("Successfully submitted SARIF assessment for task %s (SARIF %s) isValidSarif: %v", taskID, sarifID, isValidSarif)
                        break
                    }
                    log.Printf("Error submitting SARIF assessment (attempt %d/%d): %v", attempt+1, maxRetries, err)
                    if attempt < maxRetries-1 {
                        time.Sleep(2 * time.Second)
                    }
                }
            }(taskID, sarifID)
            h.processedSarifs.Store(sarifID, true)
        }
    }

    // Prepare response
    response := models.SarifInValidResponse{
        SarifID:  sarifID,
        IsInvalid: isInvalid,
    }

    log.Printf("Sarif invalidity results: %v", response)
    c.JSON(http.StatusOK, response)
}

func (h *Handler) SubmitSarifInvalid(c *gin.Context) {
    taskID := c.Param("task_id")
    sarifID := c.Param("broadcast_sarif_id")

    // If already processed, return early
    if val, ok := h.processedSarifs.Load(sarifID); ok && val.(bool) {
        log.Printf("SARIF %s for task %s already processed as invalid", sarifID, taskID)
        response := models.SarifInValidResponse{
            SarifID:  sarifID,
            IsInvalid: 1,
        }
        c.JSON(http.StatusOK, response)
        return
    }

    // Submit the invalid SARIF assessment
    err := h.submitSarifAssessment(context.Background(), taskID, sarifID, "", "", false, c.Request.Header)
    if err != nil {
        log.Printf("Error submitting SARIF assessment: %v", err)
        c.JSON(http.StatusInternalServerError, models.Error{Message: "Error submitting SARIF assessment"})
        return
    }

    log.Printf("Successfully submitted invalid SARIF assessment for task %s (SARIF %s)", taskID, sarifID)
    response := models.SarifInValidResponse{
        SarifID:  sarifID,
        IsInvalid: 1,
    }
    c.JSON(http.StatusOK, response)
    h.processedSarifs.Store(sarifID, true)
}


func saveTaskDetailToJson(taskDetail models.TaskDetail) error {
    
    filePath := filepath.Join("/app", fmt.Sprintf("task_detail_%s.json", taskDetail.TaskID))

    // Marshal the taskDetail struct to JSON with indentation for readability
    jsonData, err := json.MarshalIndent(taskDetail, "", "  ")
    if err != nil {
    return fmt.Errorf("failed to marshal task detail: %v", err)
    }

    // Write the JSON data to the file
    err = os.WriteFile(filePath, jsonData, 0644)
    if err != nil {
    // Try with sudo if regular write fails
    if os.IsPermission(err) {
        tempFileName := fmt.Sprintf("/tmp/task_detail_%s.json", taskDetail.TaskID)
        if tempErr := os.WriteFile(tempFileName, jsonData, 0644); tempErr != nil {
            return fmt.Errorf("failed to write temporary file: %v", tempErr)
        }
        
        cmd := exec.Command("sudo", "cp", tempFileName, filePath)
        if cpErr := cmd.Run(); cpErr != nil {
            return fmt.Errorf("failed to copy file with sudo: %v", cpErr)
        }
        
        chmodCmd := exec.Command("sudo", "chmod", "0644", filePath)
        if chmodErr := chmodCmd.Run(); chmodErr != nil {
            log.Printf("Warning: failed to set file permissions: %v", chmodErr)
        }
        
        os.Remove(tempFileName)
    } else {
        return fmt.Errorf("failed to write task detail to file: %v", err)
    }
    }

    log.Printf("Successfully saved task detail to %s", filePath)
    return nil
}

// finalizeBundle is invoked ~30 min before the task’s deadline.
// It makes sure that
//   • every SARIF broadcast has been assessed,
//   • every canonical-signature group has a *valid* bundle,
//   • every invalid bundle is removed.
func (h *Handler) finalizeBundle(taskID string, hdr http.Header) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()

    log.Printf("[finalizeBundle] BEGIN task %s", taskID)

    log.Printf("[DEBUG] sarifs: %v processedSarifs: %v",h.sarifs,h.processedSarifs)

	//--------------------------------------------------------------------
	// 1. Mark every still-unprocessed SARIF as “invalid”
	//--------------------------------------------------------------------
	if sarifsAny, ok := h.sarifs.Load(taskID); ok {
		for _, bc := range sarifsAny.([]models.SARIFBroadcastDetail) {
			sid := bc.SarifID.String()
            log.Printf("[DEBUG] sid: %s", sid)
			if done, ok := h.processedSarifs.Load(sid); ok && done.(bool) {
				continue // already handled
			}
            log.Printf("[submitSarifAssessment] false sid: %s", sid)

			go func(id string) {
				const retries = 3
				for i := 0; i < retries; i++ {
					if err := h.submitSarifAssessment(ctx, taskID, id, "","", false, hdr); err == nil {
						h.processedSarifs.Store(id, true)
						return
					} else {
                        log.Printf("Error submitting SARIF assessment (retries=%d): %v",retries, err)
                    }
					time.Sleep(2 * time.Second)
				}
			}(sid)
		}
	}

	//--------------------------------------------------------------------
	// 2. Build one snapshot map with the latest PASS / FAIL state
	//--------------------------------------------------------------------
	type artefacts struct {
		POV, Patch, Sarif string
		povPass, patchPass bool
	}
	byGroup := map[string]*artefacts{}

	// helper: canonical signature for a PoV/Patch signature
	canonOf := func(sig string) string {
		if mAny, ok := h.povSignatureGroups.Load(taskID); ok {
			if canonAny, ok := mAny.(*sync.Map).Load(sig); ok {
				return canonAny.(string)
			}
		}
		return sig
	}

	subAny, _ := h.tasks.LoadOrStore(taskID, &sync.Map{})
	submissions := subAny.(*sync.Map)

	// collect ids
	submissions.Range(func(_, vAny interface{}) bool {
		switch v := vAny.(type) {
		case models.POVSubmissionResponse:
            sig := ""
            if subAny, ok:= h.povSubmissions.Load(v.POVID); ok {
                sig = subAny.(models.POVSubmission).Signature
            }
			canon := canonOf(sig)
			st := byGroup[canon]
			if st == nil { st = &artefacts{}; byGroup[canon] = st }
			st.POV = v.POVID
		case models.PatchSubmissionResponse:
			// canon := canonOf(v.PoVSignature)
			// st := byGroup[canon]
			// if st == nil { st = &artefacts{}; byGroup[canon] = st }
			// st.Patch = v.PatchID

        case models.BundleSubmissionResponseVerbose:

            // ① – figure out the canonical signature of this bundle
            patchCanon := func(pid string) string {
                if pgAny, ok := h.patchByGroup.Load(taskID); ok {
                    var found string
                    pgAny.(*sync.Map).Range(func(k, vv interface{}) bool {
                        switch ids := vv.(type) {
                        case string:
                            if ids == pid { found = k.(string); return false }
                        case []string:
                            for _, id := range ids {
                                if id == pid { found = k.(string); return false }
                            }
                        }
                        return true
                    })
                    return found
                }
                return ""
            }

            canon := canonOf(v.POVID)
            if canon == "" {
                canon = patchCanon(v.PatchID)
            }
            if canon == "" {
                canon = v.BroadcastSarifID // last resort, unique per group
            }

            // ② – remember bundle-ID → canonical mapping
            if grpAny, ok := h.bundleByGroup.Load(taskID); ok {
                grpAny.(*sync.Map).Store(canon, v.BundleID)
            }
            
            st := byGroup[canon]
			if st == nil {
				st = &artefacts{}
				byGroup[canon] = st
			}
			// fill in what we know
			if st.POV == ""   { st.POV   = v.POVID }
			if st.Patch == "" { st.Patch = v.PatchID }
			if st.Sarif == "" { st.Sarif = v.BroadcastSarifID }
		}
		return true
	})

	// second pass – add patches from patchByGroup ----------------
	if pgAny, ok := h.patchByGroup.Load(taskID); ok {
		pgAny.(*sync.Map).Range(func(k, v interface{}) bool {
			canon := k.(string)
            var ids []string
            switch vv := v.(type) {
            case string:
                ids = []string{vv}
            case []string:
                ids = vv
            default:
                return true
            }
            if len(ids) == 0 {
                return true
            }
			patchID := ids[len(ids)-1]
			st := byGroup[canon]
			if st == nil {
				st = &artefacts{}
				byGroup[canon] = st
			}
			st.Patch = patchID
			return true
		})
	}

	// poll host-API once per artefact
	for grp, st := range byGroup {
		if st.POV != "" {
			if s, _ := h.getPOVStatus(ctx, taskID, st.POV, hdr); s != nil {
                log.Printf("[DEBUG] finalizeBundle] POV status: %v", s)
				st.povPass = (s.Status == models.SubmissionStatusPassed)
			}
		}
		if st.Patch != "" {
			if s, _ := h.getPatchStatus(ctx, taskID, st.Patch, hdr); s != nil {
                log.Printf("[DEBUG] finalizeBundle] Patch status: %v", s)
				st.patchPass = s.Status == string(models.SubmissionStatusPassed)
			}
		}
		// SARIF → already validated when we stored processedSarifs
        log.Printf("[finalizeBundle] group=%s pov=%s(pass=%t) patch=%s(pass=%t) sarif=%s", grp, st.POV, st.povPass, st.Patch, st.patchPass, st.Sarif)
	}

	//--------------------------------------------------------------------
	// 3. Validate / delete existing bundles, then create the missing ones
	//--------------------------------------------------------------------
	bundleMapAny, _ := h.bundleByGroup.LoadOrStore(taskID, &sync.Map{})
	bundleMap := bundleMapAny.(*sync.Map)

	deleteBundle := func(bundleID, canon string) {
        if bundleID != "" {
            url := fmt.Sprintf("%s/v1/task/%s/bundle/%s", h.hostAPIBaseURL, taskID, bundleID)
            req, _ := http.NewRequestWithContext(ctx, "DELETE", url, nil)
            req.Header = hdr
            _, _ = doRequest(req) // best-effort
            bundleMap.Delete(canon)
            submissions.Delete(bundleID)
            log.Printf("Deleted invalid bundle %s for task %s", bundleID, taskID)
        }
	}

	for canon, st := range byGroup {
		bidAny, hasBundle := bundleMap.Load(canon)

        // RULE 1: POV must be non-empty and must have passed.
		// If not, this group cannot form a valid bundle. Delete if one exists.
        invalid := false
        if st.POV != "" {
            invalid = !st.povPass
        } else {
            if st.Patch == "" || !st.patchPass {
                invalid = true
            }
        }

        if invalid {
			if hasBundle {
                bundleID := bidAny.(string)
                // Load the verbose bundle to compare its PoV ID.
                if vbAny, ok := submissions.Load(bundleID); ok {
                    if vb, ok := vbAny.(models.BundleSubmissionResponseVerbose); ok {
                        if vb.POVID == "" || vb.POVID == st.POV {
                            deleteBundle(bundleID, canon)
                        }
                    } else {
                        // Unknown type – delete defensively.
                        deleteBundle(bundleID, canon)
                    }
                } else {
                    // No cached entry – delete defensively.
                    deleteBundle(bundleID, canon)
                }
			}
			continue // Move to the next group
		}

		// ----------------------------------------------------------------
		// Enforce rules
		//   1.  A patch is included only if it **passed**.
		//   2.  A bundle must contain ≥ 2 artefacts; single-item bundles
		//       are deleted / never (re)created.
		// ----------------------------------------------------------------
		effectivePatchID := ""
		if st.Patch != "" { // A patch ID exists
			if st.patchPass {
				effectivePatchID = st.Patch // Patch is valid and passed
			} else {
				// Patch exists but did NOT pass. It will not be included.
				// effectivePatchID remains ""
			}
		}
		// Count artefacts that will end up in the bundle
		items := 0
		if st.POV != "" && st.povPass {
			items++
		}
		if effectivePatchID != "" {
			items++
		}
		if st.Sarif != "" {
			items++
		}

		needBundle := items >= 2        // bundles with <2 artefacts are invalid

		if hasBundle && !needBundle {
			deleteBundle(bidAny.(string), canon)
			hasBundle = false
		}

        if needBundle && !hasBundle {
			go h.bundleOneGroup(
				context.Background(),
				taskID,
				canon,
				st.POV,
				effectivePatchID,   // include patch only if it passed
				st.Sarif,
				"",                 // freeformID unused here
				hdr,
				submissions,
			)
		}
	}

    log.Printf("[finalizeBundle] END (task=%s)", taskID)
}

func (h *Handler) HandleTask(c *gin.Context) {
	// Parse the request
	var challenge models.Task
    if err := c.ShouldBindJSON(&challenge); err != nil {
        log.Printf("Error binding JSON: %v", err)
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    for i, t := range challenge.Tasks {
        log.Printf("  Task[%d]:", i)
        log.Printf("    TaskID: %s", t.TaskID)
        log.Printf("    Type: %s", t.Type)
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


    // Copy the headers to pass to finalizeBundle
	headerCopy := make(http.Header)
	for k, v := range c.Request.Header {
		headerCopy[k] = v
	}

	for _, taskDetail := range challenge.Tasks {
		go func(detail models.TaskDetail) {
            saveTaskDetailToJson(taskDetail)
		}(taskDetail)
        taskID := taskDetail.TaskID.String()
       
        // Create or get the task map for this taskID
        taskMapAny, _ := h.tasks.LoadOrStore(taskID, &sync.Map{})
        taskMap := taskMapAny.(*sync.Map)
        
        // Store the task details in a standard location in the task map
        taskMap.Store("taskDetail", taskDetail)

        // Setup a timer for 30 minutes before the deadline to finalize bundle
		deadlineTime := time.Unix(taskDetail.Deadline/1000, 0)
		finalizationTime := deadlineTime.Add(-30 * time.Minute)
		
		// Calculate duration until finalization
		durationUntilFinalization := time.Until(finalizationTime)
		
		// Only schedule if the finalization is in the future
		if durationUntilFinalization > 0 {
			go func(tID string, headers http.Header) {
				log.Printf("Scheduled bundle finalization for task %s at %s (in %v)", 
					tID, finalizationTime.Format(time.RFC3339), durationUntilFinalization)
				
				timer := time.NewTimer(durationUntilFinalization)
				<-timer.C
				
				// Execute finalization
				h.finalizeBundle(tID, headers)
			}(taskID, headerCopy)
		} else {
			// If we're already past the finalization time, call immediately
			log.Printf("Task %s is already past finalization time, calling finalizeBundle immediately", taskID)
			go func(tID string, headers http.Header) {
				h.finalizeBundle(tID, headers)
			}(taskID, headerCopy)
		}
	}

	// Return the task ID to the client
	c.JSON(http.StatusAccepted, gin.H{
		"status":  "accepted",
		"message_id": challenge.MessageID,
		"message": "Task submitted to the submission server successfully",
	})
}


func (h *Handler) tryCreateBundle(taskID, povID, sarifID, patchID, freeformID string, c *gin.Context) {
	// ------------------------------------------------------------------
	// Context / helpers
	// ------------------------------------------------------------------
	ctx := context.Background()
	header := c.Request.Header

	// Make sure a submission map exists for this task
	taskMapAny, _ := h.tasks.LoadOrStore(taskID, &sync.Map{})
	taskMap := taskMapAny.(*sync.Map)

    groupMapAny, _ := h.povSignatureGroups.LoadOrStore(taskID, &sync.Map{})
    groupMap := groupMapAny.(*sync.Map)          // sig -> canonical

    patchGroupAny, _ := h.patchByGroup.LoadOrStore(taskID, &sync.Map{})
    patchByGroup := patchGroupAny.(*sync.Map)    // canonical -> patchID

    // Detailed invocation log
    log.Printf(
        "tryCreateBundle: taskID=%s povID=%s sarifID=%s patchID=%s freeformID=%s",
        taskID, povID, sarifID, patchID, freeformID,
    )


    // ------------------------------------------------------------------
    // 1. Build povByGroup  (canonical → povID)
    // ------------------------------------------------------------------
    povByGroup := make(map[string]string)

    if povID != "" {
        if subAny, ok := h.povSubmissions.Load(povID); ok {
            if canonAny, ok := groupMap.Load(subAny.(models.POVSubmission).Signature); ok {
                povByGroup[canonAny.(string)] = povID
            }
        }
    }
    taskMap.Range(func(_, vAny interface{}) bool {
        if resp, ok := vAny.(models.POVSubmissionResponse); ok {
            if subAny, ok := h.povSubmissions.Load(resp.POVID); ok {
                if canonAny, ok := groupMap.Load(subAny.(models.POVSubmission).Signature); ok {
                    canonical := canonAny.(string)
                    if _, exists := povByGroup[canonical]; !exists {
                        povByGroup[canonical] = resp.POVID
                    }
                }
            }
        }
        return true
    })


    // ------------------------------------------------------------------
    // 2. Build sarifByGroup  (canonical → sarifID) – only if we know PoV
    // ------------------------------------------------------------------
    sarifByGroup := make(map[string]string)
    if sarifID != "" && povID != "" {
        if subAny, ok := h.povSubmissions.Load(povID); ok {
            if canonAny, ok := groupMap.Load(subAny.(models.POVSubmission).Signature); ok {
                sarifByGroup[canonAny.(string)] = sarifID
            }
        }
    }

    if sarifID != "" && patchID != "" && len(sarifByGroup) == 0 {
        patchByGroup.Range(func(k, v interface{}) bool {
            switch vv := v.(type) {
            case string:
                if vv == patchID {
                    sarifByGroup[k.(string)] = sarifID
                    return false
                }
            case []string:
                for _, id := range vv {
                    if id == patchID {
                        sarifByGroup[k.(string)] = sarifID
                        return false
                    }
                }
            }
            return true
        })
    }

    // ------------------------------------------------------------------
    // 3. Union of all canonical signatures we know about
    // ------------------------------------------------------------------
    sigSet := map[string]struct{}{}
    for k := range povByGroup { sigSet[k] = struct{}{} }
    sarifGroup := func(k string) string { return sarifByGroup[k] }
    patchByGroup.Range(func(k, _ interface{}) bool { sigSet[k.(string)] = struct{}{}; return true })

    // ------------------------------------------------------------------
    // 4. For each canonical signature spawn a bundle worker
    // ------------------------------------------------------------------
    for canonical := range sigSet {
        var patchIDForCanonical string
        if v, ok := patchByGroup.Load(canonical); ok {
            switch vv := v.(type) {
            case string:
                patchIDForCanonical = vv
            case []string:
                if len(vv) >0 {
                    patchIDForCanonical = vv[len(vv)-1]
                }
            }
        }

        povIDsForCanonical := povByGroup[canonical] // This is []string
        sarifIDForCanonical := sarifGroup(canonical) // Assuming this returns a string ID

        notEmptyCount := 0
        if len(povIDsForCanonical) > 0 {
            notEmptyCount++
        }
        if patchIDForCanonical != "" {
            notEmptyCount++
        }
        if sarifIDForCanonical != "" { // Assuming sarifGroup returns an ID string; adjust if it's a slice/map
            notEmptyCount++
        }
        if notEmptyCount >= 2 {
            go h.bundleOneGroup(
                ctx,
                taskID,
                canonical,
                povIDsForCanonical,
                patchIDForCanonical,
                sarifIDForCanonical,
                freeformID,
                header,
                taskMap,
            )
        }
    }
}

// -------------------------------------------------------------------
// bundleOneGroup does the *old* single-bundle logic but restricted to
// one canonical signature.
// -------------------------------------------------------------------
func (h *Handler) bundleOneGroup(
	ctx context.Context,
	taskID, canonical, povID, patchID, sarifID, freeformID string,
	header http.Header,
	taskMap *sync.Map,
) {
	log.Printf("bundleOneGroup[%s]: (task=%s pov=%s patch=%s sarifID=%s)", canonical, taskID, povID, patchID,sarifID)
    patchGroupAny, _ := h.patchByGroup.LoadOrStore(taskID, &sync.Map{})
    patchGroupMap := patchGroupAny.(*sync.Map)
    
	// ---------- wait for artefacts to PASS/ACCEPT as before ----------
	timeout := time.After(15 * time.Minute)
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()

	for {
		select {
		case <-timeout:
			log.Printf("bundleOneGroup[%s]: timeout", canonical)
			return
		case <-tick.C:
			// ---- check PoV ----
			povPassed := true
			if povID != "" {
				status, err := h.getPOVStatus(ctx, taskID, povID, header)
				if err != nil {
					log.Printf("bundleOneGroup[%s]: getPOVStatus err: %v", canonical, err)
					continue
				}
				switch status.Status {
				case models.SubmissionStatusPassed:
					povPassed = true
				case models.SubmissionStatusAccepted:
					continue // still running
                case models.SubmissionStatusFailed:
                    povPassed = false
                    taskMap.Delete(povID)
                    h.povSubmissions.Delete(povID)
                    log.Printf("bundleOneGroup[%s]: PoV failed (%s) povID=%s", canonical, status.Status,povID)
					return
				default:
                    //errored
					log.Printf("bundleOneGroup[%s]: PoV errored (%s) povID=%s", canonical, status.Status,povID)
					return
				}
			}

			// ---- check Patch ----
			patchPassed := false
			if patchID != "" {
				status, err := h.getPatchStatus(ctx, taskID, patchID, header)
				if err != nil {
					log.Printf("bundleOneGroup[%s]: getPatchStatus err: %v", canonical, err)
					continue
				}
				switch {
				case status.Status == string(models.SubmissionStatusPassed):
					patchPassed = true
				case status.FunctionalityTestsPassing != nil && *status.FunctionalityTestsPassing:
					// patchPassed = true
                    continue
				case status.Status == string(models.SubmissionStatusAccepted):
					continue // running
				default:
					log.Printf("bundleOneGroup[%s]: Patch failed (%s)", canonical, status.Status)

                    if any, ok := patchGroupMap.Load(canonical); ok {
                            ids := any.([]string)
                            cleaned := make([]string, 0, len(ids))
                            for _, id := range ids {
                                if id != patchID { // keep everything except the failed one
                                    cleaned = append(cleaned, id)
                                } else {
                                    taskMap.Delete(id) // optional: free memory
                                }
                            }
                            patchGroupMap.Store(canonical, cleaned)
                        }

					return
				}
			}

            //make sure the patch passed if it exists
            if patchID != "" && !patchPassed{
                log.Printf("bundleOneGroup[%s]: Patch failed (patchPassed=%t)", canonical, patchPassed)
                return
            }

            readyCnt := 0
            if povPassed {readyCnt++}
            if patchPassed {readyCnt++}
            if sarifID!="" {readyCnt++}
            if readyCnt < 2 {
                continue
            }
			// ---------------- create / update bundle ----------------
			// Ensure only one goroutine creates/updates the bundle
			grpAny, _ := h.bundleByGroup.LoadOrStore(taskID, &sync.Map{})
			grp := grpAny.(*sync.Map)
                    v, loaded := grp.LoadOrStore(canonical, "IN_PROGRESS")
                    if loaded {
                        if v.(string) == "IN_PROGRESS" {
                            return // creator still running
                        }
                        if patchID == "" && sarifID == "" {
                            return // nothing new to contribute
                        }
                        // we have new artefacts → keep going to PATCH bundle
                    }
            h.createOrUpdateBundle(ctx, taskID, povID, patchID, sarifID, freeformID, canonical, header, taskMap)
			return
		}
	}
}


// createOrUpdateBundle keeps the original POST / PATCH logic
func (h *Handler) createOrUpdateBundle(
	ctx context.Context,
	taskID, povID, patchID, sarifID, freeformID, canonicalSig string,
	header http.Header,
	taskMap *sync.Map,
) {
	// ------------------------------------------------------------
	// 1. Look up an existing bundle for this canonical signature
	// ------------------------------------------------------------
	var (
		existingBundle   *models.BundleSubmissionResponseVerbose
		existingBundleID string
	)
	if grpAny, ok := h.bundleByGroup.Load(taskID); ok {
		if idAny, ok := grpAny.(*sync.Map).Load(canonicalSig); ok {
			bundleID := idAny.(string)
			if v, ok := taskMap.Load(bundleID); ok {
				b := v.(models.BundleSubmissionResponseVerbose)
				existingBundle = &b
				existingBundleID = bundleID
			}
		}
	}

	// ------------------------------------------------------------
	// 2a. UPDATE existing bundle (PATCH)
	// ------------------------------------------------------------
	if existingBundle != nil {
        changed := false
		if povID != "" && povID !=existingBundle.POVID  {
			existingBundle.POVID = povID
            changed = true
		}
		if patchID != "" && patchID != existingBundle.PatchID {
			existingBundle.PatchID = patchID
            changed = true
		}
		if sarifID != "" && sarifID !=  existingBundle.BroadcastSarifID{
			existingBundle.BroadcastSarifID = sarifID
            changed = true
		}
        if !changed {
            return
        }

		bJSON, _ := json.Marshal(existingBundle)
		url := fmt.Sprintf("%s/v1/task/%s/bundle/%s",
			h.hostAPIBaseURL, taskID, existingBundleID)
		req, _ := http.NewRequest("PATCH", url, bytes.NewReader(bJSON))
		req.Header = header

		if _, err := doRequest(req); err != nil {
			log.Printf("PATCH bundle error for %s: %v", taskID, err)
			return
		}
		taskMap.Store(existingBundleID, *existingBundle)
		log.Printf("Bundle updated: task %s (BundleID=%s) existingBundle: %v", taskID, existingBundleID, *existingBundle)
		return
	}

	// ------------------------------------------------------------
	// 2b. CREATE new bundle (POST)
	// ------------------------------------------------------------
	newBundle := models.BundleSubmission{
		POVID:       povID,
		FreeformID:  freeformID,
		Description: fmt.Sprintf("Bundle for task %s", taskID),
	}
	if patchID != "" {
		newBundle.PatchID = patchID
	}
	if sarifID != "" {
		newBundle.BroadcastSarifID = sarifID
	}

	bJSON, _ := json.Marshal(newBundle)
	url := fmt.Sprintf("%s/v1/task/%s/bundle/", h.hostAPIBaseURL, taskID)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(bJSON))
	req.Header = header

	respBody, err := doRequest(req)
	if err != nil {
		log.Printf("POST bundle error for %s: %v", taskID, err)
		return
	}

	var resp models.BundleSubmissionResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		log.Printf("Bundle response unmarshal error: %v", err)
		return
	}

	verbose := models.BundleSubmissionResponseVerbose{
		BundleSubmissionResponse: resp,
		POVID:            povID,
		PatchID:          patchID,
		BroadcastSarifID: sarifID,
		FreeformID:       freeformID,
		Description:      newBundle.Description,
	}
	taskMap.Store(resp.BundleID, verbose)

	grpAny, _ := h.bundleByGroup.LoadOrStore(taskID, &sync.Map{})
	grpAny.(*sync.Map).Store(canonicalSig, verbose.BundleID)

	log.Printf("Bundle created: task %s (BundleID=%s) verbose: %v",
		taskID, resp.BundleID, verbose)
}

var sharedHTTP = &http.Client{
    Timeout: 60 * time.Second,
    Transport: &http.Transport{
        MaxIdleConns:        100,
        MaxIdleConnsPerHost: 100,
        IdleConnTimeout:     90 * time.Second,
        DialContext: (&net.Dialer{
            Timeout:   5 * time.Second,   // quick fail
            KeepAlive: 30 * time.Second,
        }).DialContext,
        TLSHandshakeTimeout:   5 * time.Second,
        ResponseHeaderTimeout: 10 * time.Second,
    },
}

func doRequest(req *http.Request) ([]byte, error) {
    const maxRetries = 3
    var lastErr error

    for attempt := 1; attempt <= maxRetries; attempt++ {
        resp, err := sharedHTTP.Do(req)
        if err != nil {
            // retry only on dial- or TLS-timeout
            if nErr, ok := err.(net.Error); ok && nErr.Timeout() && attempt < maxRetries {
                time.Sleep(time.Duration(attempt) * time.Second) // 1 s, 2 s …
                lastErr = err
                continue
            }
            return nil, err
        }

        defer resp.Body.Close()
        return io.ReadAll(resp.Body)
    }
    return nil, lastErr
}

// Patch handlers
func (h *Handler) SubmitPatch(c *gin.Context) {

    taskID := c.Param("task_id")

	// ------------------------------------------------------------------
	// 0. Telemetry context
	// ------------------------------------------------------------------
	ctx, span := telemetry.StartSpan(c.Request.Context(), "SubmitPatch")
	defer span.End()

	telemetry.AddSpanAttributes(ctx,
		attribute.String("crs.action.category", "scoring_submission"),
		attribute.String("crs.action.name", "SubmitPatch"),
	)

	if taskID == "" {
		telemetry.AddSpanEvent(ctx, "error", attribute.String("error", "empty task_id"))
		c.JSON(http.StatusBadRequest, models.Error{Message: "invalid task_id"})
		return
	}
    telemetry.AddSpanAttributes(ctx, attribute.String("task.id", taskID))


	// ------------------------------------------------------------------
	// 1. Read raw body (for logging + replay)
	// ------------------------------------------------------------------
	rawData, err := io.ReadAll(c.Request.Body)
	if err != nil {
		telemetry.AddSpanError(ctx, err)
		log.Printf("Error reading request body for task %s: %v", taskID, err)
		c.JSON(http.StatusBadRequest, models.Error{Message: "failed to read request body"})
		return
	}
	truncated := string(rawData)
	if len(truncated) > 10_000 {
		truncated = truncated[:10_000] + "..."
	}
	log.Printf("Received Patch submission for task %s: %s", taskID, truncated)
	telemetry.AddSpanEvent(ctx, "patch_submission_received",
		attribute.String("raw_data", truncated),
		attribute.Int("data_size", len(rawData)),
	)

    c.Request.Body = io.NopCloser(bytes.NewBuffer(rawData))

	// ------------------------------------------------------------------
	// 2. Bind JSON → models.PatchSubmission
	// ------------------------------------------------------------------
	var submission models.PatchSubmission
	if err := c.ShouldBindJSON(&submission); err != nil {
		telemetry.AddSpanError(ctx, err)
		c.JSON(http.StatusBadRequest, models.Error{Message: err.Error()})
		return
	}

	// ------------------------------------------------------------------
	// 3. Get (or create) the per-task sync.Map
	// ------------------------------------------------------------------
	taskMapAny, _ := h.tasks.LoadOrStore(taskID, &sync.Map{})
	taskMap := taskMapAny.(*sync.Map)


    groupMapAny, _ := h.povSignatureGroups.LoadOrStore(taskID, &sync.Map{})
    groupMap := groupMapAny.(*sync.Map)


    // canonicalSig = group representative for this patch’s PoV signature
    povSig := submission.PoVSignature
    canonicalSigAny, ok := groupMap.Load(povSig)
    canonicalSig := povSig
    if ok {
        canonicalSig = canonicalSigAny.(string)
    } else {
        // should only be here for xpatch
        if strings.HasPrefix(povSig,"xpatch") {
            log.Printf("[XPATCH] Received xpatch for taskID=%s povSig=%s", taskID, povSig)
        } else {
            log.Printf("LIKELY ERROR! The povSig first appeared in Patch! taskID=%s povSig=%s", taskID, povSig)
        }
        groupMap.Store(povSig, canonicalSig) // new group
    }

    patchGroupMapAny, _ := h.patchByGroup.LoadOrStore(taskID, &sync.Map{})
    patchGroupMap := patchGroupMapAny.(*sync.Map)

    // Skip patches with the same canonicalSig that arrive
    //           within a 3-second window.
    {
        infoTaskAny, _ := h.lastPatchTime.LoadOrStore(taskID, &sync.Map{})
        infoTask := infoTaskAny.(*sync.Map)

        now := time.Now()
        if infoAny, ok := infoTask.Load(canonicalSig); ok {
            if info, okC := infoAny.(patchSubmitInfo); okC && now.Sub(info.Time) <= 3*time.Second {
                dupID := info.PatchID
                // If PatchID not yet known, fall back to the most-recent one
                if dupID == "" {
                    if idsAny, ok := patchGroupMap.Load(canonicalSig); ok {
                        ids := idsAny.([]string)
                        if len(ids) > 0 {
                            dupID = ids[len(ids)-1]
                        }
                    }
                }
                log.Printf("Skipping patch: same signature within 3 s (task=%s sig=%s) → dupID=%s",
                    taskID, canonicalSig, dupID)
                c.JSON(http.StatusOK, models.PatchSubmissionResponse{
                    PatchID: dupID,
                    Status:  "duplicate",
                })
                return
            }
        }
        // Record “seen now” (PatchID filled in later once we get host reply)
        infoTask.Store(canonicalSig, patchSubmitInfo{Time: now})
    }

    // ------------------------------------------------------------------
    // A)  Fingerprint of the incoming patch
    // ------------------------------------------------------------------
    fingerprint := sha256Hex(normaliseDiff(submission.PatchDiff))

    fpTaskAny, _ := h.patchFingerprintByGroup.LoadOrStore(taskID, &sync.Map{})
    fpTask := fpTaskAny.(*sync.Map)

    fpByCanonAny, _ := fpTask.LoadOrStore(canonicalSig, &sync.Map{})
    fpByCanon := fpByCanonAny.(*sync.Map)

    // Exact duplicate?  → re-use the earlier response and return
    if existingIDAny, ok := fpByCanon.Load(fingerprint); ok {
        if respAny, ok := h.tasks.Load(taskID); ok {
            if resp, ok := respAny.(*sync.Map).Load(existingIDAny.(string)); ok {
                if psr, ok := resp.(models.PatchSubmissionResponse); ok {
                    log.Printf("Identical patch detected – re-using %s (task=%s sig=%s)",
                        psr.PatchID, taskID, canonicalSig)
                    c.JSON(http.StatusOK, psr)
                    return
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // B)  ‘Almost identical’ duplicate?  (cheap string distance)
    // ------------------------------------------------------------------
    duplicate := false
    duplicatePatchID := ""
    fpByCanon.Range(func(_, v interface{}) bool {
        oldID := v.(string)
        if respAny, ok := h.tasks.Load(taskID); ok {
            if resp, ok := respAny.(*sync.Map).Load(oldID); ok {
                if subResp, ok := resp.(models.PatchSubmission); ok {
                    if similar(normaliseDiff(submission.PatchDiff),
                            normaliseDiff(subResp.PatchDiff)) {
                        log.Printf("Near-duplicate patch skipped (new vs %s)", oldID)
                        duplicatePatchID = subResp.PatchID
                        duplicate = true
                        return false // break Range
                    }
                }
            }
        }
        return true
    })
    if duplicate {
        c.JSON(http.StatusOK, models.PatchSubmissionResponse{
            PatchID: duplicatePatchID,
            Status:  "duplicate",
        })
        return
    }

    // ------------------------------------------------------------------
    // 4. If the group already has a patch, decide reuse / replace / skip
    // ------------------------------------------------------------------
    if true {
        // if existingPatchIDAny, ok := patchGroupMap.Load(canonicalSig); ok {
        //     existingPatchID := existingPatchIDAny.(string)

        //     // Fetch the cached PatchSubmissionResponse
        //     if vAny, ok := taskMap.Load(existingPatchID); ok {
        //         if resp, ok := vAny.(models.PatchSubmissionResponse); ok {
        //             patchStatus, err := h.getPatchStatus(ctx, taskID, resp.PatchID, c.Request.Header)
        //             if err == nil && patchStatus != nil {
        //                 switch {
        //                 // Passing → reuse
        //                 case patchStatus.FunctionalityTestsPassing != nil && *patchStatus.FunctionalityTestsPassing:
        //                     log.Printf("Re-using PASSING patch %s for task %s (group %s)",
        //                         resp.PatchID, taskID, canonicalSig)
        //                     c.JSON(http.StatusOK, resp)
        //                     return
        //                 // Failed → allow replacement (continue to send new patch)
        //                 case patchStatus.Status == string(models.SubmissionStatusFailed) ||
        //                     (patchStatus.FunctionalityTestsPassing != nil && !*patchStatus.FunctionalityTestsPassing):
        //                     log.Printf("Replacing FAILED patch %s for task %s (group %s)",
        //                         resp.PatchID, taskID, canonicalSig)
        //                 // Running / unknown → skip duplicate submission
        //                 default:
        //                     log.Printf("Patch %s for task %s (group %s) still running – duplicate skipped",
        //                         resp.PatchID, taskID, canonicalSig)
        //                     c.JSON(http.StatusOK, resp)
        //                     return
        //                 }
        //             }
        //         }
        //     }
        // }

        //NEW: ALLOW MULTIPLE PATCHES
        if existingAny, ok := patchGroupMap.Load(canonicalSig); ok {
            patchIDs := existingAny.([]string)
            patchLimit := 5
            if strings.HasPrefix(canonicalSig, "xpatch-") {patchLimit = 3}

            if len(patchIDs) >= patchLimit {
                log.Printf("Skipped this patch because already %d submitted patches for task %s (group %s)",
                patchLimit, taskID, canonicalSig)
                return
            }
            
            // Re-use the first “passing” patch we encounter
            for _, existingPatchID := range patchIDs {
                if vAny, ok := taskMap.Load(existingPatchID); ok {
                    if resp, ok := vAny.(models.PatchSubmissionResponse); ok {
                        s, err := h.getPatchStatus(ctx, taskID, resp.PatchID, c.Request.Header)
                        if err == nil && s.Status == string(models.SubmissionStatusPassed) {
                            log.Printf("Re-using PASSING patch %s for task %s (group %s)",
                                resp.PatchID, taskID, canonicalSig)
                            c.JSON(http.StatusOK, resp)
                            return
                        }
                    }
                }
            }
            // No passing patch found → we’ll submit a new one and append it.
        }
    } 
    // Create simplified submission for forwarding
    simplifiedSubmission := SimplifiedPatchSubmission{
        Patch:      submission.Patch,
    }
    
    simplifiedData, err := json.Marshal(simplifiedSubmission)
    if err != nil {
        telemetry.AddSpanError(ctx, err)
        log.Printf("Error marshaling simplified submission: %v", err)
        c.JSON(http.StatusInternalServerError, models.Error{Message: "failed to process submission"})
        return
    }

	// ------------------------------------------------------------------
	// 5. Forward submission to host API
	// ------------------------------------------------------------------
	hostAPIURL := fmt.Sprintf("%s/v1/task/%s/patch/", h.hostAPIBaseURL, taskID)

	telemetry.AddSpanAttributes(ctx, attribute.String("host_api_url", hostAPIURL))

	hostReq, err := http.NewRequest("POST", hostAPIURL, bytes.NewBuffer(simplifiedData))
	if err != nil {
		telemetry.AddSpanError(ctx, err)
		c.JSON(http.StatusInternalServerError, models.Error{Message: "failed to forward request"})
		return
	}
	hostReq.Header = c.Request.Header

    // log.Printf("DEBUG: PATCH Forwarding raw data to host API (%s): %s", hostAPIURL, string(rawData))

	respBody, statusCode, err := forwardRequest(hostReq)
	if err != nil {
		// `forwardRequest` already logged & handled typical errors; just return
		c.JSON(statusCode, err)
		return
	}

	// ------------------------------------------------------------------
	// 6. Parse host response → PatchSubmissionResponse
	// ------------------------------------------------------------------
	var respObj models.PatchSubmissionResponse
	if err := json.Unmarshal(respBody, &respObj); err != nil {
		telemetry.AddSpanError(ctx, err)
		c.JSON(http.StatusInternalServerError, models.Error{Message: "failed to parse response"})
		return
	}

	// ------------------------------------------------------------------
	// 7. Cache & respond
	// ------------------------------------------------------------------
	taskMap.Store(respObj.PatchID, respObj)
    fpByCanon.Store(fingerprint, respObj.PatchID)
    // NEW – append to slice in patchByGroup
    var ids []string
    if idsAny, ok := patchGroupMap.Load(canonicalSig); ok {
        ids = idsAny.([]string)
    }
    ids = append(ids, respObj.PatchID)
    patchGroupMap.Store(canonicalSig, ids)

    // Update lastPatchTime with the real PatchID now that we have it
    if infoTaskAny, ok := h.lastPatchTime.Load(taskID); ok {
        infoTask := infoTaskAny.(*sync.Map)
        infoTask.Store(canonicalSig, patchSubmitInfo{Time: time.Now(), PatchID: respObj.PatchID})
    }

	telemetry.AddSpanAttributes(ctx,
		attribute.String("patch_id", respObj.PatchID),
		attribute.String("status", string(respObj.Status)),
	)
	log.Printf("Patch submission accepted: Task=%s PatchID=%s Status=%s",
		taskID, respObj.PatchID, respObj.Status)

            // Run the SARIF check in a separate goroutine
    go func() {
        sarifID := ""
        // Get SARIFs for this task
        sarifsAny, ok := h.sarifs.Load(taskID)
        if ok {
            sarifs := sarifsAny.([]models.SARIFBroadcastDetail)
            if len(sarifs) > 0 && strings.HasPrefix(submission.PoVSignature, "xpatch-sarif-") {
                patchID := respObj.PatchID
                log.Printf("Found %d SARIF broadcasts to check for task %s patchID %s", len(sarifs), taskID, patchID)
                for _, broadcast := range sarifs {
                    if broadcast.SarifID.String() == submission.SarifID {                        
                        sarifID = submission.SarifID

                        if done, ok := h.processedSarifs.Load(sarifID); ok && done.(bool) {
                            log.Printf("SARIF %s already processed!", sarifID)
                        } else {
                            maxRetries := 3
                            for attempt := 0; attempt < maxRetries; attempt++ {
                                err := h.submitSarifAssessment(ctx, taskID, sarifID, "", patchID,true, c.Request.Header)
                                if err != nil {
                                    log.Printf("Error submitting SARIF assessment: %v", err)
                                } else {
                                    log.Printf("Successfully submitted valid SARIF assessment for task %s (SARIF %s, PATCH %s)", 
                                        taskID, sarifID, patchID)
                                    break
                                }
                            }
                        }
                        h.processedSarifs.Store(sarifID, true)
                        break
                    }
                }
            }
        }
        // Try to create bundle in a separate goroutine
        h.tryCreateBundle(taskID, "", sarifID, respObj.PatchID, "", c)
    }()

	c.JSON(http.StatusOK, respObj)
}

// ----------------------------------------------------------------------
// helper: forwardRequest – executes the prepared *http.Request with
// standard timeouts and richer error handling; returns body & status code
// ----------------------------------------------------------------------
func forwardRequest(req *http.Request) ([]byte, int, error) {
	client := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("host API request error: %v", err)
		return nil, http.StatusServiceUnavailable, fmt.Errorf("host API unavailable: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		log.Printf("host API non-200: %d body=%s", resp.StatusCode, string(body))
		return body, resp.StatusCode, fmt.Errorf("host API error")
	}

	return body, http.StatusOK, nil
}

func (h *Handler) getPOVStatus(ctx context.Context, taskID, povID string, validHeader http.Header) (*models.POVSubmissionResponse, error) {
    // ------------------------------------------------------------------
    // ❶ Fast-path: return cached value if present
    // ------------------------------------------------------------------
    // if taskMapAny, ok := h.tasks.Load(taskID); ok {
    //     if cached, ok := taskMapAny.(*sync.Map).Load(povID); ok {
    //         if resp, ok := cached.(models.POVSubmissionResponse); ok {
    //             return &resp, nil
    //         }
    //     }
    // }

    // ------------------------------------------------------------------
    // ❷ Not cached → query host API
    // ------------------------------------------------------------------
    ctx, span := telemetry.StartSpan(ctx, "getPOVStatus")
    defer span.End()

    telemetry.AddSpanAttributes(ctx,
        attribute.String("task.id", taskID),
        attribute.String("pov.id", povID),
    )

    hostAPIURL := fmt.Sprintf("%s/v1/task/%s/pov/%s", h.hostAPIBaseURL, taskID, povID)
    req, err := http.NewRequestWithContext(ctx, "GET", hostAPIURL, nil)
    if err != nil {
        return nil, fmt.Errorf("error creating request: %w", err)
    }
    req.Header = validHeader

    body, err := doRequest(req)
    if err != nil {
        return nil, err
    }

    var status models.POVSubmissionResponse
    if err := json.Unmarshal(body, &status); err != nil {
        return nil, fmt.Errorf("error parsing response: %w", err)
    }

    // ------------------------------------------------------------------
    // ❸ Cache result in per-task map
    // ------------------------------------------------------------------
    taskMapAny, _ := h.tasks.LoadOrStore(taskID, &sync.Map{})
    taskMap := taskMapAny.(*sync.Map)
    taskMap.Store(povID, status)

    return &status, nil
}

// getPatchStatus retrieves the current status of a patch, including functionality test results
func (h *Handler) getPatchStatus(ctx context.Context, taskID, patchID string, validHeader http.Header) (*models.PatchStatusResponse, error) {
    // ------------------------------------------------------------------
    // ❶ Fast-path: cached?
    // ------------------------------------------------------------------
    // if taskMapAny, ok := h.tasks.Load(taskID); ok {
    //     if cached, ok := taskMapAny.(*sync.Map).Load(patchID); ok {
    //         if resp, ok := cached.(models.PatchStatusResponse); ok {
    //             return &resp, nil
    //         }
    //     }
    // }

    // ------------------------------------------------------------------
    // ❷ Query host API
    // ------------------------------------------------------------------
    ctx, span := telemetry.StartSpan(ctx, "getPatchStatus")
    defer span.End()

    telemetry.AddSpanAttributes(ctx,
        attribute.String("task.id", taskID),
        attribute.String("patch.id", patchID),
    )

    hostAPIURL := fmt.Sprintf("%s/v1/task/%s/patch/%s", h.hostAPIBaseURL, taskID, patchID)
    req, err := http.NewRequestWithContext(ctx, "GET", hostAPIURL, nil)
    if err != nil {
        return nil, fmt.Errorf("error creating request: %w", err)
    }
    req.Header = validHeader

    body, err := doRequest(req)
    if err != nil {
        return nil, err
    }

    var status models.PatchStatusResponse
    if err := json.Unmarshal(body, &status); err != nil {
        return nil, fmt.Errorf("error parsing response: %w", err)
    }

    // ------------------------------------------------------------------
    // ❸ Cache result
    // ------------------------------------------------------------------
    taskMapAny, _ := h.tasks.LoadOrStore(taskID, &sync.Map{})
    taskMap := taskMapAny.(*sync.Map)
    taskMap.Store(patchID, status)

    return &status, nil
}

// SARIF handlers
func (h *Handler) SubmitSARIFX(c *gin.Context) {

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

    for _, broadcast := range sarifBroadcast.Broadcasts {
            taskID := broadcast.TaskID.String()
    
        // Skip broadcasts that do not belong to any task we track
        if _, ok := h.tasks.Load(taskID); !ok {
            log.Printf("Received SARIF for unknown task: %s", taskID)
            continue
        }

        // Append to slice in h.sarifs (sync.Map)
        sliceAny, _ := h.sarifs.LoadOrStore(taskID, []models.SARIFBroadcastDetail{})
        slice := sliceAny.([]models.SARIFBroadcastDetail)
        slice = append(slice, broadcast)
        h.sarifs.Store(taskID, slice)

        // Mark as not yet processed
        h.processedSarifs.Store(broadcast.SarifID.String(), false)

        log.Printf("Saved SARIF to sarifs and set processedSarifs to false. SarifID: %s", broadcast.SarifID.String())

    }
    // Create response structure
    response := gin.H{
        "status": "success",
        "message": "SARIF broadcasts received",
        "count": len(sarifBroadcast.Broadcasts),
    }

    c.JSON(http.StatusOK, response)
}


// Ping handler
func (h *Handler) Ping(c *gin.Context) {
    // Forward to host API
    hostAPIURL := fmt.Sprintf("%s/v1/ping/", h.hostAPIBaseURL)
    
    // Create a new request to the host API
    hostReq, err := http.NewRequest("GET", hostAPIURL, nil)
    if err != nil {
        log.Printf("Error creating ping request to host API: %v", err)
        c.JSON(http.StatusInternalServerError, models.Error{Message: "failed to forward request"})
        return
    }
    
    // Copy headers from original request
    hostReq.Header = c.Request.Header
    
    // Send the request
    client := &http.Client{}
    resp, err := client.Do(hostReq)
    if err != nil {
        log.Printf("Error sending ping request to host API: %v", err)
        c.JSON(http.StatusInternalServerError, models.Error{Message: "failed to forward request"})
        return
    }
    defer resp.Body.Close()
    
    // Read the response body
    respBody, err := io.ReadAll(resp.Body)
    if err != nil {
        log.Printf("Error reading ping response from host API: %v", err)
        c.JSON(http.StatusInternalServerError, models.Error{Message: "failed to read response"})
        return
    }
    
    // Parse the response
    var response models.PingResponse
    if err := json.Unmarshal(respBody, &response); err != nil {
        log.Printf("Error parsing ping response from host API: %v", err)
        c.JSON(resp.StatusCode, models.Error{Message: "failed to parse response"})
        return
    }
    
    c.JSON(resp.StatusCode, response)
}
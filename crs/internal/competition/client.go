// SPDX-License-Identifier: Apache-2.0
package competition

import (
    "bytes"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net/http"
    
    "crs/internal/models"
)

type Client struct {
    baseURL  string
    username string
    password string
    client   *http.Client
}

func NewClient(baseURL, username, password string) *Client {
    return &Client{
        baseURL:  baseURL,
        username: username,
        password: password,
        client:   &http.Client{},
    }
}

// SubmitPOV submits a vulnerability proof to the competition API
func (c *Client) SubmitPOV(taskID string, fuzzerName, sanitizer string, testcase []byte) (string, error) {
    url := fmt.Sprintf("%s/v1/task/%s/pov/", c.baseURL, taskID)
    
    // Create the POV submission
    submission := models.POVSubmission{
        Architecture: "x86_64",
        FuzzerName:   fuzzerName,
        Sanitizer:    sanitizer,
        Testcase:     base64.StdEncoding.EncodeToString(testcase),
    }
    
    // Marshal the submission to JSON
    data, err := json.Marshal(submission)
    if err != nil {
        return "", fmt.Errorf("failed to marshal POV submission: %v", err)
    }
    
    // Create the request
    req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
    if err != nil {
        return "", fmt.Errorf("failed to create request: %v", err)
    }
    
    // Set headers
    req.Header.Set("Content-Type", "application/json")
    req.SetBasicAuth(c.username, c.password)
    
    // Send the request
    resp, err := c.client.Do(req)
    if err != nil {
        return "", fmt.Errorf("failed to send request: %v", err)
    }
    defer resp.Body.Close()
    
    // Read the response body
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return "", fmt.Errorf("failed to read response body: %v", err)
    }
    
    // Check the response status
    if resp.StatusCode != http.StatusOK {
        return "", fmt.Errorf("POV submission failed with status %d: %s", resp.StatusCode, string(body))
    }
    
    // Parse the response
    var response models.POVSubmissionResponse
    if err := json.Unmarshal(body, &response); err != nil {
        return "", fmt.Errorf("failed to parse response: %v", err)
    }
    
    log.Printf("Successfully submitted POV for task %s. POV ID: %s", taskID, response.POVID)
    return response.POVID, nil
}

// SubmitPatch submits a patch to the competition API
func (c *Client) SubmitPatch(taskID string, patch []byte) (string, error) {
    url := fmt.Sprintf("%s/v1/task/%s/patch/", c.baseURL, taskID)
    
    // Create the patch submission
    submission := models.PatchSubmission{
        Patch: base64.StdEncoding.EncodeToString(patch),
    }
    
    // Marshal the submission to JSON
    data, err := json.Marshal(submission)
    if err != nil {
        return "", fmt.Errorf("failed to marshal patch submission: %v", err)
    }
    
    // Create the request
    req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
    if err != nil {
        return "", fmt.Errorf("failed to create request: %v", err)
    }
    
    // Set headers
    req.Header.Set("Content-Type", "application/json")
    req.SetBasicAuth(c.username, c.password)
    
    // Send the request
    resp, err := c.client.Do(req)
    if err != nil {
        return "", fmt.Errorf("failed to send request: %v", err)
    }
    defer resp.Body.Close()
    
    // Read the response body
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return "", fmt.Errorf("failed to read response body: %v", err)
    }
    
    // Check the response status
    if resp.StatusCode != http.StatusOK {
        return "", fmt.Errorf("patch submission failed with status %d: %s", resp.StatusCode, string(body))
    }
    
    // Parse the response
    var response models.PatchSubmissionResponse
    if err := json.Unmarshal(body, &response); err != nil {
        return "", fmt.Errorf("failed to parse response: %v", err)
    }
    
    log.Printf("Successfully submitted patch for task %s. Patch ID: %s", taskID, response.PatchID)
    return response.PatchID, nil
}

// SubmitSARIF submits a SARIF report to the competition API
func (c *Client) SubmitSARIF(taskID string, sarif interface{}) (string, error) {
    url := fmt.Sprintf("%s/v1/task/%s/submitted-sarif/", c.baseURL, taskID)
    
    // Create the SARIF submission
    submission := struct {
        SARIF interface{} `json:"sarif"`
    }{
        SARIF: sarif,
    }
    
    // Marshal the submission to JSON
    data, err := json.Marshal(submission)
    if err != nil {
        return "", fmt.Errorf("failed to marshal SARIF submission: %v", err)
    }
    
    // Create the request
    req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
    if err != nil {
        return "", fmt.Errorf("failed to create request: %v", err)
    }
    
    // Set headers
    req.Header.Set("Content-Type", "application/json")
    req.SetBasicAuth(c.username, c.password)
    
    // Send the request
    resp, err := c.client.Do(req)
    if err != nil {
        return "", fmt.Errorf("failed to send request: %v", err)
    }
    defer resp.Body.Close()
    
    // Read the response body
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return "", fmt.Errorf("failed to read response body: %v", err)
    }
    
    // Check the response status
    if resp.StatusCode != http.StatusOK {
        return "", fmt.Errorf("SARIF submission failed with status %d: %s", resp.StatusCode, string(body))
    }
    
    // Parse the response
    var response struct {
        Status string `json:"status"`
        SubmittedSarifID string `json:"submitted_sarif_id"`
    }
    if err := json.Unmarshal(body, &response); err != nil {
        return "", fmt.Errorf("failed to parse response: %v", err)
    }
    
    log.Printf("Successfully submitted SARIF for task %s. SARIF ID: %s", taskID, response.SubmittedSarifID)
    return response.SubmittedSarifID, nil
}

// SubmitBundle submits a bundle to the competition API
func (c *Client) SubmitBundle(taskID, povID, patchID, submittedSarifID, broadcastSarifID, description string) (string, error) {
    url := fmt.Sprintf("%s/v1/task/%s/bundle/", c.baseURL, taskID)
    
    // Create the bundle submission
    submission := struct {
        POVID string `json:"pov_id,omitempty"`
        PatchID string `json:"patch_id,omitempty"`
        SubmittedSarifID string `json:"submitted_sarif_id,omitempty"`
        BroadcastSarifID string `json:"broadcast_sarif_id,omitempty"`
        Description string `json:"description,omitempty"`
    }{
        POVID: povID,
        PatchID: patchID,
        SubmittedSarifID: submittedSarifID,
        BroadcastSarifID: broadcastSarifID,
        Description: description,
    }
    
    // Marshal the submission to JSON
    data, err := json.Marshal(submission)
    if err != nil {
        return "", fmt.Errorf("failed to marshal bundle submission: %v", err)
    }
    
    // Create the request
    req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
    if err != nil {
        return "", fmt.Errorf("failed to create request: %v", err)
    }
    
    // Set headers
    req.Header.Set("Content-Type", "application/json")
    req.SetBasicAuth(c.username, c.password)
    
    // Send the request
    resp, err := c.client.Do(req)
    if err != nil {
        return "", fmt.Errorf("failed to send request: %v", err)
    }
    defer resp.Body.Close()
    
    // Read the response body
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return "", fmt.Errorf("failed to read response body: %v", err)
    }
    
    // Check the response status
    if resp.StatusCode != http.StatusOK {
        return "", fmt.Errorf("bundle submission failed with status %d: %s", resp.StatusCode, string(body))
    }
    
    // Parse the response
    var response struct {
        Status string `json:"status"`
        BundleID string `json:"bundle_id"`
    }
    if err := json.Unmarshal(body, &response); err != nil {
        return "", fmt.Errorf("failed to parse response: %v", err)
    }
    
    log.Printf("Successfully submitted bundle for task %s. Bundle ID: %s", taskID, response.BundleID)
    return response.BundleID, nil
}
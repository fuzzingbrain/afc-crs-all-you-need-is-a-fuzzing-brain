package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"crs/internal/models"
)

// Placeholder functions for patching strategies - to be moved from crs_services.go

func runPatchingStrategies(fuzzer, taskDir, projectDir, sanitizer, language, povMetadataDir string,
	taskDetail models.TaskDetail, task models.Task, deadlineTime time.Time, submissionEndpoint string) bool {
	// TODO: Move implementation from crs_services.go
	log.Printf("TODO: runPatchingStrategies not yet implemented in executor package")
	return false
}

func runXPatchingStrategiesWithoutPOV(fuzzer, taskDir, projectDir, sanitizer, language string,
	taskDetail models.TaskDetail, task models.Task, deadlineTime time.Time, submissionEndpoint string) bool {
	// TODO: Move implementation from crs_services.go
	log.Printf("TODO: runXPatchingStrategiesWithoutPOV not yet implemented in executor package")
	return false
}

func runXPatchSarifStrategies(fuzzer, taskDir, sarifPath, language string,
	taskDetail models.TaskDetail, deadlineTime time.Time, submissionEndpoint string) bool {
	// TODO: Move implementation from crs_services.go
	log.Printf("TODO: runXPatchSarifStrategies not yet implemented in executor package")
	return false
}

func getPOVStatsFromSubmissionService(taskID, submissionEndpoint string) (int, int, error) {
	url := fmt.Sprintf("%s/v1/task/%s/pov_stats/", submissionEndpoint, taskID)

	// Create the HTTP request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("Error creating getPOVStats request for taskID %s: %v", taskID, err)
		return 0, 0, err
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")

	// Get API credentials from environment
	apiKeyID := os.Getenv("COMPETITION_API_KEY_ID")
	apiToken := os.Getenv("COMPETITION_API_KEY_TOKEN")
	if apiKeyID != "" && apiToken != "" {
		req.SetBasicAuth(apiKeyID, apiToken)
	}

	// Set context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	// Create a client with custom timeout settings
	client := &http.Client{
		Timeout: 180 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
		},
	}

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error getting POV statistics from submission service: %v", err)
		if ctx.Err() == context.DeadlineExceeded {
			log.Printf("Request timed out, may need to increase timeout or check server load")
		}
		return 0, 0, err
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Submission service returned non-200 status: %d, body: %s", resp.StatusCode, string(body))
		return 0, 0, fmt.Errorf("submission service returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var response models.POVStatsResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		log.Printf("Error decoding POV stats response: %v", err)
		return 0, 0, err
	}

	return response.Count, response.PatchCount, nil
}

package executor

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"crs/internal/competition"
	"crs/internal/models"
	"crs/internal/utils/helpers"
	"crs/internal/utils/libfuzzer"
	"github.com/google/uuid"
)

// POVMetadata represents the metadata for a Proof of Vulnerability
type POVMetadata struct {
	FuzzerOutput string `json:"fuzzer_output"`
	BlobFile     string `json:"blob_file"`
	FuzzerName   string `json:"fuzzer_name"`
	Sanitizer    string `json:"sanitizer"`
	ProjectName  string `json:"project_name"`
}

// ─────────────────────────────────────────────────────────────────────────────
// POV Metadata Management Functions
// ─────────────────────────────────────────────────────────────────────────────

// SavePOVMetadata saves the POV metadata to a JSON file in the POV metadata directory
func SavePOVMetadata(taskDir, fuzzerPath, blobPath string, output string, taskDetail models.TaskDetail, povMetadataDir string) error {
	fuzzDir := filepath.Dir(fuzzerPath)

	// Create POV metadata directory if it doesn't exist
	povMetadataDirPath := filepath.Join(fuzzDir, povMetadataDir)
	if err := os.MkdirAll(povMetadataDirPath, 0755); err != nil {
		// If regular creation fails due to permissions, try with sudo
		if os.IsPermission(err) {
			// log.Printf("Permission denied creating directory, attempting with sudo: %s", povMetadataDirPath)
			cmd := exec.Command("sudo", "mkdir", "-p", povMetadataDirPath)
			if sudoErr := cmd.Run(); sudoErr != nil {
				return fmt.Errorf("failed to create POV metadata directory with sudo: %v", sudoErr)
			}

			// Set permissions after sudo creation
			chmodCmd := exec.Command("sudo", "chmod", "0777", povMetadataDirPath)
			if chmodErr := chmodCmd.Run(); chmodErr != nil {
				return fmt.Errorf("failed to set permissions on POV metadata directory: %v", chmodErr)
			}

			// Make sure the directory is fully accessible to all users
			chmodCmd = exec.Command("sudo", "chmod", "a+rwx", povMetadataDirPath)
			if chmodErr := chmodCmd.Run(); chmodErr != nil {
				log.Printf("Warning: failed to set a+rwx permissions: %v", chmodErr)
			}
		}
	}

	// Extract fuzzer name and sanitizer from fuzzer path
	fuzzerName := filepath.Base(fuzzerPath)
	dirParts := strings.Split(fuzzDir, "-")
	sanitizer := dirParts[len(dirParts)-1] // Last part should be the sanitizer

	// Generate unique identifier for this POV
	timestamp := time.Now().Format("20060102-150405")
	uniqueID := fmt.Sprintf("%s-%s", timestamp, uuid.New().String()[:8])

	// Save the fuzzer output to a file
	outputFileName := fmt.Sprintf("fuzzer_output_%s.txt", uniqueID)
	outputFilePath := filepath.Join(povMetadataDirPath, outputFileName)
	if err := os.WriteFile(outputFilePath, []byte(output), 0644); err != nil {
		// If permission denied, try using sudo
		if os.IsPermission(err) {
			log.Printf("Permission denied writing file, attempting with sudo: %s", outputFilePath)

			// Create a temporary file first
			tempFile := "/tmp/fuzzer_output_temp"
			if tempErr := os.WriteFile(tempFile, []byte(output), 0644); tempErr != nil {
				return fmt.Errorf("failed to write temporary file: %v", tempErr)
			}

			// Use sudo to move the temp file to the target location
			cmd := exec.Command("sudo", "cp", tempFile, outputFilePath)
			if cpErr := cmd.Run(); cpErr != nil {
				return fmt.Errorf("failed to copy file with sudo: %v", cpErr)
			}

			// Set permissions on the new file
			chmodCmd := exec.Command("sudo", "chmod", "0644", outputFilePath)
			if chmodErr := chmodCmd.Run(); chmodErr != nil {
				return fmt.Errorf("failed to set permissions on file: %v", chmodErr)
			}

			// Clean up temp file
			os.Remove(tempFile)
			return nil
		}
		return fmt.Errorf("failed to save fuzzer output: %v", err)
	}

	// Copy the blob file to the POV metadata directory
	blobFileName := fmt.Sprintf("test_blob_%s.bin", uniqueID)
	blobDestPath := filepath.Join(povMetadataDirPath, blobFileName)
	blobData, err := os.ReadFile(blobPath)
	if err != nil {
		return fmt.Errorf("failed to read blob file: %v", err)
	}
	if err := os.WriteFile(blobDestPath, blobData, 0644); err != nil {
		return fmt.Errorf("failed to save blob file: %v", err)
	}

	// Create the metadata
	metadata := POVMetadata{
		FuzzerOutput: outputFileName,
		BlobFile:     blobFileName,
		FuzzerName:   fuzzerName,
		Sanitizer:    sanitizer,
		ProjectName:  taskDetail.ProjectName,
	}

	// Save metadata to JSON file
	metadataFileName := fmt.Sprintf("pov_metadata_%s.json", uniqueID)
	metadataFilePath := filepath.Join(povMetadataDirPath, metadataFileName)
	metadataJSON, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metadata to JSON: %v", err)
	}
	if err := os.WriteFile(metadataFilePath, metadataJSON, 0644); err != nil {
		return fmt.Errorf("failed to save metadata file: %v", err)
	}

	log.Printf("Saved POV metadata to %s", metadataFilePath)
	return nil
}

// RunCrashTest tests if a crash file actually triggers a crash
func RunCrashTest(crashFile string, taskDetail models.TaskDetail, taskDir, projectDir string, fuzzerName string, sanitizer string) (bool, string, error) {
	uniqueBlobName := filepath.Base(crashFile)
	outDir := filepath.Join(taskDir, "fuzz-tooling", "build", "out", fmt.Sprintf("%s-%s", taskDetail.ProjectName, sanitizer))
	workDir := filepath.Join(taskDir, "fuzz-tooling", "build", "work", fmt.Sprintf("%s-%s", taskDetail.ProjectName, sanitizer))

	// Prepare docker command
	dockerArgs := []string{
		"run", "--rm",
		"--platform", "linux/amd64",
		"-e", "FUZZING_ENGINE=libfuzzer",
		"-e", fmt.Sprintf("SANITIZER=%s", sanitizer),
		// "-e", "UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1",
		"-e", "ARCHITECTURE=x86_64",
		"-e", fmt.Sprintf("PROJECT_NAME=%s", taskDetail.ProjectName),
		"-v", fmt.Sprintf("%s:/src/%s", projectDir, taskDetail.ProjectName),
		"-v", fmt.Sprintf("%s:/out", outDir),
		"-v", fmt.Sprintf("%s:/work", workDir),
		fmt.Sprintf("aixcc-afc/%s", taskDetail.ProjectName),
		fmt.Sprintf("/out/%s", fuzzerName),
		"-timeout=30",
		"-timeout_exitcode=99",
		fmt.Sprintf("/out/crashes/%s", uniqueBlobName),
	}

	// Create command
	cmd := exec.Command("docker", dockerArgs...)

	// Capture output
	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &outBuf

	// Log the command being executed
	log.Printf("Running: docker %s", strings.Join(dockerArgs, " "))

	// Run the command
	err := cmd.Run()
	output := outBuf.String()

	// Check for crash regardless of command error (libfuzzer exits with non-zero on crash)
	if err != nil && libfuzzer.IsCrashOutput(output) {
		log.Printf("CrashFile %s works!", crashFile)
		return true, output, nil
	}
	// If there was an error but no crash detected, it's an error
	if err != nil {
		return false, output, fmt.Errorf("error running fuzzer: %v", err)
	}
	log.Printf("CrashFile %s fails to trigger a crash!", crashFile)
	// No crash found
	return false, output, nil
}

// SaveAllCrashesAsPOVs processes all crash files in a directory and saves them as POVs
func SaveAllCrashesAsPOVs(crashesDir, taskDir, fuzzerPath, fuzzDir, projectDir string, output string, sanitizer string, taskDetail models.TaskDetail, fuzzerName string, povMetadataDir string) string {

	// Helper function to process crash files in a directory
	processCrashFiles := func(dir string) []string {
		var allCrashFiles []string

		// Try libFuzzer crash files
		libFuzzerPattern := path.Join(dir, "crash-*")
		log.Printf("Looking for libFuzzer crash files in: %s", libFuzzerPattern)

		if files, err := filepath.Glob(libFuzzerPattern); err == nil {
			allCrashFiles = append(allCrashFiles, files...)
		} else {
			log.Printf("Error finding libFuzzer crash files in %s: %v", dir, err)
		}

		// Try libFuzzer timeout files
		if os.Getenv("DETECT_TIMEOUT_CRASH") == "1" {
			libFuzzerPattern := path.Join(dir, "timeout-*")
			log.Printf("Looking for libFuzzer timeout files in: %s", libFuzzerPattern)

			if files, err := filepath.Glob(libFuzzerPattern); err == nil {
				allCrashFiles = append(allCrashFiles, files...)
			} else {
				log.Printf("Error finding libFuzzer timeout files in %s: %v", dir, err)
			}
		}

		return allCrashFiles
	}

	// Search in all directories
	var allFiles []string
	searchDirs := []string{crashesDir}
	for _, dir := range searchDirs {
		allFiles = append(allFiles, processCrashFiles(dir)...)
	}

	if len(allFiles) == 0 {
		log.Printf("No crash files found in crashes directory. Saving POV metadata with fuzzer output only...")

		// Create a temporary blob file with the output content
		tempBlobPath := filepath.Join(fuzzDir, "temp_crash_blob.bin")
		if err := os.WriteFile(tempBlobPath, []byte(output), 0644); err != nil {
			log.Printf("Error creating temporary blob file: %v", err)
			return ""
		}

		if err := SavePOVMetadata(taskDir, fuzzerPath, tempBlobPath, output, taskDetail, povMetadataDir); err != nil {
			log.Printf("Warning: Failed to save POV metadata: %v", err)
		}

		// Clean up the temporary file
		os.Remove(tempBlobPath)
		return ""
	}

	log.Printf("Found total of %d crash files across all directories", len(allFiles))
	crash_output := ""
	confirmedCount := 0
	maxConfirmed := 5 // Maximum number of confirmed crashes to process
	processedFiles := make([]string, 0, len(allFiles))

	// Process each crash file
	for i, crashFile := range allFiles {
		log.Printf("Processing crash file %d/%d: %s", i+1, len(allFiles), crashFile)
		//TODO: make sure crashFile will lead to crashes, if not skip it
		crashed, output, err := RunCrashTest(crashFile, taskDetail, taskDir, projectDir, fuzzerName, sanitizer)
		if err != nil {
			log.Printf("Error running crash test for %s: %v", crashFile, err)
			continue
		}
		processedFiles = append(processedFiles, crashFile)

		// If it crashed, save the POV metadata
		if crashed {
			confirmedCount++
			log.Printf("Confirmed crash for %s with fuzzer %s", crashFile, fuzzerName)
			crash_output = output
			if err := SavePOVMetadata(taskDir, fuzzerPath, crashFile, output, taskDetail, povMetadataDir); err != nil {
				log.Printf("Warning: Failed to save POV metadata for crash file %s: %v", crashFile, err)
			}
			// Break the loop if we've reached the maximum number of confirmed crashes
			if confirmedCount >= maxConfirmed {
				log.Printf("Reached maximum number of confirmed crashes (%d). Stopping processing.", maxConfirmed)
				break
			}
		}
	}
	log.Printf("Processed %d/%d crash files, found %d confirmed crashes",
	          len(processedFiles), len(allFiles), confirmedCount)
	// Delete all crash files after processing
	// log.Printf("Cleaning up crash files...")
	var deleteErrors int = 0

	// Delete all files in the crashesDir
	filesToDelete, _ := filepath.Glob(filepath.Join(crashesDir, "*"))
	for _, file := range filesToDelete {
		// Check if it's a regular file, not a directory
		fileInfo, err := os.Stat(file)
		if err != nil || fileInfo.IsDir() {
			continue
		}

		if err := os.Remove(file); err != nil {
			// Try with sudo if permission denied
			if os.IsPermission(err) {
				cmd := exec.Command("sudo", "rm", file)
				if err := cmd.Run(); err != nil {
					log.Printf("Failed to delete crash file %s: %v", file, err)
					deleteErrors++
				}
			} else {
				log.Printf("Failed to delete crash file %s: %v", file, err)
				deleteErrors++
			}
		}
	}

	if deleteErrors > 0 {
		log.Printf("Warning: Failed to delete %d crash files", deleteErrors)
	}

	return crash_output
}

// ─────────────────────────────────────────────────────────────────────────────
// POV Submission and Statistics Functions
// ─────────────────────────────────────────────────────────────────────────────

// POVSubmissionParams contains all parameters needed for POV submission
type POVSubmissionParams struct {
	CrashesDir            string
	FuzzDir               string
	TaskDir               string
	ProjectDir            string
	Sanitizer             string
	TaskDetail            models.TaskDetail
	Fuzzer                string
	Output                string
	VulnSignature         string
	SubmissionEndpoint    string
	WorkerIndex           string
	CompetitionClient     *competition.Client
	POVMetadataDir        string
	UnharnessedFuzzerSrc  map[string]string
}

// GenerateCrashSignatureAndSubmit generates a crash signature and submits it
func GenerateCrashSignatureAndSubmit(params POVSubmissionParams) error {

	// Read crash data
	crashData := helpers.ReadCrashFile(params.FuzzDir, params.POVMetadataDir)
	// Skip submission if crash file is empty
	if len(crashData) == 0 {
		log.Printf("Libfuzzer skipping submission for empty crash input data")
		return nil
	}

	encodedCrashData := base64.StdEncoding.EncodeToString(crashData)


	// 2. Submit to either the submission service (if in worker mode) or directly to the Competition API
	if params.SubmissionEndpoint != "" && params.WorkerIndex != "" {
		// We're in worker mode, submit to the submission service
		log.Printf("Libfuzzer Worker %s submitting POV for fuzzer %s with sanitizer %s to submission service",
		            params.WorkerIndex, params.Fuzzer, params.Sanitizer)

		// Extract crash trace from the output
		crashTrace := extractCrashTrace(params.Output)
		if crashTrace != "" {
			//check crash trace contains error in application code, not purely fuzzer
			//code pattern not totally reliable
			if strings.Contains(crashTrace, params.TaskDetail.ProjectName) || strings.Contains(crashTrace, "apache")  || strings.Contains(crashTrace, "org") {
				log.Printf("Valid Crash Trace: %s", crashTrace)
			} else {
				//TODO ask AI to check
				log.Printf("Libfuzzer skipping submission due to invalid crash trace (TODO better check): %s", crashTrace)
				return nil
			}
		} else {
			log.Printf("Libfuzzer skipping submission due to empty crash trace!")
			return nil
		}
		// Create the submission payload
		submission := map[string]interface{}{
			"task_id": params.TaskDetail.TaskID.String(),
			"architecture": "x86_64",
			"engine": "libfuzzer",
			"fuzzer_name": params.Fuzzer,
			"sanitizer": params.Sanitizer,
			"testcase": encodedCrashData,
			"signature": params.Fuzzer+"-"+params.VulnSignature,
			"strategy": "libfuzzer",
			"crash_trace": crashTrace,
		}


		var submissionURL string
		if !params.TaskDetail.HarnessesIncluded {
			submissionURL = fmt.Sprintf("%s/v1/task/%s/freeform/pov/", params.SubmissionEndpoint, params.TaskDetail.TaskID.String())
			submission["strategy"] = "libfuzzer-freeform"
			if srcPath, ok := params.UnharnessedFuzzerSrc[params.TaskDetail.TaskID.String()]; ok {
				submission["fuzzer_file"] = srcPath
				if data, err := os.ReadFile(srcPath); err == nil {
					submission["fuzzer_source"] = string(data)
				} else {
					log.Printf("Warning: failed to read fuzzer source %s: %v", srcPath, err)
					submission["fuzzer_source"] = ""
				}
			} else {
				submission["fuzzer_file"]   = ""
				submission["fuzzer_source"] = ""
				log.Printf("No unharnessed fuzzer source recorded for task %s", params.TaskDetail.TaskID)
			}

			log.Printf("Submitting to freeform endpoint: %s", submissionURL)
		} else{
			submissionURL = fmt.Sprintf("%s/v1/task/%s/pov/", params.SubmissionEndpoint, params.TaskDetail.TaskID.String())
			// Log the submission endpoint for debugging
			log.Printf("Submitting to endpoint: %s",submissionURL)
		}

		// Marshal the submission
		submissionJSON, err := json.Marshal(submission)
		if err != nil {
			return fmt.Errorf("failed to marshal submission: %v", err)
		}

		// Create HTTP client
		client := &http.Client{
			Timeout: 60 * time.Second,
		}

		// Implement retry logic with exponential backoff
		maxRetries := 3
		var lastErr error
		var resp *http.Response

		for attempt := 1; attempt <= maxRetries; attempt++ {
			log.Printf("Submission attempt %d of %d for fuzzer %s with sanitizer %s",
			            attempt, maxRetries, params.Fuzzer, params.Sanitizer)


			// Create the request
			req, err := http.NewRequest("POST", submissionURL, bytes.NewBuffer(submissionJSON))
			if err != nil {
				return fmt.Errorf("failed to create submission request: %v", err)
			}

			// Set headers
			req.Header.Set("Content-Type", "application/json")

			// Get API credentials from environment
			apiKeyID := os.Getenv("COMPETITION_API_KEY_ID")
			apiToken := os.Getenv("COMPETITION_API_KEY_TOKEN")
			if apiKeyID != "" && apiToken != "" {
				req.SetBasicAuth(apiKeyID, apiToken)
			} else {
				apiKeyID = os.Getenv("CRS_KEY_ID")
				apiToken = os.Getenv("CRS_KEY_TOKEN")
				req.SetBasicAuth(apiKeyID, apiToken)
			}

			// Send the request
			resp, err = client.Do(req)
			// If successful, break out of the retry loop
			if err == nil {
				break
			}

			// Store the last error
			lastErr = err
			log.Printf("Attempt %d failed: %v", attempt, err)

			// Don't sleep after the last attempt
			if attempt < maxRetries {
				// Exponential backoff: 1s, 2s, 4s, etc.
				backoffTime := time.Duration(1<<(attempt-1)) * time.Second
				log.Printf("Retrying in %v...", backoffTime)
				time.Sleep(backoffTime)
			}
		}

		// If all attempts failed, return the last error
		if lastErr != nil {
			log.Printf("All %d submission attempts failed: %v", maxRetries, lastErr)
			return fmt.Errorf("failed to submit to submission service after %d attempts: %v",
			                    maxRetries, lastErr)
		}

		defer resp.Body.Close()

		// Check response
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			body, _ := io.ReadAll(resp.Body)
			log.Printf("submission service returned non-OK status: %d, body: %s",
			resp.StatusCode, string(body))
			return fmt.Errorf("submission service returned non-OK status: %d, body: %s",
			                    resp.StatusCode, string(body))
		}

		log.Printf("Successfully submitted POV to submission service")
	} else {
		// 3. Submit to Competition API using the client
		log.Printf("Submitting POV for fuzzer %s with sanitizer %s", params.Fuzzer, params.Sanitizer)
		_, err := params.CompetitionClient.SubmitPOV(
			params.TaskDetail.TaskID.String(),
			params.Fuzzer,
			params.Sanitizer,
			crashData,
		)
		if err != nil {
			return fmt.Errorf("failed to submit POV: %v", err)
		}
	}

	return nil
}

// GetValidPOVs retrieves valid POVs from the submission service
func GetValidPOVs(taskID string, submissionEndpoint string) ([]models.POVSubmission, error) {
	url := fmt.Sprintf("%s/v1/task/%s/valid_povs/", submissionEndpoint, taskID)
	//TODO set headers
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("non-200 response from submission server: %d, body: %s", resp.StatusCode, body)
	}

	var response models.TaskValidPOVsResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}

	return response.POVs, nil
}

// GetPOVStatsFromSubmissionService retrieves POV statistics from the submission service
func GetPOVStatsFromSubmissionService(taskID string, submissionEndpoint string) (int, int, error) {

	url := fmt.Sprintf("%s/v1/task/%s/pov_stats/", submissionEndpoint, taskID)
	// Create the HTTP request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("Error creating getPOVStats request for taskID %s: %v", taskID, err)
		return 0,0, err
	}

	{
		// Set headers
		req.Header.Set("Content-Type", "application/json")

		// Get API credentials from environment
		apiKeyID := os.Getenv("COMPETITION_API_KEY_ID")
		apiToken := os.Getenv("COMPETITION_API_KEY_TOKEN")
		if apiKeyID != "" && apiToken != "" {
			req.SetBasicAuth(apiKeyID, apiToken)
		}


// Increase the timeout for the HTTP request
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second) // Increase to 3 minutes
defer cancel()
req = req.WithContext(ctx)

// Create a client with custom timeout settings
client := &http.Client{
	Timeout: 180 * time.Second, // Set client timeout to match context timeout
	Transport: &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second, // Connection timeout
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
	log.Printf("Error getting POV statistics at submission service: %v", err)
	// Consider implementing a retry mechanism here
	if ctx.Err() == context.DeadlineExceeded {
		log.Printf("Request timed out, may need to increase timeout or check server load")
	}
	return 0,0, err
}
defer resp.Body.Close()

		// Check response
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			log.Printf("Submission service returned non-200 status: %d, body: %s", resp.StatusCode, string(body))
			return 0,0, fmt.Errorf("Submission service returned non-200 status: %d, body: %s", resp.StatusCode, string(body))
		} else {

			var response models.POVStatsResponse
			if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
				return 0,0, err
			}

			return response.Count, response.PatchCount, nil
		}

	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility Functions
// ─────────────────────────────────────────────────────────────────────────────

// GetSourceCode retrieves source code for a given task and file path
func GetSourceCode(taskID, filePath string) (string, error) {
	// Implement based on your source code access mechanism
	// This might involve accessing a local file system, making an API call, etc.
	// For now, we'll return a placeholder
	return "", fmt.Errorf("source code access not implemented")
}

// FindProjectDir finds the project directory for a given task
func FindProjectDir(taskID string, workDir string, tasks map[string]*models.TaskDetail) (string, error) {
	// Get task details to obtain focus
	taskDetail, exists := tasks[taskID]

	if !exists {
		return "", fmt.Errorf("task %s not found", taskID)
	}

	// Search for directories with pattern taskID-*
	pattern := filepath.Join(workDir, taskID+"-*")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return "", fmt.Errorf("error searching for task directory: %v", err)
	}

	if len(matches) == 0 {
		return "", fmt.Errorf("no task directory found for task %s", taskID)
	}

	// Find the most recent directory (if multiple exist)
	var latestDir string
	var latestTime time.Time

	for _, dir := range matches {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}

		if latestDir == "" || info.ModTime().After(latestTime) {
			latestDir = dir
			latestTime = info.ModTime()
		}
	}

	if latestDir == "" {
		return "", fmt.Errorf("no valid task directory found for task %s", taskID)
	}

	// Construct the project directory path
	projectDir := filepath.Join(latestDir, taskDetail.Focus)

	// Verify the directory exists
	if _, err := os.Stat(projectDir); os.IsNotExist(err) {
		return "", fmt.Errorf("project directory %s does not exist", projectDir)
	}

	return projectDir, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal Helper Functions
// ─────────────────────────────────────────────────────────────────────────────

// extractCrashTrace extracts the crash trace from the output
func extractCrashTrace(output string) string {
	var crashTrace string

	// Check for UndefinedBehaviorSanitizer errors
	runtimeErrorRegex := regexp.MustCompile(`(.*runtime error:.*)`)
	ubsanMatch := runtimeErrorRegex.FindStringSubmatch(output)

	if len(ubsanMatch) > 1 {
		// Found UBSan error
		ubsanError := strings.TrimSpace(ubsanMatch[1])
		crashTrace = "UndefinedBehaviorSanitizer Error: " + ubsanError + "\n\n"

		// Extract stack trace - lines starting with #
		stackRegex := regexp.MustCompile(`(?m)(#\d+.*)`)
		stackMatches := stackRegex.FindAllString(output, -1)

		if len(stackMatches) > 0 {
			crashTrace += "Stack Trace:\n"
			for _, line := range stackMatches {
				crashTrace += line + "\n"
			}
		}

		// Extract summary
		summaryRegex := regexp.MustCompile(`SUMMARY: UndefinedBehaviorSanitizer: (.*)`)
		summaryMatch := summaryRegex.FindStringSubmatch(output)
		if len(summaryMatch) > 1 {
			crashTrace += "\nSummary: " + summaryMatch[1] + "\n"
		}
	} else {
		// Fall back to the original ERROR: pattern
		errorIndex := strings.Index(output, "ERROR:")
		if errorIndex != -1 {
			crashTrace = output[errorIndex:]
		}
	}

	// Limit the size of the crash trace if it's too large
	const maxTraceSize = 10000
	if len(crashTrace) > maxTraceSize {
		crashTrace = crashTrace[:maxTraceSize] + "... (truncated)"
	}

	return crashTrace
}

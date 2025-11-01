package services

import (
	"bufio"
	"bytes"
	"context"
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
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"crs/internal/competition"
	"crs/internal/config"
	"crs/internal/executor"
	"crs/internal/models"
	"crs/internal/utils/build"
	"crs/internal/utils/environment"
	"crs/internal/utils/fuzzer"
	"crs/internal/utils/helpers"
)

// WorkerCRSService implements CRSService for worker mode (task execution)
type WorkerCRSService struct {
	cfg                     *config.Config
	workDir                 string
	povMetadataDir          string
	povMetadataDir0         string
	povAdvcancedMetadataDir string
	patchWorkDir            string
	submissionEndpoint      string
	workerIndex             string
	analysisServiceUrl      string
	model                   string
	competitionClient       *competition.Client
	unharnessedFuzzerSrc    sync.Map
	workerPort              int

	cpuUsageFn      func() (float64, error)
	processTaskFunc func(string, models.TaskDetail, models.Task) error
}

// NewWorkerService creates a new worker service instance
func NewWorkerService(cfg *config.Config) CRSService {
	// Get API configuration from config
	apiEndpoint := os.Getenv("COMPETITION_API_ENDPOINT")
	if apiEndpoint == "" {
		apiEndpoint = "http://localhost:7081"
	}

	// Define default work directory
	workDir := "/crs-workdir"
	if envWorkDir := os.Getenv("CRS_WORKDIR"); envWorkDir != "" {
		workDir = envWorkDir
	}

	// Create the work directory if it doesn't exist
	if err := helpers.EnsureWorkDir(workDir); err != nil {
		log.Printf("Warning: Could not create work directory at %s: %v", workDir, err)

		homeDir, err := os.UserHomeDir()
		if err == nil {
			workDir = filepath.Join(homeDir, "crs-workdir")
			log.Printf("Trying fallback work directory: %s", workDir)

			if err := helpers.EnsureWorkDir(workDir); err != nil {
				log.Printf("Warning: Could not create fallback work directory: %v", err)
				tempDir, err := os.MkdirTemp("", "crs-workdir-")
				if err == nil {
					workDir = tempDir
					log.Printf("Using temporary directory as work directory: %s", workDir)
				} else {
					workDir = "."
					log.Printf("Warning: Using current directory as work directory")
				}
			}
		} else {
			workDir = "."
			log.Printf("Warning: Using current directory as work directory")
		}
	}

	service := &WorkerCRSService{
		cfg:                     cfg,
		workDir:                 workDir,
		competitionClient:       competition.NewClient(apiEndpoint, cfg.Auth.KeyID, cfg.Auth.Token),
		povMetadataDir:          "successful_povs",
		povMetadataDir0:         "successful_povs_0",
		povAdvcancedMetadataDir: "successful_povs_advanced",
		patchWorkDir:            "patch_workspace",
		model:                   cfg.AI.Model,
		workerIndex:             cfg.Worker.Index,
		submissionEndpoint:      cfg.Services.SubmissionURL,
		analysisServiceUrl:      cfg.Services.AnalysisURL,
		workerPort:              cfg.Worker.Port,
	}

	service.cpuUsageFn = getAverageCPUUsage
	service.processTaskFunc = service.processTask

	return service
}

// GetStatus returns worker status
func (s *WorkerCRSService) GetStatus() models.Status {
	// Workers can report their current status
	return models.Status{
		Ready: true,
		State: models.StatusState{
			Tasks: models.StatusTasksState{},
		},
	}
}

// SubmitLocalTask is not supported in worker mode
func (s *WorkerCRSService) SubmitLocalTask(taskPath string) error {
	return errNotSupportedInWorkerMode
}

// SubmitTask is not supported in worker mode
func (s *WorkerCRSService) SubmitTask(task models.Task) error {
	return errNotSupportedInWorkerMode
}

// SubmitWorkerTask implements worker task submission
func (s *WorkerCRSService) SubmitWorkerTask(task models.WorkerTask) error {
	if len(task.Tasks) == 0 {
		return fmt.Errorf("no tasks provided")
	}

	// Extract task details
	td := task.Tasks[0]
	taskID := td.TaskID.String()

	// Check CPU usage
	avgCPU, err := s.cpuUsageFn()
	if err != nil {
		log.Printf("Warning: could not get CPU usage: %v", err)
	} else {
		log.Printf("Average CPU usage: %.2f%%", avgCPU)
		if avgCPU > 80.0 && s.hasActiveWorkTasks() {
			return fmt.Errorf("system is too busy (CPU usage %.2f%% > 80%%), rejecting new task", avgCPU)
		}
		if avgCPU < 50.0 {
			// Accept the task regardless of taskID
			log.Printf("CPU usage low (%.2f%%), accepting task %s", avgCPU, taskID)
			go s.startWorkerTask(td, task, taskID)
			log.Printf("Worker task %s with fuzzer %s accepted for processing", taskID, task.Fuzzer)
			return nil
		}
	}

	// Try to acquire the lock and check if this task is already running
	workerTaskMutex.Lock()
	if activeWorkerTasks[taskID] {
		workerTaskMutex.Unlock()
		log.Printf("Worker is already processing task %s w/ fuzzer %s. New task will be rejected.", taskID, task.Fuzzer)
		return fmt.Errorf("worker is already processing task %s w/ fuzzer %s", taskID, task.Fuzzer)
	}
	// Mark this task as active
	activeWorkerTasks[taskID] = true
	workerTaskMutex.Unlock()

	go s.startWorkerTask(td, task, taskID)

	// Return immediately to allow handler to respond with StatusAccepted
	log.Printf("Worker task %s with fuzzer %s accepted for processing", taskID, task.Fuzzer)
	return nil
}

// startWorkerTask starts processing a worker task
func (s *WorkerCRSService) startWorkerTask(td models.TaskDetail, task models.WorkerTask, taskID string) {
	defer func() {
		workerTaskMutex.Lock()
		delete(activeWorkerTasks, taskID)
		workerTaskMutex.Unlock()

		if r := recover(); r != nil {
			log.Printf("Recovered from panic in worker task %s: %v", taskID, r)
			debug.PrintStack()
		}
	}()

	log.Printf("Starting worker task processing for task %s with fuzzer %s", taskID, task.Fuzzer)

	// Process the task using worker's processTask method
	if err := s.processTaskFunc(task.Fuzzer, td, models.Task{
		MessageID:   task.MessageID,
		MessageTime: task.MessageTime,
		Tasks:       []models.TaskDetail{td},
	}); err != nil {
		log.Printf("Error processing worker task %s: %v", taskID, err)
	} else {
		log.Printf("Successfully completed worker task %s", taskID)
	}
}

// hasActiveWorkTasks checks if there are any active worker tasks
func (s *WorkerCRSService) hasActiveWorkTasks() bool {
	workerTaskMutex.Lock()
	defer workerTaskMutex.Unlock()

	return len(activeWorkerTasks) > 0
}

// IsWorkerBusy returns whether the worker is busy and list of active task IDs
func (s *WorkerCRSService) IsWorkerBusy() (bool, []string) {
	workerTaskMutex.Lock()
	defer workerTaskMutex.Unlock()

	var activeIDs []string
	for taskID := range activeWorkerTasks {
		activeIDs = append(activeIDs, taskID)
	}
	return len(activeWorkerTasks) > 0, activeIDs
}

// CancelTask is not supported in worker mode
func (s *WorkerCRSService) CancelTask(taskID string) error {
	return errNotSupportedInWorkerMode
}

// CancelAllTasks is not supported in worker mode
func (s *WorkerCRSService) CancelAllTasks() error {
	return errNotSupportedInWorkerMode
}

// SubmitSarif handles SARIF broadcast submission from worker
// TODO: SARIF workflow to be implemented later
func (s *WorkerCRSService) SubmitSarif(sarifBroadcast models.SARIFBroadcast) error {
	return errNotSupportedInWorkerMode
}

// HandleSarifBroadcastWorker handles SARIF broadcasts received by worker
func (s *WorkerCRSService) HandleSarifBroadcastWorker(broadcastWorker models.SARIFBroadcastDetailWorker) error {
	taskID := broadcastWorker.Broadcast.TaskID.String()
	broadcast := broadcastWorker.Broadcast

	log.Printf("Worker received SARIF broadcast for task %s, SARIF ID %s", taskID, broadcast.SarifID)

	// Process the SARIF report for this worker's assigned fuzzer
	return s.processSarif(taskID, broadcast)
}

// SetWorkerIndex sets the worker index
func (s *WorkerCRSService) SetWorkerIndex(index string) {
	s.workerIndex = index
}

// SetSubmissionEndpoint sets the submission endpoint
func (s *WorkerCRSService) SetSubmissionEndpoint(endpoint string) {
	s.submissionEndpoint = endpoint
}

// SetAnalysisServiceUrl sets the analysis service URL
func (s *WorkerCRSService) SetAnalysisServiceUrl(url string) {
	s.analysisServiceUrl = url
}

// GetWorkDir returns the work directory
func (s *WorkerCRSService) GetWorkDir() string {
	return s.workDir
}

// processTask processes a single task detail (worker executes directly)
func (s *WorkerCRSService) processTask(myFuzzer string, taskDetail models.TaskDetail, fullTask models.Task) error {
	taskID := taskDetail.TaskID.String()
	log.Printf("Processing task %s", taskID)

	// Create task directory with unique name
	timestamp := time.Now().Format("20060102-150405")
	taskDir := path.Join(s.workDir, fmt.Sprintf("%s-%s", taskID, timestamp))

	// If fuzzer path is provided, use its parent directory up to fuzz-tooling/build/out
	if myFuzzer != "" {
		// Find the index of "fuzz-tooling/" in the fuzzer path
		fuzzToolingIndex := strings.Index(myFuzzer, "fuzz-tooling/")
		if fuzzToolingIndex != -1 {
			// Extract the base directory (everything before fuzz-tooling/build/out)
			taskDir = myFuzzer[:fuzzToolingIndex]
			// Remove trailing slash if present
			taskDir = strings.TrimRight(taskDir, "/")
		}
	}

	// Get absolute paths
	absTaskDir, err := filepath.Abs(taskDir)
	if err != nil {
		return fmt.Errorf("failed to get absolute task dir path: %v", err)
	}

	projectDir := path.Join(absTaskDir, taskDetail.Focus)
	dockerfilePath := path.Join(absTaskDir, "fuzz-tooling/projects", taskDetail.ProjectName)
	dockerfileFullPath := path.Join(dockerfilePath, "Dockerfile")
	fuzzerDir := path.Join(taskDir, "fuzz-tooling/build/out", taskDetail.ProjectName)

	log.Printf("Project dir: %s", projectDir)
	log.Printf("Dockerfile: %s", dockerfileFullPath)

	// Use executor package to prepare environment
	params := environment.PrepareEnvironmentParams{
		MyFuzzer:           &myFuzzer,
		TaskDir:            taskDir,
		TaskDetail:         taskDetail,
		DockerfilePath:     dockerfilePath,
		DockerfileFullPath: dockerfileFullPath,
		FuzzerDir:          fuzzerDir,
		ProjectDir:         projectDir,
		FuzzerBuilder:      s.buildFuzzersDocker,
		FindFuzzers:        fuzzer.FindFuzzers,
		SanitizerOverride:  s.cfg.Fuzzer.GetSanitizerList(), // Use config sanitizers if set
	}

	cfg, sanitizerDirs, err := environment.PrepareEnvironment(params)
	if err != nil {
		return err
	}

	// Collect all fuzzers from all sanitizer builds
	var allFuzzers []string
	sanitizerDirsCopy := make([]string, len(sanitizerDirs))
	copy(sanitizerDirsCopy, sanitizerDirs)

	// Now use the copy to find fuzzers
	for _, sdir := range sanitizerDirsCopy {
		fuzzers, err := fuzzer.FindFuzzers(sdir)
		if err != nil {
			log.Printf("Warning: failed to find fuzzers in %s: %v", sdir, err)
			continue
		}

		for _, fz := range fuzzers {
			fuzzerPath := filepath.Join(sdir, fz)
			allFuzzers = append(allFuzzers, fuzzerPath)
		}
	}

	if len(allFuzzers) == 0 {
		log.Printf("No fuzzers found after building all sanitizers")
		return nil
	}

	// Filter fuzzers
	const MAX_FUZZERS = 10
	if true {
		var allFilteredFuzzers []string
		for _, fuzzerPath := range allFuzzers {
			if strings.Contains(fuzzerPath, "-address/") || (strings.Contains(fuzzerPath, "-memory/") && len(allFuzzers) < MAX_FUZZERS) {
				allFilteredFuzzers = append(allFilteredFuzzers, fuzzerPath)
			}
		}
		allFuzzers = helpers.SortFuzzersByGroup(allFilteredFuzzers)
	}

	log.Printf("Found %d fuzzers: %v", len(allFuzzers), allFuzzers)

	// Process the task using executor package
	execParams := executor.TaskExecutionParams{
		Fuzzer:                   myFuzzer,
		TaskDir:                  taskDir,
		TaskDetail:               taskDetail,
		Task:                     fullTask,
		ProjectConfig:            cfg,
		AllFuzzers:               allFuzzers,
		SubmissionEndpoint:       s.submissionEndpoint,
		POVMetadataDir:           s.povMetadataDir,
		POVMetadataDir0:          s.povMetadataDir0,
		POVAdvancedMetadataDir:   s.povAdvcancedMetadataDir,
		Model:                    s.model,
		WorkerIndex:              s.workerIndex,
		AnalysisServiceUrl:       s.analysisServiceUrl,
		UnharnessedFuzzerSrcPath: "",
		StrategyConfig:           &s.cfg.Strategy,
		FuzzerConfig:             &s.cfg.Fuzzer,
		Sanitizer:                s.cfg.Fuzzer.PreferredSanitizer,
	}

	if err := executor.ExecuteFuzzingTask(execParams); err != nil {
		log.Printf("Processing task %s: %v fuzzer: %s", taskDetail.TaskID, err, myFuzzer)
	}

	return nil
}

// buildFuzzersDocker builds fuzzers using Docker for the specified sanitizer
func (s *WorkerCRSService) buildFuzzersDocker(myFuzzer *string, taskDir, projectDir, sanitizerDir string, sanitizer string, language string, taskDetail models.TaskDetail) error {
	// Create a sanitizer-specific copy of the project directory
	sanitizerProjectDir := fmt.Sprintf("%s-%s", projectDir, sanitizer)

	// Create the directory if it doesn't exist
	if err := os.MkdirAll(sanitizerProjectDir, 0755); err != nil {
		return fmt.Errorf("failed to create sanitizer-specific project directory: %v", err)
	}

	// Copy the project files to the sanitizer-specific directory
	cpCmd := exec.Command("cp", "-r", fmt.Sprintf("%s/.", projectDir), sanitizerProjectDir)
	log.Printf("Copying project files to sanitizer-specific directory: %s", cpCmd.String())
	if err := cpCmd.Run(); err != nil {
		return fmt.Errorf("failed to copy project files to sanitizer-specific directory: %v", err)
	}

	log.Printf("Created sanitizer-specific project directory: %s", sanitizerProjectDir)

	// Check for build.patch in the project's directory
	projectToolingDir := filepath.Join(taskDir, "fuzz-tooling", "projects", taskDetail.ProjectName)
	buildPatchPath := filepath.Join(projectToolingDir, "build.patch")

	// If build.patch exists, copy it to both the root and project subdirectory in the sanitizer directory
	if _, err := os.Stat(buildPatchPath); err == nil {
		log.Printf("Found build.patch at %s", buildPatchPath)

		// Copy to the root of the sanitizer directory
		rootPatchPath := filepath.Join(sanitizerProjectDir, "build.patch")
		cpRootPatchCmd := exec.Command("cp", buildPatchPath, rootPatchPath)
		if err := cpRootPatchCmd.Run(); err != nil {
			log.Printf("Warning: Failed to copy build.patch to root of sanitizer directory: %v", err)
		} else {
			log.Printf("Copied build.patch to %s", rootPatchPath)
		}

		// Also copy to the project subdirectory within the sanitizer directory
		projectSubdir := filepath.Join(sanitizerProjectDir, taskDetail.ProjectName)
		if err := os.MkdirAll(projectSubdir, 0755); err != nil {
			log.Printf("Warning: Failed to create project subdirectory in sanitizer directory: %v", err)
		} else {
			projectPatchPath := filepath.Join(projectSubdir, "build.patch")
			cpProjectPatchCmd := exec.Command("cp", buildPatchPath, projectPatchPath)
			if err := cpProjectPatchCmd.Run(); err != nil {
				log.Printf("Warning: Failed to copy build.patch to project subdirectory: %v", err)
			} else {
				log.Printf("Copied build.patch to %s", projectPatchPath)
			}
		}
	}

	if *myFuzzer == UNHARNESSED && sanitizer != "coverage" {
		log.Printf("Handling unharnessed task: %s", *myFuzzer)
		cloneOssFuzzAndMainRepoOnce(taskDir, taskDetail.ProjectName, sanitizerDir)

		newFuzzerSrcPath, newFuzzerPath, err := generateFuzzerForUnharnessedTask(
			taskDir,
			taskDetail.Focus,
			sanitizerDir,
			taskDetail.ProjectName,
			sanitizer,
		)
		if err != nil {
			log.Printf("Failed to generate fuzzer: %v", err)
		} else {
			s.unharnessedFuzzerSrc.Store(taskDetail.TaskID.String(), newFuzzerSrcPath)
			log.Printf("New fuzzer source: %s", newFuzzerSrcPath)

			*myFuzzer = newFuzzerPath
			log.Printf("New fuzzer generated: %s", *myFuzzer)
		}
	} else {
		// For both Java and C tasks on worker
		if true {
			build.BuildAFCFuzzers(taskDir, sanitizer, taskDetail.ProjectName, sanitizerProjectDir, sanitizerDir)
		} else {
			workDir := filepath.Join(taskDir, "fuzz-tooling", "build", "work", fmt.Sprintf("%s-%s", taskDetail.ProjectName, sanitizer))

			cmdArgs := []string{
				"run",
				"--privileged",
				"--shm-size=8g",
				"--platform", "linux/amd64",
				"--rm",
				"-e", "FUZZING_ENGINE=libfuzzer",
				"-e", fmt.Sprintf("SANITIZER=%s", sanitizer),
				"-e", "ARCHITECTURE=x86_64",
				"-e", fmt.Sprintf("PROJECT_NAME=%s", taskDetail.ProjectName),
				"-e", "HELPER=True",
				"-e", fmt.Sprintf("FUZZING_LANGUAGE=%s", language),
				"-v", fmt.Sprintf("%s:/src/%s", sanitizerProjectDir, taskDetail.ProjectName),
				"-v", fmt.Sprintf("%s:/out", sanitizerDir),
				"-v", fmt.Sprintf("%s:/work", workDir),
				"-t", fmt.Sprintf("aixcc-afc/%s", taskDetail.ProjectName),
			}

			buildCmd := exec.Command("docker", cmdArgs...)

			var buildOutput bytes.Buffer
			buildCmd.Stdout = &buildOutput
			buildCmd.Stderr = &buildOutput

			log.Printf("Running Docker build for sanitizer=%s, project=%s\nCommand: %v",
				sanitizer, taskDetail.ProjectName, buildCmd.Args)

			if err := buildCmd.Run(); err != nil {
				log.Printf("Build fuzzer output:\n%s", buildOutput.String())
				return fmt.Errorf("failed to build fuzzers with sanitizer=%s: %v\nOutput: %s",
					sanitizer, err, buildOutput.String())
			}
		}
	}
	return nil
}

// ============================================================================
// SARIF Processing Methods
// ============================================================================

func (s *WorkerCRSService) processSarif(taskID string, broadcast models.SARIFBroadcastDetail) error {
	log.Printf("Worker processing SARIF report for task %s, SARIF ID %s", taskID, broadcast.SarifID)

	// 0. save Sarif Broadcast
	helpers.SaveSarifBroadcast(s.workDir, taskID, broadcast)

	// 1. Extract and validate the SARIF report
	sarifData, err := helpers.ExtractSarifData(broadcast.SARIF)
	if err != nil {
		return fmt.Errorf("failed to extract SARIF data: %w", err)
	}

	// 2. Analyze the SARIF report to identify vulnerabilities
	vulnerabilities, err := helpers.AnalyzeSarifVulnerabilities(sarifData)
	if err != nil {
		return fmt.Errorf("failed to analyze vulnerabilities: %w", err)
	}

	if len(vulnerabilities) == 0 {
		log.Printf("No vulnerabilities found in SARIF report for task %s", taskID)
		return nil
	}

	log.Printf("Found %d vulnerabilities in SARIF report for task %s", len(vulnerabilities), taskID)

	helpers.ShowVulnerabilityDetail(taskID, vulnerabilities)

	// Worker directly runs POV strategies for the SARIF report
	// TODO: Implement actual POV strategy execution
	log.Printf("TODO: Worker needs to run POV strategies for task %s", taskID)

	return nil
}

func (s *WorkerCRSService) checkIfSarifValid(taskID string, broadcast models.SARIFBroadcastDetail) (bool, error) {

	broadcastJSON, err := json.Marshal(broadcast)
	if err != nil {
		log.Printf("Error json.Marshal for broadcast SarifID %s: %v", broadcast.SarifID, err)
		return false, err
	}

	url := fmt.Sprintf("%s/v1/sarifx/%s/%s/", s.submissionEndpoint, taskID, broadcast.SarifID)
	// Create the HTTP request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(broadcastJSON))
	if err != nil {
		log.Printf("Error creating request for broadcast.SarifID %s: %v", broadcast.SarifID, err)
		return false, err
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
		ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second) // Increase to 3 minutes
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
			log.Printf("Error checking broadcast validity at submission service: %v", err)
			// Consider implementing a retry mechanism here
			if ctx.Err() == context.DeadlineExceeded {
				log.Printf("Request timed out, may need to increase timeout or check server load")
			}
			return false, err
		}
		defer resp.Body.Close()

		// Check response
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			log.Printf("Submission service returned non-200 status: %d, body: %s", resp.StatusCode, string(body))
			return false, fmt.Errorf("Submission service returned non-200 status: %d, body: %s", resp.StatusCode, string(body))
		} else {

			var response models.SarifValidResponse
			if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
				return false, err
			}

			return response.IsValid, nil
		}

	}
}

func (s *WorkerCRSService) checkIfSarifInValid(taskID string, ctxs []models.CodeContext, broadcast models.SARIFBroadcastDetail) (int, error) {

	payload := struct {
		Broadcast models.SARIFBroadcastDetail `json:"broadcast"`
		Contexts  []models.CodeContext        `json:"contexts"`
	}{
		Broadcast: broadcast,
		Contexts:  ctxs,
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Error json.Marshal for payload with SarifID %s: %v", broadcast.SarifID, err)
		return 0, err
	}

	url := fmt.Sprintf("%s/v1/sarifx/check_invalid/%s/%s/", s.submissionEndpoint, taskID, broadcast.SarifID)
	// Create the HTTP request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payloadJSON))
	if err != nil {
		log.Printf("Error creating request for broadcast.SarifID %s: %v", broadcast.SarifID, err)
		return 0, err
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

		ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
		defer cancel()
		req = req.WithContext(ctx)

		// Send the request
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("Error checking sarif broadcast invalidity at submission service: %v", err)
			return 0, err
		}
		defer resp.Body.Close()

		// Check response
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			log.Printf("Submission service returned non-200 status: %d, body: %s", resp.StatusCode, string(body))
			return 0, fmt.Errorf("Submission service returned non-200 status: %d, body: %s", resp.StatusCode, string(body))
		} else {

			var response models.SarifInValidResponse
			if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
				return 0, err
			}

			return response.IsInvalid, nil
		}

	}
}

func (s *WorkerCRSService) submitSarifInvalid(taskID string, broadcast models.SARIFBroadcastDetail) error {

	url := fmt.Sprintf("%s/v1/sarifx/invalid/%s/%s/", s.submissionEndpoint, taskID, broadcast.SarifID)

	broadcastJSON, err := json.Marshal(broadcast)
	if err != nil {
		log.Printf("Error json.Marshal for broadcast SarifID %s: %v", broadcast.SarifID, err)
		return err
	}

	// Create the HTTP request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(broadcastJSON))
	if err != nil {
		log.Printf("Error creating request for broadcast.SarifID %s: %v", broadcast.SarifID, err)
		return err
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

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		req = req.WithContext(ctx)

		// Send the request
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("Error sending broadcast to submission service: %v", err)
			return err
		}
		defer resp.Body.Close()

		// Check response
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			log.Printf("Submission service returned non-200 status: %d, body: %s", resp.StatusCode, string(body))
			return fmt.Errorf("Submission service returned non-200 status: %d, body: %s", resp.StatusCode, string(body))
		}
	}

	return nil
}

func (s *WorkerCRSService) runSarifPOVStrategies(myFuzzer, taskDir, sarifFilePath string, language string, taskDetail *models.TaskDetail, timeout int,
	phase int) bool {
	// Find all strategy files under /app/strategy/
	strategyDir := "/app/strategy"
	strategyFilePattern := "sarif_pov*.py"
	strategyFiles, err := filepath.Glob(filepath.Join(strategyDir, "**", strategyFilePattern))
	if err != nil {
		log.Printf("Failed to find strategy files: %v", err)
		return false
	}

	if len(strategyFiles) == 0 {
		log.Printf("No Sarif POV strategy files found in %s", strategyDir)
		return false
	}

	log.Printf("Found %d Sarif POV strategy files: %v", len(strategyFiles), strategyFiles)

	povSuccess := false
	var successMutex sync.Mutex
	var wg sync.WaitGroup

	for _, strategyFile := range strategyFiles {
		wg.Add(1)
		go func(strategyPath string) {
			defer wg.Done()
			strategyName := filepath.Base(strategyPath)
			log.Printf("Running Sarif POV strategy: %s", strategyPath)

			pythonInterpreter := "/tmp/crs_venv/bin/python3"
			isRoot := helpers.GetEffectiveUserID() == 0
			hasSudo := helpers.CheckSudoAvailable()
			maxIterations := 5

			log.Printf("Setting max iterations to %d", maxIterations)

			args := []string{
				strategyPath,
				myFuzzer,
				sarifFilePath,
				taskDetail.ProjectName,
				taskDetail.Focus,
				language,
				"--model", s.model,
				"--do-patch=false",
				"--pov-metadata-dir", s.povAdvcancedMetadataDir,
				"--check-patch-success",
				fmt.Sprintf("--fuzzing-timeout=%d", timeout),
				fmt.Sprintf("--pov-phase=%d", phase),
				fmt.Sprintf("--max-iterations=%d", maxIterations),
			}

			var runCmd *exec.Cmd
			if isRoot {
				runCmd = exec.Command(pythonInterpreter, args...)
			} else if hasSudo {
				sudoArgs := append([]string{"-E", pythonInterpreter}, args...)
				runCmd = exec.Command("sudo", sudoArgs...)
			} else {
				log.Printf("Warning: Not running as root and sudo not available. Trying direct execution.")
				runCmd = exec.Command(pythonInterpreter, args...)
			}

			log.Printf("[SARIF-POV] Executing: %s", runCmd.String())

			runCmd.Dir = taskDir
			runCmd.Env = append(os.Environ(),
				"VIRTUAL_ENV=/tmp/crs_venv",
				"PATH=/tmp/crs_venv/bin:"+os.Getenv("PATH"),
				fmt.Sprintf("SUBMISSION_ENDPOINT=%s", s.submissionEndpoint),
				fmt.Sprintf("TASK_ID=%s", taskDetail.TaskID.String()),
				fmt.Sprintf("CRS_KEY_ID=%s", s.cfg.Auth.KeyID),
				fmt.Sprintf("CRS_KEY_TOKEN=%s", s.cfg.Auth.Token),
				fmt.Sprintf("COMPETITION_API_KEY_ID=%s", os.Getenv("COMPETITION_API_KEY_ID")),
				fmt.Sprintf("COMPETITION_API_KEY_TOKEN=%s", os.Getenv("COMPETITION_API_KEY_TOKEN")),
				fmt.Sprintf("WORKER_INDEX=%s", s.workerIndex),
				fmt.Sprintf("ANALYSIS_SERVICE_URL=%s", s.analysisServiceUrl),
				"PYTHONUNBUFFERED=1",
			)

			// If we generated an unharnessed fuzzer for this task, pass its source path.
			if srcAny, ok := s.unharnessedFuzzerSrc.Load(taskDetail.TaskID.String()); ok {
				runCmd.Env = append(runCmd.Env,
					fmt.Sprintf("NEW_FUZZER_SRC_PATH=%s", srcAny.(string)))
			}

			// --- Streaming logs setup ---
			stdoutPipe, err := runCmd.StdoutPipe()
			if err != nil {
				log.Printf("Failed to create stdout pipe: %v", err)
				return
			}
			stderrPipe, err := runCmd.StderrPipe()
			if err != nil {
				log.Printf("Failed to create stderr pipe: %v", err)
				return
			}

			if err := runCmd.Start(); err != nil {
				log.Printf("Failed to start strategy %s: %v", strategyName, err)
				return
			}

			var outputLines []string
			var outputMutex sync.Mutex

			// Stream stdout
			go func() {
				scanner := bufio.NewScanner(stdoutPipe)
				for scanner.Scan() {
					line := scanner.Text()
					log.Printf("[SARIF][%s Phase-%d] %s", strategyName, phase, line)
					outputMutex.Lock()
					outputLines = append(outputLines, line)
					outputMutex.Unlock()
				}
			}()
			// Stream stderr
			go func() {
				scanner := bufio.NewScanner(stderrPipe)
				for scanner.Scan() {
					line := scanner.Text()
					log.Printf("[SARIF ERR][%s Phase-%d] %s", strategyName, phase, line)
					outputMutex.Lock()
					outputLines = append(outputLines, line)
					outputMutex.Unlock()
				}
			}()

			startTime := time.Now()
			err = runCmd.Wait()
			duration := time.Since(startTime)

			// Combine all output for POV SUCCESS detection
			outputMutex.Lock()
			combinedOutput := strings.Join(outputLines, "\n")
			outputMutex.Unlock()

			if err != nil {
				log.Printf("Sarif POV Strategy %s failed after %v: %v", strategyName, duration, err)
			} else {
				log.Printf("Sarif POV Strategy %s completed successfully in %v", strategyName, duration)
				successMutex.Lock()
				if strings.Contains(combinedOutput, "POV SUCCESS!") {
					log.Printf("Sarif POV Strategy %s POV successful!", strategyName)
					povSuccess = true
				}
				successMutex.Unlock()
			}
		}(strategyFile)
	}

	wg.Wait()
	return povSuccess
}

func (s *WorkerCRSService) runXPatchSarifStrategies(myFuzzer, taskDir, sarifFilePath string, language string, taskDetail models.TaskDetail,
	deadlineTime time.Time) bool {

	log.Printf("runXPatchSarifStrategies: starting patch attempt with sarif "+
		"(task type: %s)", taskDetail.Type)

	strategyDir := "/app/strategy"
	strategyFilePattern := "xpatch_sarif.py"
	strategyFiles, err := filepath.Glob(filepath.Join(strategyDir, "**", strategyFilePattern))
	if err != nil {
		log.Printf("Failed to find strategy files: %v", err)
		return false
	}

	if len(strategyFiles) == 0 {
		log.Printf("No XPATCH Sarif strategy files found in %s", strategyDir)
		return false
	}

	log.Printf("Found %d XPATCH Sarif strategy files: %v", len(strategyFiles), strategyFiles)

	patchSuccess := false
	// Calculate patching timeout based on deadline
	remainingMinutes := int(time.Until(deadlineTime).Minutes())
	// Reserve 5 minutes as safety buffer
	patchingTimeout := remainingMinutes - 5
	if patchingTimeout < 5 {
		patchingTimeout = 5
	}

	patchWorkDir := filepath.Join(taskDir, s.patchWorkDir)

	var successMutex sync.Mutex
	var wg sync.WaitGroup

	for _, strategyFile := range strategyFiles {
		wg.Add(1)
		go func(strategyPath string) {
			defer wg.Done()
			strategyName := filepath.Base(strategyPath)
			log.Printf("Running XPATCH Sarif strategy: %s", strategyPath)

			pythonInterpreter := "/tmp/crs_venv/bin/python3"
			isRoot := helpers.GetEffectiveUserID() == 0
			hasSudo := helpers.CheckSudoAvailable()
			maxIterations := 5

			log.Printf("Setting max iterations to %d", maxIterations)

			args := []string{
				strategyPath,
				myFuzzer,
				sarifFilePath,
				taskDetail.ProjectName,
				taskDetail.Focus,
				language,
				"--model", s.model,
				fmt.Sprintf("--patching-timeout=%d", patchingTimeout),
				"--patch-workspace-dir", patchWorkDir,
			}

			var runCmd *exec.Cmd
			if isRoot {
				runCmd = exec.Command(pythonInterpreter, args...)
			} else if hasSudo {
				sudoArgs := append([]string{"-E", pythonInterpreter}, args...)
				runCmd = exec.Command("sudo", sudoArgs...)
			} else {
				log.Printf("Warning: Not running as root and sudo not available. Trying direct execution.")
				runCmd = exec.Command(pythonInterpreter, args...)
			}

			log.Printf("[XPATCH-SARIF] Executing: %s", runCmd.String())

			runCmd.Dir = taskDir
			runCmd.Env = append(os.Environ(),
				"VIRTUAL_ENV=/tmp/crs_venv",
				"PATH=/tmp/crs_venv/bin:"+os.Getenv("PATH"),
				fmt.Sprintf("SUBMISSION_ENDPOINT=%s", s.submissionEndpoint),
				fmt.Sprintf("TASK_ID=%s", taskDetail.TaskID.String()),
				fmt.Sprintf("CRS_KEY_ID=%s", s.cfg.Auth.KeyID),
				fmt.Sprintf("CRS_KEY_TOKEN=%s", s.cfg.Auth.Token),
				fmt.Sprintf("COMPETITION_API_KEY_ID=%s", os.Getenv("COMPETITION_API_KEY_ID")),
				fmt.Sprintf("COMPETITION_API_KEY_TOKEN=%s", os.Getenv("COMPETITION_API_KEY_TOKEN")),
				fmt.Sprintf("WORKER_INDEX=%s", s.workerIndex),
				fmt.Sprintf("ANALYSIS_SERVICE_URL=%s", s.analysisServiceUrl),
				"PYTHONUNBUFFERED=1",
			)

			// --- Streaming logs setup ---
			stdoutPipe, err := runCmd.StdoutPipe()
			if err != nil {
				log.Printf("Failed to create stdout pipe: %v", err)
				return
			}
			stderrPipe, err := runCmd.StderrPipe()
			if err != nil {
				log.Printf("Failed to create stderr pipe: %v", err)
				return
			}

			if err := runCmd.Start(); err != nil {
				log.Printf("Failed to start strategy %s: %v", strategyName, err)
				return
			}

			var outputLines []string
			var outputMutex sync.Mutex

			// Stream stdout
			go func() {
				scanner := bufio.NewScanner(stdoutPipe)
				for scanner.Scan() {
					line := scanner.Text()
					log.Printf("[XPATCH-SARIF][%s] %s", strategyName, line)
					outputMutex.Lock()
					outputLines = append(outputLines, line)
					outputMutex.Unlock()
				}
			}()
			// Stream stderr
			go func() {
				scanner := bufio.NewScanner(stderrPipe)
				for scanner.Scan() {
					line := scanner.Text()
					log.Printf("[XPATCH-SARIF ERR][%s] %s", strategyName, line)
					outputMutex.Lock()
					outputLines = append(outputLines, line)
					outputMutex.Unlock()
				}
			}()

			startTime := time.Now()
			err = runCmd.Wait()
			duration := time.Since(startTime)

			outputMutex.Lock()
			combinedOutput := strings.Join(outputLines, "\n")
			outputMutex.Unlock()

			if err != nil {
				log.Printf("XPATCH-Sarif Strategy %s failed after %v: %v", strategyName, duration, err)
			} else {
				log.Printf("XPATCH-Sarif Strategy %s completed successfully in %v", strategyName, duration)
				successMutex.Lock()
				if strings.Contains(combinedOutput, "PATCH SUCCESS!") {
					log.Printf("XPATCH-Sarif Strategy %s successful!", strategyName)
					patchSuccess = true
				}
				successMutex.Unlock()
			}
		}(strategyFile)
	}

	wg.Wait()
	return patchSuccess
}

package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"crs/internal/competition"
	"crs/internal/config"
	"crs/internal/models"
	"crs/internal/utils/environment"
	"crs/internal/utils/fuzzer"
	"crs/internal/utils/helpers"
)

// WebCRSService implements CRSService for web service mode (task scheduling and distribution)
type WebCRSService struct {
	cfg                    *config.Config
	tasks                  map[string]*models.TaskDetail
	tasksMutex             sync.RWMutex
	workDir                string
	competitionClient      *competition.Client
	statusMutex            sync.RWMutex
	status                 models.StatusTasksState
	povMetadataDir         string
	povMetadataDir0        string
	povAdvcancedMetadataDir string
	patchWorkDir           string
	submissionEndpoint     string
	workerIndex            string
	analysisServiceUrl     string
	workerNodes            int
	workerBasePort         int
	model                  string

	// Fields for tracking historical task distribution
	totalTasksDistributed int
	distributionMutex     sync.Mutex
	fuzzerToWorkerMap     map[string]int
	taskToWorkersMap      map[string][]WorkerFuzzerPair

	workerStatus         map[int]*WorkerStatus
	workerStatusMux      sync.Mutex
	unharnessedFuzzerSrc sync.Map
}

// NewWebService creates a new web service instance
func NewWebService(cfg *config.Config) CRSService {
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

	service := &WebCRSService{
		cfg:                     cfg,
		tasks:                   make(map[string]*models.TaskDetail),
		workDir:                 workDir,
		competitionClient:       competition.NewClient(apiEndpoint, cfg.Auth.KeyID, cfg.Auth.Token),
		status:                  models.StatusTasksState{},
		povMetadataDir:          "successful_povs",
		povMetadataDir0:         "successful_povs_0",
		povAdvcancedMetadataDir: "successful_povs_advanced",
		patchWorkDir:            "patch_workspace",
		workerNodes:             cfg.Worker.Nodes,
		workerBasePort:          cfg.Server.WorkerBasePort,
		model:                   cfg.AI.Model,
		submissionEndpoint:      cfg.Services.SubmissionURL,
		analysisServiceUrl:      cfg.Services.AnalysisURL,
		totalTasksDistributed:   0,
		workerStatus:            make(map[int]*WorkerStatus),
		fuzzerToWorkerMap:       make(map[string]int),
		taskToWorkersMap:        make(map[string][]WorkerFuzzerPair),
	}

	// Initialize worker status for each worker
	for i := 0; i < service.workerNodes; i++ {
		service.workerStatus[i] = &WorkerStatus{
			LastAssignedTime: time.Time{},
			FailureCount:     0,
			BlacklistedUntil: time.Time{},
			AssignedTasks:    0,
		}
	}

	return service
}

// GetStatus returns current web service status
func (s *WebCRSService) GetStatus() models.Status {
	s.statusMutex.RLock()
	defer s.statusMutex.RUnlock()

	return models.Status{
		Ready: true,
		State: models.StatusState{
			Tasks: s.status,
		},
	}
}

// SubmitLocalTask is not supported in web mode
func (s *WebCRSService) SubmitLocalTask(taskPath string) error {
	return errNotSupportedInWebMode
}

// SubmitTask implements web service task submission
func (s *WebCRSService) SubmitTask(task models.Task) error {
	// Validate task
	if err := s.validateTask(task); err != nil {
		return err
	}

	// Update status with new pending tasks
	s.statusMutex.Lock()
	s.status.Pending += len(task.Tasks)
	s.statusMutex.Unlock()

	// Process each task
	for _, taskDetail := range task.Tasks {
		// Store task
		s.tasksMutex.Lock()
		taskDetail.State = models.TaskStatePending
		s.tasks[taskDetail.TaskID.String()] = &taskDetail
		s.tasksMutex.Unlock()

		// Process task asynchronously
		go func(td models.TaskDetail) {
			//TODO: for unharnessed tasks, set fuzzer to "UNHARNESSED" and send to a worker directly
			//Worker will try to synthesize a harness
			if !taskDetail.HarnessesIncluded {
				allFuzzers := []string{UNHARNESSED}
				s.distributeFuzzers(allFuzzers, taskDetail, task)
			} else if err := s.processTask("", td, task); err != nil {
				log.Printf("Error processing task %s: %v", td.TaskID, err)

				// Update task state
				s.tasksMutex.Lock()
				if task, exists := s.tasks[td.TaskID.String()]; exists {
					task.State = models.TaskStateErrored
				}
				s.status.Errored++
				s.tasksMutex.Unlock()
			}
		}(taskDetail)
	}

	return nil
}

// SubmitWorkerTask is not supported in web mode
func (s *WebCRSService) SubmitWorkerTask(task models.WorkerTask) error {
	return errNotSupportedInWebMode
}

// CancelTask implements task cancellation
func (s *WebCRSService) CancelTask(taskID string) error {
	s.tasksMutex.Lock()
	defer s.tasksMutex.Unlock()

	task, exists := s.tasks[taskID]
	if !exists {
		return nil // Task not found, consider it already canceled
	}

	// Update task state
	task.State = models.TaskStateCanceled

	// Update status
	s.statusMutex.Lock()
	defer s.statusMutex.Unlock()

	// Decrement the appropriate counter based on previous state
	switch task.State {
	case models.TaskStatePending:
		s.status.Pending--
	case models.TaskStateRunning:
		s.status.Processing--
	}

	// Increment canceled counter
	s.status.Canceled++

	delete(s.tasks, taskID)
	return nil
}

// CancelAllTasks implements cancellation of all tasks
func (s *WebCRSService) CancelAllTasks() error {
	s.tasksMutex.Lock()
	defer s.tasksMutex.Unlock()

	// Update all tasks to canceled
	for _, task := range s.tasks {
		task.State = models.TaskStateCanceled
	}

	// Reset the task map
	s.tasks = make(map[string]*models.TaskDetail)

	// Update status
	s.statusMutex.Lock()
	defer s.statusMutex.Unlock()

	// Reset all counters except canceled
	s.status.Canceled += s.status.Pending + s.status.Processing + s.status.Waiting
	s.status.Pending = 0
	s.status.Processing = 0
	s.status.Waiting = 0

	return nil
}

// SubmitSarif handles SARIF broadcast submission
// TODO: SARIF workflow to be implemented later
func (s *WebCRSService) SubmitSarif(sarifBroadcast models.SARIFBroadcast) error {
	// Forward SARIF broadcast to submission server
	taskJSON, err := json.Marshal(sarifBroadcast)
	if err != nil {
		log.Printf("Error marshaling SARIF broadcast: %v", err)
		return err
	}

	// Send the broadcast to submission endpoint
	url := fmt.Sprintf("%s/sarifx/", s.submissionEndpoint)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(taskJSON))
	if err != nil {
		log.Printf("Error sending SARIF request: %v", err)
		return err
	}
	defer resp.Body.Close()

	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response: %v", err)
		return err
	}

	// Print response
	fmt.Printf("\nResponse from server (status %d):\n", resp.StatusCode)

	// Format JSON response if possible
	var prettyJSON bytes.Buffer
	err = json.Indent(&prettyJSON, respBody, "", "  ")
	if err != nil {
		// Not valid JSON, print as-is
		fmt.Println(string(respBody))
	} else {
		fmt.Println(prettyJSON.String())
	}

	log.Printf("Successfully forwarded SARIF broadcast to submission server: message id %s", sarifBroadcast.MessageID)
	return nil
}

// HandleSarifBroadcastWorker handles SARIF broadcasts from workers
// TODO: SARIF workflow to be implemented later
func (s *WebCRSService) HandleSarifBroadcastWorker(broadcastWorker models.SARIFBroadcastDetailWorker) error {
	return errNotSupportedInWebMode
}

// SetWorkerIndex is not used in web mode (no-op)
func (s *WebCRSService) SetWorkerIndex(index string) {
	s.workerIndex = index
}

// SetSubmissionEndpoint sets the submission endpoint
func (s *WebCRSService) SetSubmissionEndpoint(endpoint string) {
	s.submissionEndpoint = endpoint
}

// SetAnalysisServiceUrl sets the analysis service URL
func (s *WebCRSService) SetAnalysisServiceUrl(url string) {
	s.analysisServiceUrl = url
}

// GetWorkDir returns the work directory
func (s *WebCRSService) GetWorkDir() string {
	return s.workDir
}

// validateTask validates the incoming task
func (s *WebCRSService) validateTask(task models.Task) error {
	if len(task.Tasks) == 0 {
		return fmt.Errorf("no tasks provided")
	}
	if task.MessageTime == 0 {
		return fmt.Errorf("message_time is required")
	}
	return nil
}

// processTask processes a single task detail
func (s *WebCRSService) processTask(myFuzzer string, taskDetail models.TaskDetail, fullTask models.Task) error {
	taskID := taskDetail.TaskID.String()
	log.Printf("Processing task %s", taskID)

	// Update task state to running
	s.tasksMutex.Lock()
	if task, exists := s.tasks[taskID]; exists {
		task.State = models.TaskStateRunning
	}
	s.tasksMutex.Unlock()

	// Update status
	s.statusMutex.Lock()
	s.status.Pending--
	s.status.Processing++
	s.statusMutex.Unlock()

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
		FuzzerBuilder:      nil, // Web service doesn't build locally
		FindFuzzers:        fuzzer.FindFuzzers,
		SanitizerOverride:  s.cfg.Fuzzer.GetSanitizerList(), // Use config sanitizers if set
	}

	_, sanitizerDirs, err := environment.PrepareEnvironment(params)
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

	// Distribute fuzzers to workers
	s.distributeFuzzers(allFuzzers, taskDetail, fullTask)

	// Update task state to succeeded
	s.tasksMutex.Lock()
	if task, exists := s.tasks[taskID]; exists {
		task.State = models.TaskStateSucceeded
	}
	s.tasksMutex.Unlock()

	// Update status
	s.statusMutex.Lock()
	s.status.Processing--
	s.status.Succeeded++
	s.statusMutex.Unlock()

	return nil
}

// distributeFuzzers distributes fuzzers across available workers
func (s *WebCRSService) distributeFuzzers(allFuzzers []string, taskDetail models.TaskDetail, fullTask models.Task) {
	maxRetries := 1000
	retryInterval := 2 * time.Minute

	// Create a slice of fuzzer status to preserve order
	type fuzzerStatus struct {
		name     string
		attempts int
		pending  bool
	}

	// Initialize status for all fuzzers
	fuzzerStatuses := make([]fuzzerStatus, len(allFuzzers))
	for i, fuzzer := range allFuzzers {
		fuzzerStatuses[i] = fuzzerStatus{
			name:     fuzzer,
			attempts: 0,
			pending:  true,
		}
	}

	// First attempt for all fuzzers - in original order
	for i := range fuzzerStatuses {
		if !fuzzerStatuses[i].pending {
			continue
		}

		fuzzer := fuzzerStatuses[i].name
		if err := s.sendFuzzerToWorker(fuzzer, taskDetail, fullTask); err != nil {
			log.Printf("Failed to distribute fuzzer %s to any worker, will retry later: %v", fuzzer, err)
		} else {
			fuzzerStatuses[i].pending = false
		}
	}

	// Count pending fuzzers
	pendingCount := 0
	for i := range fuzzerStatuses {
		if fuzzerStatuses[i].pending {
			pendingCount++
		}
	}

	// If we still have pending fuzzers, start retry loop
	for pendingCount > 0 {
		log.Printf("Waiting %v before retrying %d pending fuzzers...", retryInterval, pendingCount)
		time.Sleep(retryInterval)

		// Try each pending fuzzer again - in original order
		for i := range fuzzerStatuses {
			if !fuzzerStatuses[i].pending {
				continue
			}

			fuzzer := fuzzerStatuses[i].name
			attempts := fuzzerStatuses[i].attempts

			// Check if we've exceeded max retries
			if attempts >= maxRetries {
				log.Printf("Exceeded maximum retries (%d) for fuzzer %s", maxRetries, fuzzer)
				fuzzerStatuses[i].pending = false
				pendingCount--
				continue
			}

			if err := s.sendFuzzerToWorker(fuzzer, taskDetail, fullTask); err != nil {
				// Increment retry count
				fuzzerStatuses[i].attempts++
				log.Printf("All workers are still busy... still could not find a worker for fuzzer %s (attempt %d/%d)",
					fuzzer, attempts+1, maxRetries)
			} else {
				fuzzerStatuses[i].pending = false
				pendingCount--
			}
		}

		// If no more pending fuzzers, exit the loop
		if pendingCount == 0 {
			break
		}
	}

	// Report on any fuzzers that couldn't be distributed
	if pendingCount > 0 {
		// Collect names of pending fuzzers for the log
		pendingFuzzers := make([]string, 0, pendingCount)
		for _, status := range fuzzerStatuses {
			if status.pending {
				pendingFuzzers = append(pendingFuzzers, status.name)
			}
		}
		log.Printf("Could not distribute %d fuzzers after maximum retries: %v",
			pendingCount, pendingFuzzers)
	}
}

// sendFuzzerToWorker sends a fuzzer task to an available worker
func (s *WebCRSService) sendFuzzerToWorker(fuzzer string, taskDetail models.TaskDetail, fullTask models.Task) error {
	// Lock to ensure consistent task distribution across concurrent requests
	s.distributionMutex.Lock()
	defer s.distributionMutex.Unlock()

	// Create a worker-specific task request with just this task and fuzzer
	workerRequest := models.WorkerTask{
		MessageID:   fullTask.MessageID,
		MessageTime: fullTask.MessageTime,
		Tasks:       []models.TaskDetail{taskDetail},
		Fuzzer:      fuzzer,
	}

	// Marshal the request
	taskJSON, err := json.Marshal(workerRequest)
	if err != nil {
		return fmt.Errorf("error marshaling task: %v", err)
	}

	// Get API credentials from config
	apiKeyID := s.cfg.Auth.KeyID
	apiToken := s.cfg.Auth.Token

	// Lock to safely access and update worker status
	s.workerStatusMux.Lock()
	defer s.workerStatusMux.Unlock()

	// Check if this fuzzer has been assigned before
	if existingWorker, exists := s.fuzzerToWorkerMap[fuzzer]; exists {
		log.Printf("Found existing assignment for fuzzer %s -> worker %d", fuzzer, existingWorker)

		// Check if the worker is not blacklisted
		workerStatus := s.workerStatus[existingWorker]
		if time.Now().After(workerStatus.BlacklistedUntil) {
			// Try to send to the existing worker first
			if s.tryWorker(existingWorker, taskJSON, apiKeyID, apiToken, fuzzer, taskDetail.TaskID.String()) {
				return nil
			}
			// If failed, continue with normal worker selection
		}
	}

	// Find the best worker to assign the task to
	selectedWorker := s.selectBestWorker()

	// If all workers are busy, reset their assigned task counts
	if selectedWorker == -1 {
		log.Printf("All workers are busy, resetting assignment counts")
		for i := range s.workerStatus {
			s.workerStatus[i].AssignedTasks = 0
		}
		selectedWorker = s.selectBestWorker()
	}

	// Try the selected worker
	if selectedWorker != -1 && s.tryWorker(selectedWorker, taskJSON, apiKeyID, apiToken, fuzzer, taskDetail.TaskID.String()) {
		return nil
	}

	// If the selected worker failed, try all non-blacklisted workers
	log.Printf("Selected worker %d failed, trying all available workers", selectedWorker)
	for j := 1; j < s.workerNodes; j++ {
		i := (selectedWorker + j) % s.workerNodes
		if i == selectedWorker {
			continue // Skip the already tried worker
		}
		// Skip blacklisted workers
		if !time.Now().After(s.workerStatus[i].BlacklistedUntil) {
			log.Printf("Worker %d is blacklisted until %v, skipping", i, s.workerStatus[i].BlacklistedUntil)
			continue
		}

		if s.tryWorker(i, taskJSON, apiKeyID, apiToken, fuzzer, taskDetail.TaskID.String()) {
			return nil
		}
	}

	// If we get here, we've tried all workers and none worked
	return fmt.Errorf("all available workers failed to accept the task")
}

// selectBestWorker finds the best worker to assign a task to
func (s *WebCRSService) selectBestWorker() int {
	now := time.Now()
	var bestWorker int = -1
	var minAssignedTasks int = int(^uint(0) >> 1) // MaxInt

	// First, look for non-blacklisted workers with the fewest assigned tasks
	for i := 0; i < s.workerNodes; i++ {
		status := s.workerStatus[i]

		// Skip blacklisted workers
		if !now.After(status.BlacklistedUntil) {
			continue
		}

		// Find the worker with the fewest assigned tasks
		if status.AssignedTasks < minAssignedTasks {
			minAssignedTasks = status.AssignedTasks
			bestWorker = i
		}
	}

	return bestWorker
}

// tryWorker attempts to send a task to a specific worker
func (s *WebCRSService) tryWorker(workerIndex int, taskJSON []byte, apiKeyID, apiToken, fuzzer, taskID string) bool {
	// Construct the worker URL
	workerURL := fmt.Sprintf("http://crs-worker-%d.crs-worker.crs-webservice.svc.cluster.local:%d/v1/task/",
		workerIndex, s.workerBasePort)

	if os.Getenv("LOCAL_TEST") != "" || s.cfg.Mode == "local" {
		workerURL = "http://localhost:9081/v1/task/"
	}

	// Send the task to the worker
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest("POST", workerURL, bytes.NewBuffer(taskJSON))
	if err != nil {
		log.Printf("Error creating request for worker %d: %v", workerIndex, err)
		s.recordWorkerFailure(workerIndex)
		return false
	}

	req.Header.Set("Content-Type", "application/json")
	if apiKeyID != "" && apiToken != "" {
		req.SetBasicAuth(apiKeyID, apiToken)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error sending task to worker %d: %v", workerIndex, err)
		s.recordWorkerFailure(workerIndex)
		return false
	}

	// Check response status
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Worker %d returned non-OK status: %d, body: %s",
			workerIndex, resp.StatusCode, string(body))
		resp.Body.Close()
		s.recordWorkerFailure(workerIndex)
		return false
	}

	// Success!
	resp.Body.Close()

	// Update the worker status
	s.workerStatus[workerIndex].LastAssignedTime = time.Now()
	s.workerStatus[workerIndex].FailureCount = 0
	s.workerStatus[workerIndex].AssignedTasks++

	// Update the fuzzer-to-worker map with the successful worker
	s.fuzzerToWorkerMap[fuzzer] = workerIndex
	s.taskToWorkersMap[taskID] = append(s.taskToWorkersMap[taskID], WorkerFuzzerPair{
		Worker: workerIndex,
		Fuzzer: fuzzer,
	})
	// Increment the counter only on successful distribution
	s.totalTasksDistributed++

	log.Printf("Successfully assigned fuzzer %s to worker %d for task %s",
		fuzzer, workerIndex, taskID)

	return true
}

// recordWorkerFailure records a failure for a worker and blacklists it if necessary
func (s *WebCRSService) recordWorkerFailure(workerIndex int) {
	status := s.workerStatus[workerIndex]
	status.FailureCount++

	// If the worker has failed too many times, blacklist it for 5 minutes
	if status.FailureCount >= 3 {
		status.BlacklistedUntil = time.Now().Add(5 * time.Minute)
		log.Printf("Worker %d has failed %d times, blacklisted until %v",
			workerIndex, status.FailureCount, status.BlacklistedUntil)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// SARIF Processing Methods
// ─────────────────────────────────────────────────────────────────────────────

// findPOVsAndNotifyWorkers finds all workers assigned to a task and notifies them of SARIF results
func (s *WebCRSService) findPOVsAndNotifyWorkers(taskID string, broadcast models.SARIFBroadcastDetail) error {
	// 1. Lock to safely access worker mapping
	s.workerStatusMux.Lock()
	defer s.workerStatusMux.Unlock()

	// 2. Find all workers that have been assigned to a fuzzer of the same taskID
	workerFuzzerPairs, exists := s.taskToWorkersMap[taskID]
	if !exists || len(workerFuzzerPairs) == 0 {
		log.Printf("No workers assigned to task %s", taskID)
		return fmt.Errorf("no workers assigned to task %s", taskID)
	}

	log.Printf("Found %d worker-fuzzer pairs assigned to task %s", len(workerFuzzerPairs), taskID)

	// 4. Get API credentials from config
	apiKeyID := s.cfg.Auth.KeyID
	apiToken := s.cfg.Auth.Token

	// 5. Send the broadcast to each worker with retry logic
	var wg sync.WaitGroup
	successCount := 0
	var successMutex sync.Mutex

	for _, pair := range workerFuzzerPairs {
		workerIndex := pair.Worker

		payload := models.SARIFBroadcastDetailWorker{
			Broadcast: broadcast,
			Fuzzer:    pair.Fuzzer,
		}
		// 3. Marshal the broadcast message
		broadcastJSON, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("error marshaling broadcast message: %v", err)
		}

		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			// Send broadcast with retry
			maxRetries := 3
			for attempt := 0; attempt < maxRetries; attempt++ {
				success := s.sendBroadcastToWorker(idx, broadcastJSON, apiKeyID, apiToken, taskID)
				if success {
					log.Printf("Successfully sent broadcast to worker %d for task %s", idx, taskID)
					successMutex.Lock()
					successCount++
					successMutex.Unlock()
					return
				}

				if attempt < maxRetries-1 {
					log.Printf("Retrying broadcast to worker %d (attempt %d/%d)", idx, attempt+1, maxRetries)
					time.Sleep(30 * time.Second) // Wait before retry
				}
			}

			log.Printf("Failed to send broadcast to worker %d after %d attempts", idx, maxRetries)
		}(workerIndex)
	}

	// Wait for all goroutines to complete
	wg.Wait()

	if successCount == 0 {
		return fmt.Errorf("Failed to send broadcast to any worker for task %s", taskID)
	}

	log.Printf("Successfully sent broadcast to %d/%d fuzzer-worker pairs for task %s", successCount, len(workerFuzzerPairs), taskID)
	return nil
}

// sendBroadcastToWorker sends a SARIF broadcast to a specific worker
func (s *WebCRSService) sendBroadcastToWorker(workerIndex int, broadcastJSON []byte, apiKeyID, apiToken, taskID string) bool {
	// Construct the worker URL
	workerURL := fmt.Sprintf("http://crs-worker-%d.crs-worker.crs-webservice.svc.cluster.local:%d/sarif_worker/",
		workerIndex, s.workerBasePort)

	// Create the HTTP request
	req, err := http.NewRequest("POST", workerURL, bytes.NewBuffer(broadcastJSON))
	if err != nil {
		log.Printf("Error creating request for worker %d: %v", workerIndex, err)
		return false
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	// Set timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error sending broadcast to worker %d: %v", workerIndex, err)
		return false
	}
	defer resp.Body.Close()

	// Check response
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Worker %d returned non-200 status: %d, body: %s", workerIndex, resp.StatusCode, string(body))
		return false
	}

	return true
}

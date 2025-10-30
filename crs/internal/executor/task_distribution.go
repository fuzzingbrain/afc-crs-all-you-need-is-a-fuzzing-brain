package executor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"crs/internal/models"
)

// WorkerStatus tracks the status of a worker node
type WorkerStatus struct {
	LastAssignedTime time.Time
	FailureCount     int
	BlacklistedUntil time.Time
	AssignedTasks    int
}

// WorkerFuzzerPair represents a fuzzer assigned to a worker
type WorkerFuzzerPair struct {
	Worker int
	Fuzzer string
}

// WorkerPool manages the state and distribution of fuzzers to worker nodes
type WorkerPool struct {
	workerNodes           int
	workerBasePort        int
	workerStatus          map[int]*WorkerStatus
	workerStatusMux       sync.Mutex
	distributionMutex     sync.Mutex
	fuzzerToWorkerMap     map[string]int
	taskToWorkersMap      map[string][]WorkerFuzzerPair
	totalTasksDistributed int
}

// NewWorkerPool creates a new worker pool for managing task distribution
func NewWorkerPool(workerNodes, workerBasePort int) *WorkerPool {
	pool := &WorkerPool{
		workerNodes:       workerNodes,
		workerBasePort:    workerBasePort,
		workerStatus:      make(map[int]*WorkerStatus),
		fuzzerToWorkerMap: make(map[string]int),
		taskToWorkersMap:  make(map[string][]WorkerFuzzerPair),
	}

	// Initialize worker status for each worker
	for i := 0; i < workerNodes; i++ {
		pool.workerStatus[i] = &WorkerStatus{
			LastAssignedTime: time.Time{},
			FailureCount:     0,
			BlacklistedUntil: time.Time{},
			AssignedTasks:    0,
		}
	}

	return pool
}

// TaskDistributionParams contains parameters for distributing fuzzing tasks to workers
type TaskDistributionParams struct {
	Fuzzers            []string
	TaskDetail         models.TaskDetail
	Task               models.Task
	SubmissionEndpoint string
	WorkerBasePort     int
	WorkerNodes        int
}

// DistributeFuzzingTasks distributes fuzzing tasks to worker nodes
// This is used by the web service to schedule tasks across workers
func DistributeFuzzingTasks(params TaskDistributionParams) error {
	log.Printf("========== TASK DISTRIBUTION: Scheduling %d fuzzers to workers ==========", len(params.Fuzzers))
	log.Printf("TaskID: %s", params.TaskDetail.TaskID)
	log.Printf("ProjectName: %s", params.TaskDetail.ProjectName)
	log.Printf("Worker nodes: %d (base port: %d)", params.WorkerNodes, params.WorkerBasePort)

	pool := NewWorkerPool(params.WorkerNodes, params.WorkerBasePort)
	return pool.distributeFuzzers(params.Fuzzers, params.TaskDetail, params.Task)
}

// distributeFuzzers handles the distribution of fuzzers to workers with retry logic
func (pool *WorkerPool) distributeFuzzers(allFuzzers []string, taskDetail models.TaskDetail, fullTask models.Task) error {
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
		if err := pool.sendFuzzerToWorker(fuzzer, taskDetail, fullTask); err != nil {
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
				//TODO Run locally as a last resort
				continue
			}

			if err := pool.sendFuzzerToWorker(fuzzer, taskDetail, fullTask); err != nil {
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

	return nil
}

// sendFuzzerToWorker attempts to send a fuzzer to an available worker
func (pool *WorkerPool) sendFuzzerToWorker(fuzzer string, taskDetail models.TaskDetail, fullTask models.Task) error {
	// Lock to ensure consistent task distribution across concurrent requests
	pool.distributionMutex.Lock()
	defer pool.distributionMutex.Unlock()

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

	// Get API credentials from environment
	apiKeyID := os.Getenv("CRS_KEY_ID")
	apiToken := os.Getenv("CRS_KEY_TOKEN")

	// Lock to safely access and update worker status
	pool.workerStatusMux.Lock()
	defer pool.workerStatusMux.Unlock()

	// Check if this fuzzer has been assigned before
	if existingWorker, exists := pool.fuzzerToWorkerMap[fuzzer]; exists {
		log.Printf("Found existing assignment for fuzzer %s -> worker %d", fuzzer, existingWorker)

		// Check if the worker is not blacklisted
		workerStatus := pool.workerStatus[existingWorker]
		if time.Now().After(workerStatus.BlacklistedUntil) {
			// Try to send to the existing worker first
			if pool.tryWorker(existingWorker, taskJSON, apiKeyID, apiToken, fuzzer, taskDetail.TaskID.String()) {
				return nil
			}
			// If failed, continue with normal worker selection
		}
	}

	// Find the best worker to assign the task to
	selectedWorker := pool.selectBestWorker()

	// If all workers are busy, reset their assigned task counts
	if selectedWorker == -1 {
		log.Printf("All workers are busy, resetting assignment counts")
		for i := range pool.workerStatus {
			pool.workerStatus[i].AssignedTasks = 0
		}
		selectedWorker = pool.selectBestWorker()
	}

	// Try the selected worker
	if selectedWorker != -1 && pool.tryWorker(selectedWorker, taskJSON, apiKeyID, apiToken, fuzzer, taskDetail.TaskID.String()) {
		return nil
	}

	// If the selected worker failed, try all non-blacklisted workers
	log.Printf("Selected worker %d failed, trying all available workers", selectedWorker)
	for j := 1; j < pool.workerNodes; j++ {
		i := (selectedWorker + j) % pool.workerNodes
		if i == selectedWorker {
			continue // Skip the already tried worker
		}
		// Skip blacklisted workers
		if !time.Now().After(pool.workerStatus[i].BlacklistedUntil) {
			log.Printf("Worker %d is blacklisted until %v, skipping", i, pool.workerStatus[i].BlacklistedUntil)
			continue
		}

		if pool.tryWorker(i, taskJSON, apiKeyID, apiToken, fuzzer, taskDetail.TaskID.String()) {
			return nil
		}
	}

	// If we get here, we've tried all workers and none worked
	return fmt.Errorf("all available workers failed to accept the task")
}

// selectBestWorker finds the best worker to assign a task to
func (pool *WorkerPool) selectBestWorker() int {
	now := time.Now()
	var bestWorker int = -1
	var minAssignedTasks int = int(^uint(0) >> 1) // math.MaxInt32

	// First, look for non-blacklisted workers with the fewest assigned tasks
	for i := 0; i < pool.workerNodes; i++ {
		status := pool.workerStatus[i]

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
func (pool *WorkerPool) tryWorker(workerIndex int, taskJSON []byte, apiKeyID, apiToken, fuzzer, taskID string) bool {
	// Construct the worker URL
	workerURL := fmt.Sprintf("http://crs-worker-%d.crs-worker.crs-webservice.svc.cluster.local:%d/v1/task/",
		workerIndex, pool.workerBasePort)

	if os.Getenv("LOCAL_TEST") != "" {
		workerURL = "http://localhost:9081/v1/task/"
	}

	// Send the task to the worker
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest("POST", workerURL, bytes.NewBuffer(taskJSON))
	if err != nil {
		log.Printf("Error creating request for worker %d: %v", workerIndex, err)
		pool.recordWorkerFailure(workerIndex)
		return false
	}

	req.Header.Set("Content-Type", "application/json")
	if apiKeyID != "" && apiToken != "" {
		req.SetBasicAuth(apiKeyID, apiToken)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error sending task to worker %d: %v", workerIndex, err)
		pool.recordWorkerFailure(workerIndex)
		return false
	}

	// Check response status
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Worker %d returned non-OK status: %d, body: %s",
			workerIndex, resp.StatusCode, string(body))
		resp.Body.Close()
		pool.recordWorkerFailure(workerIndex)
		return false
	}

	// Success!
	resp.Body.Close()

	// Update the worker status
	pool.workerStatus[workerIndex].LastAssignedTime = time.Now()
	pool.workerStatus[workerIndex].FailureCount = 0
	pool.workerStatus[workerIndex].AssignedTasks++

	// Update the fuzzer-to-worker map with the successful worker
	pool.fuzzerToWorkerMap[fuzzer] = workerIndex
	pool.taskToWorkersMap[taskID] = append(pool.taskToWorkersMap[taskID], WorkerFuzzerPair{
		Worker: workerIndex,
		Fuzzer: fuzzer,
	})
	// Increment the counter only on successful distribution
	pool.totalTasksDistributed++

	log.Printf("Successfully assigned fuzzer %s to worker %d for task %s",
		fuzzer, workerIndex, taskID)

	return true
}

// recordWorkerFailure records a worker failure and potentially blacklists it
func (pool *WorkerPool) recordWorkerFailure(workerIndex int) {
	pool.workerStatusMux.Lock()
	defer pool.workerStatusMux.Unlock()

	status := pool.workerStatus[workerIndex]
	status.FailureCount++

	// If the worker has failed too many times, blacklist it for 5 minutes
	if status.FailureCount >= 3 {
		status.BlacklistedUntil = time.Now().Add(5 * time.Minute)
		log.Printf("Worker %d has failed %d times, blacklisted until %v",
			workerIndex, status.FailureCount, status.BlacklistedUntil)
	}
}

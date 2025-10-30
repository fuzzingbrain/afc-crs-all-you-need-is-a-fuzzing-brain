package services

import (
	"fmt"
	"log"
	"runtime/debug"

	"crs/internal/models"
)

// WorkerCRSService implements CRSService for worker mode (task execution)
type WorkerCRSService struct {
	// Embed defaultCRSService temporarily to reuse helper methods
	// TODO: Remove this once all methods are migrated
	*defaultCRSService

	// Worker-specific fields
	workerIndex string
	workerPort  int
}

// NewWorkerService creates a new worker service instance
func NewWorkerService(workerIndex string, workerPort int, model string) CRSService {
	// Create the embedded defaultCRSService for helper methods
	embedded := NewCRSService(0, workerPort, model).(*defaultCRSService)

	return &WorkerCRSService{
		defaultCRSService: embedded,
		workerIndex:       workerIndex,
		workerPort:        workerPort,
	}
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
	avgCPU, err := getAverageCPUUsage()
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

	// Process the task using the embedded defaultCRSService's processTask method
	if err := s.processTask(task.Fuzzer, td, models.Task{
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
// TODO: SARIF workflow to be implemented later
func (s *WorkerCRSService) HandleSarifBroadcastWorker(broadcastWorker models.SARIFBroadcastDetailWorker) error {
	log.Printf("SARIF workflow not yet implemented in WorkerCRSService")
	return nil
}

// SetWorkerIndex sets the worker index
func (s *WorkerCRSService) SetWorkerIndex(index string) {
	s.workerIndex = index
}

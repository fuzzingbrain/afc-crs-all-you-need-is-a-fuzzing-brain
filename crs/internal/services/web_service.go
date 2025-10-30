package services

import (
	"log"

	"crs/internal/models"
)

// WebCRSService implements CRSService for web service mode (task scheduling and distribution)
type WebCRSService struct {
	// Embed defaultCRSService temporarily to reuse helper methods
	// TODO: Remove this once all methods are migrated
	*defaultCRSService
}

// NewWebService creates a new web service instance
func NewWebService(workerNodes int, workerBasePort int, model string) CRSService {
	// Create the embedded defaultCRSService for helper methods
	embedded := NewCRSService(workerNodes, workerBasePort, model).(*defaultCRSService)

	return &WebCRSService{
		defaultCRSService: embedded,
	}
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
	log.Printf("SARIF workflow not yet implemented in WebCRSService")
	return nil
}

// HandleSarifBroadcastWorker handles SARIF broadcasts from workers
// TODO: SARIF workflow to be implemented later
func (s *WebCRSService) HandleSarifBroadcastWorker(broadcastWorker models.SARIFBroadcastDetailWorker) error {
	return errNotSupportedInWebMode
}

// SetWorkerIndex is not used in web mode (no-op)
func (s *WebCRSService) SetWorkerIndex(index string) {
	// No-op for web mode
}

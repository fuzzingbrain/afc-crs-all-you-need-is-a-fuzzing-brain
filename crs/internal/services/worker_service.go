package services

import (
	"log"

	"crs/internal/models"
)

// WorkerCRSService implements CRSService for worker mode (task execution)
type WorkerCRSService struct {
	baseService

	// Worker-specific fields
	workerIndex string
	workerPort  int
}

// NewWorkerService creates a new worker service instance
// TODO: This currently delegates to the original NewCRSService
// In future commits, we will migrate the implementation to WorkerCRSService
func NewWorkerService(workerIndex string, workerPort int, model string) CRSService {
	// Temporarily use the original implementation
	service := NewCRSService(0, workerPort, model)
	// Set worker-specific configuration
	service.SetWorkerIndex(workerIndex)
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
	// This will be moved from the original implementation
	panic("SubmitWorkerTask: to be implemented")
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

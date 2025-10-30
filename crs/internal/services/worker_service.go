package services

import (
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
func NewWorkerService(workerIndex string, workerPort int, model string) CRSService {
	workDir := initializeWorkDir()
	apiEndpoint, apiKeyID, apiToken := initializeCompetitionAPI()

	return &WorkerCRSService{
		baseService: baseService{
			workDir:                 workDir,
			competitionClient:       initializeCompetitionClient(apiEndpoint, apiKeyID, apiToken),
			model:                   model,
			povMetadataDir:          "successful_povs",
			povMetadataDir0:         "successful_povs_0",
			povAdvcancedMetadataDir: "successful_povs_advanced",
			patchWorkDir:            "patch_workspace",
		},
		workerIndex: workerIndex,
		workerPort:  workerPort,
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
func (s *WorkerCRSService) SubmitSarif(sarifBroadcast models.SARIFBroadcast) error {
	// This will use the shared SARIF handling logic
	panic("SubmitSarif: to be implemented")
}

// HandleSarifBroadcastWorker is not used in worker mode
func (s *WorkerCRSService) HandleSarifBroadcastWorker(broadcastWorker models.SARIFBroadcastDetailWorker) error {
	return errNotSupportedInWorkerMode
}

// SetWorkerIndex sets the worker index
func (s *WorkerCRSService) SetWorkerIndex(index string) {
	s.workerIndex = index
}

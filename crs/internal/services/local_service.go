package services

import (
	"crs/internal/models"
)

// LocalCRSService implements CRSService for local CLI mode
type LocalCRSService struct {
	baseService
}

// NewLocalService creates a new local service instance
func NewLocalService(model string) CRSService {
	// Use the same workDir initialization logic from NewCRSService
	workDir := initializeWorkDir()

	apiEndpoint, apiKeyID, apiToken := initializeCompetitionAPI()

	return &LocalCRSService{
		baseService: baseService{
			workDir:                 workDir,
			competitionClient:       initializeCompetitionClient(apiEndpoint, apiKeyID, apiToken),
			model:                   model,
			povMetadataDir:          "successful_povs",
			povMetadataDir0:         "successful_povs_0",
			povAdvcancedMetadataDir: "successful_povs_advanced",
			patchWorkDir:            "patch_workspace",
		},
	}
}

// GetStatus returns empty status for local mode (no task tracking)
func (s *LocalCRSService) GetStatus() models.Status {
	return models.Status{
		Ready: true,
		State: models.StatusState{
			Tasks: models.StatusTasksState{},
		},
	}
}

// SubmitLocalTask implements local task submission
func (s *LocalCRSService) SubmitLocalTask(taskPath string) error {
	// This will be moved from the original implementation
	// For now, return unimplemented
	panic("SubmitLocalTask: to be implemented")
}

// SubmitTask is not supported in local mode
func (s *LocalCRSService) SubmitTask(task models.Task) error {
	return errNotSupportedInLocalMode
}

// SubmitWorkerTask is not supported in local mode
func (s *LocalCRSService) SubmitWorkerTask(task models.WorkerTask) error {
	return errNotSupportedInLocalMode
}

// CancelTask is not supported in local mode
func (s *LocalCRSService) CancelTask(taskID string) error {
	return errNotSupportedInLocalMode
}

// CancelAllTasks is not supported in local mode
func (s *LocalCRSService) CancelAllTasks() error {
	return errNotSupportedInLocalMode
}

// SubmitSarif handles SARIF broadcast submission
func (s *LocalCRSService) SubmitSarif(sarifBroadcast models.SARIFBroadcast) error {
	// This will use the shared SARIF handling logic
	panic("SubmitSarif: to be implemented")
}

// HandleSarifBroadcastWorker is not typically used in local mode
func (s *LocalCRSService) HandleSarifBroadcastWorker(broadcastWorker models.SARIFBroadcastDetailWorker) error {
	return errNotSupportedInLocalMode
}

// SetWorkerIndex is not used in local mode (no-op)
func (s *LocalCRSService) SetWorkerIndex(index string) {
	// No-op for local mode
}

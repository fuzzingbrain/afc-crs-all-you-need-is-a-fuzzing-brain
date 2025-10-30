package services

import (
	"sync"

	"crs/internal/models"
)

// ServerCRSService implements CRSService for server mode (task scheduling and distribution)
type ServerCRSService struct {
	baseService

	// Task management
	tasks       map[string]*models.TaskDetail
	tasksMutex  sync.RWMutex
	status      models.StatusTasksState
	statusMutex sync.RWMutex

	// Worker management
	workerNodes    int
	workerBasePort int

	// Task distribution tracking
	totalTasksDistributed int
	distributionMutex     sync.Mutex
	fuzzerToWorkerMap     map[string]int
	taskToWorkersMap      map[string][]WorkerFuzzerPair

	// Worker status tracking
	workerStatus        map[int]*WorkerStatus
	workerStatusMux     sync.Mutex
	unharnessedFuzzerSrc sync.Map
}

// NewServerService creates a new server service instance
// TODO: This currently delegates to the original NewCRSService
// In future commits, we will migrate the implementation to ServerCRSService
func NewServerService(workerNodes int, workerBasePort int, model string) CRSService {
	// Temporarily use the original implementation
	return NewCRSService(workerNodes, workerBasePort, model)
}

// GetStatus returns current server status
func (s *ServerCRSService) GetStatus() models.Status {
	s.statusMutex.RLock()
	defer s.statusMutex.RUnlock()

	return models.Status{
		Ready: true,
		State: models.StatusState{
			Tasks: s.status,
		},
	}
}

// SubmitLocalTask is not supported in server mode
func (s *ServerCRSService) SubmitLocalTask(taskPath string) error {
	return errNotSupportedInServerMode
}

// SubmitTask implements server task submission
func (s *ServerCRSService) SubmitTask(task models.Task) error {
	// This will be moved from the original implementation
	panic("SubmitTask: to be implemented")
}

// SubmitWorkerTask is not supported in server mode
func (s *ServerCRSService) SubmitWorkerTask(task models.WorkerTask) error {
	return errNotSupportedInServerMode
}

// CancelTask implements task cancellation
func (s *ServerCRSService) CancelTask(taskID string) error {
	// This will be moved from the original implementation
	panic("CancelTask: to be implemented")
}

// CancelAllTasks implements cancellation of all tasks
func (s *ServerCRSService) CancelAllTasks() error {
	// This will be moved from the original implementation
	panic("CancelAllTasks: to be implemented")
}

// SubmitSarif handles SARIF broadcast submission
func (s *ServerCRSService) SubmitSarif(sarifBroadcast models.SARIFBroadcast) error {
	// This will use the shared SARIF handling logic
	panic("SubmitSarif: to be implemented")
}

// HandleSarifBroadcastWorker handles SARIF broadcasts from workers
func (s *ServerCRSService) HandleSarifBroadcastWorker(broadcastWorker models.SARIFBroadcastDetailWorker) error {
	// This will be moved from the original implementation
	panic("HandleSarifBroadcastWorker: to be implemented")
}

// SetWorkerIndex is not used in server mode (no-op)
func (s *ServerCRSService) SetWorkerIndex(index string) {
	// No-op for server mode
}

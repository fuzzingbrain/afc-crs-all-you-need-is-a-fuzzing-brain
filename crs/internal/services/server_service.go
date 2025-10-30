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
func NewServerService(workerNodes int, workerBasePort int, model string) CRSService {
	workDir := initializeWorkDir()
	apiEndpoint, apiKeyID, apiToken := initializeCompetitionAPI()

	return &ServerCRSService{
		baseService: baseService{
			workDir:           workDir,
			competitionClient: initializeCompetitionClient(apiEndpoint, apiKeyID, apiToken),
			model:             model,
		},
		tasks: make(map[string]*models.TaskDetail),
		status: models.StatusTasksState{
			Pending:    0,
			Processing: 0,
			Waiting:    0,
			Succeeded:  0,
			Failed:     0,
			Errored:    0,
			Canceled:   0,
		},
		workerNodes:           workerNodes,
		workerBasePort:        workerBasePort,
		totalTasksDistributed: 0,
		fuzzerToWorkerMap:     make(map[string]int),
		taskToWorkersMap:      make(map[string][]WorkerFuzzerPair),
		workerStatus:          make(map[int]*WorkerStatus),
	}
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

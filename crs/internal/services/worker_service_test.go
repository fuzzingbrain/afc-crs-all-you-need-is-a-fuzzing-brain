package services

import (
	"sync"
	"testing"
	"time"

	"crs/internal/config"
	"crs/internal/models"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewWorkerService(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.Config
	}{
		{
			name: "valid worker config with all fields",
			cfg: &config.Config{
				Mode: "worker",
				Auth: config.AuthConfig{
					KeyID: "worker_key_id",
					Token: "worker_token",
				},
				Worker: config.WorkerConfig{
					Nodes:   24,
					Port:    9081,
					Index:   "0",
					PodName: "crs-worker-0",
				},
				Services: config.ServicesConfig{
					SubmissionURL: "http://localhost:7081",
					AnalysisURL:   "http://localhost:7082",
				},
				AI: config.AIConfig{
					Model: "claude-sonnet-4-20250514",
				},
			},
		},
		{
			name: "worker config with index extraction from pod name",
			cfg: &config.Config{
				Mode: "worker",
				Auth: config.AuthConfig{
					KeyID: "key",
					Token: "token",
				},
				Worker: config.WorkerConfig{
					Nodes:   10,
					Port:    9090,
					Index:   "5",
					PodName: "crs-worker-5",
				},
				Services: config.ServicesConfig{
					SubmissionURL: "http://submit",
					AnalysisURL:   "http://analysis",
				},
				AI: config.AIConfig{
					Model: "test-model",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := NewWorkerService(tt.cfg)
			require.NotNil(t, service)

			// Type assertion to access internal fields
			workerService, ok := service.(*WorkerCRSService)
			require.True(t, ok, "service should be *WorkerCRSService")

			// Verify config is stored
			assert.Equal(t, tt.cfg, workerService.cfg)

			// Verify config values are used
			assert.Equal(t, tt.cfg.Worker.Port, workerService.workerPort)
			assert.Equal(t, tt.cfg.Worker.Index, workerService.workerIndex)
			assert.Equal(t, tt.cfg.AI.Model, workerService.model)
			assert.Equal(t, tt.cfg.Services.SubmissionURL, workerService.submissionEndpoint)
			assert.Equal(t, tt.cfg.Services.AnalysisURL, workerService.analysisServiceUrl)

			// Verify status
			status := service.GetStatus()
			assert.True(t, status.Ready)
		})
	}
}

func TestWorkerService_GetStatus(t *testing.T) {
	t.Setenv("CRS_WORKDIR", t.TempDir())
	cfg := &config.Config{
		Mode: "worker",
		Auth: config.AuthConfig{KeyID: "key", Token: "token"},
		Worker: config.WorkerConfig{
			Nodes:   2,
			Port:    9081,
			Index:   "0",
			PodName: "worker-0",
		},
		Services: config.ServicesConfig{
			SubmissionURL: "http://localhost:7081",
			AnalysisURL:   "http://localhost:7082",
		},
		AI: config.AIConfig{Model: "test-model"},
	}

	service := NewWorkerService(cfg)
	require.NotNil(t, service)

	status := service.GetStatus()
	assert.True(t, status.Ready)
	assert.Equal(t, 0, status.State.Tasks.Pending)
	assert.Equal(t, 0, status.State.Tasks.Processing)
}

func TestWorkerService_GetWorkDir(t *testing.T) {
	t.Setenv("CRS_WORKDIR", t.TempDir())
	cfg := &config.Config{
		Mode: "worker",
		Auth: config.AuthConfig{KeyID: "key", Token: "token"},
		Worker: config.WorkerConfig{
			Nodes:   2,
			Port:    9081,
			Index:   "1",
			PodName: "worker-1",
		},
		Services: config.ServicesConfig{
			SubmissionURL: "http://localhost:7081",
			AnalysisURL:   "http://localhost:7082",
		},
		AI: config.AIConfig{Model: "test-model"},
	}

	service := NewWorkerService(cfg)
	require.NotNil(t, service)

	workDir := service.GetWorkDir()
	assert.NotEmpty(t, workDir, "work directory should not be empty")
}

func TestWorkerService_ConfigIntegration(t *testing.T) {
	// Test that config values are properly used throughout the service
	t.Setenv("CRS_WORKDIR", t.TempDir())
	cfg := &config.Config{
		Mode: "worker",
		Auth: config.AuthConfig{
			KeyID: "integration_worker_key",
			Token: "integration_worker_token",
		},
		Worker: config.WorkerConfig{
			Nodes:         24,
			Port:          9999,
			Index:         "7",
			PodName:       "crs-worker-7",
			WebServiceURL: "http://crs-web:7080",
		},
		Services: config.ServicesConfig{
			SubmissionURL: "http://custom-submit:8080",
			AnalysisURL:   "http://custom-analysis:8082",
		},
		AI: config.AIConfig{
			Model:           "custom-worker-model",
			AnthropicAPIKey: "test-worker-api-key",
		},
	}

	service := NewWorkerService(cfg)
	require.NotNil(t, service)

	workerService, ok := service.(*WorkerCRSService)
	require.True(t, ok)

	// Verify all config values are correctly propagated
	assert.Equal(t, 9999, workerService.workerPort)
	assert.Equal(t, "7", workerService.workerIndex)
	assert.Equal(t, "custom-worker-model", workerService.model)
	assert.Equal(t, "http://custom-submit:8080", workerService.submissionEndpoint)
	assert.Equal(t, "http://custom-analysis:8082", workerService.analysisServiceUrl)

	// Verify metadata directories are set
	assert.Equal(t, "successful_povs", workerService.povMetadataDir)
	assert.Equal(t, "successful_povs_0", workerService.povMetadataDir0)
	assert.Equal(t, "successful_povs_advanced", workerService.povAdvcancedMetadataDir)
	assert.Equal(t, "patch_workspace", workerService.patchWorkDir)
}

func TestWorkerService_IsWorkerBusy(t *testing.T) {
	t.Setenv("CRS_WORKDIR", t.TempDir())
	cfg := &config.Config{
		Mode: "worker",
		Auth: config.AuthConfig{KeyID: "key", Token: "token"},
		Worker: config.WorkerConfig{
			Nodes: 1,
			Port:  9081,
			Index: "0",
		},
		Services: config.ServicesConfig{
			SubmissionURL: "http://localhost:7081",
			AnalysisURL:   "http://localhost:7082",
		},
		AI: config.AIConfig{Model: "test-model"},
	}

	service := NewWorkerService(cfg)
	require.NotNil(t, service)

	workerService, ok := service.(*WorkerCRSService)
	require.True(t, ok)

	// Initially, worker should not be busy
	busy, taskIDs := workerService.IsWorkerBusy()
	assert.False(t, busy)
	assert.Empty(t, taskIDs)
}

func TestWorkerServiceUnsupportedOperations(t *testing.T) {
	t.Setenv("CRS_WORKDIR", t.TempDir())
	service := NewWorkerService(&config.Config{
		Mode: "worker",
		Auth: config.AuthConfig{KeyID: "key", Token: "token"},
		Worker: config.WorkerConfig{
			Nodes: 1,
			Port:  9000,
		},
		Services: config.ServicesConfig{
			SubmissionURL: "http://submit",
			AnalysisURL:   "http://analysis",
		},
		AI: config.AIConfig{Model: "test"},
	}).(*WorkerCRSService)

	assert.Equal(t, errNotSupportedInWorkerMode, service.SubmitLocalTask("/tmp/path"))
	assert.Equal(t, errNotSupportedInWorkerMode, service.SubmitTask(models.Task{}))

	service.SetWorkerIndex("5")
	service.SetSubmissionEndpoint("http://new-submit")
	service.SetAnalysisServiceUrl("http://new-analysis")

	assert.Equal(t, "5", service.workerIndex)
	assert.Equal(t, "http://new-submit", service.submissionEndpoint)
	assert.Equal(t, "http://new-analysis", service.analysisServiceUrl)
}

func TestWorkerServiceSubmitWorkerTaskRequiresTasks(t *testing.T) {
	t.Setenv("CRS_WORKDIR", t.TempDir())
	service := NewWorkerService(&config.Config{
		Mode: "worker",
		Auth: config.AuthConfig{KeyID: "key", Token: "token"},
		Worker: config.WorkerConfig{
			Nodes: 1,
			Port:  9000,
		},
		Services: config.ServicesConfig{
			SubmissionURL: "http://submit",
			AnalysisURL:   "http://analysis",
		},
		AI: config.AIConfig{Model: "test"},
	}).(*WorkerCRSService)

	err := service.SubmitWorkerTask(models.WorkerTask{})
	assert.Error(t, err)
}

func TestWorkerServiceHasActiveTasks(t *testing.T) {
	t.Setenv("CRS_WORKDIR", t.TempDir())
	service := NewWorkerService(&config.Config{
		Mode: "worker",
		Auth: config.AuthConfig{KeyID: "key", Token: "token"},
		Worker: config.WorkerConfig{
			Nodes: 1,
			Port:  9000,
		},
		Services: config.ServicesConfig{
			SubmissionURL: "http://submit",
			AnalysisURL:   "http://analysis"},
		AI: config.AIConfig{Model: "test"},
	}).(*WorkerCRSService)

	workerTaskMutex.Lock()
	activeWorkerTasks = map[string]bool{"task1": true}
	workerTaskMutex.Unlock()
	defer func() {
		workerTaskMutex.Lock()
		activeWorkerTasks = make(map[string]bool)
		workerTaskMutex.Unlock()
	}()

	assert.True(t, service.hasActiveWorkTasks())
}

func TestWorkerServiceSubmitWorkerTaskLowCPU(t *testing.T) {
	service := NewWorkerService(&config.Config{
		Mode:     "worker",
		Auth:     config.AuthConfig{KeyID: "key", Token: "token"},
		Worker:   config.WorkerConfig{Nodes: 1, Port: 9000},
		Services: config.ServicesConfig{SubmissionURL: "http://submit", AnalysisURL: "http://analysis"},
		AI:       config.AIConfig{Model: "test"},
	}).(*WorkerCRSService)

	service.cpuUsageFn = func() (float64, error) { return 10.0, nil }
	var wg sync.WaitGroup
	wg.Add(1)
	service.processTaskFunc = func(fuzzer string, td models.TaskDetail, task models.Task) error {
		defer wg.Done()
		assert.Equal(t, "fuzzer", fuzzer)
		return nil
	}

	workerTaskMutex.Lock()
	activeWorkerTasks = make(map[string]bool)
	workerTaskMutex.Unlock()

	workerTask := models.WorkerTask{
		MessageID:   uuid.New(),
		MessageTime: time.Now().Unix(),
		Fuzzer:      "fuzzer",
		Tasks:       []models.TaskDetail{{TaskID: uuid.New()}},
	}

	assert.NoError(t, service.SubmitWorkerTask(workerTask))

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("processTaskFunc was not invoked")
	}
}

func TestWorkerServiceSubmitWorkerTaskHighCPURejects(t *testing.T) {
	service := NewWorkerService(&config.Config{
		Mode:     "worker",
		Auth:     config.AuthConfig{KeyID: "key", Token: "token"},
		Worker:   config.WorkerConfig{Nodes: 1, Port: 9000},
		Services: config.ServicesConfig{SubmissionURL: "http://submit", AnalysisURL: "http://analysis"},
		AI:       config.AIConfig{Model: "test"},
	}).(*WorkerCRSService)

	service.cpuUsageFn = func() (float64, error) { return 90.0, nil }
	service.processTaskFunc = func(string, models.TaskDetail, models.Task) error {
		t.Fatal("processTaskFunc should not be called")
		return nil
	}

	workerTaskMutex.Lock()
	activeWorkerTasks = map[string]bool{"task": true}
	workerTaskMutex.Unlock()

	err := service.SubmitWorkerTask(models.WorkerTask{
		MessageID: uuid.New(),
		Tasks:     []models.TaskDetail{{TaskID: uuid.New()}},
	})
	assert.Error(t, err)
}

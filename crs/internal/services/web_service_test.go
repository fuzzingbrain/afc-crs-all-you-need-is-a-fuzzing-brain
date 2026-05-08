// SPDX-License-Identifier: Apache-2.0
package services

import (
	"testing"

	"crs/internal/config"
	"crs/internal/models"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewWebService(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.Config
	}{
		{
			name: "valid config with all fields",
			cfg: &config.Config{
				Mode: "server",
				Auth: config.AuthConfig{
					KeyID: "test_key_id",
					Token: "test_token",
				},
				Server: config.ServerConfig{
					Port:           "7080",
					WorkerBasePort: 9081,
				},
				Worker: config.WorkerConfig{
					Nodes: 24,
					Port:  9081,
				},
				Services: config.ServicesConfig{
					SubmissionURL: "http://localhost:7081",
					AnalysisURL:   "http://localhost:7082",
				},
				AI: config.AIConfig{
					Model: "claude-sonnet-4-5-20250929",
				},
			},
		},
		{
			name: "minimal config",
			cfg: &config.Config{
				Mode: "server",
				Auth: config.AuthConfig{
					KeyID: "key",
					Token: "token",
				},
				Server: config.ServerConfig{
					Port:           "8080",
					WorkerBasePort: 9000,
				},
				Worker: config.WorkerConfig{
					Nodes: 1,
					Port:  9001,
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
			service := NewWebService(tt.cfg)
			require.NotNil(t, service)

			// Type assertion to access internal fields
			webService, ok := service.(*WebCRSService)
			require.True(t, ok, "service should be *WebCRSService")

			// Verify config is stored
			assert.Equal(t, tt.cfg, webService.cfg)

			// Verify config values are used
			assert.Equal(t, tt.cfg.Worker.Nodes, webService.workerNodes)
			assert.Equal(t, tt.cfg.Server.WorkerBasePort, webService.workerBasePort)
			assert.Equal(t, tt.cfg.AI.Model, webService.model)
			assert.Equal(t, tt.cfg.Services.SubmissionURL, webService.submissionEndpoint)
			assert.Equal(t, tt.cfg.Services.AnalysisURL, webService.analysisServiceUrl)

			// Verify worker status is initialized
			assert.NotNil(t, webService.workerStatus)
			assert.Equal(t, tt.cfg.Worker.Nodes, len(webService.workerStatus))

			// Verify maps are initialized
			assert.NotNil(t, webService.tasks)
			assert.NotNil(t, webService.fuzzerToWorkerMap)
			assert.NotNil(t, webService.taskToWorkersMap)

			// Verify status
			status := service.GetStatus()
			assert.True(t, status.Ready)
		})
	}
}

func TestWebService_GetStatus(t *testing.T) {
	cfg := &config.Config{
		Mode:   "server",
		Auth:   config.AuthConfig{KeyID: "key", Token: "token"},
		Server: config.ServerConfig{Port: "7080", WorkerBasePort: 9081},
		Worker: config.WorkerConfig{Nodes: 2, Port: 9081},
		Services: config.ServicesConfig{
			SubmissionURL: "http://localhost:7081",
			AnalysisURL:   "http://localhost:7082",
		},
		AI: config.AIConfig{Model: "test-model"},
	}

	service := NewWebService(cfg)
	require.NotNil(t, service)

	status := service.GetStatus()
	assert.True(t, status.Ready)
	assert.Equal(t, 0, status.State.Tasks.Pending)
	assert.Equal(t, 0, status.State.Tasks.Processing)
	assert.Equal(t, 0, status.State.Tasks.Succeeded)
	assert.Equal(t, 0, status.State.Tasks.Errored)
}

func TestWebService_GetWorkDir(t *testing.T) {
	cfg := &config.Config{
		Mode:   "server",
		Auth:   config.AuthConfig{KeyID: "key", Token: "token"},
		Server: config.ServerConfig{Port: "7080", WorkerBasePort: 9081},
		Worker: config.WorkerConfig{Nodes: 2, Port: 9081},
		Services: config.ServicesConfig{
			SubmissionURL: "http://localhost:7081",
			AnalysisURL:   "http://localhost:7082",
		},
		AI: config.AIConfig{Model: "test-model"},
	}

	service := NewWebService(cfg)
	require.NotNil(t, service)

	workDir := service.GetWorkDir()
	assert.NotEmpty(t, workDir, "work directory should not be empty")
}

func TestWebService_ConfigIntegration(t *testing.T) {
	// Test that config values are properly used throughout the service
	cfg := &config.Config{
		Mode: "server",
		Auth: config.AuthConfig{
			KeyID: "integration_key",
			Token: "integration_token",
		},
		Server: config.ServerConfig{
			Port:           "7080",
			WorkerBasePort: 9999,
		},
		Worker: config.WorkerConfig{
			Nodes: 5,
			Port:  9081,
		},
		Services: config.ServicesConfig{
			SubmissionURL: "http://custom-submit:8080",
			AnalysisURL:   "http://custom-analysis:8082",
		},
		AI: config.AIConfig{
			Model:           "custom-model-v1",
			AnthropicAPIKey: "test-api-key",
		},
	}

	service := NewWebService(cfg)
	require.NotNil(t, service)

	webService, ok := service.(*WebCRSService)
	require.True(t, ok)

	// Verify all config values are correctly propagated
	assert.Equal(t, 5, webService.workerNodes)
	assert.Equal(t, 9999, webService.workerBasePort)
	assert.Equal(t, "custom-model-v1", webService.model)
	assert.Equal(t, "http://custom-submit:8080", webService.submissionEndpoint)
	assert.Equal(t, "http://custom-analysis:8082", webService.analysisServiceUrl)

	// Verify worker status initialized for all nodes
	assert.Equal(t, 5, len(webService.workerStatus))
	for i := 0; i < 5; i++ {
		assert.NotNil(t, webService.workerStatus[i])
		assert.Equal(t, 0, webService.workerStatus[i].FailureCount)
		assert.Equal(t, 0, webService.workerStatus[i].AssignedTasks)
	}
}

func TestWebServiceCancelTask(t *testing.T) {
	t.Setenv("CRS_WORKDIR", t.TempDir())
	service := NewWebService(&config.Config{
		Mode: "server",
		Auth: config.AuthConfig{KeyID: "key", Token: "token"},
		Server: config.ServerConfig{
			Port:           "7080",
			WorkerBasePort: 9000,
		},
		Worker:   config.WorkerConfig{Nodes: 1, Port: 9001},
		Services: config.ServicesConfig{SubmissionURL: "http://submit", AnalysisURL: "http://analysis"},
		AI:       config.AIConfig{Model: "test"},
	})

	webService := service.(*WebCRSService)
	taskID := uuid.New()
	webService.tasks[taskID.String()] = &models.TaskDetail{TaskID: taskID}

	err := webService.CancelTask(taskID.String())
	require.NoError(t, err)

	_, exists := webService.tasks[taskID.String()]
	assert.False(t, exists)
	assert.Equal(t, 1, webService.status.Canceled)
}

func TestWebServiceCancelAllTasks(t *testing.T) {
	t.Setenv("CRS_WORKDIR", t.TempDir())
	service := NewWebService(&config.Config{
		Mode: "server",
		Auth: config.AuthConfig{KeyID: "key", Token: "token"},
		Server: config.ServerConfig{
			Port:           "7080",
			WorkerBasePort: 9000,
		},
		Worker:   config.WorkerConfig{Nodes: 1, Port: 9001},
		Services: config.ServicesConfig{SubmissionURL: "http://submit", AnalysisURL: "http://analysis"},
		AI:       config.AIConfig{Model: "test"},
	})

	webService := service.(*WebCRSService)
	webService.tasks["a"] = &models.TaskDetail{TaskID: uuid.New()}
	webService.tasks["b"] = &models.TaskDetail{TaskID: uuid.New()}
	webService.status.Pending = 2

	err := webService.CancelAllTasks()
	require.NoError(t, err)
	assert.Empty(t, webService.tasks)
	assert.Equal(t, 2, webService.status.Canceled)
}

func TestWebServiceSetters(t *testing.T) {
	t.Setenv("CRS_WORKDIR", t.TempDir())
	service := NewWebService(&config.Config{
		Mode: "server",
		Auth: config.AuthConfig{KeyID: "key", Token: "token"},
		Server: config.ServerConfig{
			Port:           "7080",
			WorkerBasePort: 9000,
		},
		Worker:   config.WorkerConfig{Nodes: 1, Port: 9001},
		Services: config.ServicesConfig{SubmissionURL: "http://submit", AnalysisURL: "http://analysis"},
		AI:       config.AIConfig{Model: "test"},
	})

	webService := service.(*WebCRSService)

	webService.SetSubmissionEndpoint("http://new-submit")
	webService.SetAnalysisServiceUrl("http://new-analysis")
	webService.SetWorkerIndex("42")

	assert.Equal(t, "http://new-submit", webService.submissionEndpoint)
	assert.Equal(t, "http://new-analysis", webService.analysisServiceUrl)
	assert.Equal(t, "42", webService.workerIndex)
}

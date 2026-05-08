// SPDX-License-Identifier: Apache-2.0
package services

import (
	"testing"

	"crs/internal/config"
	"crs/internal/models"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLocalService(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.Config
	}{
		{
			name: "valid local config with all fields",
			cfg: &config.Config{
				Mode: "local",
				Auth: config.AuthConfig{
					KeyID: "local_key_id",
					Token: "local_token",
				},
				Services: config.ServicesConfig{
					SubmissionURL: "http://localhost:7081",
					AnalysisURL:   "http://localhost:7082",
				},
				AI: config.AIConfig{
					Model:           "claude-sonnet-4-5-20250929",
					AnthropicAPIKey: "test-api-key",
				},
			},
		},
		{
			name: "local config with GPT model",
			cfg: &config.Config{
				Mode: "local",
				Auth: config.AuthConfig{
					KeyID: "key",
					Token: "token",
				},
				Services: config.ServicesConfig{
					SubmissionURL: "http://submit",
					AnalysisURL:   "http://analysis",
				},
				AI: config.AIConfig{
					Model:        "gpt-4o",
					OpenAIAPIKey: "openai-test-key",
				},
			},
		},
		{
			name: "local config with Gemini model",
			cfg: &config.Config{
				Mode: "local",
				Auth: config.AuthConfig{
					KeyID: "key",
					Token: "token",
				},
				Services: config.ServicesConfig{
					SubmissionURL: "http://submit",
					AnalysisURL:   "http://analysis",
				},
				AI: config.AIConfig{
					Model:        "gemini-2.5-pro",
					GeminiAPIKey: "gemini-test-key",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := NewLocalService(tt.cfg)
			require.NotNil(t, service)

			// Type assertion to access internal fields
			localService, ok := service.(*LocalCRSService)
			require.True(t, ok, "service should be *LocalCRSService")

			// Verify config is stored
			assert.Equal(t, tt.cfg, localService.cfg)

			// Verify config values are used
			assert.Equal(t, tt.cfg.AI.Model, localService.model)
			assert.Equal(t, tt.cfg.Services.SubmissionURL, localService.submissionEndpoint)
			assert.Equal(t, tt.cfg.Services.AnalysisURL, localService.analysisServiceUrl)

			// Verify status
			status := service.GetStatus()
			assert.True(t, status.Ready)
		})
	}
}

func TestLocalService_GetStatus(t *testing.T) {
	cfg := &config.Config{
		Mode: "local",
		Auth: config.AuthConfig{KeyID: "key", Token: "token"},
		Services: config.ServicesConfig{
			SubmissionURL: "http://localhost:7081",
			AnalysisURL:   "http://localhost:7082",
		},
		AI: config.AIConfig{
			Model:           "claude-sonnet-4-5-20250929",
			AnthropicAPIKey: "test-key",
		},
	}

	service := NewLocalService(cfg)
	require.NotNil(t, service)

	status := service.GetStatus()
	assert.True(t, status.Ready)
	// Local service doesn't track task states
	assert.Equal(t, 0, status.State.Tasks.Pending)
	assert.Equal(t, 0, status.State.Tasks.Processing)
}

func TestLocalService_GetWorkDir(t *testing.T) {
	cfg := &config.Config{
		Mode: "local",
		Auth: config.AuthConfig{KeyID: "key", Token: "token"},
		Services: config.ServicesConfig{
			SubmissionURL: "http://localhost:7081",
			AnalysisURL:   "http://localhost:7082",
		},
		AI: config.AIConfig{
			Model:           "test-model",
			AnthropicAPIKey: "test-key",
		},
	}

	service := NewLocalService(cfg)
	require.NotNil(t, service)

	workDir := service.GetWorkDir()
	assert.NotEmpty(t, workDir, "work directory should not be empty")
}

func TestLocalService_ConfigIntegration(t *testing.T) {
	// Test that config values are properly used throughout the service
	cfg := &config.Config{
		Mode: "local",
		Auth: config.AuthConfig{
			KeyID: "integration_local_key",
			Token: "integration_local_token",
		},
		Services: config.ServicesConfig{
			SubmissionURL: "http://custom-local-submit:8080",
			AnalysisURL:   "http://custom-local-analysis:8082",
		},
		AI: config.AIConfig{
			Model:           "custom-local-model",
			AnthropicAPIKey: "test-local-api-key",
			OpenAIAPIKey:    "test-openai-key",
			GeminiAPIKey:    "test-gemini-key",
		},
	}

	service := NewLocalService(cfg)
	require.NotNil(t, service)

	localService, ok := service.(*LocalCRSService)
	require.True(t, ok)

	// Verify all config values are correctly propagated
	assert.Equal(t, "custom-local-model", localService.model)
	assert.Equal(t, "http://custom-local-submit:8080", localService.submissionEndpoint)
	assert.Equal(t, "http://custom-local-analysis:8082", localService.analysisServiceUrl)

	// Verify metadata directories are set
	assert.Equal(t, "successful_povs", localService.povMetadataDir)
	assert.Equal(t, "successful_povs_0", localService.povMetadataDir0)
	assert.Equal(t, "successful_povs_advanced", localService.povAdvcancedMetadataDir)

	// Worker index should be empty for local service
	assert.Empty(t, localService.workerIndex)
}

func TestLocalService_UnsupportedMethods(t *testing.T) {
	cfg := &config.Config{
		Mode: "local",
		Auth: config.AuthConfig{KeyID: "key", Token: "token"},
		Services: config.ServicesConfig{
			SubmissionURL: "http://localhost:7081",
			AnalysisURL:   "http://localhost:7082",
		},
		AI: config.AIConfig{
			Model:           "test-model",
			AnthropicAPIKey: "test-key",
		},
	}

	service := NewLocalService(cfg)
	require.NotNil(t, service)

	// These methods should return errors in local mode
	t.Run("SubmitTask should return error", func(t *testing.T) {
		var task models.Task
		err := service.SubmitTask(task)
		assert.Error(t, err)
		assert.Equal(t, errNotSupportedInLocalMode, err)
	})

	t.Run("SubmitWorkerTask should return error", func(t *testing.T) {
		var workerTask models.WorkerTask
		err := service.SubmitWorkerTask(workerTask)
		assert.Error(t, err)
		assert.Equal(t, errNotSupportedInLocalMode, err)
	})

	t.Run("CancelTask should return error", func(t *testing.T) {
		err := service.CancelTask("test-task-id")
		assert.Error(t, err)
		assert.Equal(t, errNotSupportedInLocalMode, err)
	})

	t.Run("CancelAllTasks should return error", func(t *testing.T) {
		err := service.CancelAllTasks()
		assert.Error(t, err)
		assert.Equal(t, errNotSupportedInLocalMode, err)
	})

	t.Run("HandleSarifBroadcastWorker should return error", func(t *testing.T) {
		var broadcast models.SARIFBroadcastDetailWorker
		err := service.HandleSarifBroadcastWorker(broadcast)
		assert.Error(t, err)
		assert.Equal(t, errNotSupportedInLocalMode, err)
	})
}

func TestLocalService_SupportedMethods(t *testing.T) {
	cfg := &config.Config{
		Mode: "local",
		Auth: config.AuthConfig{KeyID: "key", Token: "token"},
		Services: config.ServicesConfig{
			SubmissionURL: "http://localhost:7081",
			AnalysisURL:   "http://localhost:7082",
		},
		AI: config.AIConfig{
			Model:           "test-model",
			AnthropicAPIKey: "test-key",
		},
	}

	service := NewLocalService(cfg)
	require.NotNil(t, service)

	// These methods should work without errors (even if they're no-ops)
	t.Run("SetWorkerIndex should not panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			service.SetWorkerIndex("test-index")
		})
	})

	t.Run("SetSubmissionEndpoint should not panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			service.SetSubmissionEndpoint("http://new-endpoint")
		})
	})

	t.Run("SetAnalysisServiceUrl should not panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			service.SetAnalysisServiceUrl("http://new-analysis")
		})
	})
}

package services

import (
	"os"
	"path/filepath"
	"testing"

	"crs/internal/config"
	"crs/internal/models"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestConfig() *config.Config {
	return &config.Config{
		Auth: config.AuthConfig{
			KeyID: "id",
			Token: "token",
		},
		Services: config.ServicesConfig{
			SubmissionURL: "http://submission",
			AnalysisURL:   "http://analysis",
		},
		AI: config.AIConfig{
			Model: "test-model",
		},
	}
}

func TestNewLocalServiceInitializesWorkDir(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("CRS_WORKDIR", tempDir)
	t.Setenv("COMPETITION_API_ENDPOINT", "http://custom")

	service := NewLocalService(newTestConfig())
	local, ok := service.(*LocalCRSService)
	require.True(t, ok)

	assert.NotNil(t, local.competitionClient)
	assert.Equal(t, tempDir, local.workDir)
	assert.Equal(t, "http://submission", local.submissionEndpoint)
	assert.Equal(t, "http://analysis", local.analysisServiceUrl)
	assert.Equal(t, "test-model", local.model)
}

func TestLocalServiceSetters(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("CRS_WORKDIR", tempDir)

	service := NewLocalService(newTestConfig()).(*LocalCRSService)

	service.SetWorkerIndex("5")
	service.SetSubmissionEndpoint("http://new-submission")
	service.SetAnalysisServiceUrl("http://new-analysis")

	assert.Equal(t, "5", service.workerIndex)
	assert.Equal(t, "http://new-submission", service.submissionEndpoint)
	assert.Equal(t, "http://new-analysis", service.analysisServiceUrl)
	assert.Equal(t, tempDir, service.GetWorkDir())
}

func TestLocalServiceUnsupportedOperations(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("CRS_WORKDIR", tempDir)
	service := NewLocalService(newTestConfig()).(*LocalCRSService)

	assert.Equal(t, errNotSupportedInLocalMode, service.SubmitTask(models.Task{}))
	assert.Equal(t, errNotSupportedInLocalMode, service.SubmitWorkerTask(models.WorkerTask{}))
	assert.Equal(t, errNotSupportedInLocalMode, service.CancelTask("id"))
	assert.Equal(t, errNotSupportedInLocalMode, service.CancelAllTasks())
	assert.Equal(t, errNotSupportedInLocalMode, service.HandleSarifBroadcastWorker(models.SARIFBroadcastDetailWorker{}))
}

func TestLocalServiceSubmitSarif(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("CRS_WORKDIR", tempDir)

	service := NewLocalService(newTestConfig()).(*LocalCRSService)
	err := service.SubmitSarif(models.SARIFBroadcast{})
	assert.NoError(t, err)
}

func TestSubmitLocalTaskMissingFuzzers(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("CRS_WORKDIR", filepath.Join(tempDir, "work"))
	taskDir := filepath.Join(tempDir, "task")
	require.NoError(t, os.MkdirAll(taskDir, 0o755))

	service := NewLocalService(newTestConfig()).(*LocalCRSService)

	// Should succeed even if no fuzzers are present (early return)
	err := service.SubmitLocalTask(taskDir)
	assert.NoError(t, err)
}

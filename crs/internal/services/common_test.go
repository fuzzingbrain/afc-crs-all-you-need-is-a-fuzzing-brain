package services

import (
	"os"
	"path/filepath"
	"testing"

	"crs/internal/competition"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBaseServiceSetters(t *testing.T) {
	b := &baseService{workDir: "/tmp/work"}

	b.SetSubmissionEndpoint("http://submit")
	b.SetAnalysisServiceUrl("http://analysis")

	assert.Equal(t, "/tmp/work", b.GetWorkDir())
	assert.Equal(t, "http://submit", b.submissionEndpoint)
	assert.Equal(t, "http://analysis", b.analysisServiceUrl)
}

func TestInitializeWorkDirUsesEnv(t *testing.T) {
	t.Setenv("CRS_WORKDIR", t.TempDir())
	dir := initializeWorkDir()
	assert.Equal(t, os.Getenv("CRS_WORKDIR"), dir)
	info, err := os.Stat(dir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestInitializeWorkDirFallback(t *testing.T) {
	tempFile := filepath.Join(t.TempDir(), "not_a_dir")
	require.NoError(t, os.WriteFile(tempFile, []byte("x"), 0o644))

	t.Setenv("CRS_WORKDIR", tempFile)

	dir := initializeWorkDir()
	assert.NotEqual(t, tempFile, dir)

	info, err := os.Stat(dir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestInitializeCompetitionAPI(t *testing.T) {
	t.Setenv("COMPETITION_API_ENDPOINT", "http://custom-endpoint")
	t.Setenv("CRS_KEY_ID", "key")
	t.Setenv("CRS_KEY_TOKEN", "token")

	endpoint, key, token := initializeCompetitionAPI()
	assert.Equal(t, "http://custom-endpoint", endpoint)
	assert.Equal(t, "key", key)
	assert.Equal(t, "token", token)
}

func TestInitializeCompetitionAPIUsesDefaults(t *testing.T) {
	t.Setenv("COMPETITION_API_ENDPOINT", "")
	t.Setenv("CRS_KEY_ID", "")
	t.Setenv("CRS_KEY_TOKEN", "")

	endpoint, key, token := initializeCompetitionAPI()
	assert.Equal(t, "http://localhost:7081", endpoint)
	assert.Empty(t, key)
	assert.Empty(t, token)
}

func TestInitializeCompetitionClient(t *testing.T) {
	client := initializeCompetitionClient("http://endpoint", "key", "token")
	require.NotNil(t, client)
	assert.IsType(t, &competition.Client{}, client)
}

func TestGetAverageCPUUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping CPU usage test in short mode (takes 2s)")
	}
	value, err := getAverageCPUUsage()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, value, 0.0)
	assert.LessOrEqual(t, value, 100.0)
}

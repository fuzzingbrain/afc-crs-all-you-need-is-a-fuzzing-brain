package executor

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"crs/internal/competition"
	"crs/internal/models"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSavePOVMetadataCreatesFiles(t *testing.T) {
	taskDir := t.TempDir()
	fuzzDir := filepath.Join(taskDir, "example-address")
	require.NoError(t, os.MkdirAll(fuzzDir, 0o755))

	fuzzerPath := filepath.Join(fuzzDir, "fuzzer")
	require.NoError(t, os.WriteFile(fuzzerPath, []byte("binary"), 0o755))

	blobPath := filepath.Join(taskDir, "blob.bin")
	require.NoError(t, os.WriteFile(blobPath, []byte("blob-data"), 0o644))

	detail := models.TaskDetail{ProjectName: "proj"}

	err := SavePOVMetadata(taskDir, fuzzerPath, blobPath, "output text", detail, "pov-data")
	require.NoError(t, err)

	files, err := os.ReadDir(filepath.Join(fuzzDir, "pov-data"))
	require.NoError(t, err)
	assert.NotEmpty(t, files)
}

func TestSaveAllCrashesAsPOVsCreatesMetadataWhenEmpty(t *testing.T) {
	baseDir := t.TempDir()
	crashesDir := filepath.Join(baseDir, "crashes")
	require.NoError(t, os.MkdirAll(crashesDir, 0o755))

	fuzzDir := filepath.Join(baseDir, "example-address")
	require.NoError(t, os.MkdirAll(fuzzDir, 0o755))
	fuzzerPath := filepath.Join(fuzzDir, "fuzzer")
	require.NoError(t, os.WriteFile(fuzzerPath, []byte("binary"), 0o755))

	projectDir := filepath.Join(baseDir, "project")
	require.NoError(t, os.MkdirAll(projectDir, 0o755))

	detail := models.TaskDetail{ProjectName: "proj"}

	result := SaveAllCrashesAsPOVs(crashesDir, baseDir, fuzzerPath, fuzzDir, projectDir, "output", "address", detail, "fuzzer", "pov-meta")
	assert.Equal(t, "", result)

	files, err := os.ReadDir(filepath.Join(fuzzDir, "pov-meta"))
	require.NoError(t, err)
	assert.NotEmpty(t, files)
}

func TestGenerateCrashSignatureAndSubmitCompetitionPath(t *testing.T) {
	var called bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		user, pass, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.Equal(t, "user", user)
		assert.Equal(t, "pass", pass)

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var payload models.POVSubmission
		require.NoError(t, json.Unmarshal(body, &payload))
		assert.Equal(t, "fuzzer", payload.FuzzerName)

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","pov_id":"123"}`))
	}))
	defer server.Close()

	fuzzDir := t.TempDir()
	metaDir := "pov-meta"
	require.NoError(t, os.MkdirAll(filepath.Join(fuzzDir, metaDir), 0o755))
	crashFile := filepath.Join(fuzzDir, metaDir, "test_blob_case.bin")
	require.NoError(t, os.WriteFile(crashFile, []byte("crash-data"), 0o644))

	taskDetail := models.TaskDetail{
		TaskID:      uuid.New(),
		ProjectName: "proj",
	}

	params := POVSubmissionParams{
		FuzzDir:           fuzzDir,
		POVMetadataDir:    metaDir,
		TaskDetail:        taskDetail,
		Fuzzer:            "fuzzer",
		Sanitizer:         "address",
		Output:            "ERROR: AddressSanitizer: issue",
		VulnSignature:     "sig",
		CompetitionClient: competition.NewClient(server.URL, "user", "pass"),
	}

	require.NoError(t, GenerateCrashSignatureAndSubmit(params))
	assert.True(t, called)
}

func TestGetValidPOVs(t *testing.T) {
	taskID := "task-test"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/task/task-test/valid_povs/", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"povs":[{"pov_id":"p1","fuzzer_name":"f","sanitizer":"asan","testcase":"d"}],"count":1}`))
	}))
	defer server.Close()

	povs, err := GetValidPOVs(taskID, server.URL)
	require.NoError(t, err)
	require.Len(t, povs, 1)
	assert.Equal(t, "p1", povs[0].POVID)
}

func TestGetPOVStatsFromSubmissionService(t *testing.T) {
	t.Setenv("COMPETITION_API_KEY_ID", "id")
	t.Setenv("COMPETITION_API_KEY_TOKEN", "token")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.Equal(t, "id", user)
		assert.Equal(t, "token", pass)

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"task_id":"task","count":2,"patch_count":1}`))
	}))
	defer server.Close()

	count, patchCount, err := GetPOVStatsFromSubmissionService("task", server.URL)
	require.NoError(t, err)
	assert.Equal(t, 2, count)
	assert.Equal(t, 1, patchCount)
}

func TestFindProjectDir(t *testing.T) {
	taskID := uuid.New().String()
	workDir := t.TempDir()

	taskDetail := &models.TaskDetail{Focus: "focus-dir"}
	tasks := map[string]*models.TaskDetail{
		taskID: taskDetail,
	}

	oldDir := filepath.Join(workDir, taskID+"-old")
	newDir := filepath.Join(workDir, taskID+"-new")

	require.NoError(t, os.MkdirAll(filepath.Join(oldDir, "focus-dir"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(newDir, "focus-dir"), 0o755))

	oldTime := time.Now().Add(-time.Hour)
	require.NoError(t, os.Chtimes(oldDir, oldTime, oldTime))

	projectDir, err := FindProjectDir(taskID, workDir, tasks)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(newDir, "focus-dir"), projectDir)
}

func TestExtractCrashTrace(t *testing.T) {
	output := `
runtime error: signed integer overflow
#0 0x0 in func
SUMMARY: UndefinedBehaviorSanitizer: issue
`
	trace := extractCrashTrace(output)
	assert.Contains(t, trace, "UndefinedBehaviorSanitizer Error")
	assert.Contains(t, trace, "Summary: issue")

	generic := "INFO\nERROR: AddressSanitizer: problem"
	assert.Equal(t, "ERROR: AddressSanitizer: problem", extractCrashTrace(generic))
}

func TestGetSourceCodeNotImplemented(t *testing.T) {
	_, err := GetSourceCode("task", "file")
	assert.Error(t, err)
}

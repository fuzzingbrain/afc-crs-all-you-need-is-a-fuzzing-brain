// SPDX-License-Identifier: Apache-2.0
package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	// "path"
	"testing"
	// "time"

	"github.com/gin-gonic/gin"
	// "github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"crs/internal/services"
	"crs/internal/models"
	"crs/internal/config"
)

// MockCRSService implements all methods from services.CRSService.
type MockCRSService struct {
	mock.Mock
}

func (m *MockCRSService) GetStatus() models.Status {
	args := m.Called()
	if val, ok := args.Get(0).(models.Status); ok {
		return val
	}
	return models.Status{}
}

func (m *MockCRSService) SubmitTask(task models.Task) error {
	args := m.Called(task)
	return args.Error(0)
}

func (m *MockCRSService) SubmitWorkerTask(task models.WorkerTask) error {
	args := m.Called(task)
	return args.Error(0)
}

func (m *MockCRSService) CancelTask(taskID string) error {
	args := m.Called(taskID)
	return args.Error(0)
}

func (m *MockCRSService) CancelAllTasks() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockCRSService) SubmitSarif(sarifBroadcast models.SARIFBroadcast) error {
	args := m.Called(sarifBroadcast)
	return args.Error(0)
}

func (m *MockCRSService) SetSubmissionEndpoint(endpoint string) {
	m.Called(endpoint)
}

func (m *MockCRSService) SetWorkerIndex(index string) {
	m.Called(index)
}

// Stub for the newly added GetWorkDir method.
func (m *MockCRSService) GetWorkDir() string {
	args := m.Called()
	if val, ok := args.Get(0).(string); ok {
		return val
	}
	return ""
}

func (m *MockCRSService) SetAnalysisServiceUrl(url string) {
	m.Called(url)
}

func (m *MockCRSService) SubmitLocalTask(taskPath string) error {
	args := m.Called(taskPath)
	return args.Error(0)
}

func (m *MockCRSService) HandleSarifBroadcastWorker(broadcastWorker models.SARIFBroadcastDetailWorker) error {
	args := m.Called(broadcastWorker)
	return args.Error(0)
}


func TestSubmitSarif_BufferOverflow_RealService(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	gin.SetMode(gin.TestMode)

	// 1. Create test config
	cfg := &config.Config{
		Mode: "server",
		Auth: config.AuthConfig{
			KeyID: "test_key",
			Token: "test_token",
		},
		Server: config.ServerConfig{
			Port:           "7080",
			WorkerBasePort: 9000,
		},
		Worker: config.WorkerConfig{
			Nodes: 2,
			Port:  9081,
		},
		Services: config.ServicesConfig{
			SubmissionURL: "http://localhost:7081",
			AnalysisURL:   "http://localhost:7082",
		},
		AI: config.AIConfig{
			Model: "claude-sonnet-4-5-20250929",
		},
	}

	// 2. Instantiate the *real* CRSService.
	crsService := services.NewWebService(cfg)

	// 3. Create a Handler that uses the real service.
	handler := NewHandler(crsService, "http://localhost:7082", "http://localhost:7081")

	// 3. Build a test router.
	router := gin.New()
	router.POST("/sarif", handler.SubmitSarif)

	// 4. Load the SARIF broadcast from file
	sarifFilePath := "/crs-workdir/sarif_reports/sarif_raw_sample.json"
	jsonData, err := os.ReadFile(sarifFilePath)
	if err != nil {
		t.Skipf("Test data file not found: %s", sarifFilePath)
		return
	}

	// 5. Optionally verify the JSON can be unmarshaled into your model
	// This step is not strictly necessary but helps catch format issues early
	var broadcast models.SARIFBroadcast
	err = json.Unmarshal(jsonData, &broadcast)
	assert.NoError(t, err, "Failed to unmarshal SARIF JSON")
	
	// Verify we have the expected data
	assert.NotEmpty(t, broadcast.MessageID, "MessageID should not be empty")
	assert.NotEmpty(t, broadcast.Broadcasts, "Broadcasts array should not be empty")
	assert.NotEmpty(t, broadcast.Broadcasts[0].TaskID, "TaskID should not be empty")

	// 6. Submit an HTTP POST request with the raw JSON data from file
	req, err := http.NewRequest("POST", "/sarif", bytes.NewBuffer(jsonData))
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// 7. Verify response is OK (200).
	assert.Equal(t, http.StatusOK, w.Code)
	
	// 8. Optional: Add more assertions to verify the service processed the data correctly
	// For example, check if files were created or data was stored as expected
}
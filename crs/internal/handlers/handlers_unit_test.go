package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"crs/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockService struct {
	status                 models.Status
	workDir                string
	submitTaskErr          error
	submitWorkerTaskErr    error
	submitSarifErr         error
	handleWorkerSarifErr   error
	cancelTaskErr          error
	cancelAllTasksErr      error
	submitTaskCalls        []models.Task
	submitWorkerTaskCalls  []models.WorkerTask
	submitSarifCalls       []models.SARIFBroadcast
	handleWorkerSarifCalls []models.SARIFBroadcastDetailWorker
	cancelTaskCalls        []string
	cancelAllTasksCalled   bool
	submitLocalTaskPaths   []string
}

func (m *mockService) GetStatus() models.Status {
	return m.status
}

func (m *mockService) SubmitTask(task models.Task) error {
	m.submitTaskCalls = append(m.submitTaskCalls, task)
	return m.submitTaskErr
}

func (m *mockService) SubmitLocalTask(taskPath string) error {
	m.submitLocalTaskPaths = append(m.submitLocalTaskPaths, taskPath)
	return nil
}

func (m *mockService) SubmitWorkerTask(task models.WorkerTask) error {
	m.submitWorkerTaskCalls = append(m.submitWorkerTaskCalls, task)
	return m.submitWorkerTaskErr
}

func (m *mockService) CancelTask(taskID string) error {
	m.cancelTaskCalls = append(m.cancelTaskCalls, taskID)
	return m.cancelTaskErr
}

func (m *mockService) CancelAllTasks() error {
	m.cancelAllTasksCalled = true
	return m.cancelAllTasksErr
}

func (m *mockService) SubmitSarif(sarifBroadcast models.SARIFBroadcast) error {
	m.submitSarifCalls = append(m.submitSarifCalls, sarifBroadcast)
	return m.submitSarifErr
}

func (m *mockService) HandleSarifBroadcastWorker(broadcastWorker models.SARIFBroadcastDetailWorker) error {
	m.handleWorkerSarifCalls = append(m.handleWorkerSarifCalls, broadcastWorker)
	return m.handleWorkerSarifErr
}

func (m *mockService) SetWorkerIndex(string)        {}
func (m *mockService) SetSubmissionEndpoint(string) {}
func (m *mockService) SetAnalysisServiceUrl(string) {}
func (m *mockService) GetWorkDir() string           { return m.workDir }

func setupRouter(h *Handler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/status", h.GetStatus)
	router.POST("/status/reset", h.ResetStatus)
	router.POST("/sarif", h.SubmitSarif)
	router.POST("/worker/sarif", h.SubmitWorkerSarif)
	router.POST("/task", h.SubmitTask)
	router.POST("/task/worker", h.SubmitWorkerTask)
	router.DELETE("/task/:task_id", h.CancelTask)
	router.DELETE("/task", h.CancelAllTasks)
	return router
}

func TestGetStatusSetsSince(t *testing.T) {
	ms := &mockService{
		status: models.Status{
			Ready: true,
		},
	}
	h := NewHandler(ms, "", "")
	router := setupRouter(h)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/status", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp models.Status
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Since > 0)
}

func TestResetStatusUpdatesStartTime(t *testing.T) {
	ms := &mockService{}
	h := NewHandler(ms, "", "")
	router := setupRouter(h)

	h.startTime = 0

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/status/reset", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Greater(t, h.startTime, int64(0))
}

func TestSubmitWorkerSarifSuccess(t *testing.T) {
	ms := &mockService{}
	h := NewHandler(ms, "", "")
	router := setupRouter(h)

	payload := models.SARIFBroadcastDetailWorker{}
	body, _ := json.Marshal(payload)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/worker/sarif", bytes.NewReader(body))
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Len(t, ms.handleWorkerSarifCalls, 1)
}

func TestSubmitSarifSavesFileAndCallsService(t *testing.T) {
	workDir := t.TempDir()
	ms := &mockService{workDir: workDir}
	h := NewHandler(ms, "", "")
	router := setupRouter(h)

	payload := models.SARIFBroadcast{
		MessageID:   uuid.New(),
		MessageTime: time.Now().Unix(),
		Broadcasts: []models.SARIFBroadcastDetail{
			{TaskID: uuid.New()},
		},
	}
	body, _ := json.Marshal(payload)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/sarif", bytes.NewReader(body))
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Len(t, ms.submitSarifCalls, 1)

	files, err := os.ReadDir(filepath.Join(workDir, "sarif_reports"))
	require.NoError(t, err)
	assert.NotEmpty(t, files)
}

func TestSubmitWorkerTaskBusy(t *testing.T) {
	ms := &mockService{
		submitWorkerTaskErr: fmt.Errorf("worker is busy right now"),
	}

	h := NewHandler(ms, "", "")
	router := setupRouter(h)

	task := models.WorkerTask{Fuzzer: "f"}
	body, _ := json.Marshal(task)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/task/worker", bytes.NewReader(body))
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Len(t, ms.submitWorkerTaskCalls, 1)
}

func TestSubmitWorkerTaskSuccess(t *testing.T) {
	ms := &mockService{}
	h := NewHandler(ms, "", "")
	router := setupRouter(h)

	task := models.WorkerTask{Fuzzer: "f"}
	body, _ := json.Marshal(task)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/task/worker", bytes.NewReader(body))
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusAccepted, w.Code)
	assert.Len(t, ms.submitWorkerTaskCalls, 1)
}

func TestSubmitTaskForwardsToServices(t *testing.T) {
	ms := &mockService{}
	h := NewHandler(ms, "", "")

	var analysisWG, submissionWG sync.WaitGroup
	analysisWG.Add(1)
	submissionWG.Add(1)

	analysisServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer analysisWG.Done()
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer analysisServer.Close()

	submissionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer submissionWG.Done()
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer submissionServer.Close()

	h.analysisService = analysisServer.URL
	h.submissionService = submissionServer.URL

	router := setupRouter(h)

	task := models.Task{
		MessageID: uuid.New(),
		Tasks: []models.TaskDetail{
			{
				TaskID:      uuid.New(),
				Type:        models.TaskTypeDelta,
				Deadline:    time.Now().Add(time.Hour).Unix() * 1000,
				ProjectName: "proj",
				Focus:       "focus",
				Metadata: map[string]string{
					"key": "value",
				},
			},
		},
	}
	body, _ := json.Marshal(task)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/task", bytes.NewReader(body))
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusAccepted, w.Code)
	assert.Len(t, ms.submitTaskCalls, 1)

	analysisWG.Wait()
	submissionWG.Wait()
}

func TestCancelTask(t *testing.T) {
	ms := &mockService{}
	h := NewHandler(ms, "", "")
	router := setupRouter(h)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodDelete, "/task/123", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, []string{"123"}, ms.cancelTaskCalls)
}

func TestCancelAllTasks(t *testing.T) {
	ms := &mockService{}
	h := NewHandler(ms, "", "")
	router := setupRouter(h)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodDelete, "/task", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, ms.cancelAllTasksCalled)
}

package executor

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"crs/internal/models"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func startWorkerServer(t *testing.T, status int) {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/task/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		_ = r.Body.Close()
		w.WriteHeader(status)
	})

	listener, err := net.Listen("tcp", "127.0.0.1:9081")
	require.NoError(t, err)

	server := &http.Server{Handler: mux}
	go func() {
		_ = server.Serve(listener)
	}()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})
}

func TestNewWorkerPoolInitializesStatus(t *testing.T) {
	pool := NewWorkerPool(3, 9081)
	assert.Len(t, pool.workerStatus, 3)
	for i := 0; i < 3; i++ {
		assert.NotNil(t, pool.workerStatus[i])
	}
}

func TestSelectBestWorkerSkipsBlacklisted(t *testing.T) {
	pool := NewWorkerPool(2, 9081)
	pool.workerStatus[0].AssignedTasks = 5
	pool.workerStatus[1].AssignedTasks = 1
	pool.workerStatus[0].BlacklistedUntil = time.Now().Add(time.Minute)

	assert.Equal(t, 1, pool.selectBestWorker())
}

func TestTryWorkerSuccess(t *testing.T) {
	startWorkerServer(t, http.StatusOK)
	t.Setenv("LOCAL_TEST", "1")

	pool := NewWorkerPool(1, 9081)

	ok := pool.tryWorker(0, []byte(`{"tasks": []}`), "", "", "fuzzer-one", "task-1")
	assert.True(t, ok)
	assert.Equal(t, 1, pool.workerStatus[0].AssignedTasks)
	assert.Equal(t, 0, pool.workerStatus[0].FailureCount)
	assert.Equal(t, 1, pool.totalTasksDistributed)
}

func TestTryWorkerFailure(t *testing.T) {
	startWorkerServer(t, http.StatusInternalServerError)
	t.Setenv("LOCAL_TEST", "1")

	pool := NewWorkerPool(1, 9081)

	ok := pool.tryWorker(0, []byte(`{}`), "", "", "fuzzer-two", "task-2")
	assert.False(t, ok)
	assert.Equal(t, 1, pool.workerStatus[0].FailureCount)
}

func TestRecordWorkerFailureBlacklistsAfterThreeAttempts(t *testing.T) {
	pool := NewWorkerPool(1, 9081)
	for i := 0; i < 3; i++ {
		pool.recordWorkerFailure(0)
	}
	assert.True(t, pool.workerStatus[0].BlacklistedUntil.After(time.Now()))
}

func TestDistributeFuzzersSuccess(t *testing.T) {
	startWorkerServer(t, http.StatusOK)
	t.Setenv("LOCAL_TEST", "1")

	pool := NewWorkerPool(1, 9081)
	taskDetail := models.TaskDetail{
		TaskID:      uuid.New(),
		ProjectName: "proj",
	}
	fullTask := models.Task{
		MessageID: uuid.New(),
	}

	err := pool.distributeFuzzers([]string{"fuzzer-a"}, taskDetail, fullTask)
	require.NoError(t, err)
	assert.Equal(t, 1, pool.totalTasksDistributed)
	assert.Len(t, pool.taskToWorkersMap[taskDetail.TaskID.String()], 1)
}

func TestDistributeFuzzingTasksWrapper(t *testing.T) {
	startWorkerServer(t, http.StatusOK)
	t.Setenv("LOCAL_TEST", "1")

	taskDetail := models.TaskDetail{
		TaskID:      uuid.New(),
		ProjectName: "proj",
	}
	params := TaskDistributionParams{
		Fuzzers:        []string{"fuzzer-main"},
		TaskDetail:     taskDetail,
		Task:           models.Task{MessageID: uuid.New()},
		WorkerBasePort: 9081,
		WorkerNodes:    1,
	}

	err := DistributeFuzzingTasks(params)
	require.NoError(t, err)
}

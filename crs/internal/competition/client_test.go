package competition

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"crs/internal/models"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSubmitPOVSuccess(t *testing.T) {
	var received models.POVSubmission

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/task/task-1/pov/", r.URL.Path)
		user, pass, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.Equal(t, "user", user)
		assert.Equal(t, "pass", pass)

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &received))

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","pov_id":"pov-123"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "user", "pass")

	id, err := client.SubmitPOV("task-1", "fuzzer", "asan", []byte("payload"))
	require.NoError(t, err)
	assert.Equal(t, "pov-123", id)
	assert.Equal(t, "fuzzer", received.FuzzerName)
}

func TestSubmitPatchFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad request"))
	}))
	defer server.Close()

	client := NewClient(server.URL, "user", "pass")
	_, err := client.SubmitPatch("task-1", []byte("patch"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed with status")
}

func TestSubmitSARIFSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/task/task-2/submitted-sarif/", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","submitted_sarif_id":"sarif-42"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "user", "pass")
	id, err := client.SubmitSARIF("task-2", map[string]string{"sarif": "data"})
	require.NoError(t, err)
	assert.Equal(t, "sarif-42", id)
}

func TestSubmitBundleSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/task/task-3/bundle/", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","bundle_id":"bundle-9"}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "user", "pass")
	id, err := client.SubmitBundle("task-3", "pov", "patch", "sarif", "broadcast", "desc")
	require.NoError(t, err)
	assert.Equal(t, "bundle-9", id)
}

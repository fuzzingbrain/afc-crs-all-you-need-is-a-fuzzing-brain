package fuzzer

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"crs/internal/executor"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindFuzzersFiltersExecutables(t *testing.T) {
	tmpDir := t.TempDir()

	execFile := filepath.Join(tmpDir, "fuzzer-bin")
	require.NoError(t, os.WriteFile(execFile, []byte("data"), 0o755))

	nonExec := filepath.Join(tmpDir, "readme.txt")
	require.NoError(t, os.WriteFile(nonExec, []byte("info"), 0o644))

	skipFile := filepath.Join(tmpDir, "clang")
	require.NoError(t, os.WriteFile(skipFile, []byte("tool"), 0o755))

	fuzzers, err := FindFuzzers(tmpDir)
	require.NoError(t, err)

	assert.Equal(t, []string{"fuzzer-bin"}, fuzzers)
}

func TestFindFuzzersReturnsErrorWhenMissing(t *testing.T) {
	tmpDir := t.TempDir()

	_, err := FindFuzzers(tmpDir)
	require.Error(t, err)
	assert.True(t, errors.Is(err, executor.ErrNoFuzzers))
}

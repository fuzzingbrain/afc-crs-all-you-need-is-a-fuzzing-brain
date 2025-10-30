package environment

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"crs/internal/models"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadProjectConfig(t *testing.T) {
	tmpDir := t.TempDir()
	projectFile := filepath.Join(tmpDir, "project.yaml")
	require.NoError(t, os.WriteFile(projectFile, []byte("language: c\nsanitizers:\n  - address\n"), 0o644))

	cfg, err := LoadProjectConfig(projectFile)
	require.NoError(t, err)
	assert.Equal(t, "c", cfg.Language)
	assert.Equal(t, []string{"address"}, cfg.Sanitizers)
}

func TestLoadProjectConfigMissing(t *testing.T) {
	_, err := LoadProjectConfig("does-not-exist.yaml")
	assert.Error(t, err)
}

func TestPrepareEnvironmentBuildsMissingSanitizers(t *testing.T) {
	tmpDir := t.TempDir()
	dockerDir := filepath.Join(tmpDir, "docker")
	require.NoError(t, os.MkdirAll(dockerDir, 0o755))

	projectContent := `
language: c
sanitizers:
  - address
  - memory
`
	require.NoError(t, os.WriteFile(filepath.Join(dockerDir, "project.yaml"), []byte(projectContent), 0o644))

	myFuzzer := ""
	var builderCalls []string
	var findCalls []string

	params := PrepareEnvironmentParams{
		MyFuzzer:       &myFuzzer,
		TaskDir:        tmpDir,
		TaskDetail:     models.TaskDetail{},
		DockerfilePath: dockerDir,
		FuzzerDir:      filepath.Join(tmpDir, "fuzzers", "example"),
		ProjectDir:     filepath.Join(tmpDir, "project"),
		FuzzerBuilder: func(myFuzzer *string, taskDir, projectDir, sanitizerDir, sanitizer, language string, detail models.TaskDetail) error {
			builderCalls = append(builderCalls, sanitizer)
			return nil
		},
		FindFuzzers: func(dir string) ([]string, error) {
			findCalls = append(findCalls, dir)
			switch {
			case strings.HasSuffix(dir, "-address"):
				return nil, nil
			case strings.HasSuffix(dir, "-memory"):
				return []string{"existing"}, nil
			default:
				// coverage directory equals params.FuzzerDir
				return nil, nil
			}
		},
	}

	t.Setenv("LOCAL_TEST", "1")

	cfg, sanitizerDirs, err := PrepareEnvironment(params)
	require.NoError(t, err)

	assert.Equal(t, "c", strings.ToLower(cfg.Language))
	assert.ElementsMatch(t, []string{
		params.FuzzerDir + "-address",
		params.FuzzerDir + "-memory",
	}, sanitizerDirs)

	require.Contains(t, builderCalls, "address")
	require.Contains(t, builderCalls, "coverage")
	assert.NotContains(t, builderCalls, "memory")
	assert.GreaterOrEqual(t, len(findCalls), 3)
}

func TestPrepareEnvironmentDefaultsWhenProjectMissing(t *testing.T) {
	tmpDir := t.TempDir()
	myFuzzer := ""

	builderCount := 0
	params := PrepareEnvironmentParams{
		MyFuzzer:       &myFuzzer,
		TaskDir:        tmpDir,
		DockerfilePath: filepath.Join(tmpDir, "missing"),
		FuzzerDir:      filepath.Join(tmpDir, "fuzzers", "example"),
		ProjectDir:     filepath.Join(tmpDir, "project"),
		FuzzerBuilder: func(myFuzzer *string, taskDir, projectDir, sanitizerDir, sanitizer, language string, detail models.TaskDetail) error {
			builderCount++
			return nil
		},
		FindFuzzers: func(dir string) ([]string, error) {
			return nil, nil
		},
	}

	cfg, sanitizerDirs, err := PrepareEnvironment(params)
	require.NoError(t, err)

	assert.Equal(t, []string{"address"}, cfg.Sanitizers)
	assert.Equal(t, []string{params.FuzzerDir + "-address"}, sanitizerDirs)
	assert.Equal(t, 1, builderCount)
}

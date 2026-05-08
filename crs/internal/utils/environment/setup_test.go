// SPDX-License-Identifier: Apache-2.0
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
	assert.Equal(t, []SanitizerEntry{{Name: "address", Experimental: false}}, cfg.Sanitizers)
}

func TestLoadProjectConfigMissing(t *testing.T) {
	_, err := LoadProjectConfig("does-not-exist.yaml")
	assert.Error(t, err)
}

func TestLoadProjectConfigWithExperimentalSanitizer(t *testing.T) {
	tmpDir := t.TempDir()
	projectFile := filepath.Join(tmpDir, "project.yaml")
	// Test YAML with nested sanitizer structure (like OpenSSL's project.yaml)
	content := `language: c++
sanitizers:
  - address
  - memory:
      experimental: true
  - undefined
`
	require.NoError(t, os.WriteFile(projectFile, []byte(content), 0o644))

	cfg, err := LoadProjectConfig(projectFile)
	require.NoError(t, err)
	assert.Equal(t, "c++", cfg.Language)
	assert.Len(t, cfg.Sanitizers, 3)

	// Check each sanitizer
	assert.Equal(t, "address", cfg.Sanitizers[0].Name)
	assert.False(t, cfg.Sanitizers[0].Experimental)

	assert.Equal(t, "memory", cfg.Sanitizers[1].Name)
	assert.True(t, cfg.Sanitizers[1].Experimental)

	assert.Equal(t, "undefined", cfg.Sanitizers[2].Name)
	assert.False(t, cfg.Sanitizers[2].Experimental)
}

func TestLoadProjectConfigMultipleFormats(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected []SanitizerEntry
	}{
		{
			name: "Simple string sanitizers",
			content: `language: jvm
sanitizers:
  - address
  - undefined
`,
			expected: []SanitizerEntry{
				{Name: "address", Experimental: false},
				{Name: "undefined", Experimental: false},
			},
		},
		{
			name: "Mixed format",
			content: `language: c++
sanitizers:
  - address
  - memory:
      experimental: true
  - thread
  - undefined:
      experimental: false
`,
			expected: []SanitizerEntry{
				{Name: "address", Experimental: false},
				{Name: "memory", Experimental: true},
				{Name: "thread", Experimental: false},
				{Name: "undefined", Experimental: false},
			},
		},
		{
			name: "Single sanitizer",
			content: `language: rust
sanitizers:
  - address
`,
			expected: []SanitizerEntry{
				{Name: "address", Experimental: false},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			projectFile := filepath.Join(tmpDir, "project.yaml")
			require.NoError(t, os.WriteFile(projectFile, []byte(tt.content), 0o644))

			cfg, err := LoadProjectConfig(projectFile)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, cfg.Sanitizers)
		})
	}
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
	// Coverage building is currently commented out in PrepareEnvironment
	// require.Contains(t, builderCalls, "coverage")
	assert.NotContains(t, builderCalls, "memory")
	// FindFuzzers is called twice: once for address, once for memory
	assert.GreaterOrEqual(t, len(findCalls), 2)
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

	assert.Equal(t, []SanitizerEntry{{Name: "address", Experimental: false}}, cfg.Sanitizers)
	assert.Equal(t, []string{params.FuzzerDir + "-address"}, sanitizerDirs)
	assert.Equal(t, 1, builderCount)
}

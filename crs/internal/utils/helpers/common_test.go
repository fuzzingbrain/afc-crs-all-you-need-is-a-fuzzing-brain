package helpers

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"crs/internal/models"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRobustCopyDirCopiesFilesAndSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated privileges on Windows")
	}

	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "src")
	require.NoError(t, os.MkdirAll(filepath.Join(src, "nested"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(src, "nested", "file.txt"), []byte("hello"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(src, "root.txt"), []byte("world"), 0o644))
	require.NoError(t, os.Symlink("root.txt", filepath.Join(src, "link")))

	dst := filepath.Join(tmpDir, "dst")
	require.NoError(t, RobustCopyDir(src, dst))

	data, err := os.ReadFile(filepath.Join(dst, "nested", "file.txt"))
	require.NoError(t, err)
	assert.Equal(t, "hello", string(data))

	linkTarget, err := os.Readlink(filepath.Join(dst, "link"))
	require.NoError(t, err)
	assert.Equal(t, "root.txt", linkTarget)
}

func TestSanitizeTerminalString(t *testing.T) {
	input := "\x1b[31mHello\x1b[0m\tWorld\x07"
	assert.Equal(t, "Hello\tWorld", SanitizeTerminalString(input))
}

func TestReadCrashFileReturnsNewest(t *testing.T) {
	tmpDir := t.TempDir()
	fuzzDir := filepath.Join(tmpDir, "fuzz")
	metaDir := "metadata"
	require.NoError(t, os.MkdirAll(filepath.Join(fuzzDir, metaDir), 0o755))

	oldPath := filepath.Join(fuzzDir, metaDir, "test_blob_old.bin")
	newPath := filepath.Join(fuzzDir, metaDir, "test_blob_new.bin")

	require.NoError(t, os.WriteFile(oldPath, []byte("old"), 0o644))
	require.NoError(t, os.WriteFile(newPath, []byte("new"), 0o644))

	oldTime := time.Now().Add(-time.Hour)
	require.NoError(t, os.Chtimes(oldPath, oldTime, oldTime))

	assert.Equal(t, "new", string(ReadCrashFile(fuzzDir, metaDir)))
}

func TestVerifyDirectoryAccess(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "file.txt"), []byte("x"), 0o644))

	assert.NoError(t, VerifyDirectoryAccess(tmpDir))

	filePath := filepath.Join(tmpDir, "file.txt")
	err := VerifyDirectoryAccess(filePath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a directory")
}

func TestDetectProjectName(t *testing.T) {
	tmpDir := t.TempDir()
	projectDir := filepath.Join(tmpDir, "example-project")
	require.NoError(t, os.MkdirAll(projectDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(projectDir, "project.yaml"), []byte("language: c"), 0o644))

	name, err := DetectProjectName(tmpDir)
	require.NoError(t, err)
	assert.Equal(t, "example-project", name)
}

func TestDetectProjectNameMissing(t *testing.T) {
	_, err := DetectProjectName(t.TempDir())
	assert.Error(t, err)
}

func TestIsSASTokenExpired(t *testing.T) {
	assert.True(t, IsSASTokenExpired("://bad-url"))
	assert.False(t, IsSASTokenExpired("https://example.com/container"))

	past := time.Now().Add(-time.Minute).Format(time.RFC3339)
	future := time.Now().Add(10 * time.Minute).Format(time.RFC3339)

	pastURL := fmt.Sprintf("https://example.com/blob?se=%s", url.QueryEscape(past))
	futureURL := fmt.Sprintf("https://example.com/blob?se=%s", url.QueryEscape(future))

	assert.True(t, IsSASTokenExpired(pastURL))
	assert.False(t, IsSASTokenExpired(futureURL))
}

func TestDownloadAndVerifySource(t *testing.T) {
	payload := []byte("archive data payload")
	sum := sha256.Sum256(payload)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(payload)))
		_, _ = w.Write(payload)
	}))
	defer server.Close()

	expiry := time.Now().Add(10 * time.Minute).Format(time.RFC3339)
	sourceURL := fmt.Sprintf("%s?se=%s", server.URL, url.QueryEscape(expiry))

	taskDir := t.TempDir()
	source := models.SourceDetail{
		Type:   models.SourceTypeRepo,
		URL:    sourceURL,
		SHA256: hex.EncodeToString(sum[:]),
	}

	require.NoError(t, DownloadAndVerifySource(taskDir, source))

	filePath := filepath.Join(taskDir, "repo.tar.gz")
	content, err := os.ReadFile(filePath)
	require.NoError(t, err)
	assert.Equal(t, payload, content)
}

func TestDownloadAndVerifySourceExpired(t *testing.T) {
	taskDir := t.TempDir()
	expiry := time.Now().Add(-time.Minute).Format(time.RFC3339)
	source := models.SourceDetail{
		Type:   models.SourceTypeRepo,
		URL:    fmt.Sprintf("https://example.com/blob?se=%s", url.QueryEscape(expiry)),
		SHA256: strings.Repeat("0", 64),
	}

	err := DownloadAndVerifySource(taskDir, source)
	assert.Error(t, err)
}

func TestEnsureWorkDir(t *testing.T) {
	tmpDir := t.TempDir()

	newDir := filepath.Join(tmpDir, "work")
	assert.NoError(t, EnsureWorkDir(newDir))
	assert.True(t, DirExists(newDir))

	filePath := filepath.Join(tmpDir, "file")
	require.NoError(t, os.WriteFile(filePath, []byte("x"), 0o644))
	assert.Error(t, EnsureWorkDir(filePath))
}

func TestDirExists(t *testing.T) {
	tmpDir := t.TempDir()
	assert.True(t, DirExists(tmpDir))
	assert.False(t, DirExists(filepath.Join(tmpDir, "missing")))
}

func TestExtractSarifData(t *testing.T) {
	payload := map[string]interface{}{"runs": []interface{}{}}
	data, err := ExtractSarifData(payload)
	require.NoError(t, err)
	assert.Equal(t, payload, data)

	_, err = ExtractSarifData("invalid")
	assert.Error(t, err)
}

func TestSaveSarifBroadcast(t *testing.T) {
	workDir := t.TempDir()
	taskID := uuid.New()
	taskDir := filepath.Join(workDir, taskID.String()+"-001")
	require.NoError(t, os.MkdirAll(taskDir, 0o755))

	broadcast := models.SARIFBroadcastDetail{
		TaskID: taskID,
		SARIF: map[string]interface{}{
			"runs": []interface{}{},
		},
		Metadata: map[string]string{"source": "unit-test"},
	}

	resultPath, err := SaveSarifBroadcast(workDir, taskID.String(), broadcast)
	require.NoError(t, err)
	assert.FileExists(t, resultPath)

	raw, err := os.ReadFile(resultPath)
	require.NoError(t, err)

	var decoded models.SARIFBroadcastDetail
	require.NoError(t, json.Unmarshal(raw, &decoded))
	assert.Equal(t, broadcast.TaskID, decoded.TaskID)
	assert.Equal(t, broadcast.Metadata["source"], decoded.Metadata["source"])
}

func TestAnalyzeSarifVulnerabilities(t *testing.T) {
	sarif := map[string]interface{}{
		"runs": []interface{}{
			map[string]interface{}{
				"results": []interface{}{
					map[string]interface{}{
						"ruleId": "TEST001",
						"message": map[string]interface{}{
							"text": "description",
						},
						"level": "error",
						"locations": []interface{}{
							map[string]interface{}{
								"physicalLocation": map[string]interface{}{
									"artifactLocation": map[string]interface{}{
										"uri": "src/file.c",
									},
									"region": map[string]interface{}{
										"startLine":   float64(10),
										"endLine":     float64(12),
										"startColumn": float64(1),
										"endColumn":   float64(5),
									},
								},
							},
						},
						"codeFlows": []interface{}{
							map[string]interface{}{
								"threadFlows": []interface{}{
									map[string]interface{}{
										"locations": []interface{}{
											map[string]interface{}{
												"message": map[string]interface{}{"text": "flow"},
												"location": map[string]interface{}{
													"physicalLocation": map[string]interface{}{
														"artifactLocation": map[string]interface{}{"uri": "src/file.c"},
														"region": map[string]interface{}{
															"startLine": float64(10),
															"endLine":   float64(10),
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	vulns, err := AnalyzeSarifVulnerabilities(sarif)
	require.NoError(t, err)
	require.Len(t, vulns, 1)

	v := vulns[0]
	assert.Equal(t, "TEST001", v.RuleID)
	assert.Equal(t, "description", v.Description)
	assert.Equal(t, "error", v.Severity)
	assert.Equal(t, "src/file.c", v.Location.FilePath)
	assert.Equal(t, 10, v.Location.StartLine)
	assert.Equal(t, 12, v.Location.EndLine)
	assert.Equal(t, 1, v.Location.StartCol)
	assert.Equal(t, 5, v.Location.EndCol)
	require.Len(t, v.CodeFlows, 1)
	require.Len(t, v.CodeFlows[0].ThreadFlows, 1)
	require.Len(t, v.CodeFlows[0].ThreadFlows[0].Locations, 1)
	assert.Equal(t, "flow", v.CodeFlows[0].ThreadFlows[0].Locations[0].Message)

	_, err = AnalyzeSarifVulnerabilities(map[string]interface{}{})
	assert.Error(t, err)
}

func TestHashStringDeterministic(t *testing.T) {
	h1 := HashString("sample")
	h2 := HashString("sample")
	h3 := HashString("different")

	assert.Equal(t, h1, h2)
	assert.NotEqual(t, h1, h3)
	assert.Len(t, h1, 16)
}

func TestSortFuzzersByGroupReturnsInput(t *testing.T) {
	input := []string{"fuzzer-a", "fuzzer-b"}
	assert.Equal(t, input, SortFuzzersByGroup(input))
}

func TestGetAverageCPUUsageReturnsError(t *testing.T) {
	_, err := GetAverageCPUUsage()
	assert.Error(t, err)
}

func TestLogDirectoryContents(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "file.txt"), []byte("x"), 0o644))
	LogDirectoryContents(tmpDir)
}

func TestSaveTaskDetailToJson(t *testing.T) {
	tmpDir := t.TempDir()
	fuzzDir := filepath.Join(tmpDir, "fuzz")
	require.NoError(t, os.MkdirAll(fuzzDir, 0o755))

	taskDetail := models.TaskDetail{TaskID: uuid.New()}
	fuzzerPath := filepath.Join(fuzzDir, "example-fuzzer")

	SaveTaskDetailToJson(taskDetail, fuzzerPath, fuzzDir)

	hash := HashString(fuzzerPath)
	outputPath := filepath.Join(fuzzDir, fmt.Sprintf("task_detail_%s.json", hash))

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	var restored models.TaskDetail
	require.NoError(t, json.Unmarshal(data, &restored))
	assert.Equal(t, taskDetail.TaskID, restored.TaskID)
}

func TestCopyFuzzDirForParallelStrategies(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("PATH", "/nonexistent")

	sanitizerDir := filepath.Join(tmpDir, "project-address")
	require.NoError(t, os.MkdirAll(sanitizerDir, 0o755))

	fuzzerName := "example"
	fuzzerPath := filepath.Join(sanitizerDir, fuzzerName)
	require.NoError(t, os.WriteFile(fuzzerPath, []byte("binary"), 0o755))

	coverageDir := filepath.Join(tmpDir, "project")
	require.NoError(t, os.MkdirAll(coverageDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(coverageDir, fuzzerName), []byte("coverage"), 0o755))

	require.NoError(t, CopyFuzzDirForParallelStrategies(fuzzerPath, sanitizerDir))

	targetDirs := []string{"ap0", "ap1", "ap2", "ap3", "xp0", "sarif0"}
	for _, td := range targetDirs {
		destBin := filepath.Join(sanitizerDir, td, fuzzerName)
		data, err := os.ReadFile(destBin)
		require.NoError(t, err, "expected binary in %s", destBin)
		assert.Equal(t, []byte("binary"), data)

		coverageBin := filepath.Join(sanitizerDir, td, fuzzerName+"-coverage")
		coverageData, err := os.ReadFile(coverageBin)
		require.NoError(t, err, "expected coverage binary in %s", coverageBin)
		assert.Equal(t, []byte("coverage"), coverageData)
	}
}

func createTarGz(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	gz := gzip.NewWriter(f)
	defer gz.Close()

	tw := tar.NewWriter(gz)
	defer tw.Close()

	for name, content := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(content)),
		}
		require.NoError(t, tw.WriteHeader(hdr))
		_, err = tw.Write([]byte(content))
		require.NoError(t, err)
	}
}

func TestExtractSources(t *testing.T) {
	tmpDir := t.TempDir()

	createTarGz(t, filepath.Join(tmpDir, "repo.tar.gz"), map[string]string{
		"repo/file.txt": "data",
	})
	createTarGz(t, filepath.Join(tmpDir, "fuzz-tooling.tar.gz"), map[string]string{
		"fuzz-tooling/info.txt": "tooling",
	})
	createTarGz(t, filepath.Join(tmpDir, "diff.tar.gz"), map[string]string{
		"diff/patch.diff": "diff",
	})

	err := ExtractSources(tmpDir, true)
	require.NoError(t, err)

	_, err = os.Stat(filepath.Join(tmpDir, "repo/file.txt"))
	assert.NoError(t, err)
	_, err = os.Stat(filepath.Join(tmpDir, "fuzz-tooling/info.txt"))
	assert.NoError(t, err)
	_, err = os.Stat(filepath.Join(tmpDir, "diff/patch.diff"))
	assert.NoError(t, err)
}

func TestShowVulnerabilityDetail(t *testing.T) {
	vulns := []models.Vulnerability{
		{
			RuleID:      "RULE",
			Description: "desc",
			Severity:    "high",
		},
	}
	ShowVulnerabilityDetail("task", vulns)
}

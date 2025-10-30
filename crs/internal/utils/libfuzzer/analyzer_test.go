package libfuzzer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsCrashOutput(t *testing.T) {
	assert.True(t, IsCrashOutput("ERROR: AddressSanitizer: heap-use-after-free"))
	assert.False(t, IsCrashOutput("all good here"))

	t.Setenv("DETECT_TIMEOUT_CRASH", "1")
	assert.True(t, IsCrashOutput("libfuzzer exit=99"))
}

func TestFilterInstrumentedLines(t *testing.T) {
	input := "INFO: skip\nline1\nServer VM warning: ignore\nline2"
	assert.Equal(t, "line1\nline2", filterInstrumentedLines(input))
}

func TestExtractCrashOutput(t *testing.T) {
	output := "prefix\nERROR: AddressSanitizer: heap-use-after-free\nstack"
	result := extractCrashOutput(output)
	assert.True(t, strings.HasPrefix(result, "ERROR: AddressSanitizer"))

	longOutput := strings.Repeat("a", 5000)
	assert.Len(t, extractCrashOutput(longOutput), 4096)
}

func TestGenerateCrashSignature(t *testing.T) {
	output := "#0 0x0 in crash_function /src/file.c:123:45"
	signature := generateCrashSignature(output, "address")
	assert.Equal(t, "crash_function /src/file.c:123", signature)
}

func TestExtractCrashLocationFallbacks(t *testing.T) {
	asanOutput := "SUMMARY: AddressSanitizer: overflow /src/foo.c:10"
	assert.Equal(t, "/src/foo.c:10", extractCrashLocation(asanOutput, "address"))

	ubsanOutput := "foo.c:5:7: runtime error: shift-exponent"
	assert.Equal(t, "foo.c:5:7", extractCrashLocation(ubsanOutput, "undefined"))

	msanOutput := "WARNING: MemorySanitizer: use-of-uninitialized-value at bar.cc:42"
	assert.Equal(t, "bar.cc:42", extractCrashLocation(msanOutput, "memory"))
}

func TestGenerateVulnerabilitySignature0(t *testing.T) {
	output := "ERROR: AddressSanitizer: heap-use-after-free\n#0 0x0 in crash_func ..."
	signature := generateVulnerabilitySignature0(output, "address")
	assert.True(t, strings.HasPrefix(signature, "ASAN:"))

	output = "runtime error: shift-exponent\n#0 0x0 in func ..."
	assert.True(t, strings.HasPrefix(generateVulnerabilitySignature0(output, "undefined"), "UBSAN:"))
}

func TestSanitizerSpecificCrashExtraction(t *testing.T) {
	asanOutput := "AddressSanitizer: heap-use-after-free\n    #0 0x0 in targetFunc ..."
	assert.Equal(t, "heap-use-after-free:targetFunc", extractASANCrashLocation(asanOutput))

	ubsanOutput := "runtime error: shift-exponent\n    #0 0x0 in otherFunc ..."
	assert.Equal(t, "shift-exponent:otherFunc", extractUBSANCrashLocation(ubsanOutput))

	msanOutput := "MemorySanitizer: use-of-uninitialized-value\n    #0 0x0 in msanFunc ..."
	assert.Equal(t, "use-of-uninitialized-value:msanFunc", extractMSANCrashLocation(msanOutput))
}

func TestGetFuzzerArgs(t *testing.T) {
	tmpDir := t.TempDir()
	fuzzDir := filepath.Join(tmpDir, "fuzz-dir")
	require.NoError(t, os.MkdirAll(fuzzDir, 0o755))

	seedCorpusPath := filepath.Join(tmpDir, "myfuzz_seed_corpus")
	require.NoError(t, os.MkdirAll(seedCorpusPath, 0o755))

	dictPath := filepath.Join(tmpDir, "myfuzz_custom.dict")
	require.NoError(t, os.WriteFile(dictPath, []byte("dict"), 0o644))

	args := getFuzzerArgs("container", fuzzDir, "myfuzz", "c++", "address", tmpDir)

	assert.Contains(t, args, "--name=container")
	assert.Contains(t, args, "-dict=/additional_dict")

	volumeFlag := false
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "-v" && strings.Contains(args[i+1], "_seed_corpus:/additional_corpus") {
			volumeFlag = true
			break
		}
	}
	assert.True(t, volumeFlag, "expected additional corpus volume mount")

	assert.Contains(t, args, "ghcr.io/aixcc-finals/base-runner:v1.3.0")
	assert.Contains(t, args, "run_fuzzer")
	assert.Contains(t, args, "myfuzz")
}

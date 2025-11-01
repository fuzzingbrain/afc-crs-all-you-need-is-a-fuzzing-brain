package config

import (
	"os"
	"testing"
)

// Helper function to clear all config-related environment variables
func clearEnv() {
	envVars := []string{
		"CRS_MODE", "CRS_KEY_ID", "CRS_KEY_TOKEN",
		"SERVER_PORT", "WORKER_BASE_PORT",
		"WORKER_NODES", "WORKER_PORT", "WORKER_INDEX", "POD_NAME", "WEB_SERVICE_URL",
		"SUBMISSION_SERVICE", "ANALYSIS_SERVICE",
		"AI_MODEL", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "OPENAI_API_KEY",
		"LOCAL_TEST", "ANALYSIS_SERVICE_TEST", "SUBMISSION_SERVICE_TEST",
	}
	for _, v := range envVars {
		os.Unsetenv(v)
	}
}

func TestLoad_DefaultValues(t *testing.T) {
	clearEnv()
	defer clearEnv()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Test Auth defaults
	if cfg.Auth.KeyID != "api_key_id" {
		t.Errorf("Expected default Auth.KeyID='api_key_id', got '%s'", cfg.Auth.KeyID)
	}
	if cfg.Auth.Token != "api_key_token" {
		t.Errorf("Expected default Auth.Token='api_key_token', got '%s'", cfg.Auth.Token)
	}

	// Test Server defaults
	if cfg.Server.Port != "7080" {
		t.Errorf("Expected default Server.Port='7080', got '%s'", cfg.Server.Port)
	}
	if cfg.Server.WorkerBasePort != 9081 {
		t.Errorf("Expected default Server.WorkerBasePort=9081, got %d", cfg.Server.WorkerBasePort)
	}

	// Test Worker defaults
	if cfg.Worker.Nodes != 24 {
		t.Errorf("Expected default Worker.Nodes=24, got %d", cfg.Worker.Nodes)
	}
	if cfg.Worker.Port != 9081 {
		t.Errorf("Expected default Worker.Port=9081, got %d", cfg.Worker.Port)
	}

	// Test Services defaults
	if cfg.Services.SubmissionURL != "http://crs-sub" {
		t.Errorf("Expected default Services.SubmissionURL='http://crs-sub', got '%s'", cfg.Services.SubmissionURL)
	}
	if cfg.Services.AnalysisURL != "http://crs-analysis" {
		t.Errorf("Expected default Services.AnalysisURL='http://crs-analysis', got '%s'", cfg.Services.AnalysisURL)
	}

	// Test AI defaults
	if cfg.AI.Model != "claude-sonnet-4-20250514" {
		t.Errorf("Expected default AI.Model='claude-sonnet-4-20250514', got '%s'", cfg.AI.Model)
	}
}

func TestLoad_CustomEnvironmentVariables(t *testing.T) {
	clearEnv()
	defer clearEnv()

	// Set custom values
	os.Setenv("CRS_KEY_ID", "custom_id")
	os.Setenv("CRS_KEY_TOKEN", "custom_token")
	os.Setenv("SERVER_PORT", "8080")
	os.Setenv("WORKER_BASE_PORT", "9999")
	os.Setenv("WORKER_NODES", "10")
	os.Setenv("WORKER_PORT", "9090")
	os.Setenv("SUBMISSION_SERVICE", "http://custom-sub")
	os.Setenv("ANALYSIS_SERVICE", "http://custom-analysis")
	os.Setenv("AI_MODEL", "gpt-4o")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Verify custom values
	if cfg.Auth.KeyID != "custom_id" {
		t.Errorf("Expected Auth.KeyID='custom_id', got '%s'", cfg.Auth.KeyID)
	}
	if cfg.Auth.Token != "custom_token" {
		t.Errorf("Expected Auth.Token='custom_token', got '%s'", cfg.Auth.Token)
	}
	if cfg.Server.Port != "8080" {
		t.Errorf("Expected Server.Port='8080', got '%s'", cfg.Server.Port)
	}
	if cfg.Server.WorkerBasePort != 9999 {
		t.Errorf("Expected Server.WorkerBasePort=9999, got %d", cfg.Server.WorkerBasePort)
	}
	if cfg.Worker.Nodes != 10 {
		t.Errorf("Expected Worker.Nodes=10, got %d", cfg.Worker.Nodes)
	}
	if cfg.Worker.Port != 9090 {
		t.Errorf("Expected Worker.Port=9090, got %d", cfg.Worker.Port)
	}
	if cfg.Services.SubmissionURL != "http://custom-sub" {
		t.Errorf("Expected Services.SubmissionURL='http://custom-sub', got '%s'", cfg.Services.SubmissionURL)
	}
	if cfg.Services.AnalysisURL != "http://custom-analysis" {
		t.Errorf("Expected Services.AnalysisURL='http://custom-analysis', got '%s'", cfg.Services.AnalysisURL)
	}
	if cfg.AI.Model != "gpt-4o" {
		t.Errorf("Expected AI.Model='gpt-4o', got '%s'", cfg.AI.Model)
	}
}

func TestLoad_TestModeOverride(t *testing.T) {
	clearEnv()
	defer clearEnv()

	os.Setenv("LOCAL_TEST", "1")
	os.Setenv("SUBMISSION_SERVICE", "http://prod-submission")
	os.Setenv("ANALYSIS_SERVICE", "http://prod-analysis")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Test mode should override service URLs
	if cfg.Services.AnalysisURL != "http://localhost:7082" {
		t.Errorf("Expected test mode AnalysisURL='http://localhost:7082', got '%s'", cfg.Services.AnalysisURL)
	}
	if cfg.Services.SubmissionURL != "http://localhost:7081" {
		t.Errorf("Expected test mode SubmissionURL='http://localhost:7081', got '%s'", cfg.Services.SubmissionURL)
	}
}

func TestLoad_WorkerIndexExtractedFromPodName(t *testing.T) {
	clearEnv()
	defer clearEnv()

	os.Setenv("POD_NAME", "crs-worker-5")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Should auto-extract "5" from pod name
	if cfg.Worker.Index != "5" {
		t.Errorf("Expected Worker.Index='5', got '%s'", cfg.Worker.Index)
	}
}

func TestLoad_WorkerIndexExplicitOverridesPodName(t *testing.T) {
	clearEnv()
	defer clearEnv()

	os.Setenv("POD_NAME", "crs-worker-5")
	os.Setenv("WORKER_INDEX", "10")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Explicit WORKER_INDEX should take precedence
	if cfg.Worker.Index != "10" {
		t.Errorf("Expected Worker.Index='10', got '%s'", cfg.Worker.Index)
	}
}

func TestValidate_ServerMode_Success(t *testing.T) {
	cfg := &Config{
		Mode: "server",
		Server: ServerConfig{
			Port: "7080",
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() should succeed for server mode with port, got error: %v", err)
	}
}

func TestValidate_ServerMode_MissingPort(t *testing.T) {
	cfg := &Config{
		Mode: "server",
		Server: ServerConfig{
			Port: "",
		},
	}

	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should fail when server port is empty")
	}
}

func TestValidate_WorkerMode_Success(t *testing.T) {
	cfg := &Config{
		Mode: "worker",
		Worker: WorkerConfig{
			Port: 9081,
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() should succeed for worker mode with port, got error: %v", err)
	}
}

func TestValidate_WorkerMode_MissingPort(t *testing.T) {
	cfg := &Config{
		Mode: "worker",
		Worker: WorkerConfig{
			Port: 0,
		},
	}

	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should fail when worker port is 0")
	}
}

func TestValidate_LocalMode_ClaudeWithAPIKey(t *testing.T) {
	cfg := &Config{
		Mode: "local",
		AI: AIConfig{
			Model:           "claude-sonnet-4-20250514",
			AnthropicAPIKey: "test-key",
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() should succeed with Anthropic API key, got error: %v", err)
	}
}

func TestValidate_LocalMode_ClaudeWithoutAPIKey(t *testing.T) {
	cfg := &Config{
		Mode: "local",
		AI: AIConfig{
			Model:           "claude-sonnet-4-20250514",
			AnthropicAPIKey: "",
		},
	}

	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should fail when Claude model specified without Anthropic API key")
	}
}

func TestValidate_LocalMode_GeminiWithAPIKey(t *testing.T) {
	cfg := &Config{
		Mode: "local",
		AI: AIConfig{
			Model:        "gemini-2.5-pro",
			GeminiAPIKey: "test-key",
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() should succeed with Gemini API key, got error: %v", err)
	}
}

func TestValidate_LocalMode_GeminiWithoutAPIKey(t *testing.T) {
	cfg := &Config{
		Mode: "local",
		AI: AIConfig{
			Model:        "gemini-2.5-pro",
			GeminiAPIKey: "",
		},
	}

	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should fail when Gemini model specified without Gemini API key")
	}
}

func TestValidate_LocalMode_GPTWithAPIKey(t *testing.T) {
	cfg := &Config{
		Mode: "local",
		AI: AIConfig{
			Model:        "gpt-4o",
			OpenAIAPIKey: "test-key",
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() should succeed with OpenAI API key, got error: %v", err)
	}
}

func TestValidate_LocalMode_GPTWithoutAPIKey(t *testing.T) {
	cfg := &Config{
		Mode: "local",
		AI: AIConfig{
			Model:        "gpt-4o",
			OpenAIAPIKey: "",
		},
	}

	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should fail when GPT model specified without OpenAI API key")
	}
}

func TestValidate_UnknownMode(t *testing.T) {
	cfg := &Config{
		Mode: "unknown",
	}

	if err := cfg.Validate(); err == nil {
		t.Error("Validate() should fail for unknown mode")
	}
}

func TestGetListenAddress_ServerMode(t *testing.T) {
	clearEnv()
	defer clearEnv()

	cfg := &Config{
		Mode: "server",
		Server: ServerConfig{
			Port: "7080",
		},
	}

	addr := cfg.GetListenAddress()
	if addr != ":7080" {
		t.Errorf("Expected listen address ':7080', got '%s'", addr)
	}
}

func TestGetListenAddress_ServerMode_LocalTest(t *testing.T) {
	clearEnv()
	defer clearEnv()

	os.Setenv("LOCAL_TEST", "1")

	cfg := &Config{
		Mode: "server",
		Server: ServerConfig{
			Port: "7080",
		},
	}

	addr := cfg.GetListenAddress()
	if addr != ":5080" {
		t.Errorf("Expected LOCAL_TEST listen address ':5080', got '%s'", addr)
	}
}

func TestGetListenAddress_WorkerMode(t *testing.T) {
	cfg := &Config{
		Mode: "worker",
		Worker: WorkerConfig{
			Port: 9081,
		},
	}

	addr := cfg.GetListenAddress()
	if addr != ":9081" {
		t.Errorf("Expected listen address ':9081', got '%s'", addr)
	}
}

func TestGetListenAddress_DefaultMode(t *testing.T) {
	cfg := &Config{
		Mode: "unknown",
	}

	addr := cfg.GetListenAddress()
	if addr != ":8080" {
		t.Errorf("Expected default listen address ':8080', got '%s'", addr)
	}
}

// ============================================================================
// FuzzerConfig Tests
// ============================================================================

func TestFuzzerConfig_GetSanitizerList(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "empty string returns nil",
			input:    "",
			expected: nil,
		},
		{
			name:     "single sanitizer",
			input:    "address",
			expected: []string{"address"},
		},
		{
			name:     "multiple sanitizers",
			input:    "address,memory,thread",
			expected: []string{"address", "memory", "thread"},
		},
		{
			name:     "with spaces",
			input:    " address , memory , thread ",
			expected: []string{"address", "memory", "thread"},
		},
		{
			name:     "filters coverage only",
			input:    "address,coverage,memory",
			expected: []string{"address", "memory"},
		},
		{
			name:     "keeps undefined",
			input:    "address,undefined,memory",
			expected: []string{"address", "undefined", "memory"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fc := &FuzzerConfig{Sanitizers: tt.input}
			result := fc.GetSanitizerList()

			if len(result) != len(tt.expected) {
				t.Errorf("expected %d sanitizers, got %d", len(tt.expected), len(result))
				return
			}

			for i, expected := range tt.expected {
				if result[i] != expected {
					t.Errorf("at index %d: expected %s, got %s", i, expected, result[i])
				}
			}
		})
	}
}

func TestFuzzerConfig_ShouldBuildSanitizer(t *testing.T) {
	tests := []struct {
		name      string
		config    string
		sanitizer string
		expected  bool
	}{
		{
			name:      "empty config allows all",
			config:    "",
			sanitizer: "address",
			expected:  true,
		},
		{
			name:      "single match",
			config:    "address",
			sanitizer: "address",
			expected:  true,
		},
		{
			name:      "single no match",
			config:    "address",
			sanitizer: "memory",
			expected:  false,
		},
		{
			name:      "multiple with match",
			config:    "address,memory,undefined",
			sanitizer: "memory",
			expected:  true,
		},
		{
			name:      "multiple no match",
			config:    "address,memory",
			sanitizer: "thread",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fc := &FuzzerConfig{Sanitizers: tt.config}
			result := fc.ShouldBuildSanitizer(tt.sanitizer)

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestFuzzerConfig_GetSelectedFuzzers(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "empty returns nil",
			input:    "",
			expected: nil,
		},
		{
			name:     "single fuzzer",
			input:    "avif_decode_fuzzer",
			expected: []string{"avif_decode_fuzzer"},
		},
		{
			name:     "multiple fuzzers",
			input:    "fuzzer1,fuzzer2,fuzzer3",
			expected: []string{"fuzzer1", "fuzzer2", "fuzzer3"},
		},
		{
			name:     "with spaces",
			input:    " fuzzer1 , fuzzer2 ",
			expected: []string{"fuzzer1", "fuzzer2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fc := &FuzzerConfig{Selected: tt.input}
			result := fc.GetSelectedFuzzers()

			if len(result) != len(tt.expected) {
				t.Errorf("expected %d fuzzers, got %d", len(tt.expected), len(result))
				return
			}

			for i, expected := range tt.expected {
				if result[i] != expected {
					t.Errorf("at index %d: expected %s, got %s", i, expected, result[i])
				}
			}
		})
	}
}

func TestFuzzerConfig_IsAutoDiscovery(t *testing.T) {
	tests := []struct {
		name     string
		mode     string
		expected bool
	}{
		{
			name:     "auto mode",
			mode:     "auto",
			expected: true,
		},
		{
			name:     "Auto with capital",
			mode:     "Auto",
			expected: true,
		},
		{
			name:     "empty is auto",
			mode:     "",
			expected: true,
		},
		{
			name:     "config mode",
			mode:     "config",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fc := &FuzzerConfig{DiscoveryMode: tt.mode}
			result := fc.IsAutoDiscovery()

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestConfig_LoadWithFuzzerConfig(t *testing.T) {
	clearEnv()
	defer clearEnv()

	// Set environment variables for testing
	os.Setenv("FUZZER_SANITIZERS", "address,memory")
	os.Setenv("FUZZER_PREFERRED_SANITIZER", "memory")
	os.Setenv("FUZZER_SELECTED", "test_fuzzer")
	os.Setenv("FUZZER_DISCOVERY_MODE", "config")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.Fuzzer.Sanitizers != "address,memory" {
		t.Errorf("expected sanitizers 'address,memory', got '%s'", cfg.Fuzzer.Sanitizers)
	}

	if cfg.Fuzzer.PreferredSanitizer != "memory" {
		t.Errorf("expected preferred sanitizer 'memory', got '%s'", cfg.Fuzzer.PreferredSanitizer)
	}

	if cfg.Fuzzer.Selected != "test_fuzzer" {
		t.Errorf("expected selected fuzzer 'test_fuzzer', got '%s'", cfg.Fuzzer.Selected)
	}

	if cfg.Fuzzer.DiscoveryMode != "config" {
		t.Errorf("expected discovery mode 'config', got '%s'", cfg.Fuzzer.DiscoveryMode)
	}
}

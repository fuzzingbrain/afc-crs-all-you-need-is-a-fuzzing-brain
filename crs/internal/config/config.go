package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
)

// Config holds all configuration for CRS
type Config struct {
	Mode     string `envconfig:"CRS_MODE" default:"server"` // server/worker/local
	Auth     AuthConfig
	Server   ServerConfig
	Worker   WorkerConfig
	Services ServicesConfig
	AI       AIConfig
	Strategy StrategyConfig
	Fuzzer   FuzzerConfig
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	KeyID string `envconfig:"CRS_KEY_ID" default:"api_key_id"`
	Token string `envconfig:"CRS_KEY_TOKEN" default:"api_key_token"`
}

// ServerConfig holds server-specific configuration
type ServerConfig struct {
	Port           string `envconfig:"SERVER_PORT" default:"7080"`
	WorkerBasePort int    `envconfig:"WORKER_BASE_PORT" default:"9081"`
}

// WorkerConfig holds worker-specific configuration
type WorkerConfig struct {
	Nodes         int    `envconfig:"WORKER_NODES" default:"24"`
	Port          int    `envconfig:"WORKER_PORT" default:"9081"`
	Index         string `envconfig:"WORKER_INDEX"`
	PodName       string `envconfig:"POD_NAME"`
	WebServiceURL string `envconfig:"WEB_SERVICE_URL" default:"http://localhost:7080"`
}

// ServicesConfig holds external service URLs
type ServicesConfig struct {
	SubmissionURL string `envconfig:"SUBMISSION_SERVICE" default:"http://crs-sub"`
	AnalysisURL   string `envconfig:"ANALYSIS_SERVICE" default:"http://crs-analysis"`
}

// AIConfig holds AI model configuration (for local mode)
type AIConfig struct {
	Model           string `envconfig:"AI_MODEL" default:"claude-sonnet-4-20250514"`
	AnthropicAPIKey string `envconfig:"ANTHROPIC_API_KEY"`
	GeminiAPIKey    string `envconfig:"GEMINI_API_KEY"`
	OpenAIAPIKey    string `envconfig:"OPENAI_API_KEY"`
}

// FuzzerConfig holds fuzzer build and selection configuration
type FuzzerConfig struct {
	// Sanitizers to build (comma-separated). Empty = use project.yaml
	Sanitizers string `envconfig:"FUZZER_SANITIZERS" default:""`

	// Preferred sanitizer when multiple are built
	PreferredSanitizer string `envconfig:"FUZZER_PREFERRED_SANITIZER" default:"address"`

	// Selected fuzzer(s) - name, pattern, or comma-separated list
	Selected string `envconfig:"FUZZER_SELECTED" default:""`

	// Discovery mode: "auto" or "config"
	DiscoveryMode string `envconfig:"FUZZER_DISCOVERY_MODE" default:"auto"`
}

// StrategyConfig holds POV and Patch strategy configuration
type StrategyConfig struct {
	// Base directory for all strategies
	BaseDir string `envconfig:"STRATEGY_BASE_DIR" default:"/app/strategy"`

	// Subdirectory for new OOP-based strategies
	NewStrategyDir string `envconfig:"STRATEGY_NEW_DIR" default:"strategies"`

	// Legacy strategy directory (for fallback)
	LegacyDir string `envconfig:"STRATEGY_LEGACY_DIR" default:"jeff"`

	// POV Strategy Configuration
	POV POVStrategyConfig

	// Patch Strategy Configuration
	Patch PatchStrategyConfig

	// Enable or disable patching phase
	EnablePatching bool `envconfig:"STRATEGY_ENABLE_PATCHING" default:"true"`
}

// POVStrategyConfig holds POV strategy patterns and selection
type POVStrategyConfig struct {
	// Basic POV strategy patterns (xs* strategies)
	BasicDeltaPattern    string `envconfig:"STRATEGY_POV_BASIC_DELTA_PATTERN" default:"xs*_delta_new.py"`
	BasicCFullPattern    string `envconfig:"STRATEGY_POV_BASIC_C_FULL_PATTERN" default:"xs*_c_full.py"`
	BasicJavaFullPattern string `envconfig:"STRATEGY_POV_BASIC_JAVA_FULL_PATTERN" default:"xs*_java_full.py"`
	BasicFullPattern     string `envconfig:"STRATEGY_POV_BASIC_FULL_PATTERN" default:"xs*_full.py"`

	// Advanced POV strategy patterns (as* strategies)
	AdvancedDeltaPattern string `envconfig:"STRATEGY_POV_ADVANCED_DELTA_PATTERN" default:"as*_delta_new.py"`
	AdvancedFullPattern  string `envconfig:"STRATEGY_POV_ADVANCED_FULL_PATTERN" default:"as*_full.py"`

	// Strategy selection (empty, "all", "none", or specific strategy name)
	SelectedBasicStrategy    string `envconfig:"STRATEGY_POV_SELECTED_BASIC" default:""`
	SelectedAdvancedStrategy string `envconfig:"STRATEGY_POV_SELECTED_ADVANCED" default:""`
}

// PatchStrategyConfig holds Patch strategy patterns and selection
type PatchStrategyConfig struct {
	// Patch strategy patterns (patch* strategies)
	DeltaPattern        string `envconfig:"STRATEGY_PATCH_DELTA_PATTERN" default:"patch*_delta.py"`
	FullPattern         string `envconfig:"STRATEGY_PATCH_FULL_PATTERN" default:"patch*_full.py"`
	SpecificDeltaName   string `envconfig:"STRATEGY_PATCH_SPECIFIC_DELTA" default:"patch_delta.py"`
	SpecificFullName    string `envconfig:"STRATEGY_PATCH_SPECIFIC_FULL" default:"patch_full.py"`

	// XPatch strategy patterns (xpatch* strategies)
	XPatchDeltaPattern string `envconfig:"STRATEGY_XPATCH_DELTA_PATTERN" default:"xpatch*_delta.py"`
	XPatchFullPattern  string `envconfig:"STRATEGY_XPATCH_FULL_PATTERN" default:"xpatch*_full.py"`
	XPatchSarifName    string `envconfig:"STRATEGY_XPATCH_SARIF_NAME" default:"xpatch_sarif.py"`

	// Strategy selection (empty, "all", "none", or specific strategy name)
	SelectedPatchStrategy  string `envconfig:"STRATEGY_PATCH_SELECTED" default:""`
	SelectedXPatchStrategy string `envconfig:"STRATEGY_XPATCH_SELECTED" default:""`
}

// GetBasicStrategyPattern returns the appropriate pattern for basic POV strategies
func (s *StrategyConfig) GetBasicStrategyPattern(taskType, language string) string {
	if taskType == "full" {
		switch strings.ToLower(language) {
		case "c", "cpp", "c++":
			return s.POV.BasicCFullPattern
		case "java", "jvm":
			return s.POV.BasicJavaFullPattern
		default:
			return s.POV.BasicFullPattern
		}
	}
	return s.POV.BasicDeltaPattern
}

// GetAdvancedStrategyPattern returns the appropriate pattern for advanced POV strategies
func (s *StrategyConfig) GetAdvancedStrategyPattern(taskType string) string {
	if taskType == "full" {
		return s.POV.AdvancedFullPattern
	}
	return s.POV.AdvancedDeltaPattern
}

// GetPatchStrategyPattern returns the appropriate pattern for patch strategies
func (s *StrategyConfig) GetPatchStrategyPattern(taskType string, useSpecific bool) string {
	if useSpecific {
		if taskType == "full" {
			return s.Patch.SpecificFullName
		}
		return s.Patch.SpecificDeltaName
	}
	if taskType == "full" {
		return s.Patch.FullPattern
	}
	return s.Patch.DeltaPattern
}

// GetXPatchStrategyPattern returns the appropriate pattern for xpatch strategies
func (s *StrategyConfig) GetXPatchStrategyPattern(taskType string) string {
	if taskType == "full" {
		return s.Patch.XPatchFullPattern
	}
	return s.Patch.XPatchDeltaPattern
}

// GetStrategyDir returns the full path to the strategy directory
func (s *StrategyConfig) GetStrategyDir() string {
	return fmt.Sprintf("%s/%s", s.BaseDir, s.NewStrategyDir)
}

// ShouldRunBasicStrategy checks if a specific basic POV strategy should be run
func (s *StrategyConfig) ShouldRunBasicStrategy(strategyName string) bool {
	selected := s.POV.SelectedBasicStrategy
	if strings.ToLower(selected) == "none" {
		return false
	}
	if selected == "" || strings.ToLower(selected) == "all" {
		return true
	}
	return strategyName == selected
}

// ShouldRunAdvancedStrategy checks if a specific advanced POV strategy should be run
func (s *StrategyConfig) ShouldRunAdvancedStrategy(strategyName string) bool {
	selected := s.POV.SelectedAdvancedStrategy
	if strings.ToLower(selected) == "none" {
		return false
	}
	if selected == "" || strings.ToLower(selected) == "all" {
		return true
	}
	return strategyName == selected
}

// ShouldRunPatchStrategy checks if a specific patch strategy should be run
func (s *StrategyConfig) ShouldRunPatchStrategy(strategyName string) bool {
	selected := s.Patch.SelectedPatchStrategy
	if strings.ToLower(selected) == "none" {
		return false
	}
	if selected == "" || strings.ToLower(selected) == "all" {
		return true
	}
	return strategyName == selected
}

// ShouldRunXPatchStrategy checks if a specific xpatch strategy should be run
func (s *StrategyConfig) ShouldRunXPatchStrategy(strategyName string) bool {
	selected := s.Patch.SelectedXPatchStrategy
	if strings.ToLower(selected) == "none" {
		return false
	}
	if selected == "" || strings.ToLower(selected) == "all" {
		return true
	}
	return strategyName == selected
}

// Load reads configuration from environment variables
func Load() (*Config, error) {
	// Try to load .env file (optional)
	_ = godotenv.Load()

	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
		return nil, fmt.Errorf("failed to process config: %w", err)
	}

	// Handle test mode overrides
	if os.Getenv("LOCAL_TEST") != "" ||
	   os.Getenv("ANALYSIS_SERVICE_TEST") != "" ||
	   os.Getenv("SUBMISSION_SERVICE_TEST") != "" {
		cfg.Services.AnalysisURL = "http://localhost:7082"
		cfg.Services.SubmissionURL = "http://localhost:7081"
	}

	// Auto-extract worker index from pod name if not set
	if cfg.Worker.Index == "" && cfg.Worker.PodName != "" {
		parts := strings.Split(cfg.Worker.PodName, "-")
		if len(parts) > 0 {
			cfg.Worker.Index = parts[len(parts)-1]
		}
	}

	return &cfg, nil
}

// Validate checks if required configuration is present based on mode
func (c *Config) Validate() error {
	switch c.Mode {
	case "server":
		if c.Server.Port == "" {
			return fmt.Errorf("server port is required")
		}
	case "worker":
		if c.Worker.Port == 0 {
			return fmt.Errorf("worker port is required")
		}
	case "local":
		// Check if appropriate API key is set based on model
		if strings.Contains(c.AI.Model, "claude") && c.AI.AnthropicAPIKey == "" {
			return fmt.Errorf("ANTHROPIC_API_KEY is required for model %s", c.AI.Model)
		}
		if strings.Contains(c.AI.Model, "gemini") && c.AI.GeminiAPIKey == "" {
			return fmt.Errorf("GEMINI_API_KEY is required for model %s", c.AI.Model)
		}
		if (strings.Contains(c.AI.Model, "gpt") || strings.HasPrefix(c.AI.Model, "o")) && c.AI.OpenAIAPIKey == "" {
			return fmt.Errorf("OPENAI_API_KEY is required for model %s", c.AI.Model)
		}
	default:
		return fmt.Errorf("unknown mode: %s", c.Mode)
	}
	return nil
}

// GetListenAddress returns the appropriate listen address based on mode
func (c *Config) GetListenAddress() string {
	switch c.Mode {
	case "server":
		if os.Getenv("LOCAL_TEST") != "" {
			return ":5080"
		}
		return ":" + c.Server.Port
	case "worker":
		return fmt.Sprintf(":%d", c.Worker.Port)
	default:
		return ":8080"
	}
}

// GetSanitizerList returns the list of sanitizers to build
// If FUZZER_SANITIZERS is set, it overrides project.yaml
// Note: Coverage is handled separately and should not be included here
func (f *FuzzerConfig) GetSanitizerList() []string {
	if f.Sanitizers == "" {
		return nil // Use project.yaml defaults
	}

	// Split comma-separated list and trim spaces
	sanitizers := strings.Split(f.Sanitizers, ",")
	result := make([]string, 0, len(sanitizers))
	for _, s := range sanitizers {
		s = strings.TrimSpace(s)
		// Filter out empty strings and 'coverage' (handled separately)
		if s != "" && s != "coverage" {
			result = append(result, s)
		}
	}
	return result
}

// ShouldBuildSanitizer checks if a specific sanitizer should be built
// Returns true if:
// - FUZZER_SANITIZERS is empty (use all from project.yaml), OR
// - The sanitizer is in the FUZZER_SANITIZERS list
func (f *FuzzerConfig) ShouldBuildSanitizer(sanitizer string) bool {
	if f.Sanitizers == "" {
		return true // Build all sanitizers from project.yaml
	}

	sanitizerList := f.GetSanitizerList()
	for _, s := range sanitizerList {
		if s == sanitizer {
			return true
		}
	}
	return false
}

// GetSelectedFuzzers returns the list of fuzzer names/patterns to use
func (f *FuzzerConfig) GetSelectedFuzzers() []string {
	if f.Selected == "" {
		return nil // Auto-discover
	}

	// Split comma-separated list and trim spaces
	fuzzers := strings.Split(f.Selected, ",")
	result := make([]string, 0, len(fuzzers))
	for _, name := range fuzzers {
		name = strings.TrimSpace(name)
		if name != "" {
			result = append(result, name)
		}
	}
	return result
}

// IsAutoDiscovery returns true if fuzzer discovery mode is auto
func (f *FuzzerConfig) IsAutoDiscovery() bool {
	return strings.ToLower(f.DiscoveryMode) == "auto" || f.DiscoveryMode == ""
}

// MatchesFuzzerSelection checks if a fuzzer path matches the configured selection criteria
// Returns true if:
// - IsAutoDiscovery() is true (auto mode), OR
// - The fuzzer name matches one of the selected fuzzer patterns
func (f *FuzzerConfig) MatchesFuzzerSelection(fuzzerPath string) bool {
	// Auto-discovery mode: accept all fuzzers
	if f.IsAutoDiscovery() {
		return true
	}

	// Config mode: check if fuzzer matches selected patterns
	selectedFuzzers := f.GetSelectedFuzzers()
	if len(selectedFuzzers) == 0 {
		// No selection specified in config mode = accept all
		return true
	}

	fuzzerName := filepath.Base(fuzzerPath)
	for _, pattern := range selectedFuzzers {
		// Exact match
		if fuzzerName == pattern {
			return true
		}
		// Pattern match (simple glob-style: contains or prefix)
		if strings.Contains(fuzzerName, pattern) {
			return true
		}
		// Wildcard pattern matching
		matched, _ := filepath.Match(pattern, fuzzerName)
		if matched {
			return true
		}
	}

	return false
}

// ShouldUseSanitizer checks if a fuzzer with a specific sanitizer should be used
// based on the PreferredSanitizer setting
func (f *FuzzerConfig) ShouldUseSanitizer(fuzzerPath string) bool {
	// If no preferred sanitizer is set, accept all
	if f.PreferredSanitizer == "" {
		return true
	}

	// Check if fuzzer path contains the preferred sanitizer
	sanitizerDir := fmt.Sprintf("-%s/", f.PreferredSanitizer)
	return strings.Contains(fuzzerPath, sanitizerDir)
}

package environment

import (
	"log"
	"os"
	"path/filepath"
	"strings"

	"crs/internal/models"
	"gopkg.in/yaml.v3"
)

// setup.go - Project environment setup and configuration loading
// This file contains functions for loading project.yaml and preparing the fuzzing environment

// SanitizerEntry represents a sanitizer entry that can be either a string or a map
type SanitizerEntry struct {
	Name         string
	Experimental bool
}

// UnmarshalYAML implements custom unmarshaling for SanitizerEntry
func (s *SanitizerEntry) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Try to unmarshal as a string first
	var str string
	if err := unmarshal(&str); err == nil {
		s.Name = str
		s.Experimental = false
		return nil
	}

	// If that fails, try to unmarshal as a map
	var m map[string]interface{}
	if err := unmarshal(&m); err != nil {
		return err
	}

	// Extract the sanitizer name (the map key)
	for key, value := range m {
		s.Name = key
		// Check if experimental field exists
		if valueMap, ok := value.(map[string]interface{}); ok {
			if exp, ok := valueMap["experimental"].(bool); ok {
				s.Experimental = exp
			}
		}
		break // Only process the first key
	}
	return nil
}

// ProjectConfig represents the configuration loaded from project.yaml
type ProjectConfig struct {
	Sanitizers []SanitizerEntry `yaml:"sanitizers"`
	Language   string           `yaml:"language"`
	MainRepo   string           `yaml:"main_repo"`
}

// LoadProjectConfig loads and parses project.yaml file
func LoadProjectConfig(projectYAMLPath string) (*ProjectConfig, error) {
	data, err := os.ReadFile(projectYAMLPath)
	if err != nil {
		return nil, err
	}
	var cfg ProjectConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// FuzzerBuilder is a function type for building fuzzers
// This allows the executor to call back to service-specific build logic
type FuzzerBuilder func(myFuzzer *string, taskDir, projectDir, sanitizerDir string, sanitizer string, language string, taskDetail models.TaskDetail) error

// PrepareEnvironmentParams contains parameters for PrepareEnvironment
type PrepareEnvironmentParams struct {
	MyFuzzer          *string
	TaskDir           string
	TaskDetail        models.TaskDetail
	DockerfilePath    string
	DockerfileFullPath string
	FuzzerDir         string
	ProjectDir        string
	FuzzerBuilder     FuzzerBuilder
	FindFuzzers       func(string) ([]string, error)
	SanitizerOverride []string // Optional: override sanitizers from config
}

// PrepareEnvironment prepares the task environment by loading config and building fuzzers
func PrepareEnvironment(params PrepareEnvironmentParams) (*ProjectConfig, []string, error) {
	var cfg *ProjectConfig
	var sanitizerDirs []string

	projectYAMLPath := filepath.Join(params.DockerfilePath, "project.yaml")
	cfg, err := LoadProjectConfig(projectYAMLPath)
	if err != nil {
		log.Printf("Warning: Could not parse project.yaml (%v). Defaulting to address sanitizer.", err)
		cfg = &ProjectConfig{Sanitizers: []SanitizerEntry{{Name: "address", Experimental: false}}}
	}
	if len(cfg.Sanitizers) == 0 {
		log.Printf("No sanitizers listed in project.yaml; defaulting to address sanitizer.")
		cfg.Sanitizers = []SanitizerEntry{{Name: "address", Experimental: false}}
	}

	// Use sanitizer override from config if provided
	var sanitizersToUse []string
	configSource := "project.yaml"
	if len(params.SanitizerOverride) > 0 {
		sanitizersToUse = params.SanitizerOverride
		configSource = ".env"
	} else {
		// Extract sanitizer names from SanitizerEntry slice
		sanitizersToUse = make([]string, 0, len(cfg.Sanitizers))
		for _, s := range cfg.Sanitizers {
			sanitizersToUse = append(sanitizersToUse, s.Name)
		}
	}

	// CRITICAL: JavaScript projects MUST use "none" sanitizer
	// OSS-Fuzz does not support address/memory/undefined sanitizers for JavaScript
	lang := strings.ToLower(cfg.Language)
	if lang == "javascript" || lang == "typescript" || lang == "js" || lang == "ts" {
		// Check if current sanitizers include anything other than "none"
		hasNonNoneSanitizer := false
		for _, s := range sanitizersToUse {
			if s != "none" {
				hasNonNoneSanitizer = true
				break
			}
		}
		if hasNonNoneSanitizer {
			log.Printf("WARNING: JavaScript projects cannot use sanitizers other than 'none'")
			log.Printf("Overriding sanitizers from %v to [none]", sanitizersToUse)
			sanitizersToUse = []string{"none"}
			configSource = "auto-detected (JavaScript)"
		}
	}

	// Print configuration summary
	log.Println("")
	log.Println("╔════════════════════════════════════════════════════════════════╗")
	log.Println("║              FUZZER BUILD CONFIGURATION                        ║")
	log.Println("╠════════════════════════════════════════════════════════════════╣")
	log.Printf("║ Configuration Source: %-41s║\n", configSource)
	log.Printf("║ Language: %-52s║\n", cfg.Language)
	log.Println("╠════════════════════════════════════════════════════════════════╣")
	log.Println("║ Sanitizers to Build:                                           ║")
	for _, san := range sanitizersToUse {
		log.Printf("║   - %-58s║\n", san)
	}
	// if strings.ToLower(cfg.Language) == "c" || strings.ToLower(cfg.Language) == "c++" {
	// 	log.Printf("║   - %-58s║\n", "coverage (mandatory for C/C++)")
	// }
	log.Println("╚════════════════════════════════════════════════════════════════╝")
	log.Println("")

	// Build fuzzers for each configurable sanitizer (address, memory, undefined, thread)
	for _, sanitizer := range sanitizersToUse {
		// Skip coverage here - it's handled separately below as mandatory
		if sanitizer == "coverage" {
			log.Printf("Skipping 'coverage' in config (built separately as mandatory)")
			continue
		}

		if *params.MyFuzzer != "" && *params.MyFuzzer != "UNHARNESSED" && !strings.Contains(*params.MyFuzzer, sanitizer) {
			continue
		}

		sanitizerDir := params.FuzzerDir + "-" + sanitizer
		sanitizerDirs = append(sanitizerDirs, sanitizerDir)

		log.Printf("fuzzerDir: %s", params.FuzzerDir)
		log.Printf("sanitizerDir: %s", sanitizerDir)

		fuzzers, _ := params.FindFuzzers(sanitizerDir)
		if len(fuzzers) == 0 {
			log.Printf("-------------------- Building fuzzers ----------------------")
			log.Printf("No fuzzers found in %s for sanitizer %s. Building...", sanitizerDir, sanitizer)
			if err := params.FuzzerBuilder(params.MyFuzzer, params.TaskDir, params.ProjectDir, sanitizerDir, sanitizer, cfg.Language, params.TaskDetail); err != nil {
				log.Printf("Error building fuzzers for sanitizer %s: %v", sanitizer, err)
			}
		} else {
			log.Printf("Found %d fuzzers in %s. Skipping build.", len(fuzzers), sanitizerDir)
		}
	}

	// ALWAYS build coverage for C/C++ projects (mandatory for control flow analysis)
	// Coverage is built in the base directory without sanitizer suffix
	// lang := strings.ToLower(cfg.Language)
	// if lang == "c" || lang == "c++" {
	// 	log.Printf("Building mandatory coverage instrumentation for C/C++ project")
	// 	san := "coverage"
	// 	sanDir := params.FuzzerDir
	// 	fuzzers, err := params.FindFuzzers(sanDir)
	// 	if err != nil {
	// 		log.Printf("Warning: problem trying to find coverage fuzzers in %s: %v", sanDir, err)
	// 	}

	// 	if len(fuzzers) == 0 {
	// 		log.Printf("-------------------- Building coverage fuzzers ----------------------")
	// 		log.Printf("No coverage fuzzers found in %s. Building with --sanitizer=%s", sanDir, san)
	// 		if err := params.FuzzerBuilder(params.MyFuzzer, params.TaskDir, params.ProjectDir, sanDir, san, cfg.Language, params.TaskDetail); err != nil {
	// 			log.Printf("Error building coverage fuzzers: %v", err)
	// 		}
	// 	} else {
	// 		log.Printf("Found %d coverage fuzzers in %s. Skipping build.", len(fuzzers), sanDir)
	// 	}
	// }

	return cfg, sanitizerDirs, nil
}

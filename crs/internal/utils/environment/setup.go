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

// ProjectConfig represents the configuration loaded from project.yaml
type ProjectConfig struct {
	Sanitizers []string `yaml:"sanitizers"`
	Language   string   `yaml:"language"`
	MainRepo   string   `yaml:"main_repo"`
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
		cfg = &ProjectConfig{Sanitizers: []string{"address"}}
	}
	if len(cfg.Sanitizers) == 0 {
		log.Printf("No sanitizers listed in project.yaml; defaulting to address sanitizer.")
		cfg.Sanitizers = []string{"address"}
	}

	// Use sanitizer override from config if provided
	sanitizersToUse := cfg.Sanitizers
	configSource := "project.yaml"
	if len(params.SanitizerOverride) > 0 {
		sanitizersToUse = params.SanitizerOverride
		configSource = ".env"
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
	if strings.ToLower(cfg.Language) == "c" || strings.ToLower(cfg.Language) == "c++" {
		log.Printf("║   - %-58s║\n", "coverage (mandatory for C/C++)")
	}
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
	lang := strings.ToLower(cfg.Language)
	if lang == "c" || lang == "c++" {
		log.Printf("Building mandatory coverage instrumentation for C/C++ project")
		san := "coverage"
		sanDir := params.FuzzerDir
		fuzzers, err := params.FindFuzzers(sanDir)
		if err != nil {
			log.Printf("Warning: problem trying to find coverage fuzzers in %s: %v", sanDir, err)
		}

		if len(fuzzers) == 0 {
			log.Printf("-------------------- Building coverage fuzzers ----------------------")
			log.Printf("No coverage fuzzers found in %s. Building with --sanitizer=%s", sanDir, san)
			if err := params.FuzzerBuilder(params.MyFuzzer, params.TaskDir, params.ProjectDir, sanDir, san, cfg.Language, params.TaskDetail); err != nil {
				log.Printf("Error building coverage fuzzers: %v", err)
			}
		} else {
			log.Printf("Found %d coverage fuzzers in %s. Skipping build.", len(fuzzers), sanDir)
		}
	}

	return cfg, sanitizerDirs, nil
}

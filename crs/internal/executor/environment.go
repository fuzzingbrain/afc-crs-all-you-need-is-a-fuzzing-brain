package executor

import (
	"log"
	"os"
	"path/filepath"
	"strings"

	"crs/internal/models"
	"gopkg.in/yaml.v3"
)

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

	// Build fuzzers for each sanitizer if they don't exist
	for _, sanitizer := range cfg.Sanitizers {
		if sanitizer == "undefined" {
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

	// Coverage for C/C++ worker fuzzers
	if os.Getenv("LOCAL_TEST") != "" || *params.MyFuzzer != "" {
		lang := strings.ToLower(cfg.Language)
		if lang == "c" || lang == "c++" {
			san := "coverage"
			sanDir := params.FuzzerDir
			fuzzers, err := params.FindFuzzers(sanDir)
			if err != nil {
				log.Printf("Warning: problem trying to find coverage fuzzers in %s: %v", sanDir, err)
			}

			if len(fuzzers) == 0 {
				log.Printf("Building fuzzers with --sanitizer=%s", san)
				if err := params.FuzzerBuilder(params.MyFuzzer, params.TaskDir, params.ProjectDir, sanDir, san, cfg.Language, params.TaskDetail); err != nil {
					log.Printf("Error building fuzzers for sanitizer %s: %v", san, err)
				}
			} else {
				log.Printf("Found %d coverage fuzzers in %s. Skipping build.", len(fuzzers), sanDir)
			}
		}
	}

	return cfg, sanitizerDirs, nil
}

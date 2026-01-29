package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// SecurityFinding represents a verified security vulnerability
type SecurityFinding struct {
	VulnerabilityType string `json:"vulnerability_type"`
	Location          string `json:"location"`
	Description       string `json:"description"`
	SeedInputPath     string `json:"seed_input_path"`
	Verification      string `json:"verification"`
	Severity          string `json:"severity"`
}

// SecurityAnalyzerConfig holds configuration for security analysis
type SecurityAnalyzerConfig struct {
	FuzzerPaths        []string // All available fuzzers for verification
	RepoPath           string
	Sanitizer          string
	OutputDir          string
	StaticAnalysisPath string
	DiffPath           string
	MaxTurns           int
	TimeoutMinutes     int
	// Docker execution settings
	ProjectName    string // OSS-Fuzz project name (e.g., "openssh")
	DockerImage    string // Docker image to use (e.g., "gcr.io/oss-fuzz/openssh:latest")
	FuzzDir        string // Directory containing fuzzers (mounted as /out)
	WorkDir        string // Work directory (mounted as /work)
}

// RunSecurityAnalyzer runs the Claude Agent-based security analyzer
// to find and verify security vulnerabilities using any of the available fuzzers
func RunSecurityAnalyzer(config SecurityAnalyzerConfig) ([]SecurityFinding, error) {
	log.Printf("========== SECURITY ANALYZER (Claude Agent) ==========")
	log.Printf("Fuzzers: %d available", len(config.FuzzerPaths))
	for i, f := range config.FuzzerPaths {
		log.Printf("  [%d] %s", i+1, filepath.Base(f))
	}
	log.Printf("Repo: %s", config.RepoPath)
	log.Printf("Sanitizer: %s", config.Sanitizer)
	log.Printf("Output: %s", config.OutputDir)
	log.Printf("======================================================")

	if len(config.FuzzerPaths) == 0 {
		log.Printf("No fuzzers provided to security analyzer")
		return nil, nil
	}

	// Set defaults
	if config.MaxTurns == 0 {
		config.MaxTurns = 50
	}
	if config.TimeoutMinutes == 0 {
		config.TimeoutMinutes = 30
	}
	if config.Sanitizer == "" {
		config.Sanitizer = "address"
	}

	// Get workspace directory and Python interpreter
	// RepoPath is like: /workspace/project/repo, so workspace is 2 levels up
	projectDir := filepath.Dir(config.RepoPath)
	workspaceDir := filepath.Dir(projectDir)
	venvPath := filepath.Join(workspaceDir, "crs_venv")
	pythonInterpreter := filepath.Join(venvPath, "bin", "python3")
	if _, err := os.Stat(pythonInterpreter); os.IsNotExist(err) {
		// Fallback: check if venv is in project dir
		venvPath = filepath.Join(projectDir, "crs_venv")
		pythonInterpreter = filepath.Join(venvPath, "bin", "python3")
		if _, err := os.Stat(pythonInterpreter); os.IsNotExist(err) {
			log.Printf("WARNING: crs_venv not found at %s, using system python3", venvPath)
			pythonInterpreter = "python3"
		}
	}
	log.Printf("Using Python interpreter: %s", pythonInterpreter)

	// Create output directory
	if config.OutputDir == "" {
		config.OutputDir = filepath.Join(projectDir, "security_findings")
	}
	os.MkdirAll(config.OutputDir, 0755)

	// Build the Python module path - use the security_analyzer module
	// The module is at crs/strategy/common/security_analyzer/agent.py
	crsDir := os.Getenv("CRS_DIR")
	if crsDir == "" {
		// Try to find crs directory relative to workspace
		crsDir = filepath.Join(workspaceDir, "..", "crs")
		if _, err := os.Stat(crsDir); os.IsNotExist(err) {
			// Fallback: try using PYTHONPATH if set
			crsDir = ""
		}
	}

	// Build command arguments for running the security analyzer
	// Pass all fuzzers so the agent can choose the best one for each vulnerability
	args := []string{
		"-m", "crs.strategy.common.security_analyzer.agent",
		config.RepoPath,
		"--sanitizer", config.Sanitizer,
		"--output-dir", config.OutputDir,
		"--max-turns", fmt.Sprintf("%d", config.MaxTurns),
	}

	// Add all fuzzers
	for _, fuzzer := range config.FuzzerPaths {
		args = append(args, "--fuzzer", fuzzer)
	}

	// Add Docker execution settings if available
	if config.ProjectName != "" {
		args = append(args, "--project-name", config.ProjectName)
	}
	if config.DockerImage != "" {
		args = append(args, "--docker-image", config.DockerImage)
	}
	if config.FuzzDir != "" {
		args = append(args, "--fuzz-dir", config.FuzzDir)
	}
	if config.WorkDir != "" {
		args = append(args, "--work-dir", config.WorkDir)
	}

	if config.StaticAnalysisPath != "" {
		args = append(args, "--static-analysis", config.StaticAnalysisPath)
	}
	if config.DiffPath != "" {
		args = append(args, "--diff", config.DiffPath)
	}

	// Set up environment
	env := os.Environ()
	env = append(env, "PYTHONUNBUFFERED=1")
	env = append(env, "VIRTUAL_ENV="+venvPath)
	// Enable verbose logging to see Docker commands from Claude Agent
	env = append(env, "CLAUDE_CODE_DEBUG=1")
	env = append(env, "CLAUDE_CODE_VERBOSE=1")
	if crsDir != "" {
		// Add crs parent directory to PYTHONPATH so "crs.strategy.common..." can be resolved
		crsParent := filepath.Dir(crsDir)
		pythonPath := os.Getenv("PYTHONPATH")
		if pythonPath != "" {
			pythonPath = crsParent + ":" + pythonPath
		} else {
			pythonPath = crsParent
		}
		env = append(env, "PYTHONPATH="+pythonPath)
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(config.TimeoutMinutes)*time.Minute)
	defer cancel()

	// Create and run command
	cmd := exec.CommandContext(ctx, pythonInterpreter, args...)
	cmd.Dir = config.RepoPath
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	log.Printf("Executing security analyzer: %s %v", pythonInterpreter, args)

	err := cmd.Run()
	if err != nil {
		log.Printf("Security analyzer execution error: %v", err)
		// Don't return error - analyzer finding nothing is not a failure
	}

	// Read results from output file
	resultsFile := filepath.Join(config.OutputDir, "security_findings.json")
	findings, err := readSecurityFindings(resultsFile)
	if err != nil {
		log.Printf("Could not read security findings: %v", err)
		return nil, nil // Not a critical error
	}

	log.Printf("Security analyzer found %d verified vulnerabilities", len(findings))
	for _, finding := range findings {
		log.Printf("  [%s] %s at %s", finding.Severity, finding.VulnerabilityType, finding.Location)
	}

	// If no findings and we have seed_corpus, run libfuzzer with the seeds
	if len(findings) == 0 && config.FuzzDir != "" {
		seedCorpusDir := filepath.Join(config.FuzzDir, "seed_corpus")
		if entries, err := os.ReadDir(seedCorpusDir); err == nil && len(entries) > 0 {
			log.Printf("No verified vulnerabilities found. Running libfuzzer with %d seed corpus files...", len(entries))
			runLibfuzzerWithSeedCorpus(config, seedCorpusDir)
		} else {
			log.Printf("No seed corpus found at %s, skipping libfuzzer run", seedCorpusDir)
		}
	}

	return findings, nil
}

// runLibfuzzerWithSeedCorpus runs libfuzzer with the agent-generated seed corpus
// Runs fuzzers in parallel using 75% of available CPU cores
func runLibfuzzerWithSeedCorpus(config SecurityAnalyzerConfig, seedCorpusDir string) {
	if len(config.FuzzerPaths) == 0 || config.DockerImage == "" {
		log.Printf("Cannot run libfuzzer: missing fuzzer paths or docker image")
		return
	}

	// Calculate parallelism: 75% of CPU cores, minimum 1
	numCPU := runtime.NumCPU()
	maxParallel := (numCPU * 3) / 4
	if maxParallel < 1 {
		maxParallel = 1
	}
	if maxParallel > len(config.FuzzerPaths) {
		maxParallel = len(config.FuzzerPaths)
	}

	log.Printf("Running %d fuzzers in parallel (75%% of %d cores = %d workers)", len(config.FuzzerPaths), numCPU, maxParallel)

	// Semaphore for limiting parallelism
	sem := make(chan struct{}, maxParallel)
	var wg sync.WaitGroup

	for _, fuzzerPath := range config.FuzzerPaths {
		wg.Add(1)
		sem <- struct{}{} // Acquire

		go func(fuzzerPath string) {
			defer wg.Done()
			defer func() { <-sem }() // Release

			fuzzerName := filepath.Base(fuzzerPath)
			log.Printf("Starting libfuzzer %s with seed corpus...", fuzzerName)

			// Build docker command
			dockerArgs := []string{
				"run", "--rm", "--platform", "linux/amd64",
				"-e", "FUZZING_ENGINE=libfuzzer",
				"-e", "SANITIZER=" + config.Sanitizer,
				"-e", "ARCHITECTURE=x86_64",
				"-e", "PROJECT_NAME=" + config.ProjectName,
				"-v", config.RepoPath + ":/src/" + config.ProjectName,
				"-v", config.FuzzDir + ":/out",
			}
			if config.WorkDir != "" {
				dockerArgs = append(dockerArgs, "-v", config.WorkDir+":/work")
			}
			dockerArgs = append(dockerArgs,
				config.DockerImage,
				"/out/"+fuzzerName,
				"-timeout=30",
				"-max_total_time=120", // 2 minutes per fuzzer
				"-print_final_stats=1",
				"/out/seed_corpus",
			)

			// Log the full command
			log.Printf("[DOCKER_CMD] docker %v", dockerArgs)

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			cmd := exec.CommandContext(ctx, "docker", dockerArgs...)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr

			err := cmd.Run()
			cancel()

			if err != nil {
				// Exit code 77 means crash found, which is good!
				if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 77 {
					log.Printf("✓ Fuzzer %s found a crash with seed corpus!", fuzzerName)
				} else {
					log.Printf("Fuzzer %s completed with: %v", fuzzerName, err)
				}
			} else {
				log.Printf("Fuzzer %s completed without crashes", fuzzerName)
			}
		}(fuzzerPath)
	}

	wg.Wait()
	log.Printf("All fuzzers completed seed corpus run")
}

// readSecurityFindings reads the security findings from the JSON output file
func readSecurityFindings(filePath string) ([]SecurityFinding, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var result struct {
		Vulnerabilities []SecurityFinding `json:"vulnerabilities"`
		FullResponse    string            `json:"full_response"`
	}

	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	return result.Vulnerabilities, nil
}

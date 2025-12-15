package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"crs/internal/competition"
	"crs/internal/config"
	"crs/internal/executor"
	"crs/internal/models"
	"crs/internal/utils/build"
	"crs/internal/utils/environment"
	"crs/internal/utils/fuzzer"
	"crs/internal/utils/helpers"

	"github.com/google/uuid"
)

// LocalCRSService implements CRSService for local CLI mode
type LocalCRSService struct {
	cfg                     *config.Config
	workDir                 string
	povMetadataDir          string
	povMetadataDir0         string
	povAdvcancedMetadataDir string
	submissionEndpoint      string
	workerIndex             string
	analysisServiceUrl      string
	model                   string
	competitionClient       *competition.Client
	unharnessedFuzzerSrc    sync.Map
}

// NewLocalService creates a new local service instance
func NewLocalService(cfg *config.Config) CRSService {
	// Get API configuration from config
	apiEndpoint := os.Getenv("COMPETITION_API_ENDPOINT")
	if apiEndpoint == "" {
		apiEndpoint = "http://localhost:7081"
	}

	// Define default work directory
	workDir := "/crs-workdir"
	if envWorkDir := os.Getenv("CRS_WORKDIR"); envWorkDir != "" {
		workDir = envWorkDir
	}

	// Create the work directory if it doesn't exist
	if err := helpers.EnsureWorkDir(workDir); err != nil {
		log.Printf("Warning: Could not create work directory at %s: %v", workDir, err)

		homeDir, err := os.UserHomeDir()
		if err == nil {
			workDir = filepath.Join(homeDir, "crs-workdir")
			log.Printf("Trying fallback work directory: %s", workDir)

			if err := helpers.EnsureWorkDir(workDir); err != nil {
				log.Printf("Warning: Could not create fallback work directory: %v", err)
				tempDir, err := os.MkdirTemp("", "crs-workdir-")
				if err == nil {
					workDir = tempDir
					log.Printf("Using temporary directory as work directory: %s", workDir)
				} else {
					workDir = "."
					log.Printf("Warning: Using current directory as work directory")
				}
			}
		} else {
			workDir = "."
			log.Printf("Warning: Using current directory as work directory")
		}
	}

	return &LocalCRSService{
		cfg:                     cfg,
		workDir:                 workDir,
		competitionClient:       competition.NewClient(apiEndpoint, cfg.Auth.KeyID, cfg.Auth.Token),
		povMetadataDir:          "successful_povs",
		povMetadataDir0:         "successful_povs_0",
		povAdvcancedMetadataDir: "successful_povs_advanced",
		model:                   cfg.AI.Model,
		submissionEndpoint:      cfg.Services.SubmissionURL,
		workerIndex:             "",
		analysisServiceUrl:      cfg.Services.AnalysisURL,
	}
}

// GetStatus returns empty status for local mode (no task tracking)
func (s *LocalCRSService) GetStatus() models.Status {
	return models.Status{
		Ready: true,
		State: models.StatusState{
			Tasks: models.StatusTasksState{},
		},
	}
}

// SubmitLocalTask implements local task submission
func (s *LocalCRSService) SubmitLocalTask(taskDir string) error {
	myFuzzer := ""

	// --- ensure LOCAL_TEST mode is enabled ---
	if os.Getenv("LOCAL_TEST") == "" {
		log.Printf("Setting LOCAL_TEST to 1")
		_ = os.Setenv("LOCAL_TEST", "1")
	}

	//----------------------------------------------------------
	// Locate and load task_detail.json from task root directory (if present)
	//----------------------------------------------------------
	var (
		taskDetail models.TaskDetail
		jsonFound  bool
	)

	// Only check for task_detail.json in the task root directory, not subdirectories
	taskDetailPath := filepath.Join(taskDir, "task_detail.json")
	if data, err := os.ReadFile(taskDetailPath); err == nil {
		if umErr := json.Unmarshal(data, &taskDetail); umErr == nil {
			jsonFound = true
			log.Printf("Loaded task detail from %s", taskDetailPath)
		} else {
			log.Printf("Failed to unmarshal %s: %v", taskDetailPath, umErr)
		}
	}

	// Fallback to stub when JSON isn't found / can't be parsed
	if !jsonFound {
		log.Printf("No valid task_detail.json found – falling back to default task detail")

		projectName := "unknown"
		focusName := "repo"

		projectsDir := filepath.Join(taskDir, "fuzz-tooling/projects/")
		files, err := os.ReadDir(projectsDir)
		if err == nil {
			for _, file := range files {
				if file.IsDir() {
					projectName = file.Name()
					focusName = "repo"
					log.Printf("Found project '%s' in fuzz-tooling/projects, source code in '%s'", projectName, focusName)
					break // Use the first one
				}
			}
		} else {
			log.Printf("Could not read fuzz-tooling/projects/ directory: %v", err)
		}

		// Determine task type based on presence of "diff" directory
		taskType := models.TaskTypeFull
		diffPath := filepath.Join(taskDir, "diff")
		if info, err := os.Stat(diffPath); err == nil && info.IsDir() {
			taskType = models.TaskTypeDelta
			log.Printf("Found 'diff' directory, setting task type to 'delta'")
		} else {
			log.Printf("No 'diff' directory found, setting task type to 'full'")
		}

		log.Printf("Saving Task Detail")

		taskDetail = models.TaskDetail{
			TaskID:            uuid.New(),
			ProjectName:       projectName,
			Focus:             focusName,
			Type:              taskType,
			Deadline:          time.Now().Add(time.Hour).Unix() * 1000,
			HarnessesIncluded: true,
			Metadata:          make(map[string]string),
		}

		log.Printf("Completed Task Detail, setting task detail to %v", taskDetail)

		// Save task detail to task directory for future runs
		jsonData, marshalErr := json.MarshalIndent(taskDetail, "", "  ")
		if marshalErr == nil {
			if writeErr := os.WriteFile(taskDetailPath, jsonData, 0644); writeErr == nil {
				log.Printf("Saved task detail to %s", taskDetailPath)
			} else {
				log.Printf("Warning: Failed to save task detail: %v", writeErr)
			}
		}
	}
	//----------------------------------------------------------

	// Get absolute paths
	log.Printf("-------------------- Getting absolute task dir path ----------------------")
	absTaskDir, err := filepath.Abs(taskDir)
	if err != nil {
		return fmt.Errorf("failed to get absolute task dir path: %v", err)
	}

	projectDir := path.Join(absTaskDir, taskDetail.Focus)
	dockerfilePath := path.Join(absTaskDir, "fuzz-tooling/projects", taskDetail.ProjectName)
	dockerfileFullPath := path.Join(dockerfilePath, "Dockerfile")
	fuzzerDir := path.Join(taskDir, "fuzz-tooling/build/out", taskDetail.ProjectName)

	log.Printf("Project dir: %s", projectDir)
	log.Printf("Dockerfile: %s", dockerfileFullPath)

	// Use executor package to prepare environment
	params := environment.PrepareEnvironmentParams{
		MyFuzzer:           &myFuzzer,
		TaskDir:            taskDir,
		TaskDetail:         taskDetail,
		DockerfilePath:     dockerfilePath,
		DockerfileFullPath: dockerfileFullPath,
		FuzzerDir:          fuzzerDir,
		ProjectDir:         projectDir,
		FuzzerBuilder:      s.buildFuzzersDocker,
		FindFuzzers:        fuzzer.FindFuzzers,
		SanitizerOverride:  s.cfg.Fuzzer.GetSanitizerList(), // Use config sanitizers if set
	}
	cfg, sanitizerDirs, err := environment.PrepareEnvironment(params)
	if err != nil {
		return err
	}

	// Collect all fuzzers from all sanitizer builds and run them in parallel
	log.Printf("-------------------- Collecting all fuzzers ----------------------")
	var allFuzzers []string
	sanitizerDirsCopy := make([]string, len(sanitizerDirs))
	copy(sanitizerDirsCopy, sanitizerDirs)

	// Now use the copy to find fuzzers
	for _, sdir := range sanitizerDirsCopy {
		fuzzers, err := fuzzer.FindFuzzers(sdir)
		if err != nil {
			log.Printf("Warning: failed to find fuzzers in %s: %v", sdir, err)
			continue // Skip this directory but continue with others
		}

		// Mark these fuzzers with the sanitizer directory so we know where they live
		for _, fz := range fuzzers {
			// We'll store the absolute path so we can directly call run_fuzzer
			fuzzerPath := filepath.Join(sdir, fz)
			allFuzzers = append(allFuzzers, fuzzerPath)
		}
	}

	if len(allFuzzers) == 0 {
		log.Printf("No fuzzers found after building all sanitizers")
		return nil
	}

	log.Printf("Discovered %d fuzzers before filtering", len(allFuzzers))

	// Apply fuzzer filtering based on configuration
	var filteredFuzzers []string
	for _, fuzzerPath := range allFuzzers {
		// Filter by fuzzer selection (FUZZER_SELECTED + FUZZER_DISCOVERY_MODE)
		if !s.cfg.Fuzzer.MatchesFuzzerSelection(fuzzerPath) {
			log.Printf("Skipping fuzzer (not selected): %s", filepath.Base(fuzzerPath))
			continue
		}

		// Filter by preferred sanitizer (FUZZER_PREFERRED_SANITIZER)
		if !s.cfg.Fuzzer.ShouldUseSanitizer(fuzzerPath) {
			log.Printf("Skipping fuzzer (wrong sanitizer): %s", fuzzerPath)
			continue
		}

		filteredFuzzers = append(filteredFuzzers, fuzzerPath)
	}

	// Legacy filtering: skip memory/undefined if too many fuzzers
	const MAX_FUZZERS = 10
	if len(filteredFuzzers) > MAX_FUZZERS {
		var finalFuzzers []string
		for _, fuzzerPath := range filteredFuzzers {
			if strings.Contains(fuzzerPath, "-address/") {
				finalFuzzers = append(finalFuzzers, fuzzerPath)
			}
		}
		log.Printf("Too many fuzzers (%d), keeping only address sanitizer (%d fuzzers)", len(filteredFuzzers), len(finalFuzzers))
		filteredFuzzers = finalFuzzers
	}

	allFuzzers = helpers.SortFuzzersByGroup(filteredFuzzers)

	// Print execution summary
	log.Println("")
	log.Println("╔════════════════════════════════════════════════════════════════╗")
	log.Println("║              FUZZER EXECUTION CONFIGURATION                    ║")
	log.Println("╠════════════════════════════════════════════════════════════════╣")
	log.Printf("║ Discovery Mode: %-47s║\n", s.cfg.Fuzzer.DiscoveryMode)
	log.Printf("║ Preferred Sanitizer: %-43s║\n", s.cfg.Fuzzer.PreferredSanitizer)
	if s.cfg.Fuzzer.Selected != "" {
		log.Printf("║ Selected Fuzzer: %-47s║\n", s.cfg.Fuzzer.Selected)
	}
	log.Println("╠════════════════════════════════════════════════════════════════╣")
	log.Printf("║ Total Discovered: %-47d║\n", len(allFuzzers))
	log.Println("║ Fuzzers to Execute:                                            ║")
	for i, fz := range allFuzzers {
		fuzzerName := filepath.Base(fz)
		if len(fuzzerName) > 55 {
			fuzzerName = fuzzerName[:52] + "..."
		}
		log.Printf("║   %2d. %-57s║\n", i+1, fuzzerName)
	}
	log.Println("╚════════════════════════════════════════════════════════════════╝")
	log.Println("")

	fullTask := models.Task{
		MessageID:   uuid.New(),
		MessageTime: time.Now().UnixMilli(),
		Tasks:       []models.TaskDetail{taskDetail},
	}

	// Use executor package for fuzzing execution
	execParams := executor.TaskExecutionParams{
		Fuzzer:                   myFuzzer,
		TaskDir:                  taskDir,
		TaskDetail:               taskDetail,
		Task:                     fullTask,
		ProjectConfig:            cfg,
		AllFuzzers:               allFuzzers,
		SubmissionEndpoint:       s.submissionEndpoint,
		POVMetadataDir:           s.povMetadataDir,
		POVMetadataDir0:          s.povMetadataDir0,
		POVAdvancedMetadataDir:   s.povAdvcancedMetadataDir,
		Model:                    s.model,
		WorkerIndex:              s.workerIndex,
		AnalysisServiceUrl:       s.analysisServiceUrl,
		UnharnessedFuzzerSrcPath: "",
		StrategyConfig:           &s.cfg.Strategy,
		FuzzerConfig:             &s.cfg.Fuzzer,
		Sanitizer:                s.cfg.Fuzzer.PreferredSanitizer,
	}

	if err := executor.ExecuteFuzzingTask(execParams); err != nil {
		log.Printf("Processing task %s: %v fuzzer: %s", taskDetail.TaskID, err, myFuzzer)
	}

	return nil
}

// SubmitTask is not supported in local mode
func (s *LocalCRSService) SubmitTask(task models.Task) error {
	return errNotSupportedInLocalMode
}

// SubmitWorkerTask is not supported in local mode
func (s *LocalCRSService) SubmitWorkerTask(task models.WorkerTask) error {
	return errNotSupportedInLocalMode
}

// CancelTask is not supported in local mode
func (s *LocalCRSService) CancelTask(taskID string) error {
	return errNotSupportedInLocalMode
}

// CancelAllTasks is not supported in local mode
func (s *LocalCRSService) CancelAllTasks() error {
	return errNotSupportedInLocalMode
}

// SubmitSarif handles SARIF broadcast submission in local mode
// TODO: SARIF workflow to be implemented later
func (s *LocalCRSService) SubmitSarif(sarifBroadcast models.SARIFBroadcast) error {
	log.Printf("SARIF workflow not yet implemented in LocalCRSService")
	return nil
}

// HandleSarifBroadcastWorker is not used in local mode
func (s *LocalCRSService) HandleSarifBroadcastWorker(broadcastWorker models.SARIFBroadcastDetailWorker) error {
	return errNotSupportedInLocalMode
}

// SetWorkerIndex is not used in local mode (no-op)
func (s *LocalCRSService) SetWorkerIndex(index string) {
	s.workerIndex = index
}

// SetSubmissionEndpoint sets the submission endpoint
func (s *LocalCRSService) SetSubmissionEndpoint(endpoint string) {
	s.submissionEndpoint = endpoint
}

// SetAnalysisServiceUrl sets the analysis service URL
func (s *LocalCRSService) SetAnalysisServiceUrl(url string) {
	s.analysisServiceUrl = url
}

// GetWorkDir returns the work directory
func (s *LocalCRSService) GetWorkDir() string {
	return s.workDir
}

// buildFuzzersDocker builds fuzzers using Docker for the specified sanitizer
func (s *LocalCRSService) buildFuzzersDocker(myFuzzer *string, taskDir, projectDir, sanitizerDir string, sanitizer string, language string, taskDetail models.TaskDetail) error {
	// Create a sanitizer-specific copy of the project directory
	sanitizerProjectDir := fmt.Sprintf("%s-%s", projectDir, sanitizer)

	// Create the directory if it doesn't exist
	if err := os.MkdirAll(sanitizerProjectDir, 0755); err != nil {
		return fmt.Errorf("failed to create sanitizer-specific project directory: %v", err)
	}

	// Copy the project files to the sanitizer-specific directory
	cpCmd := exec.Command("cp", "-r", fmt.Sprintf("%s/.", projectDir), sanitizerProjectDir)
	log.Printf("Copying project files to sanitizer-specific directory: %s", cpCmd.String())
	if err := cpCmd.Run(); err != nil {
		return fmt.Errorf("failed to copy project files to sanitizer-specific directory: %v", err)
	}

	log.Printf("Created sanitizer-specific project directory: %s", sanitizerProjectDir)

	// Check for build.patch in the project's directory
	projectToolingDir := filepath.Join(taskDir, "fuzz-tooling", "projects", taskDetail.ProjectName)
	buildPatchPath := filepath.Join(projectToolingDir, "build.patch")

	// If build.patch exists, copy it to both the root and project subdirectory in the sanitizer directory
	if _, err := os.Stat(buildPatchPath); err == nil {
		log.Printf("Found build.patch at %s", buildPatchPath)

		// Copy to the root of the sanitizer directory
		rootPatchPath := filepath.Join(sanitizerProjectDir, "build.patch")
		cpRootPatchCmd := exec.Command("cp", buildPatchPath, rootPatchPath)
		if err := cpRootPatchCmd.Run(); err != nil {
			log.Printf("Warning: Failed to copy build.patch to root of sanitizer directory: %v", err)
		} else {
			log.Printf("Copied build.patch to %s", rootPatchPath)
		}

		// Also copy to the project subdirectory within the sanitizer directory
		projectSubdir := filepath.Join(sanitizerProjectDir, taskDetail.ProjectName)
		if err := os.MkdirAll(projectSubdir, 0755); err != nil {
			log.Printf("Warning: Failed to create project subdirectory in sanitizer directory: %v", err)
		} else {
			projectPatchPath := filepath.Join(projectSubdir, "build.patch")
			cpProjectPatchCmd := exec.Command("cp", buildPatchPath, projectPatchPath)
			if err := cpProjectPatchCmd.Run(); err != nil {
				log.Printf("Warning: Failed to copy build.patch to project subdirectory: %v", err)
			} else {
				log.Printf("Copied build.patch to %s", projectPatchPath)
			}
		}
	}

	if *myFuzzer == UNHARNESSED && sanitizer != "coverage" {
		log.Printf("Handling unharnessed task: %s", *myFuzzer)
		cloneOssFuzzAndMainRepoOnce(taskDir, taskDetail.ProjectName, sanitizerDir)

		newFuzzerSrcPath, newFuzzerPath, err := generateFuzzerForUnharnessedTask(
			taskDir,
			taskDetail.Focus,
			sanitizerDir,
			taskDetail.ProjectName,
			sanitizer,
		)
		if err != nil {
			log.Printf("Failed to generate fuzzer: %v", err)
		} else {
			s.unharnessedFuzzerSrc.Store(taskDetail.TaskID.String(), newFuzzerSrcPath)
			log.Printf("New fuzzer source: %s", newFuzzerSrcPath)

			*myFuzzer = newFuzzerPath
			log.Printf("New fuzzer generated: %s", *myFuzzer)
		}
	} else {
		// For both Java and C tasks on worker
		if true {
			output, err := build.BuildAFCFuzzers(taskDir, sanitizer, taskDetail.ProjectName, sanitizerProjectDir, sanitizerDir)
			if err != nil {
				log.Printf("[BuildAFCFuzzers] Build failed for %s-%s: %v", taskDetail.ProjectName, sanitizer, err)
				if output != "" {
					log.Printf("[BuildAFCFuzzers] Output:\n%s", output)
				}
			} else if output != "" {
				log.Printf("[BuildAFCFuzzers] Build completed for %s-%s", taskDetail.ProjectName, sanitizer)
			}
		} else {
			workDir := filepath.Join(taskDir, "fuzz-tooling", "build", "work", fmt.Sprintf("%s-%s", taskDetail.ProjectName, sanitizer))

			cmdArgs := []string{
				"run",
				"--privileged",
				"--shm-size=8g",
				"--platform", "linux/amd64",
				"--rm",
				"-e", "FUZZING_ENGINE=libfuzzer",
				"-e", fmt.Sprintf("SANITIZER=%s", sanitizer),
				"-e", "ARCHITECTURE=x86_64",
				"-e", fmt.Sprintf("PROJECT_NAME=%s", taskDetail.ProjectName),
				"-e", "HELPER=True",
				"-e", fmt.Sprintf("FUZZING_LANGUAGE=%s", language),
				"-v", fmt.Sprintf("%s:/src/%s", sanitizerProjectDir, taskDetail.ProjectName),
				"-v", fmt.Sprintf("%s:/out", sanitizerDir),
				"-v", fmt.Sprintf("%s:/work", workDir),
				"-t", fmt.Sprintf("aixcc-afc/%s", taskDetail.ProjectName),
			}

			buildCmd := exec.Command("docker", cmdArgs...)

			var buildOutput bytes.Buffer
			buildCmd.Stdout = &buildOutput
			buildCmd.Stderr = &buildOutput

			log.Printf("Running Docker build for sanitizer=%s, project=%s\nCommand: %v",
				sanitizer, taskDetail.ProjectName, buildCmd.Args)

			if err := buildCmd.Run(); err != nil {
				log.Printf("Build fuzzer output:\n%s", buildOutput.String())
				return fmt.Errorf("failed to build fuzzers with sanitizer=%s: %v\nOutput: %s",
					sanitizer, err, buildOutput.String())
			}
		}
	}
	return nil
}

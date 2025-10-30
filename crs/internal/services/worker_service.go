package services

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"crs/internal/models"
	"crs/internal/competition"
	"crs/internal/executor"
)

// WorkerCRSService implements CRSService for worker mode (task execution)
type WorkerCRSService struct {
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
	workerPort              int
}

// NewWorkerService creates a new worker service instance
func NewWorkerService(workerIndex string, workerPort int, model string) CRSService {
	// Get API configuration
	apiEndpoint := os.Getenv("COMPETITION_API_ENDPOINT")
	if apiEndpoint == "" {
		apiEndpoint = "http://localhost:7081"
	}

	apiKeyID := os.Getenv("CRS_KEY_ID")
	apiToken := os.Getenv("CRS_KEY_TOKEN")
	if apiKeyID == "" || apiToken == "" {
		log.Printf("Warning: CRS_KEY_ID or CRS_KEY_TOKEN not set")
	}

	// Define default work directory
	workDir := "/crs-workdir"
	if envWorkDir := os.Getenv("CRS_WORKDIR"); envWorkDir != "" {
		workDir = envWorkDir
	}

	// Create the work directory if it doesn't exist
	if err := ensureWorkDir(workDir); err != nil {
		log.Printf("Warning: Could not create work directory at %s: %v", workDir, err)

		homeDir, err := os.UserHomeDir()
		if err == nil {
			workDir = filepath.Join(homeDir, "crs-workdir")
			log.Printf("Trying fallback work directory: %s", workDir)

			if err := ensureWorkDir(workDir); err != nil {
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

	return &WorkerCRSService{
		workDir:                 workDir,
		competitionClient:       competition.NewClient(apiEndpoint, apiKeyID, apiToken),
		povMetadataDir:          "successful_povs",
		povMetadataDir0:         "successful_povs_0",
		povAdvcancedMetadataDir: "successful_povs_advanced",
		model:                   model,
		workerIndex:             workerIndex,
		submissionEndpoint:      "",
		analysisServiceUrl:      "",
		workerPort:              workerPort,
	}
}

// GetStatus returns worker status
func (s *WorkerCRSService) GetStatus() models.Status {
	// Workers can report their current status
	return models.Status{
		Ready: true,
		State: models.StatusState{
			Tasks: models.StatusTasksState{},
		},
	}
}

// SubmitLocalTask is not supported in worker mode
func (s *WorkerCRSService) SubmitLocalTask(taskPath string) error {
	return errNotSupportedInWorkerMode
}

// SubmitTask is not supported in worker mode
func (s *WorkerCRSService) SubmitTask(task models.Task) error {
	return errNotSupportedInWorkerMode
}

// SubmitWorkerTask implements worker task submission
func (s *WorkerCRSService) SubmitWorkerTask(task models.WorkerTask) error {
	if len(task.Tasks) == 0 {
		return fmt.Errorf("no tasks provided")
	}

	// Extract task details
	td := task.Tasks[0]
	taskID := td.TaskID.String()

	// Check CPU usage
	avgCPU, err := getAverageCPUUsage()
	if err != nil {
		log.Printf("Warning: could not get CPU usage: %v", err)
	} else {
		log.Printf("Average CPU usage: %.2f%%", avgCPU)
		if avgCPU > 80.0 && s.hasActiveWorkTasks() {
			return fmt.Errorf("system is too busy (CPU usage %.2f%% > 80%%), rejecting new task", avgCPU)
		}
		if avgCPU < 50.0 {
			// Accept the task regardless of taskID
			log.Printf("CPU usage low (%.2f%%), accepting task %s", avgCPU, taskID)
			go s.startWorkerTask(td, task, taskID)
			log.Printf("Worker task %s with fuzzer %s accepted for processing", taskID, task.Fuzzer)
			return nil
		}
	}

	// Try to acquire the lock and check if this task is already running
	workerTaskMutex.Lock()
	if activeWorkerTasks[taskID] {
		workerTaskMutex.Unlock()
		log.Printf("Worker is already processing task %s w/ fuzzer %s. New task will be rejected.", taskID, task.Fuzzer)
		return fmt.Errorf("worker is already processing task %s w/ fuzzer %s", taskID, task.Fuzzer)
	}
	// Mark this task as active
	activeWorkerTasks[taskID] = true
	workerTaskMutex.Unlock()

	go s.startWorkerTask(td, task, taskID)

	// Return immediately to allow handler to respond with StatusAccepted
	log.Printf("Worker task %s with fuzzer %s accepted for processing", taskID, task.Fuzzer)
	return nil
}

// startWorkerTask starts processing a worker task
func (s *WorkerCRSService) startWorkerTask(td models.TaskDetail, task models.WorkerTask, taskID string) {
	defer func() {
		workerTaskMutex.Lock()
		delete(activeWorkerTasks, taskID)
		workerTaskMutex.Unlock()

		if r := recover(); r != nil {
			log.Printf("Recovered from panic in worker task %s: %v", taskID, r)
			debug.PrintStack()
		}
	}()

	log.Printf("Starting worker task processing for task %s with fuzzer %s", taskID, task.Fuzzer)

	// Process the task using worker's processTask method
	if err := s.processTask(task.Fuzzer, td, models.Task{
		MessageID:   task.MessageID,
		MessageTime: task.MessageTime,
		Tasks:       []models.TaskDetail{td},
	}); err != nil {
		log.Printf("Error processing worker task %s: %v", taskID, err)
	} else {
		log.Printf("Successfully completed worker task %s", taskID)
	}
}

// hasActiveWorkTasks checks if there are any active worker tasks
func (s *WorkerCRSService) hasActiveWorkTasks() bool {
	workerTaskMutex.Lock()
	defer workerTaskMutex.Unlock()

	return len(activeWorkerTasks) > 0
}

// IsWorkerBusy returns whether the worker is busy and list of active task IDs
func (s *WorkerCRSService) IsWorkerBusy() (bool, []string) {
	workerTaskMutex.Lock()
	defer workerTaskMutex.Unlock()

	var activeIDs []string
	for taskID := range activeWorkerTasks {
		activeIDs = append(activeIDs, taskID)
	}
	return len(activeWorkerTasks) > 0, activeIDs
}

// CancelTask is not supported in worker mode
func (s *WorkerCRSService) CancelTask(taskID string) error {
	return errNotSupportedInWorkerMode
}

// CancelAllTasks is not supported in worker mode
func (s *WorkerCRSService) CancelAllTasks() error {
	return errNotSupportedInWorkerMode
}

// SubmitSarif handles SARIF broadcast submission from worker
// TODO: SARIF workflow to be implemented later
func (s *WorkerCRSService) SubmitSarif(sarifBroadcast models.SARIFBroadcast) error {
	return errNotSupportedInWorkerMode
}

// HandleSarifBroadcastWorker handles SARIF broadcasts received by worker
// TODO: SARIF workflow to be implemented later
func (s *WorkerCRSService) HandleSarifBroadcastWorker(broadcastWorker models.SARIFBroadcastDetailWorker) error {
	log.Printf("SARIF workflow not yet implemented in WorkerCRSService")
	return nil
}

// SetWorkerIndex sets the worker index
func (s *WorkerCRSService) SetWorkerIndex(index string) {
	s.workerIndex = index
}

// SetSubmissionEndpoint sets the submission endpoint
func (s *WorkerCRSService) SetSubmissionEndpoint(endpoint string) {
	s.submissionEndpoint = endpoint
}

// SetAnalysisServiceUrl sets the analysis service URL
func (s *WorkerCRSService) SetAnalysisServiceUrl(url string) {
	s.analysisServiceUrl = url
}

// GetWorkDir returns the work directory
func (s *WorkerCRSService) GetWorkDir() string {
	return s.workDir
}

// processTask processes a single task detail (worker executes directly)
func (s *WorkerCRSService) processTask(myFuzzer string, taskDetail models.TaskDetail, fullTask models.Task) error {
	taskID := taskDetail.TaskID.String()
	log.Printf("Processing task %s", taskID)

	// Create task directory with unique name
	timestamp := time.Now().Format("20060102-150405")
	taskDir := path.Join(s.workDir, fmt.Sprintf("%s-%s", taskID, timestamp))

	// If fuzzer path is provided, use its parent directory up to fuzz-tooling/build/out
	if myFuzzer != "" {
		// Find the index of "fuzz-tooling/" in the fuzzer path
		fuzzToolingIndex := strings.Index(myFuzzer, "fuzz-tooling/")
		if fuzzToolingIndex != -1 {
			// Extract the base directory (everything before fuzz-tooling/build/out)
			taskDir = myFuzzer[:fuzzToolingIndex]
			// Remove trailing slash if present
			taskDir = strings.TrimRight(taskDir, "/")
		}
	}

	// Get absolute paths
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
	params := executor.PrepareEnvironmentParams{
		MyFuzzer:           &myFuzzer,
		TaskDir:            taskDir,
		TaskDetail:         taskDetail,
		DockerfilePath:     dockerfilePath,
		DockerfileFullPath: dockerfileFullPath,
		FuzzerDir:          fuzzerDir,
		ProjectDir:         projectDir,
		FuzzerBuilder:      s.buildFuzzersDocker,
		FindFuzzers:        executor.FindFuzzers,
	}

	cfg, sanitizerDirs, err := executor.PrepareEnvironment(params)
	if err != nil {
		return err
	}

	// Collect all fuzzers from all sanitizer builds
	var allFuzzers []string
	sanitizerDirsCopy := make([]string, len(sanitizerDirs))
	copy(sanitizerDirsCopy, sanitizerDirs)

	// Now use the copy to find fuzzers
	for _, sdir := range sanitizerDirsCopy {
		fuzzers, err := executor.FindFuzzers(sdir)
		if err != nil {
			log.Printf("Warning: failed to find fuzzers in %s: %v", sdir, err)
			continue
		}

		for _, fz := range fuzzers {
			fuzzerPath := filepath.Join(sdir, fz)
			allFuzzers = append(allFuzzers, fuzzerPath)
		}
	}

	if len(allFuzzers) == 0 {
		log.Printf("No fuzzers found after building all sanitizers")
		return nil
	}

	// Filter fuzzers
	const MAX_FUZZERS = 10
	if true {
		var allFilteredFuzzers []string
		for _, fuzzerPath := range allFuzzers {
			if strings.Contains(fuzzerPath, "-address/") || (strings.Contains(fuzzerPath, "-memory/") && len(allFuzzers) < MAX_FUZZERS) {
				allFilteredFuzzers = append(allFilteredFuzzers, fuzzerPath)
			}
		}
		allFuzzers = executor.SortFuzzersByGroup(allFilteredFuzzers)
	}

	log.Printf("Found %d fuzzers: %v", len(allFuzzers), allFuzzers)

	// Process the task using executor package
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
	}

	if err := executor.ExecuteFuzzingTask(execParams); err != nil {
		log.Printf("Processing task %s: %v fuzzer: %s", taskDetail.TaskID, err, myFuzzer)
	}

	return nil
}

// buildFuzzersDocker builds fuzzers using Docker for the specified sanitizer
func (s *WorkerCRSService) buildFuzzersDocker(myFuzzer *string, taskDir, projectDir, sanitizerDir string, sanitizer string, language string, taskDetail models.TaskDetail) error {
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
			BuildAFCFuzzers(taskDir, sanitizer, taskDetail.ProjectName, sanitizerProjectDir, sanitizerDir)
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

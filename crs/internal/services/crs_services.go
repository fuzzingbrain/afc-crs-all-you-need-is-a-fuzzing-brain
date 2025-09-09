package services

import (
    "os/signal"
    "io/fs"
    "math/rand"
    "runtime"
    "time"
    "runtime/debug"
    "net/url"
    "bytes"
    "path/filepath"
    "fmt"
    "os"
    "path"
    "os/exec"
    "encoding/json"
    "math"
    "errors"
    "encoding/base64"
    "bufio"
    "net"
    "net/http"
    "io"
    "log"
    "unicode"
    "sort"
    "strings"
    "crypto/sha256"
    "encoding/hex"
    "crs/internal/models"
    "crs/internal/competition"
    "github.com/google/uuid"
    "regexp"
    "sync"
    "sync/atomic"
    "syscall"
    "gopkg.in/yaml.v3"
    "context"
    "crs/internal/telemetry"
    "go.opentelemetry.io/otel/attribute"
    "github.com/shirou/gopsutil/v3/cpu"
)

const (
	UNHARNESSED = "UNHARNESSED"
)

// ─── Terminal-output sanitiser ──────────────────────────────────────────
var ansiRegexp = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

func sanitizeTerminalString(s string) string {
	// Remove ANSI colour / cursor-movement codes.
	s = ansiRegexp.ReplaceAllString(s, "")

	// Drop any remaining control characters.
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, s)

	return strings.TrimSpace(s)
}

var (
    childGroups   = make(map[int]struct{})
    childGroupsMu sync.Mutex
)

func registerChildPG(pgid int) {
    childGroupsMu.Lock()
    childGroups[pgid] = struct{}{}
    childGroupsMu.Unlock()
}

func killAllChildren(sig syscall.Signal) {
    childGroupsMu.Lock()
    for pgid := range childGroups {
        syscall.Kill(-pgid, sig)
    }
    childGroupsMu.Unlock()
}

type ProjectConfig struct {
    Sanitizers []string `yaml:"sanitizers"`
    Language string  `yaml:"language"`
    MainRepo string `yaml:"main_repo"`
}

type CRSService interface {
    GetStatus() models.Status
    SubmitLocalTask(taskPath string) error
    SubmitTask(task models.Task) error
    SubmitWorkerTask(task models.WorkerTask) error
    CancelTask(taskID string) error
    CancelAllTasks() error
    SubmitSarif(sarifBroadcast models.SARIFBroadcast) error
    HandleSarifBroadcastWorker(broadcastWorker models.SARIFBroadcastDetailWorker) error

    // New methods for worker mode
    SetSubmissionEndpoint(endpoint string)
    SetWorkerIndex(index string)
    SetAnalysisServiceUrl(url string)
    GetWorkDir() string
}

type WorkerFuzzerPair struct {
    Worker int
    Fuzzer  string
}
type defaultCRSService struct {
    tasks   map[string]*models.TaskDetail
    tasksMutex sync.RWMutex
    workDir string
    competitionClient *competition.Client
    statusMutex sync.RWMutex
    status models.StatusTasksState
    povMetadataDir     string 
    povMetadataDir0     string 
    povAdvcancedMetadataDir     string 
    patchWorkDir       string
    submissionEndpoint string
    workerIndex        string
    analysisServiceUrl string
    //for worker only
    workerNodes int
    workerBasePort int
    model          string

    // Add these fields for tracking historical task distribution
    totalTasksDistributed int
    distributionMutex     sync.Mutex
    fuzzerToWorkerMap     map[string]int  // Maps fuzzer names to worker indices
    taskToWorkersMap      map[string][]WorkerFuzzerPair // Maps task ids to pairs of (fuzzer, worker indices)

    workerStatus     map[int]*WorkerStatus
    workerStatusMux  sync.Mutex
    unharnessedFuzzerSrc sync.Map
}

func (s *defaultCRSService) SetSubmissionEndpoint(endpoint string) {
    s.submissionEndpoint = endpoint
}

func (s *defaultCRSService) SetWorkerIndex(index string) {
    s.workerIndex = index
}

func (s *defaultCRSService) SetAnalysisServiceUrl(url string) {
    s.analysisServiceUrl = url
}

func (s *defaultCRSService) GetWorkDir() string {
    return s.workDir
}
// Add VulnerabilitySubmission model
type VulnerabilitySubmission struct {
    ChallengeID  string `json:"challenge_id"`
    TestHarness  string `json:"harness_name"`
    Sanitizer    string `json:"sanitizer"`
    Architecture string `json:"architecture"`
    CrashData    []byte `json:"data_file"`
}

func NewCRSService(workerNodes int, workerBasePort int, model string) CRSService {
    apiEndpoint := os.Getenv("COMPETITION_API_ENDPOINT")
    if apiEndpoint == "" {
        apiEndpoint = "http://localhost:7081"  // default value
    }

    apiKeyID := os.Getenv("CRS_KEY_ID")
    apiToken := os.Getenv("CRS_KEY_TOKEN")
    if apiKeyID == "" || apiToken == "" {
        log.Printf("Warning: CRS_KEY_ID or CRS_KEY_TOKEN not set")
    }

        // Define default work directory
        workDir := "/crs-workdir"
    
        // Check if environment variable is set to override the default
        if envWorkDir := os.Getenv("CRS_WORKDIR"); envWorkDir != "" {
            workDir = envWorkDir
        }
        
        // Create the work directory if it doesn't exist
        if err := ensureWorkDir(workDir); err != nil {
            // If we can't create the default directory, try a fallback in the user's home directory
            log.Printf("Warning: Could not create work directory at %s: %v", workDir, err)
            
            // Get user's home directory as fallback
            homeDir, err := os.UserHomeDir()
            if err == nil {
                workDir = filepath.Join(homeDir, "crs-workdir")
                log.Printf("Trying fallback work directory: %s", workDir)
                
                if err := ensureWorkDir(workDir); err != nil {
                    // If even the fallback fails, use a temporary directory
                    log.Printf("Warning: Could not create fallback work directory: %v", err)
                    tempDir, err := os.MkdirTemp("", "crs-workdir-")
                    if err == nil {
                        workDir = tempDir
                        log.Printf("Using temporary directory as work directory: %s", workDir)
                    } else {
                        // Last resort: use current directory
                        workDir = "."
                        log.Printf("Warning: Using current directory as work directory")
                    }
                }
            } else {
                // If we can't get home directory, use current directory
                workDir = "."
                log.Printf("Warning: Using current directory as work directory")
            }
        }

    service :=  &defaultCRSService {
        tasks:   make(map[string]*models.TaskDetail),
        workDir: workDir,
        competitionClient: competition.NewClient(apiEndpoint, apiKeyID, apiToken),
        status: models.StatusTasksState{
            Pending:    0,
            Processing: 0,
            Waiting:    0,
            Succeeded:  0,
            Failed:     0,
            Errored:    0,
            Canceled:   0,
        },
        povMetadataDir:     "successful_povs",
        povMetadataDir0:     "successful_povs_0",  
        povAdvcancedMetadataDir: "successful_povs_advanced",
        patchWorkDir:       "patch_workspace",
        workerNodes: workerNodes,
        workerBasePort: workerBasePort,
        model: model,
        // Initialize the new fields
        totalTasksDistributed: 0,

        workerStatus:    make(map[int]*WorkerStatus),
        fuzzerToWorkerMap: make(map[string]int),
        taskToWorkersMap: make(map[string][]WorkerFuzzerPair),
    }

        // Initialize worker status for each worker
        for i := 0; i < service.workerNodes; i++ {
            service.workerStatus[i] = &WorkerStatus{
                LastAssignedTime: time.Time{},
                FailureCount:     0,
                BlacklistedUntil: time.Time{},
                AssignedTasks:    0,
            }
        }
        return service
}

// ensureWorkDir creates the work directory if it doesn't exist
func ensureWorkDir(dir string) error {
    // Check if directory exists
    info, err := os.Stat(dir)
    if err == nil {
        // Directory exists, check if it's a directory
        if !info.IsDir() {
            return fmt.Errorf("%s exists but is not a directory", dir)
        }
        
        // Check if we have write permission
        testFile := filepath.Join(dir, ".crs-write-test")
        f, err := os.Create(testFile)
        if err != nil {
            return fmt.Errorf("directory exists but is not writable: %v", err)
        }
        f.Close()
        os.Remove(testFile)
        
        return nil
    }
    
    // Directory doesn't exist, try to create it
    if os.IsNotExist(err) {
        // Create directory with full permissions for the current user
        if err := os.MkdirAll(dir, 0755); err != nil {
            return fmt.Errorf("failed to create directory: %v", err)
        }
        return nil
    }
    
    // Some other error occurred
    return fmt.Errorf("error checking directory: %v", err)
}
// getGitReference returns the current Git reference (commit hash or tag)
func getGitReference() string {
    // First try to read from VERSION file
    versionFile := "./VERSION"
    content, err := os.ReadFile(versionFile)
    if err == nil && len(content) > 0 {
        return strings.TrimSpace(string(content))
    }

    // Try to get the current Git tag first
    cmd := exec.Command("git", "describe", "--tags", "--exact-match", "HEAD")
    output, err := cmd.Output()
    if err == nil && len(output) > 0 {
        // Successfully found a tag
        return strings.TrimSpace(string(output))
    }
    
    // If no tag is found, get the commit hash
    cmd = exec.Command("git", "rev-parse", "--short", "HEAD")
    output, err = cmd.Output()
    if err == nil && len(output) > 0 {
        return strings.TrimSpace(string(output))
    }
    
    // If all else fails, return unknown
    return "unknown"
}
func (s *defaultCRSService) GetStatus() models.Status {
    s.statusMutex.RLock()
    defer s.statusMutex.RUnlock()
    
    // Get the Git reference (commit hash or tag)
    gitRef := getGitReference()
    
    return models.Status{
        Ready: true,
        State: models.StatusState{
            Tasks: s.status,
        },
        Version: "v0.3.0",
        GitRef: gitRef,
    }
}

func (s *defaultCRSService) CancelTask(taskID string) error {
    s.tasksMutex.Lock()
    defer s.tasksMutex.Unlock()
    
    task, exists := s.tasks[taskID]
    if !exists {
        return fmt.Errorf("task %s not found", taskID)
    }
    
    // Update task state
    task.State = models.TaskStateCanceled
    
    // Update status
    s.statusMutex.Lock()
    defer s.statusMutex.Unlock()
    
    // Decrement the appropriate counter based on previous state
    switch task.State {
    case models.TaskStatePending:
        s.status.Pending--
    case models.TaskStateRunning:
        s.status.Processing--
    }
    
    // Increment canceled counter
    s.status.Canceled++
    
    delete(s.tasks, taskID)
    return nil
}
func (s *defaultCRSService) CancelAllTasks() error {
    s.tasksMutex.Lock()
    defer s.tasksMutex.Unlock()
    
    // Update all tasks to canceled
    for _, task := range s.tasks {
        task.State = models.TaskStateCanceled
    }
    
    // Reset the task map
    s.tasks = make(map[string]*models.TaskDetail)
    
    // Update status
    s.statusMutex.Lock()
    defer s.statusMutex.Unlock()
    
    // Reset all counters except canceled
    s.status.Canceled += s.status.Pending + s.status.Processing + s.status.Waiting
    s.status.Pending = 0
    s.status.Processing = 0
    s.status.Waiting = 0
    
    return nil
}
func (s *defaultCRSService) validateTask(task models.Task) error {
    if len(task.Tasks) == 0 {
        return fmt.Errorf("no tasks provided")
    }
    if task.MessageTime == 0 {
        return fmt.Errorf("message_time is required")
    }
    return nil
}

// isCrashOutput determines if the fuzzer output indicates a real crash
func (s *defaultCRSService) isCrashOutput(output string) bool {
    // Check for common crash indicators that always represent errors
    errorIndicators := []string{
        "ERROR: AddressSanitizer:",
        // "ERROR: LeakSanitizer:",
        "ERROR: MemorySanitizer:",
        "WARNING: MemorySanitizer:",
        "ERROR: ThreadSanitizer:",
        "ERROR: UndefinedBehaviorSanitizer:",
        // "ERROR: libFuzzer: timeout", // <-- remove from here
        "SEGV on unknown address",
        "Segmentation fault",
        "AddressSanitizer: heap-buffer-overflow",
        "AddressSanitizer: heap-use-after-free",
        "UndefinedBehaviorSanitizer: undefined-behavior",
        "ERROR: HWAddressSanitizer:",
        "WARNING: ThreadSanitizer:",
        "runtime error:",                     // UBSan generic line
        "AddressSanitizer:DEADLYSIGNAL",
        "libfuzzer exit=1",
        // "libfuzzer exit=99",
        "Java Exception: com.code_intelligence.jazzer",
    }
    if os.Getenv("DETECT_TIMEOUT_CRASH") == "1" {
        errorIndicators = append(errorIndicators, "ERROR: libFuzzer: timeout")
        errorIndicators = append(errorIndicators, "libfuzzer exit=99")
    }

    for _, indicator := range errorIndicators {
        if strings.Contains(output, indicator) {
            return true
        }
    }

    // For MemorySanitizer, we need to be more careful
    if strings.Contains(output, "MemorySanitizer:") {
        // Only count as crash if it's an ERROR, not a WARNING
        // if !strings.Contains(output, "ERROR: MemorySanitizer:") {
        //     return false // It's a warning, not an error
        // }
        
        // Ignore issues in system libraries or fuzzer infrastructure
        ignoredPatterns := []string{
            "in start_thread",
            "in __clone",
            "in fuzzer::",
            "in std::__Fuzzer::",
            "in __msan_",
            "in operator new",
        }
        
        for _, pattern := range ignoredPatterns {
            if strings.Contains(output, pattern) {
                // This is likely an infrastructure issue, not a real crash
                return false
            }
        }
        
        // If we get here, it's a MemorySanitizer error not in the ignored patterns
        return true
    }

    // For ThreadSanitizer, only count ERROR reports, not WARNINGs
    if strings.Contains(output, "ThreadSanitizer:") {
        // if !strings.Contains(output, "ERROR: ThreadSanitizer:") {
        //     return false // It's a warning, not an error
        // }
        
        // Similar to MSAN, ignore infrastructure issues
        ignoredPatterns := []string{
            "in start_thread",
            "in __clone",
            "in fuzzer::",
            "in std::__Fuzzer::",
        }
        
        for _, pattern := range ignoredPatterns {
            if strings.Contains(output, pattern) {
                return false
            }
        }
        
        return true
    }

    // For LeakSanitizer, only count ERROR reports
    // if strings.Contains(output, "LeakSanitizer:") {
    //     if !strings.Contains(output, "ERROR: LeakSanitizer:") {
    //         return false // It's a warning or summary, not an error
    //     }
    //     return true
    // }

    return false
}

func (s *defaultCRSService) readCrashFile(fuzzDir string) []byte {
    // Define the povMetadataDir
    povMetadataDir := filepath.Join(fuzzDir, s.povMetadataDir)
    
    // Search specifically for test_blob_*.bin files
    blobPattern := filepath.Join(povMetadataDir, "test_blob_*.bin")
    // log.Printf("Looking for crash files with pattern: %s", blobPattern)
    
    files, err := filepath.Glob(blobPattern)
    if err != nil {
        log.Printf("Error finding crash files with pattern %s: %v", blobPattern, err)
        return nil
    }
    
    if len(files) == 0 {
        log.Printf("No crash files found matching pattern %s", blobPattern)
        return nil
    }
    
    // Sort files by modification time (newest first)
    sort.Slice(files, func(i, j int) bool {
        iInfo, err := os.Stat(files[i])
        if err != nil {
            return false
        }
        jInfo, err := os.Stat(files[j])
        if err != nil {
            return true
        }
        return iInfo.ModTime().After(jInfo.ModTime())
    })
    
    // Get the newest file
    newestFile := files[0]
    log.Printf("Found crash file: %s", newestFile)
    
    // Read the file
    data, err := os.ReadFile(newestFile)
    if err != nil {
        log.Printf("Error reading crash file %s: %v", newestFile, err)
        return nil
    }
    
    log.Printf("Successfully read crash file, size: %d bytes", len(data))
    return data
}

var (
    workerTaskMutex    sync.Mutex
    activeWorkerTasks  = make(map[string]bool) // Track active task IDs
)

func getAverageCPUUsage() (float64, error) {
    // cpu.Percent returns percent used per CPU, over the interval
    percents, err := cpu.Percent(2*time.Second, true)
    if err != nil {
        return 0, err
    }
    var sum float64
    for _, p := range percents {
        sum += p
    }
    return sum / float64(len(percents)), nil
}

func (s *defaultCRSService) SubmitWorkerTask(task models.WorkerTask) error {
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
        // Optionally, you could choose to reject or accept by default here
    } else {
        log.Printf("Average CPU usage: %.2f%%", avgCPU)
        if avgCPU > 80.0 && s.hasActiveWorkTasks(){
            return fmt.Errorf("system is too busy (CPU usage %.2f%% > 80%%), rejecting new task", avgCPU)
        }
        if avgCPU < 50.0 {
            // Accept the task regardless of taskID
            log.Printf("CPU usage low (%.2f%%), accepting task %s", avgCPU, taskID)
            // No need to check for duplicate taskID
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

func (s *defaultCRSService) startWorkerTask(td models.TaskDetail, task models.WorkerTask, taskID string) {
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

    // Process the task
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

func (s *defaultCRSService) hasActiveWorkTasks() bool {
    workerTaskMutex.Lock()
    defer workerTaskMutex.Unlock()

    return len(activeWorkerTasks) > 0
}

func (s *defaultCRSService) IsWorkerBusy() (bool, []string) {
    workerTaskMutex.Lock()
    defer workerTaskMutex.Unlock()

    var activeIDs []string
    for taskID := range activeWorkerTasks {
        activeIDs = append(activeIDs, taskID)
    }
    return len(activeWorkerTasks) > 0, activeIDs
}

func (s *defaultCRSService) SubmitLocalTask(taskDir string) error {
    myFuzzer := ""
    // --- ensure LOCAL_TEST mode is enabled ---
    if os.Getenv("LOCAL_TEST") == "" {
        log.Printf("Setting LOCAL_TEST to 1")
        _ = os.Setenv("LOCAL_TEST", "1")
    }
    
    //----------------------------------------------------------
    // Locate and load task_detail*.json (if present)
    //----------------------------------------------------------
    var (
        taskDetail models.TaskDetail
        jsonFound  bool
    )

    walkErr := filepath.WalkDir(taskDir, func(p string, d fs.DirEntry, err error) error {
        if err != nil || d.IsDir() {
            return nil // Skip errors & directories
        }

        name := d.Name()
        if strings.HasPrefix(name, "task_detail") && strings.HasSuffix(name, ".json") {
            data, rdErr := os.ReadFile(p)
            if rdErr != nil {
                log.Printf("Failed to read %s: %v (continuing search)", p, rdErr)
                return nil
            }
            if umErr := json.Unmarshal(data, &taskDetail); umErr != nil {
                log.Printf("Failed to unmarshal %s: %v (continuing search)", p, umErr)
                return nil
            }
            // log.Printf("Loaded task detail from %s", p)
            jsonFound = true
            return filepath.SkipDir // Stop walking once we succeed
        }
        return nil
    })
    if walkErr != nil {
        log.Printf("Directory walk error: %v", walkErr)
    }

	// Fallback to stub when JSON isn’t found / can’t be parsed
	if !jsonFound {
		log.Printf("No valid task_detail.json found – falling back to default task detail")

		projectName := "test"
		focusName := "test"

		projectsDir := filepath.Join(taskDir, "fuzz-tooling/projects/")
		files, err := os.ReadDir(projectsDir)
		if err == nil {
			for _, file := range files {
				if file.IsDir() {
					projectName = file.Name()
					focusName = "afc-" + projectName
					log.Printf("Found project '%s' in fuzz-tooling/projects, setting focus to '%s'", projectName, focusName)
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
			Deadline:          time.Now().Add(time.Hour).Unix(),
			HarnessesIncluded: true,
			Metadata:          make(map[string]string),
		}

        log.Printf("Completed Task Detail, setting task detail to %v", taskDetail)

        // save task detail to file, project_name.json
        taskDetailFile := path.Join(taskDir, "task_detail.json")
        if err := os.WriteFile(taskDetailFile, []byte(taskDetail.String()), 0644); err != nil {
            log.Printf("Failed to save task detail to file: %v", err)
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
    dockerfilePath := path.Join(absTaskDir, "fuzz-tooling/projects",taskDetail.ProjectName)
    dockerfileFullPath := path.Join(dockerfilePath, "Dockerfile")
    fuzzerDir := path.Join(taskDir, "fuzz-tooling/build/out", taskDetail.ProjectName)

    log.Printf("Project dir: %s", projectDir)
    log.Printf("Dockerfile: %s", dockerfileFullPath)

    cfg, sanitizerDirs, err := s.prepareTaskEnvironment(
        &myFuzzer,
        taskDir,
        taskDetail,
        dockerfilePath,
        dockerfileFullPath,
        fuzzerDir,
        projectDir,
    )
    if err != nil {
        return err // Or handle the error however you were before
    }

    // Collect all fuzzers from all sanitizer builds and run them in parallel
    log.Printf("-------------------- Collecting all fuzzers ----------------------")
    var allFuzzers []string
    sanitizerDirsCopy := make([]string, len(sanitizerDirs))
    copy(sanitizerDirsCopy, sanitizerDirs)
    
    // Now use the copy to find fuzzers
    for _, sdir := range sanitizerDirsCopy {
        fuzzers, err := s.findFuzzers(sdir)
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

    //TODO: skip memory and undefined sanitizers if too many fuzzers
    // keep only address sanitizer
    const MAX_FUZZERS = 10
    if true {
        var allFilteredFuzzers []string
        for _, fuzzerPath := range allFuzzers {
            if strings.Contains(fuzzerPath, "-address/") || (strings.Contains(fuzzerPath, "-memory/") && len(allFuzzers) < MAX_FUZZERS) {
                allFilteredFuzzers = append(allFilteredFuzzers, fuzzerPath)
            }
        }
        allFuzzers = sortFuzzersByGroup(allFilteredFuzzers)
    }

    // log.Printf("Sorted fuzzers: %v", allFuzzers)
    log.Printf("Found %d fuzzers: %v", len(allFuzzers), allFuzzers)

    fullTask := models.Task{
        MessageID:   uuid.New(),
        MessageTime: time.Now().UnixMilli(),
        Tasks:       []models.TaskDetail{taskDetail},
    }

    // Process the task based on its type
    if err := s.runFuzzing(myFuzzer,taskDir, taskDetail, fullTask, cfg, allFuzzers); err != nil {
        log.Printf("Processing task %s: %v fuzzer: %s", taskDetail.TaskID, err, myFuzzer)
    }

    return nil
}


func (s *defaultCRSService) SubmitTask(task models.Task) error {
    // Validate task
    if err := s.validateTask(task); err != nil {
        return err
    }

    // Update status with new pending tasks
    s.statusMutex.Lock()
    s.status.Pending += len(task.Tasks)
    s.statusMutex.Unlock()

    // Process each task
    for _, taskDetail := range task.Tasks {
        // Store task
        s.tasksMutex.Lock()
        taskDetail.State = models.TaskStatePending
        s.tasks[taskDetail.TaskID.String()] = &taskDetail
        s.tasksMutex.Unlock()

        // Process task asynchronously
        go func(td models.TaskDetail) {

            //TODO: for unharnessed tasks, set fuzzer to "UNHARNESSED" and send to a worker directly
            //Worker will try to synthesize a harness
            if !taskDetail.HarnessesIncluded {
                allFuzzers:= []string{UNHARNESSED}
                s.distributeFuzzers(allFuzzers,taskDetail,task)

            } else if err := s.processTask("",td, task); err != nil {
                log.Printf("Error processing task %s: %v", td.TaskID, err)
                
                // Update task state
                s.tasksMutex.Lock()
                if task, exists := s.tasks[td.TaskID.String()]; exists {
                    task.State = models.TaskStateErrored
                }
                s.status.Errored++
                s.tasksMutex.Unlock()
            }
        }(taskDetail)
    }

    return nil
}

var (
    dirMutexes = sync.Map{}
    sanitizerDirsMutex sync.Mutex
)

// Helper function to get or create a mutex for a specific directory
func getDirMutex(dir string) *sync.Mutex {
    key := filepath.Clean(dir)
    actual, _ := dirMutexes.LoadOrStore(key, &sync.Mutex{})
    return actual.(*sync.Mutex)
}


func BuildAFCFuzzers(taskDir string, sanitizer, projectName, projectDir, sanitizerDir string) (string, error) {
    // ***** NEW: give every build its own out/work dirs *****
    buildRoot   := filepath.Join(taskDir, "fuzz-tooling", "build")
    uniqOutDir  := filepath.Join(buildRoot, "out",  fmt.Sprintf("%s-%s", projectName, sanitizer))
    uniqWorkDir := filepath.Join(buildRoot, "work", fmt.Sprintf("%s-%s", projectName, sanitizer))

    // Make sure they exist.
    if err := os.MkdirAll(uniqOutDir, 0o755); err != nil {
        return "", fmt.Errorf("mkdir %s: %w", uniqOutDir, err)
    }
    if err := os.MkdirAll(uniqWorkDir, 0o755); err != nil {
        return "", fmt.Errorf("mkdir %s: %w", uniqWorkDir, err)
    }

    // The helper script mounts …/out/<project> → /out (and the same for work).
    // Replace those locations with symlinks that point to our per-sanitizer dirs,
    // *holding an exclusive lock while we do so* to avoid concurrent swaps.
    linkOut  := filepath.Join(buildRoot, "out",  projectName)
    linkWork := filepath.Join(buildRoot, "work", projectName)
    lockFile := filepath.Join(buildRoot, fmt.Sprintf("%s.lock", projectName))
    lk, err  := os.OpenFile(lockFile, os.O_CREATE|os.O_RDWR, 0o600)
    if err != nil {
        return "", fmt.Errorf("open lock: %w", err)
    }
    defer lk.Close()
    if err := syscall.Flock(int(lk.Fd()), syscall.LOCK_EX); err != nil {
        return "", fmt.Errorf("flock: %w", err)
    }
    // ----- critical section -----
    _ = os.RemoveAll(linkOut)
    _ = os.RemoveAll(linkWork)
    if err := os.Symlink(uniqOutDir, linkOut); err != nil {
        return "", fmt.Errorf("symlink(out): %w", err)
    }
    if err := os.Symlink(uniqWorkDir, linkWork); err != nil {
        return "", fmt.Errorf("symlink(work): %w", err)
    }
    // ----- end critical section -----
    defer syscall.Flock(int(lk.Fd()), syscall.LOCK_UN)

    // -------------------------------------------------------

    helperCmd := exec.Command("python3",
        filepath.Join(taskDir, "fuzz-tooling/infra/helper.py"),
        "build_fuzzers",
        "--clean",
        "--sanitizer", sanitizer,
        "--engine", "libfuzzer",
        projectName,
        projectDir,
    )
    
    var cmdOutput bytes.Buffer
    helperCmd.Stdout = &cmdOutput
    helperCmd.Stderr = &cmdOutput
    
    log.Printf("[BuildAFCFuzzers] Building fuzzers for %s %s sanitizer\nCommand: %v", projectName,sanitizer, helperCmd.Args)
    
    if err := helperCmd.Run(); err != nil {
        output := cmdOutput.String()
        lines := strings.Split(output, "\n")
        
        // Truncate output if it's very long
        if len(lines) > 30 {
            firstLines := lines[:10]
            lastLines := lines[len(lines)-20:]
            
            truncatedOutput := strings.Join(firstLines, "\n") + 
                "\n\n[...TRUNCATED " + fmt.Sprintf("%d", len(lines)-30) + " LINES...]\n\n" + 
                strings.Join(lastLines, "\n")
            
            output = truncatedOutput
        }
        
        return output, err
    }

    return cmdOutput.String(), nil
}

func BuildAFCFuzzers0(taskDir string, sanitizer, projectName, projectDir, sanitizerDir string) (string, error) {
    // Build the command to run helper.py
    // python3 infra/helper.py build_fuzzers --clean --sanitizer sanitizer --engine "libfuzzer" taskDetail.ProjectName sanitizerProjectDir

    helperCmd := exec.Command("python3",
        filepath.Join(taskDir, "fuzz-tooling/infra/helper.py"),
        "build_fuzzers",
        "--clean",
        "--sanitizer", sanitizer,
        "--engine", "libfuzzer",
        projectName,
        projectDir,
    )
    
    var cmdOutput bytes.Buffer
    helperCmd.Stdout = &cmdOutput
    helperCmd.Stderr = &cmdOutput
    
    log.Printf("[BuildAFCFuzzers] Building fuzzers for %s %s sanitizer\nCommand: %v", projectName,sanitizer, helperCmd.Args)
    
    if err := helperCmd.Run(); err != nil {
        output := cmdOutput.String()
        lines := strings.Split(output, "\n")
        
        // Truncate output if it's very long
        if len(lines) > 30 {
            firstLines := lines[:10]
            lastLines := lines[len(lines)-20:]
            
            truncatedOutput := strings.Join(firstLines, "\n") + 
                "\n\n[...TRUNCATED " + fmt.Sprintf("%d", len(lines)-30) + " LINES...]\n\n" + 
                strings.Join(lastLines, "\n")
            
            output = truncatedOutput
        }
        
        return output, err
    }

    //TODO: copy outDir to sanitizerDir
    outDir := filepath.Join(taskDir, "fuzz-tooling", "build", "out", projectName)
    if err := robustCopyDir(outDir, sanitizerDir); err != nil {
        log.Printf("[BuildAFCFuzzers] failed to copy fuzzer files: outDir %s %v", outDir, err)
    } else {
        log.Printf("[BuildAFCFuzzers] fuzzer files copied to %s", sanitizerDir)
    }

    return cmdOutput.String(), nil
}

// PullAFCDockerImage runs the helper.py script to build and pull Docker images for the project
func PullAFCDockerImage(taskDir string, projectName string) (string, error) {
    // Build the command to run helper.py
    helperCmd := exec.Command("python3",
        filepath.Join(taskDir, "fuzz-tooling/infra/helper.py"),
        "build_image",
        "--pull",
        projectName,
    )
    
    var cmdOutput bytes.Buffer
    helperCmd.Stdout = &cmdOutput
    helperCmd.Stderr = &cmdOutput
    
    log.Printf("Building and pulling Docker images for %s\nCommand: %v", projectName, helperCmd.Args)
    
    if err := helperCmd.Run(); err != nil {
        output := cmdOutput.String()
        lines := strings.Split(output, "\n")
        
        // Truncate output if it's very long
        if len(lines) > 30 {
            firstLines := lines[:10]
            lastLines := lines[len(lines)-20:]
            
            truncatedOutput := strings.Join(firstLines, "\n") + 
                "\n\n[...TRUNCATED " + fmt.Sprintf("%d", len(lines)-30) + " LINES...]\n\n" + 
                strings.Join(lastLines, "\n")
            
            output = truncatedOutput
        }
        
        return output, err
    }
    
    dstImage := fmt.Sprintf("aixcc-afc/%s", projectName)
    // Check if dstImage already exists
    checkDstCmd := exec.Command("docker", "image", "inspect", dstImage)
    if err := checkDstCmd.Run(); err != nil {

        // Tag the image as aixcc-afc/<projectName>
        srcImage := fmt.Sprintf("gcr.io/oss-fuzz/%s", projectName)

        // Check if srcImage exists
        checkSrcCmd := exec.Command("docker", "image", "inspect", srcImage)
        if err := checkSrcCmd.Run(); err != nil {
            log.Printf("Source image %s does not exist, cannot tag.", srcImage)
            return cmdOutput.String() + "\nSource image does not exist.", fmt.Errorf("source image %s does not exist", srcImage)
        }

        tagCmd := exec.Command("docker", "tag", srcImage, dstImage)
        var tagOutput bytes.Buffer
        tagCmd.Stdout = &tagOutput
        tagCmd.Stderr = &tagOutput
        if err := tagCmd.Run(); err != nil {
            log.Printf("Failed to tag image: %s -> %s\nOutput: %s", srcImage, dstImage, tagOutput.String())
            return cmdOutput.String() + "\n" + tagOutput.String(), err
        }
        log.Printf("Tagged image as %s", dstImage)
    }

    return cmdOutput.String(), nil
}

// dirExists reports whether path exists and is a directory.
func dirExists(p string) bool {
    info, err := os.Stat(p)
    if err != nil {
        return false
    }
    return info.IsDir()
}
    
// fileExists reports whether path exists and is a regular file.
func fileExists(p string) bool {
    info, err := os.Stat(p)
    if err != nil {
        return false
    }
    return !info.IsDir()
}

// prepareTaskEnvironment handles all task directory setup, source extraction, and fuzzer builds.
// It returns the sanitizer directories and project configuration.
func (s *defaultCRSService) prepareTaskEnvironment0(
    myFuzzer *string,
    taskDir string,
    taskDetail models.TaskDetail,
    dockerfilePath string,
    dockerfileFullPath string,
    fuzzerDir string,
    projectDir string,
) (*ProjectConfig, []string, error) {
    var cfg *ProjectConfig
    var sanitizerDirs []string
    
    // Get a mutex specific to this task directory
    mutex := getDirMutex(taskDir)
    
    // Lock the mutex to prevent race conditions
    mutex.Lock()
    
    // We'll handle unlocking explicitly, not with defer
    
    // Check if directory exists
    _, err := os.Stat(taskDir)
    taskDirExists := !os.IsNotExist(err)
    
    if !taskDirExists {
        defer func() {
            // Clean up the mutex if we're done with it and created a new directory
            dirMutexes.Delete(filepath.Clean(taskDir))
        }()
        
        // Now create the directory with the unique name
        if err := os.MkdirAll(taskDir, 0755); err != nil {
            mutex.Unlock() // Unlock before returning error
            return nil, nil, fmt.Errorf("failed to create task directory: %v", err)
        }

        log.Printf("Created task directory: %s", taskDir)

        //for workers, save a copy under taskDir
        if *myFuzzer != "" {
            saveTaskDetailToJson(taskDetail,*myFuzzer,taskDir)
        }

        // Download and process sources
        for _, source := range taskDetail.Source {
            if len(source.URL) > 0 {
                if err := s.downloadAndVerifySource(taskDir, source); err != nil {
                    mutex.Unlock() // Unlock before returning error
                    return nil, nil, fmt.Errorf("failed to download source %s: %v", source.Type, err)
                }
            }
        }
        
        is_delta := (taskDetail.Type == "delta")
        // 1. Extract archives first
        if err := s.extractSources(taskDir, is_delta); err != nil {
            mutex.Unlock() // Unlock before returning error
            return nil, nil, fmt.Errorf("failed to extract sources: %v", err)
        }
        
        if is_delta {
            // 1. Extract and analyze diff
            diffPath := filepath.Join(taskDir, "diff", "ref.diff")
            analyzeDiff(taskDetail, diffPath)
            // Find the correct directory to apply the diff
            applyCmd := exec.Command("git", "apply", diffPath)
            applyCmd.Dir = projectDir  // Use projectDir instead of taskDir
            
            var applyOutput bytes.Buffer
            applyCmd.Stdout = &applyOutput
            applyCmd.Stderr = &applyOutput
            
            log.Printf("Applying diff in directory: %s", applyCmd.Dir)
            
            if err := applyCmd.Run(); err != nil {
                log.Printf("Git apply failed, trying standard patch command instead...")
                
                // Reset the output buffer
                applyOutput.Reset()
                
                // Try using the standard patch command instead
                patchCmd := exec.Command("patch", "-p1", "-i", diffPath)
                patchCmd.Dir = projectDir
                patchCmd.Stdout = &applyOutput
                patchCmd.Stderr = &applyOutput
                
                if patchErr := patchCmd.Run(); patchErr != nil {
                    // Try to list files in the directory to debug
                    log.Printf("Directory contents of %s:", applyCmd.Dir)
                    files, _ := os.ReadDir(applyCmd.Dir)
                    for _, file := range files {
                        log.Printf("  %s", file.Name())
                    }
                    
                    log.Printf("Git apply and patch command both failed.\nGit apply output:\n%s\nPatch output:\n%s", 
                            err.Error(), applyOutput.String())
                    mutex.Unlock() // Unlock before returning error
                    return nil, nil, fmt.Errorf("failed to apply diff with both git apply and patch: %v\nOutput: %s", 
                                    patchErr, applyOutput.String())
                }
                
                log.Printf("Successfully applied diff using standard patch command to %s", patchCmd.Dir)
            } else {
                log.Printf("Successfully applied diff using git apply to %s", applyCmd.Dir)
            }
        }
            
        if false {
            buildOutput, err := PullAFCDockerImage(taskDir, taskDetail.ProjectName) 
            if err != nil {
                log.Printf("Docker image pull build failed: %s", buildOutput)
                log.Printf("Trying Docker build instead: %s", dockerfileFullPath)

                // build docker image for the project
                buildCmd := exec.Command("docker", 
                    "build",
                    "--no-cache",
                    "-t", "aixcc-afc/"+taskDetail.ProjectName,
                    "--file", dockerfileFullPath,  
                    dockerfilePath,
                )
                var buildOutput bytes.Buffer
                buildCmd.Stdout = &buildOutput
                buildCmd.Stderr = &buildOutput

                log.Printf("Building docker image aixcc-afc/%s\nbuildCmd: %v\n", taskDetail.ProjectName,buildCmd)
                
                if err := buildCmd.Run(); err != nil {
                    log.Printf("Docker build output:\n%s", buildOutput.String())
                    mutex.Unlock() // Unlock before returning error
                    return nil, nil, fmt.Errorf("failed to build Docker image: %v\nOutput: %s", err, buildOutput.String())
                }
            }
        } else {

                // Make sure dockerfilePath exists
                if os.Getenv("LOCAL_TEST") != "" {
                    //TODO if dockerfilePath does not exist, if taskDetail.ProjectName == integration-test
                    //copy /datadrive/FUZZ/oss-fuzz-aixcc/projects/integration-test to dockerfilePath
                    if _, err := os.Stat(dockerfilePath); os.IsNotExist(err) &&
                        taskDetail.ProjectName == "integration-test" {

                        srcPath := "/datadrive/FUZZ/oss-fuzz-aixcc/projects/integration-test"
                        log.Printf("[LOCAL_TEST] dockerfilePath %s missing – copying from %s", dockerfilePath, srcPath)

                        if err := robustCopyDir(srcPath, dockerfilePath); err != nil {
                            log.Printf("[LOCAL_TEST] failed to copy integration-test files: %v", err)
                        } else {
                            log.Printf("[LOCAL_TEST] integration-test files copied to %s", dockerfilePath)
                        }
                    }
                }
            
            //IMPORTANT - we must build it successfully
            //for unharnessed tasks, projects folder is not present, let's try oss-fuzz/projects
            if !taskDetail.HarnessesIncluded || !fileExists(dockerfileFullPath){
               if !fileExists(dockerfileFullPath) {
                    cloneOssFuzzAndMainRepoOnce(taskDir,taskDetail.ProjectName, fuzzerDir)
                    dockerfilePath_x := path.Join(taskDir, "oss-fuzz/projects",taskDetail.ProjectName)
                    if dirExists(dockerfilePath_x) {
                        dockerfilePath = dockerfilePath_x
                        dockerfileFullPath = path.Join(dockerfilePath_x, "Dockerfile")
                    } else {
                        log.Printf("Failed to clone oss-fuzz and main repo for unharnessed task %s %s", taskDetail.ProjectName, taskDetail.TaskID)
                        
                        if  taskDetail.ProjectName == "integration-test" {
                            srcPath := "/app/strategy/jeff/integration-test"
                            log.Printf("[INTEGRATION_TEST] dockerfilePath %s missing – copying from %s", dockerfilePath, srcPath)

                            if err := robustCopyDir(srcPath, dockerfilePath); err != nil {
                                log.Printf("[INTEGRATION_TEST] failed to copy integration-test files: %v", err)
                            } else {
                                log.Printf("[INTEGRATION_TEST] integration-test files copied to %s", dockerfilePath)
                            }

                            if err := robustCopyDir(srcPath, dockerfilePath_x); err != nil {
                                log.Printf("[INTEGRATION_TEST] failed to copy integration-test files: %v", err)
                            } else {
                                log.Printf("[INTEGRATION_TEST] integration-test files copied to %s", dockerfilePath_x)
                            }
                        }
                    }
                } else {
                    log.Printf("[HarnessesIncluded: %t] dockerfileFullPath NOT exists %s", taskDetail.HarnessesIncluded, dockerfileFullPath)
                }
            } else {
                log.Printf("[HarnessesIncluded: %t] dockerfileFullPath %s", taskDetail.HarnessesIncluded, dockerfileFullPath)
            }

            if !fileExists(dockerfileFullPath) {
                log.Printf("[HarnessesIncluded: %t] dockerfileFullPath does not exist: %s", taskDetail.HarnessesIncluded, dockerfileFullPath)
                return nil, nil, fmt.Errorf("DockerfileFullPath does not exist: %s", dockerfileFullPath)
            }

            maxAttempts := 5
            for attempt := 1; attempt <= maxAttempts; attempt++ {
                // build docker image for the project
                buildCmd := exec.Command("docker", 
                    "build",
                    "--no-cache",
                    "-t", "aixcc-afc/"+taskDetail.ProjectName,
                    "--file", dockerfileFullPath,  
                    dockerfilePath,
                    )
                var buildOutput bytes.Buffer
                buildCmd.Stdout = &buildOutput
                buildCmd.Stderr = &buildOutput

                log.Printf("Building docker image aixcc-afc/%s (attempt=%d)\nbuildCmd: %v\n", taskDetail.ProjectName,attempt,buildCmd)
                
                if err := buildCmd.Run(); err != nil {
                    log.Printf("Docker build failed. Output:\n%s", buildOutput.String())
                    log.Printf("Try building with PullAFCDockerImage")
                    buildOutputAFC, err := PullAFCDockerImage(taskDir, taskDetail.ProjectName) 
                    if err != nil {
                        log.Printf("Building with PullAFCDockerImage failed too (attempt=%d). buildOutputAFC:\n%s",attempt,buildOutputAFC)
                        if attempt == maxAttempts {
                            mutex.Unlock() // Unlock before returning error
                            return nil, nil, fmt.Errorf("Failed to build Docker image: %v\nOutput: %s", err, buildOutputAFC)
                        }
                        // Wait before retrying
                        time.Sleep(2 * time.Second)
                        continue
                    }
                    break
                }
                break
            }
        }
    }

    // These operations don't need the lock anymore
    projectYAMLPath := filepath.Join(dockerfilePath, "project.yaml")
    cfg, err = loadProjectConfig(projectYAMLPath)
    if err != nil {
        log.Printf("Warning: Could not parse project.yaml (%v). Defaulting to address sanitizer.", err)
        cfg = &ProjectConfig{Sanitizers: []string{"address"}}
    }
    if len(cfg.Sanitizers) == 0 {
        log.Printf("No sanitizers listed in project.yaml; defaulting to address sanitizer.")
        cfg.Sanitizers = []string{"address"}
    }

    if !taskDirExists {
        // 3. Build fuzzers
        var wg sync.WaitGroup
        // For each sanitizer in the YAML, run build_fuzzers
        for _, sanitizer := range cfg.Sanitizers {
            //skip undefined
            if sanitizer == "undefined" {
                continue
            }
            if *myFuzzer != "" && *myFuzzer !=UNHARNESSED && !strings.Contains(*myFuzzer, sanitizer) {
                continue
            }

            sanitizerDir := fuzzerDir + "-" + sanitizer
            // Keep track of each sanitizer's output path
            sanitizerDirs = append(sanitizerDirs, sanitizerDir)
            // Capture loop variables
            san := sanitizer
            sanDir := sanitizerDir
            wg.Add(1)
            go func() {
                defer wg.Done()
                log.Printf("Building fuzzers with --sanitizer=%s", san)
                if err := s.buildFuzzersDocker(myFuzzer, taskDir, projectDir, sanDir, san, cfg.Language, taskDetail); err != nil {
                    log.Printf("Error building fuzzers for sanitizer %s: %v", san, err)
                    // We're ignoring errors here, which is not ideal
                }
            }()  
        }

        //coverage for C worker fuzzers
        if os.Getenv("LOCAL_TEST") != "" || *myFuzzer != "" {
            lang := strings.ToLower(cfg.Language)
            if lang == "c" || lang == "c++" {
                wg.Add(1)
                go func() {
                    defer wg.Done()
                    san := "coverage"
                    sanDir := fuzzerDir
                    log.Printf("Building fuzzers with --sanitizer=%s", san)
                    if err := s.buildFuzzersDocker(myFuzzer, taskDir, projectDir, sanDir, san, cfg.Language, taskDetail); err != nil {
                        log.Printf("Error building fuzzers for sanitizer %s: %v", san, err)
                        // We're ignoring errors here, which is not ideal
                    }
                }()  
            }
        }
        // Wait for all builds to complete
        wg.Wait()
    } else {
        // Directory already exists, just populate sanitizerDirs
        for _, sanitizer := range cfg.Sanitizers {
            sanitizerDir := fuzzerDir + "-" + sanitizer
            // Keep track of each sanitizer's output path
            sanitizerDirs = append(sanitizerDirs, sanitizerDir)
        }
    }
    
    mutex.Unlock()

    return cfg, sanitizerDirs, nil
}

func (s *defaultCRSService) prepareTaskEnvironment(
	myFuzzer *string,
	taskDir string,
	taskDetail models.TaskDetail,
	dockerfilePath string,
	dockerfileFullPath string,
	fuzzerDir string,
	projectDir string,
) (*ProjectConfig, []string, error) {
	var cfg *ProjectConfig
	var sanitizerDirs []string

	projectYAMLPath := filepath.Join(dockerfilePath, "project.yaml")
	cfg, err := loadProjectConfig(projectYAMLPath)
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
		if *myFuzzer != "" && *myFuzzer != UNHARNESSED && !strings.Contains(*myFuzzer, sanitizer) {
			continue
		}
		sanitizerDir := fuzzerDir + "-" + sanitizer
		sanitizerDirs = append(sanitizerDirs, sanitizerDir)

        log.Printf("fuzzerDir: %s", fuzzerDir)
        log.Printf("sanitizerDir: %s", sanitizerDir)

		fuzzers, _ := s.findFuzzers(sanitizerDir)
		// if err != nil {
		// 	log.Printf("Warning: problem trying to find fuzzers in %s: %v", sanitizerDir, err)
		// }
		if len(fuzzers) == 0 {
            log.Printf("-------------------- Building fuzzers ----------------------")
			log.Printf("No fuzzers found in %s for sanitizer %s. Building...", sanitizerDir, sanitizer)
			if err := s.buildFuzzersDocker(myFuzzer, taskDir, projectDir, sanitizerDir, sanitizer, cfg.Language, taskDetail); err != nil {
				log.Printf("Error building fuzzers for sanitizer %s: %v", sanitizer, err)
			}
		} else {
			log.Printf("Found %d fuzzers in %s. Skipping build.", len(fuzzers), sanitizerDir)
		}
	}

	// Coverage for C/C++ worker fuzzers
	if os.Getenv("LOCAL_TEST") != "" || *myFuzzer != "" {
		lang := strings.ToLower(cfg.Language)
		if lang == "c" || lang == "c++" {
			san := "coverage"
			sanDir := fuzzerDir
			fuzzers, err := s.findFuzzers(sanDir)
			if err != nil {
				log.Printf("Warning: problem trying to find coverage fuzzers in %s: %v", sanDir, err)
			}

			if len(fuzzers) == 0 {
				log.Printf("Building fuzzers with --sanitizer=%s", san)
				if err := s.buildFuzzersDocker(myFuzzer, taskDir, projectDir, sanDir, san, cfg.Language, taskDetail); err != nil {
					log.Printf("Error building fuzzers for sanitizer %s: %v", san, err)
				}
			} else {
				log.Printf("Found %d coverage fuzzers in %s. Skipping build.", len(fuzzers), sanDir)
			}
		}
	}

	return cfg, sanitizerDirs, nil
}    
func (s *defaultCRSService) processTask(myFuzzer string, taskDetail models.TaskDetail, fullTask models.Task) error {
    taskID := taskDetail.TaskID.String()
    log.Printf("Processing task %s", taskID)
    
    // Update task state to running
    s.tasksMutex.Lock()
    if task, exists := s.tasks[taskID]; exists {
        task.State = models.TaskStateRunning
    }
    s.tasksMutex.Unlock()
    
    // Update status
    s.statusMutex.Lock()
    s.status.Pending--
    s.status.Processing++
    s.statusMutex.Unlock()
    
    // Create task directory with unique name 
    timestamp := time.Now().Format("20060102-150405")
    taskDir := path.Join(s.workDir, fmt.Sprintf("%s-%s", taskID, timestamp))

    // If fuzzer path is provided, use its parent directory up to fuzz-tooling/build/out
    if myFuzzer != "" {
        // Find the index of "fuzz-tooling/build/out" in the fuzzer path
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
    dockerfilePath := path.Join(absTaskDir, "fuzz-tooling/projects",taskDetail.ProjectName)
    dockerfileFullPath := path.Join(dockerfilePath, "Dockerfile")
    fuzzerDir := path.Join(taskDir, "fuzz-tooling/build/out", taskDetail.ProjectName)

    log.Printf("Project dir: %s", projectDir)
    log.Printf("Dockerfile: %s", dockerfileFullPath)

    cfg, sanitizerDirs, err := s.prepareTaskEnvironment(
        &myFuzzer,
        taskDir,
        taskDetail,
        dockerfilePath,
        dockerfileFullPath,
        fuzzerDir,
        projectDir,
    )
    if err != nil {
        return err // Or handle the error however you were before
    }

    // Collect all fuzzers from all sanitizer builds and run them in parallel
    var allFuzzers []string
    // Make a thread-safe copy of the sanitizer directories
    sanitizerDirsMutex.Lock()
    sanitizerDirsCopy := make([]string, len(sanitizerDirs))
    copy(sanitizerDirsCopy, sanitizerDirs)
    sanitizerDirsMutex.Unlock()
    
    // Now use the copy to find fuzzers
    for _, sdir := range sanitizerDirsCopy {
        fuzzers, err := s.findFuzzers(sdir)
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

    //TODO: skip memory and undefined sanitizers if too many fuzzers
    // keep only address sanitizer
    const MAX_FUZZERS = 10
    if true {
        var allFilteredFuzzers []string
        for _, fuzzerPath := range allFuzzers {
            if strings.Contains(fuzzerPath, "-address/") || (strings.Contains(fuzzerPath, "-memory/") && len(allFuzzers) < MAX_FUZZERS) {
                allFilteredFuzzers = append(allFilteredFuzzers, fuzzerPath)
            }
        }
        allFuzzers = sortFuzzersByGroup(allFilteredFuzzers)
    }

    // log.Printf("Sorted fuzzers: %v", allFuzzers)
    log.Printf("Found %d fuzzers: %v", len(allFuzzers), allFuzzers)

    // Process the task based on its type
    if err := s.runFuzzing(myFuzzer,taskDir, taskDetail, fullTask, cfg, allFuzzers); err != nil {
        log.Printf("Processing task %s: %v fuzzer: %s", taskDetail.TaskID, err, myFuzzer)
    }

    // Update task state to succeeded
    s.tasksMutex.Lock()
    if task, exists := s.tasks[taskID]; exists {
        task.State = models.TaskStateSucceeded
    }
    s.tasksMutex.Unlock()
    
    // Update status
    s.statusMutex.Lock()
    s.status.Processing--
    s.status.Succeeded++
    s.statusMutex.Unlock()
    
    return nil
}

func sortFuzzersByGroup(allFuzzers []string) []string {
    if true {
        //skip random
        return allFuzzers
    }

	var address, undefined, memory []string

	for _, f := range allFuzzers {
		switch {
		case strings.Contains(f, "-address/"):
			address = append(address, f)
		case strings.Contains(f, "-undefined/"):
			undefined = append(undefined, f)
		case strings.Contains(f, "-memory/"):
			memory = append(memory, f)
		}
	}

	// Shuffle each group for random order
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(address), func(i, j int) { address[i], address[j] = address[j], address[i] })
	rand.Shuffle(len(undefined), func(i, j int) { undefined[i], undefined[j] = undefined[j], undefined[i] })
	rand.Shuffle(len(memory), func(i, j int) { memory[i], memory[j] = memory[j], memory[i] })

	// Concatenate in the desired order
	return append(append(address, undefined...), memory...)
}

func (s *defaultCRSService) forwardSarifBroadcast(sarifBroadcast models.SARIFBroadcast) error {

    taskJSON, err := json.Marshal(sarifBroadcast)
    if err != nil {
        log.Printf("Error processing taskJSON: %v", err)
        return err
    }
    // Send the broadcast
    url := fmt.Sprintf("%s/sarifx/", s.submissionEndpoint)
    resp, err := http.Post(url, "application/json", bytes.NewBuffer(taskJSON))
    if err != nil {
        log.Printf("Error sending request: %v", err)
        return err
    }
    defer resp.Body.Close()

    // Read response
    respBody, err := io.ReadAll(resp.Body)
    if err != nil {
        log.Printf("Error reading response: %v", err)
        return err
    }

    // Print response
    fmt.Printf("\nResponse from server (status %d):\n", resp.StatusCode)

    // Format JSON response if possible
    var prettyJSON bytes.Buffer
    err = json.Indent(&prettyJSON, respBody, "", "  ")
    if err != nil {
        // Not valid JSON, print as-is
        fmt.Println(string(respBody))
    } else {
        fmt.Println(prettyJSON.String())
    }

    log.Printf("Successfully forwarded sarifBroadcast to the submission server: message id %s", sarifBroadcast.MessageID)
    return nil
}

func (s *defaultCRSService) SubmitSarif(sarifBroadcast models.SARIFBroadcast) error {

    go s.forwardSarifBroadcast(sarifBroadcast)

    // Process each SARIF broadcast
    for _, broadcast := range sarifBroadcast.Broadcasts {
        taskID := broadcast.TaskID.String()
        
        // Check if this is for one of our tasks
        s.tasksMutex.RLock()
        _, exists := s.tasks[taskID]
        s.tasksMutex.RUnlock()
        
        if !exists {
            log.Printf("Received SARIF for unknown task: %s", taskID)
            // continue
        }
        
        // Process the SARIF report
        if err := s.processSarif(taskID, broadcast); err != nil {
            log.Printf("Error processing SARIF for task %s: %v", taskID, err)
            continue
        }
    }
    
    return nil
}

// extractSarifData extracts the relevant data from the SARIF report
func extractSarifData(sarifInterface interface{}) (map[string]interface{}, error) {
    sarifData, ok := sarifInterface.(map[string]interface{})
    if !ok {
        return nil, fmt.Errorf("invalid SARIF data format")
    }
    
    return sarifData, nil
}

// getSourceCode retrieves the source code for a file
func (s *defaultCRSService) getSourceCode(taskID, filePath string) (string, error) {
    // Implement based on your source code access mechanism
    // This might involve accessing a local file system, making an API call, etc.
    // For now, we'll return a placeholder
    return "", fmt.Errorf("source code access not implemented")
}

func saveSarifBroadcast(workDir string, taskID string, broadcast models.SARIFBroadcastDetail) (string, error) {
    
    var sarifFilePath string

    // Step 0: Save the broadcast to a JSON file
    // First, find the task directory
    entries, err := os.ReadDir(workDir)
    if err != nil {
        return sarifFilePath, fmt.Errorf("failed to read work directory: %w", err)
    }
    
    var taskDir string
    for _, entry := range entries {
        if entry.IsDir() && strings.HasPrefix(entry.Name(), taskID+"-") {
            taskDir = path.Join(workDir, entry.Name())
            break
        }
    }
    
    if taskDir == "" {
        return sarifFilePath, fmt.Errorf("task directory for task %s not found", taskID)
    }
    
    // Create sarif_broadcasts directory if it doesn't exist
    sarifDir := path.Join(taskDir, "sarif_broadcasts")
    if err := os.MkdirAll(sarifDir, 0755); err != nil {
        return sarifFilePath, fmt.Errorf("failed to create sarif_broadcasts directory: %w", err)
    }
    
    // Marshal the broadcast to JSON
    sarifJSON, err := json.MarshalIndent(broadcast, "", "  ")
    if err != nil {
        return sarifFilePath, fmt.Errorf("failed to marshal SARIF broadcast: %w", err)
    }
    
    // Save to file with SARIF ID as name
    sarifFilePath = path.Join(sarifDir, fmt.Sprintf("%s.json", broadcast.SarifID))
    if err := os.WriteFile(sarifFilePath, sarifJSON, 0644); err != nil {
        return sarifFilePath, fmt.Errorf("failed to save SARIF broadcast to file: %w", err)
    }
    
    log.Printf("Saved SARIF broadcast to %s", sarifFilePath)
    return sarifFilePath, nil
}
func (s *defaultCRSService) processSarif(taskID string, broadcast models.SARIFBroadcastDetail) error {
    log.Printf("Processing SARIF report for task %s, SARIF ID %s", taskID, broadcast.SarifID)
    
    // 0. save Sarif Broadcast
    saveSarifBroadcast(s.workDir,taskID,broadcast)

    // 1. Extract and validate the SARIF report
    sarifData, err := extractSarifData(broadcast.SARIF)
    if err != nil {
        return fmt.Errorf("failed to extract SARIF data: %w", err)
    }
    
    // 2. Analyze the SARIF report to identify vulnerabilities
    vulnerabilities, err := analyzeSarifVulnerabilities(sarifData)
    if err != nil {
        return fmt.Errorf("failed to analyze vulnerabilities: %w", err)
    }
    
    if len(vulnerabilities) == 0 {
        log.Printf("No vulnerabilities found in SARIF report for task %s", taskID)
        return nil
    }
    
    log.Printf("Found %d vulnerabilities in SARIF report for task %s", len(vulnerabilities), taskID)
    
    showVulnerabilityDetail(taskID, vulnerabilities)


   go s.processSarifForTask(taskID, broadcast, vulnerabilities)

    return nil
}


// Get valid POVs from submission server
func (s *defaultCRSService) getValidPOVs(taskID string) ([]models.POVSubmission, error) {
    url := fmt.Sprintf("%s/v1/task/%s/valid_povs/", s.submissionEndpoint, taskID)
    //TODO set headers
    resp, err := http.Get(url)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("non-200 response from submission server: %d, body: %s", resp.StatusCode, body)
    }
    
    var response models.TaskValidPOVsResponse
    if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
        return nil, err
    }
    
    return response.POVs, nil
}

func (s *defaultCRSService) getPOVStatsFromSubmissionService(taskID string) (int, int, error) {
    
    url := fmt.Sprintf("%s/v1/task/%s/pov_stats/", s.submissionEndpoint, taskID)
    // Create the HTTP request
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        log.Printf("Error creating getPOVStats request for taskID %s: %v", taskID, err)
        return 0,0, err
    }

    {
        // Set headers
        req.Header.Set("Content-Type", "application/json")

        // Get API credentials from environment
        apiKeyID := os.Getenv("COMPETITION_API_KEY_ID")
        apiToken := os.Getenv("COMPETITION_API_KEY_TOKEN")
        if apiKeyID != "" && apiToken != "" {
            req.SetBasicAuth(apiKeyID, apiToken)
        }


// Increase the timeout for the HTTP request
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second) // Increase to 3 minutes
defer cancel()
req = req.WithContext(ctx)

// Create a client with custom timeout settings
client := &http.Client{
    Timeout: 180 * time.Second, // Set client timeout to match context timeout
    Transport: &http.Transport{
        DialContext: (&net.Dialer{
            Timeout:   30 * time.Second, // Connection timeout
            KeepAlive: 30 * time.Second,
        }).DialContext,
        TLSHandshakeTimeout:   15 * time.Second,
        ResponseHeaderTimeout: 30 * time.Second,
        ExpectContinueTimeout: 1 * time.Second,
        MaxIdleConns:          100,
        IdleConnTimeout:       90 * time.Second,
    },
}

// Send the request
resp, err := client.Do(req)
if err != nil {
    log.Printf("Error getting POV statistics at submission service: %v", err)
    // Consider implementing a retry mechanism here
    if ctx.Err() == context.DeadlineExceeded {
        log.Printf("Request timed out, may need to increase timeout or check server load")
    }
    return 0,0, err
}
defer resp.Body.Close()
        
        // Check response
        if resp.StatusCode != http.StatusOK {
            body, _ := io.ReadAll(resp.Body)
            log.Printf("Submission service returned non-200 status: %d, body: %s", resp.StatusCode, string(body))
            return 0,0, fmt.Errorf("Submission service returned non-200 status: %d, body: %s", resp.StatusCode, string(body)) 
        } else {

            var response models.POVStatsResponse
            if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
                return 0,0, err
            }
            
            return response.Count, response.PatchCount, nil
        }
        
    }
}

func (s *defaultCRSService) checkIfSarifValid(taskID string, broadcast models.SARIFBroadcastDetail) (bool, error) {
    
    broadcastJSON, err := json.Marshal(broadcast)
    if err != nil {
        log.Printf("Error json.Marshal for broadcast SarifID %s: %v", broadcast.SarifID, err)
        return false, err
    }

    url := fmt.Sprintf("%s/v1/sarifx/%s/%s/", s.submissionEndpoint, taskID, broadcast.SarifID)
    // Create the HTTP request
    req, err := http.NewRequest("POST", url, bytes.NewBuffer(broadcastJSON))
    if err != nil {
        log.Printf("Error creating request for broadcast.SarifID %s: %v", broadcast.SarifID, err)
        return false, err
    }


    {
        // Set headers
        req.Header.Set("Content-Type", "application/json")

        // Get API credentials from environment
        apiKeyID := os.Getenv("COMPETITION_API_KEY_ID")
        apiToken := os.Getenv("COMPETITION_API_KEY_TOKEN")
        if apiKeyID != "" && apiToken != "" {
            req.SetBasicAuth(apiKeyID, apiToken)
        }


// Increase the timeout for the HTTP request
ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second) // Increase to 3 minutes
defer cancel()
req = req.WithContext(ctx)

// Create a client with custom timeout settings
client := &http.Client{
    Timeout: 180 * time.Second, // Set client timeout to match context timeout
    Transport: &http.Transport{
        DialContext: (&net.Dialer{
            Timeout:   30 * time.Second, // Connection timeout
            KeepAlive: 30 * time.Second,
        }).DialContext,
        TLSHandshakeTimeout:   15 * time.Second,
        ResponseHeaderTimeout: 30 * time.Second,
        ExpectContinueTimeout: 1 * time.Second,
        MaxIdleConns:          100,
        IdleConnTimeout:       90 * time.Second,
    },
}

// Send the request
resp, err := client.Do(req)
if err != nil {
    log.Printf("Error checking broadcast validity at submission service: %v", err)
    // Consider implementing a retry mechanism here
    if ctx.Err() == context.DeadlineExceeded {
        log.Printf("Request timed out, may need to increase timeout or check server load")
    }
    return false, err
}
defer resp.Body.Close()
        
        // Check response
        if resp.StatusCode != http.StatusOK {
            body, _ := io.ReadAll(resp.Body)
            log.Printf("Submission service returned non-200 status: %d, body: %s", resp.StatusCode, string(body))
            return false, fmt.Errorf("Submission service returned non-200 status: %d, body: %s", resp.StatusCode, string(body)) 
        } else {

            var response models.SarifValidResponse
            if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
                return false, err
            }
            
            return response.IsValid, nil
        }
        
    }
}
func (s *defaultCRSService) checkIfSarifInValid(taskID string, ctxs []models.CodeContext, broadcast models.SARIFBroadcastDetail) (int, error) {
    
    payload := struct {
        Broadcast models.SARIFBroadcastDetail `json:"broadcast"`
        Contexts  []models.CodeContext        `json:"contexts"`
    }{
        Broadcast: broadcast,
        Contexts:  ctxs,
    }

    payloadJSON, err := json.Marshal(payload)
    if err != nil {
        log.Printf("Error json.Marshal for payload with SarifID %s: %v", broadcast.SarifID, err)
        return 0, err
    }

    url := fmt.Sprintf("%s/v1/sarifx/check_invalid/%s/%s/", s.submissionEndpoint, taskID, broadcast.SarifID)
    // Create the HTTP request
    req, err := http.NewRequest("POST", url, bytes.NewBuffer(payloadJSON))
    if err != nil {
        log.Printf("Error creating request for broadcast.SarifID %s: %v", broadcast.SarifID, err)
        return 0, err
    }

    {
        // Set headers
        req.Header.Set("Content-Type", "application/json")

        // Get API credentials from environment
        apiKeyID := os.Getenv("COMPETITION_API_KEY_ID")
        apiToken := os.Getenv("COMPETITION_API_KEY_TOKEN")
        if apiKeyID != "" && apiToken != "" {
            req.SetBasicAuth(apiKeyID, apiToken)
        }


        ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
        defer cancel()
        req = req.WithContext(ctx)
        
        // Send the request
        client := &http.Client{}
        resp, err := client.Do(req)
        if err != nil {
            log.Printf("Error checking sarif broadcast invalidity at submission service: %v", err)
            return 0, err
        }
        defer resp.Body.Close()
        
        // Check response
        if resp.StatusCode != http.StatusOK {
            body, _ := io.ReadAll(resp.Body)
            log.Printf("Submission service returned non-200 status: %d, body: %s", resp.StatusCode, string(body))
            return 0, fmt.Errorf("Submission service returned non-200 status: %d, body: %s", resp.StatusCode, string(body)) 
        } else {

            var response models.SarifInValidResponse
            if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
                return 0, err
            }
            
            return response.IsInvalid, nil
        }
        
    }
} 


func (s *defaultCRSService) submitSarifInvalid(taskID string, broadcast models.SARIFBroadcastDetail) error {

    url := fmt.Sprintf("%s/v1/sarifx/invalid/%s/%s/", s.submissionEndpoint,taskID, broadcast.SarifID)

    broadcastJSON, err := json.Marshal(broadcast)
    if err != nil {
        log.Printf("Error json.Marshal for broadcast SarifID %s: %v", broadcast.SarifID, err)
        return err
    }

    // Create the HTTP request
    req, err := http.NewRequest("POST", url, bytes.NewBuffer(broadcastJSON))
    if err != nil {
        log.Printf("Error creating request for broadcast.SarifID %s: %v", broadcast.SarifID, err)
        return err
    }

    {
        // Set headers
        req.Header.Set("Content-Type", "application/json")

        // Get API credentials from environment
        apiKeyID := os.Getenv("COMPETITION_API_KEY_ID")
        apiToken := os.Getenv("COMPETITION_API_KEY_TOKEN")
        if apiKeyID != "" && apiToken != "" {
            req.SetBasicAuth(apiKeyID, apiToken)
        }


        ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
        defer cancel()
        req = req.WithContext(ctx)
        
        // Send the request
        client := &http.Client{}
        resp, err := client.Do(req)
        if err != nil {
            log.Printf("Error sending broadcast to submission service: %v", err)
            return err
        }
        defer resp.Body.Close()
        
        // Check response
        if resp.StatusCode != http.StatusOK {
            body, _ := io.ReadAll(resp.Body)
            log.Printf("Submission service returned non-200 status: %d, body: %s", resp.StatusCode, string(body))
            return fmt.Errorf("Submission service returned non-200 status: %d, body: %s", resp.StatusCode, string(body)) 
        }
    }
            
    return nil
}

const (
	defaultContextLines = 20
	maxFunctionScanUp   = 200 // Max lines to scan upwards for a function signature
	maxFunctionScanDown = 700 // Max lines to scan downwards for function end (from signature start)
	maxSnippetLines     = 500 // Max lines for the final snippet
)

// Helper to check if a token is a common control-flow keyword (for C-style and Java)
func isControlKeyword(name string, lang string) bool {
	lowerName := strings.ToLower(name)
	var keywords []string
	if lang == "java" {
		keywords = []string{"if", "for", "while", "switch", "synchronized", "catch", "try"}
	} else { // C-style
		keywords = []string{"if", "for", "while", "switch", "catch", "try", "else"} // "else" because "else {" doesn't have "()"
	}

	for _, keyword := range keywords {
		if lowerName == keyword {
			return true
		}
	}
	return false
}

// findCStyleFunctionBoundaries tries to identify function boundaries for C-like languages.
func findCStyleFunctionBoundaries(lines []string, locStartLine int, locEndLine int) (funcName string, funcBodyStart int, funcBodyEnd int) {
	potentialFuncName := ""
	// Initialize boundaries to a default context window that will be used if a specific function isn't found.
	funcBodyStart = locStartLine
	funcBodyEnd = locEndLine
	foundSpecificFunction := false

	// 1. Scan upwards for function start
	sigLineNum := 0 // 1-indexed line number of the signature (line with '{')
	for i := locStartLine; i >= 1 && i >= locStartLine-maxFunctionScanUp; i-- {
		currentLineContent := lines[i-1]
		trimmedLine := strings.TrimSpace(currentLineContent)

		if strings.HasSuffix(trimmedLine, "{") {
			lineForNameExtraction := strings.TrimSuffix(trimmedLine, "{")
			lineForNameExtraction = strings.TrimSpace(lineForNameExtraction)

			// Check for pattern like name(...)
			if strings.Contains(lineForNameExtraction, "(") && strings.HasSuffix(lineForNameExtraction, ")") {
				extractedName := ""
				if idx := strings.Index(lineForNameExtraction, "("); idx != -1 {
					beforeParen := strings.TrimSpace(lineForNameExtraction[:idx])
					tokens := strings.Fields(beforeParen) // Splits by whitespace
					if len(tokens) > 0 {
						// The last token before '(' is usually the function name
						nameCandidate := tokens[len(tokens)-1]
						// Clean common generic syntax like <...> from the end of the name
						if gIdx := strings.Index(nameCandidate, "<"); gIdx != -1 {
							if strings.HasSuffix(nameCandidate, ">") && strings.Count(nameCandidate, "<") == 1 && strings.Count(nameCandidate, ">") == 1 {
								nameCandidate = nameCandidate[:gIdx]
							}
						}
						// Ensure name doesn't start with characters that are unlikely for a function name
						if len(nameCandidate) > 0 && (unicode.IsLetter(rune(nameCandidate[0])) || nameCandidate[0] == '_') {
							extractedName = nameCandidate
						}
					}
				}

				if extractedName != "" && !isControlKeyword(extractedName, "c") {
					potentialFuncName = extractedName
					sigLineNum = i
					foundSpecificFunction = true
					break
				}
			}
		}
	}

	if !foundSpecificFunction { // Fallback if no signature found
		funcBodyStart = locStartLine - defaultContextLines
		if funcBodyStart < 1 {
			funcBodyStart = 1
		}
		funcBodyEnd = locEndLine + defaultContextLines
		if funcBodyEnd > len(lines) {
			funcBodyEnd = len(lines)
		}
		return "", funcBodyStart, funcBodyEnd
	}

	funcBodyStart = sigLineNum

	// 2. Scan downwards for function end (matching '}')
	braceCount := 0
	// Initialize braceCount by counting on the signature line itself
	sigLineContent := lines[sigLineNum-1]
	for _, char := range sigLineContent {
		if char == '{' {
			braceCount++
		}
	}

	currentFuncEnd := funcBodyStart // Default if no clear end found within scan limit
	if braceCount == 0 && strings.Contains(sigLineContent, "{") { 
		// This can happen if { is immediately followed by } on the same line, e.g. func() {}
		// However, our upward scan expects `name(...) {`, so this needs robust brace counting from start.
		// If the opening brace was indeed on sigLineNum, braceCount should be > 0.
		// Re-evaluate: if first line has balanced braces, it's the end.
		tempBraceCheck := 0
		for _, char := range sigLineContent {
			if char == '{' { tempBraceCheck++ }
			if char == '}' { tempBraceCheck-- }
		}
		if tempBraceCheck == 0 && strings.Contains(sigLineContent, "{") {
			funcBodyEnd = sigLineNum
			return potentialFuncName, funcBodyStart, funcBodyEnd
		}
	}


	if braceCount > 0 { // Only proceed if we actually found an opening brace to match
		for i := sigLineNum + 1; i <= len(lines) && i <= sigLineNum+maxFunctionScanDown; i++ {
			lineContent := lines[i-1]
			for _, char := range lineContent {
            if char == '{' {
                braceCount++
            } else if char == '}' {
                braceCount--
                if braceCount == 0 {
						currentFuncEnd = i
						goto endFoundCStyle
					}
				}
			}
		}
	}
endFoundCStyle:
	if currentFuncEnd > funcBodyStart { // Check if we actually moved downwards
		funcBodyEnd = currentFuncEnd
	} else if braceCount != 0 { // Did not find matching brace
		funcBodyEnd = min(sigLineNum+maxFunctionScanDown, len(lines)) // Cap at scan limit or EOF
	} else {
		funcBodyEnd = funcBodyStart // e.g. func() {} case
	}


	return potentialFuncName, funcBodyStart, funcBodyEnd
}

// findJavaFunctionBoundaries tries to identify method boundaries for Java.
func findJavaFunctionBoundaries(lines []string, locStartLine int, locEndLine int) (funcName string, funcBodyStart int, funcBodyEnd int) {
	potentialFuncName := ""
	funcBodyStart = locStartLine
	funcBodyEnd = locEndLine
	foundSpecificFunction := false

	// Java method signatures can be complex (annotations, generics, throws)
	// Heuristic: look for typical modifiers, return type, name(...) {
	sigLineNum := 0
	javaKeywords := []string{
		"public", "private", "protected", "static", "final", "abstract", "native", "synchronized",
		"void", // common return type
		// common class/interface keywords - methods are inside these but these aren't method names
		"class", "interface", "enum",
	}
	_ = javaKeywords // Currently unused directly in this simplified name check

	for i := locStartLine; i >= 1 && i >= locStartLine-maxFunctionScanUp; i-- {
		currentLineContent := lines[i-1]
		trimmedLine := strings.TrimSpace(currentLineContent)

		if strings.HasSuffix(trimmedLine, "{") {
			lineForNameExtraction := strings.TrimSuffix(trimmedLine, "{")
			lineForNameExtraction = strings.TrimSpace(lineForNameExtraction)

			if strings.Contains(lineForNameExtraction, "(") && strings.HasSuffix(lineForNameExtraction, ")") {
				extractedName := ""
				if idx := strings.Index(lineForNameExtraction, "("); idx != -1 {
					beforeParen := strings.TrimSpace(lineForNameExtraction[:idx])
					tokens := strings.Fields(beforeParen)
					if len(tokens) > 0 {
						nameCandidate := tokens[len(tokens)-1]
						if gIdx := strings.Index(nameCandidate, "<"); gIdx != -1 {
                             if strings.HasSuffix(nameCandidate, ">") && strings.Count(nameCandidate, "<") == 1 && strings.Count(nameCandidate, ">") == 1 {
								nameCandidate = nameCandidate[:gIdx]
							}
                        }
						if len(nameCandidate) > 0 && (unicode.IsLetter(rune(nameCandidate[0])) || nameCandidate[0] == '_') {
							// Further check: is it a constructor? (same name as a class usually starts uppercase)
							// Is it a common control keyword?
							if !isControlKeyword(nameCandidate, "java") {
								// Basic check for things that are not typical method starting keywords
								isLikelyMethod := true
								if len(tokens) > 1 {
									prevToken := strings.ToLower(tokens[len(tokens)-2])
									if prevToken == "new" { // e.g. new MyClass(...){ // anonymous inner class
										isLikelyMethod = false
									}
								}
								// Avoid class MyClass<T> extends Other { (if line has "class" or "interface")
								if strings.Contains(strings.ToLower(beforeParen), " class ") || strings.Contains(strings.ToLower(beforeParen), " interface ") || strings.Contains(strings.ToLower(beforeParen), " enum ") {
									isLikelyMethod = false
								}


								if isLikelyMethod {
									extractedName = nameCandidate
								}
							}
						}
					}
				}

				if extractedName != "" {
					potentialFuncName = extractedName
					sigLineNum = i
					foundSpecificFunction = true
            break
				}
			}
		}
	}

	if !foundSpecificFunction {
		funcBodyStart = locStartLine - defaultContextLines
		if funcBodyStart < 1 {
			funcBodyStart = 1
		}
		funcBodyEnd = locEndLine + defaultContextLines
		if funcBodyEnd > len(lines) {
			funcBodyEnd = len(lines)
		}
		return "", funcBodyStart, funcBodyEnd
	}

	funcBodyStart = sigLineNum

	// Scan downwards for method end
	braceCount := 0
	sigLineContent := lines[sigLineNum-1]
	for _, char := range sigLineContent {
		if char == '{' {
			braceCount++
		}
	}
	
	currentFuncEnd := funcBodyStart
	if braceCount == 0 && strings.Contains(sigLineContent, "{") {
		tempBraceCheck := 0
		for _, char := range sigLineContent {
			if char == '{' { tempBraceCheck++ }
			if char == '}' { tempBraceCheck-- }
		}
		if tempBraceCheck == 0 && strings.Contains(sigLineContent, "{") {
			funcBodyEnd = sigLineNum
			return potentialFuncName, funcBodyStart, funcBodyEnd
		}
	}


	if braceCount > 0 {
		for i := sigLineNum + 1; i <= len(lines) && i <= sigLineNum+maxFunctionScanDown; i++ {
			lineContent := lines[i-1]
			for _, char := range lineContent {
				if char == '{' {
					braceCount++
				} else if char == '}' {
					braceCount--
					if braceCount == 0 {
						currentFuncEnd = i
						goto endFoundJava
					}
				}
			}
		}
	}
endFoundJava:
	if currentFuncEnd > funcBodyStart {
		funcBodyEnd = currentFuncEnd
	} else if braceCount != 0 {
		funcBodyEnd = min(sigLineNum+maxFunctionScanDown, len(lines))
	} else {
		funcBodyEnd = funcBodyStart 
	}

	return potentialFuncName, funcBodyStart, funcBodyEnd
    }
    
    // Helper function to add line numbers to code
func formatWithLineNumbers(codeLines []string, startLineNum int) string {
        var sb strings.Builder
        for i, line := range codeLines {
            lineNum := startLineNum + i
            sb.WriteString(fmt.Sprintf("%4d: %s\n", lineNum, line))
        }
        return sb.String()
    }
    
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func extractRelevantSourceCode(projectDir string, loc struct {
	FilePath  string
	StartLine int // 1-indexed
	EndLine   int // 1-indexed
	StartCol  int
	EndCol    int
}) (filePath, funcName, codeSnippet string) {
	targetBase := filepath.Base(loc.FilePath)
	var foundPath string
	_ = filepath.WalkDir(projectDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if filepath.Base(path) == targetBase {
			foundPath = path
			return filepath.SkipAll // Use SkipAll to stop searching efficiently
		}
		return nil
	})

	if foundPath == "" {
		return loc.FilePath, "", "" // Could not find file
	}
	filePath = foundPath

	data, err := os.ReadFile(foundPath)
	if err != nil {
		return filePath, "", "" // Error reading file
	}
	lines := strings.Split(string(data), "\n")

	// Ensure loc.StartLine and loc.EndLine are within file bounds and loc.StartLine <= loc.EndLine
	originalLocStartLine := loc.StartLine // Preserve original for backup logic if needed
	originalLocEndLine := loc.EndLine     // Preserve original for backup logic if needed

	if loc.StartLine <= 0 {
		loc.StartLine = 1
	}
	if loc.StartLine > len(lines) { // If start is beyond file, cap it
		loc.StartLine = len(lines)
	}
	if loc.EndLine < loc.StartLine { // If end is before start (or invalid), set to start
		loc.EndLine = loc.StartLine
	}
	if loc.EndLine > len(lines) { // If end is beyond file, cap it
		loc.EndLine = len(lines)
	}


	var determinedFuncName string
	var functionWideStart, functionWideEnd int // These are the boundaries of the containing function/method

	fileExt := strings.ToLower(filepath.Ext(foundPath))

	switch fileExt {
	case ".java":
		determinedFuncName, functionWideStart, functionWideEnd = findJavaFunctionBoundaries(lines, loc.StartLine, loc.EndLine)
	case ".c", ".cpp", ".cc", ".h", ".hpp", ".m", ".mm": // C, C++, Objective-C
		determinedFuncName, functionWideStart, functionWideEnd = findCStyleFunctionBoundaries(lines, loc.StartLine, loc.EndLine)
	default: // Fallback to C-style for other unknown types or simple scripts
		determinedFuncName, functionWideStart, functionWideEnd = findCStyleFunctionBoundaries(lines, loc.StartLine, loc.EndLine)
	}
	funcName = determinedFuncName

	// Now, create the snippet using the determined function boundaries and the original loc focus.
	vulnLinesCount := loc.EndLine - loc.StartLine + 1
	if vulnLinesCount < 0 { vulnLinesCount = 0} // Should be non-negative due to clamping

	remainingLinesForContext := maxSnippetLines - vulnLinesCount
	if remainingLinesForContext < 0 {
		remainingLinesForContext = 0 
	}

	linesBeforeTarget := remainingLinesForContext / 2
	linesAfterTarget := remainingLinesForContext - linesBeforeTarget

	snippetStartLine := max(loc.StartLine-linesBeforeTarget, functionWideStart)
	snippetEndLine := min(loc.EndLine+linesAfterTarget, functionWideEnd)

	currentSnippetLength := snippetEndLine - snippetStartLine + 1
	if currentSnippetLength < maxSnippetLines && currentSnippetLength > 0 {
		neededBefore := loc.StartLine - snippetStartLine
		if neededBefore < 0 { neededBefore = 0 } // Can't be negative
		canAddMoreBefore := linesBeforeTarget - neededBefore
		if canAddMoreBefore > 0 && snippetStartLine == functionWideStart { // We hit functionWideStart early
			snippetEndLine = min(snippetEndLine+canAddMoreBefore, functionWideEnd)
		}

		currentSnippetLength = snippetEndLine - snippetStartLine + 1 
		if currentSnippetLength < 0 { currentSnippetLength = 0 }

		if currentSnippetLength < maxSnippetLines { 
			neededAfter := snippetEndLine - loc.EndLine
			if neededAfter < 0 { neededAfter = 0 } // Can't be negative
			canAddMoreAfter := linesAfterTarget - neededAfter
			if canAddMoreAfter > 0 && snippetEndLine == functionWideEnd { // We hit functionWideEnd early
				snippetStartLine = max(snippetStartLine-canAddMoreAfter, functionWideStart)
			}
		}
	}
    
    snippetStartLine = max(snippetStartLine, 1) // Clamp to file start
    snippetEndLine = min(snippetEndLine, len(lines)) // Clamp to file end
    snippetStartLine = max(snippetStartLine, functionWideStart) 
    snippetEndLine = min(snippetEndLine, functionWideEnd) 
    if snippetStartLine > snippetEndLine { // Ensure start is not after end
        snippetStartLine = snippetEndLine
    }


   // ───────────────────────── Ensure we include the full SARIF region ───────────────
   clampedOrigEnd := min(max(1, originalLocEndLine), len(lines)) // safe end-line
   if snippetEndLine < clampedOrigEnd {
       snippetEndLine = clampedOrigEnd
   }

	var sb strings.Builder
	if snippetStartLine <= snippetEndLine && snippetStartLine > 0 { // Check for valid range
		if snippetStartLine > functionWideStart && snippetStartLine > 1 {
			if functionWideStart < snippetStartLine-1 {
				sb.WriteString(fmt.Sprintf("// ... %d lines omitted from start of %s ...\n", snippetStartLine-functionWideStart, determinedFuncNameOrBlock(funcName)))
			}
		}

		sb.WriteString(formatWithLineNumbers(lines[snippetStartLine-1:snippetEndLine], snippetStartLine))

		if snippetEndLine < functionWideEnd && snippetEndLine < len(lines) {
			if functionWideEnd > snippetEndLine+1 {
				sb.WriteString(fmt.Sprintf("// ... %d lines omitted from end of %s ...\n", functionWideEnd-snippetEndLine, determinedFuncNameOrBlock(funcName)))
			}
		}
	} else { // Fallback if snippet range became invalid (e.g. functionWideStart/End were out of loc range)
		safeStart := loc.StartLine // Already clamped
		safeEnd := loc.EndLine     // Already clamped
		if safeStart <= safeEnd && safeStart > 0 {
			sb.WriteString(formatWithLineNumbers(lines[safeStart-1:safeEnd], safeStart))
		}
	}
    codeSnippet = sb.String()
    
	// --- Backup Logic ---
	// If the generated snippet shows fewer actual code lines than requested by the original loc.StartLine/loc.EndLine,
	// then revert to showing exactly that original range.
	numEffectiveSnippetLines := 0
	if snippetStartLine <= snippetEndLine && snippetStartLine > 0 && snippetEndLine <= len(lines) {
		numEffectiveSnippetLines = snippetEndLine - snippetStartLine + 1
	}

	// Use original (but clamped) loc for requested lines.
	// Clamping for originalLocStartLine / originalLocEndLine
	clampedOrigLocStart := max(1, originalLocStartLine)
	clampedOrigLocStart = min(clampedOrigLocStart, len(lines))
	clampedOrigLocEnd := max(1, originalLocEndLine)
	clampedOrigLocEnd = min(clampedOrigLocEnd, len(lines))
	if clampedOrigLocStart > clampedOrigLocEnd { // Ensure start <= end
		clampedOrigLocStart = clampedOrigLocEnd
	}
	
	requestedMinLocLines := 0
	if clampedOrigLocStart <= clampedOrigLocEnd {
		 requestedMinLocLines = clampedOrigLocEnd - clampedOrigLocStart + 1
	}


	if requestedMinLocLines > 0 && numEffectiveSnippetLines < requestedMinLocLines && numEffectiveSnippetLines >= 0 {
		var backupSb strings.Builder
		// Use the clamped original loc for the backup display
		backupSb.WriteString(formatWithLineNumbers(lines[clampedOrigLocStart-1:clampedOrigLocEnd], clampedOrigLocStart))
		codeSnippet = backupSb.String()
		// funcName remains as determined; omission markers are removed by this override.
	}
	// --- End of Backup Logic ---

	return filePath, funcName, codeSnippet
}

func determinedFuncNameOrBlock(funcName string) string {
	if funcName == "" {
		return "block"
	}
	return funcName
}


// findProjectDir searches for a directory with the pattern taskID-* under workDir
// and returns the full path to the project directory (workDir/taskID-*/focus)
func (s *defaultCRSService) findProjectDir(taskID string) (string, error) {
    // Get task details to obtain focus
    s.tasksMutex.Lock()
    taskDetail, exists := s.tasks[taskID]
    s.tasksMutex.Unlock()
    
    if !exists {
        return "", fmt.Errorf("task %s not found", taskID)
    }
    
    // Search for directories with pattern taskID-*
    pattern := filepath.Join(s.workDir, taskID+"-*")
    matches, err := filepath.Glob(pattern)
    if err != nil {
        return "", fmt.Errorf("error searching for task directory: %v", err)
    }
    
    if len(matches) == 0 {
        return "", fmt.Errorf("no task directory found for task %s", taskID)
    }
    
    // Find the most recent directory (if multiple exist)
    var latestDir string
    var latestTime time.Time
    
    for _, dir := range matches {
        info, err := os.Stat(dir)
        if err != nil || !info.IsDir() {
            continue
        }
        
        if latestDir == "" || info.ModTime().After(latestTime) {
            latestDir = dir
            latestTime = info.ModTime()
        }
    }
    
    if latestDir == "" {
        return "", fmt.Errorf("no valid task directory found for task %s", taskID)
    }
    
    // Construct the project directory path
    projectDir := filepath.Join(latestDir, taskDetail.Focus)
    
    // Verify the directory exists
    if _, err := os.Stat(projectDir); os.IsNotExist(err) {
        return "", fmt.Errorf("project directory %s does not exist", projectDir)
    }
    
    return projectDir, nil
}

func (s *defaultCRSService) processSarifForTask(taskID string, broadcast models.SARIFBroadcastDetail, vulnerabilities []models.Vulnerability) error {
    maxRetries := 5
    retryDelay := 1 * time.Minute
    retries := 0

    for ; retries < maxRetries; retries++ {
        log.Printf("SARIF processing attempt %d/%d for task %s", retries+1, maxRetries, taskID)
        
        // Check if this broadcast is valid from the submission server
        isValid, err := s.checkIfSarifValid(taskID,broadcast)
        if err != nil {
            log.Printf("Error checking sarif validity for task %s: %v", taskID, err)
            time.Sleep(retryDelay)
            continue
        }        
        
        if isValid {
            //true positive, job done, validity submitted by sub service
            return nil
        }

        projectDir, err := s.findProjectDir(taskID)
        if err != nil {
            log.Printf("SOMETHING IS WRONG Error finding project directory for task %s: %v", taskID, err)
            // Handle error appropriately - you might want to continue with default behavior
            // or return an error depending on your requirements
        } else {
            //-------------------------------------------------
            // gather code snippets for ALL vulnerabilities
            //-------------------------------------------------
            var ctxs []models.CodeContext
            for _, v := range vulnerabilities {
                if v.Location.StartLine <= 0 { continue } // skip if no line info

                fmt.Printf("v.Location: %v\n",v.Location)

                file, fnName, snip := extractRelevantSourceCode(projectDir, v.Location)
                ctxs = append(ctxs, models.CodeContext{File: file, Func: fnName, Snip: snip})
            }

            if len(ctxs) == 0 {
                // nothing to validate against – treat as unknown
                fmt.Printf("SOMETHING IS WRONG no source code located for any vulnerability")
            } else {
                fmt.Printf("sarif ctxs: %v",ctxs)
            }

            // Check if this broadcast is absolutely invalid from the submission server
            isInvalid, err := s.checkIfSarifInValid(taskID,ctxs,broadcast)
            if err != nil {
                // log.Printf("Error checking sarif invalidity for task %s: %v", taskID, err)
                time.Sleep(retryDelay)
                continue
            } 
            
            if isInvalid == 1 {
                //false positive, job done, validity submitted by sub service
                return nil
            } else {
                log.Printf("SARIF determined to be (potentially) true positive. Trying to assign to workers...\n")
            }
        }

        //If UNKNOWN or true positive but not processed, try POV by the workers
        err = s.findPOVsAndNotifyWorkers(taskID, broadcast)
        if err == nil {
            //job done with sending sarif to workers, no more work to do for webapp node
            return nil
        } else {
            log.Printf("Error in findPOVsAndNotifyWorkers: %v\n", err)
        }
        time.Sleep(retryDelay)
    }
    return nil

}


// Find POVs with timeout and send broadcasts to assigned workers
func (s *defaultCRSService) findPOVsAndNotifyWorkers(taskID string, broadcast models.SARIFBroadcastDetail) error {
    // 1. Lock to safely access worker mapping
    s.workerStatusMux.Lock()
    defer s.workerStatusMux.Unlock()
    
    // 2. Find all workers that have been assigned to a fuzzer of the same taskID
    workerFuzzerPairs, exists := s.taskToWorkersMap[taskID]
    if !exists || len(workerFuzzerPairs) == 0 {
        log.Printf("No workers assigned to task %s", taskID)
        return fmt.Errorf("no workers assigned to task %s", taskID)
    }
    
    log.Printf("Found %d worker-fuzzer pairs assigned to task %s", len(workerFuzzerPairs), taskID)
    
    
    // 4. Get API credentials
    apiKeyID := os.Getenv("CRS_KEY_ID")
    apiToken := os.Getenv("CRS_KEY_TOKEN")
    
    // 5. Send the broadcast to each worker with retry logic
    var wg sync.WaitGroup
    successCount := 0
    var successMutex sync.Mutex
    
    for _, pair := range workerFuzzerPairs {
        workerIndex := pair.Worker
        
        payload := models.SARIFBroadcastDetailWorker{
            Broadcast: broadcast,
            Fuzzer: pair.Fuzzer,
        }
        // 3. Marshal the broadcast message
        broadcastJSON, err := json.Marshal(payload)
        if err != nil {
            return fmt.Errorf("error marshaling broadcast message: %v", err)
        }

        wg.Add(1)
        go func(idx int) {
            defer wg.Done()
            
            // Send broadcast with retry
            maxRetries := 3
            for attempt := 0; attempt < maxRetries; attempt++ {
                success := s.sendBroadcastToWorker(idx, broadcastJSON, apiKeyID, apiToken, taskID)
                if success {
                    log.Printf("Successfully sent broadcast to worker %d for task %s", idx, taskID)
                    successMutex.Lock()
                    successCount++
                    successMutex.Unlock()
                    return
                }
                
                if attempt < maxRetries-1 {
                    log.Printf("Retrying broadcast to worker %d (attempt %d/%d)", idx, attempt+1, maxRetries)
                    time.Sleep(30 * time.Second) // Wait before retry
                }
            }
            
            log.Printf("Failed to send broadcast to worker %d after %d attempts", idx, maxRetries)
        }(workerIndex)
    }
    
    // Wait for all goroutines to complete
    wg.Wait()
    
    if successCount == 0 {
        return fmt.Errorf("Failed to send broadcast to any worker for task %s", taskID)
    }
    
    log.Printf("Successfully sent broadcast to %d/%d fuzzer-worker pairs for task %s", successCount, len(workerFuzzerPairs), taskID)
    return nil
}

// Helper method to send broadcast to a specific worker
func (s *defaultCRSService) sendBroadcastToWorker(workerIndex int, broadcastJSON []byte, apiKeyID, apiToken, taskID string) bool {

        // Construct the worker URL
        workerURL := fmt.Sprintf("http://crs-worker-%d.crs-worker.crs-webservice.svc.cluster.local:%d/sarif_worker/", 
        workerIndex, s.workerBasePort)


    // Create the HTTP request
    req, err := http.NewRequest("POST", workerURL, bytes.NewBuffer(broadcastJSON))
    if err != nil {
        log.Printf("Error creating request for worker %d: %v", workerIndex, err)
        return false
    }
    
    // Set headers
    req.Header.Set("Content-Type", "application/json")
        // Set timeout context
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    req = req.WithContext(ctx)
    
    // Send the request
    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        log.Printf("Error sending broadcast to worker %d: %v", workerIndex, err)
        return false
    }
    defer resp.Body.Close()
    
    // Check response
    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        log.Printf("Worker %d returned non-200 status: %d, body: %s", workerIndex, resp.StatusCode, string(body))
        return false
    }
    
    return true
}

func showVulnerabilityDetail(taskID string, vulnerabilities []models.Vulnerability) {
    for _, vuln := range vulnerabilities {
        // 3. Print details of each vulnerability
        log.Printf("Vulnerability details for task %s:", taskID)
        log.Printf("  - Rule ID: %s", vuln.RuleID)
        log.Printf("  - Description: %s", vuln.Description)
        log.Printf("  - Severity: %s", vuln.Severity)
        
        // Print location information
        log.Printf("  - Location: %s (lines %d-%d, columns %d-%d)", 
            vuln.Location.FilePath, 
            vuln.Location.StartLine,
            vuln.Location.EndLine,
            vuln.Location.StartCol,
            vuln.Location.EndCol)
        
        // Print code flows if available
        if len(vuln.CodeFlows) > 0 {
            log.Printf("  - Code Flows:")
            for i, flow := range vuln.CodeFlows {
                log.Printf("    - Flow #%d:", i+1)
                for j, threadFlow := range flow.ThreadFlows {
                    log.Printf("      - Thread Flow #%d:", j+1)
                    for k, loc := range threadFlow.Locations {
                        log.Printf("        - Step %d: %s (lines %d-%d) - %s", 
                            k+1,
                            loc.FilePath,
                            loc.StartLine,
                            loc.EndLine,
                            loc.Message)
                    }
                }
            }
        }
        
        log.Printf("  -----------------------------")
    }
}


func analyzeSarifVulnerabilities(sarifData map[string]interface{}) ([]models.Vulnerability, error) {
    var vulnerabilities []models.Vulnerability
    
    // Extract the runs from the SARIF data
    runs, ok := sarifData["runs"].([]interface{})
    if !ok || len(runs) == 0 {
        return nil, fmt.Errorf("no runs found in SARIF data")
    }
    
    // Process each run
    for _, runInterface := range runs {
        run, ok := runInterface.(map[string]interface{})
        if !ok {
            continue
        }
        
        // Extract results from the run
        resultsInterface, ok := run["results"].([]interface{})
        if !ok {
            continue
        }
        
        // Process each result
        for _, resultInterface := range resultsInterface {
            result, ok := resultInterface.(map[string]interface{})
            if !ok {
                continue
            }
            
            // Create a vulnerability from the result
            vuln, err := createVulnerabilityFromResult(result, run)
            if err != nil {
                log.Printf("Error creating vulnerability from result: %v", err)
                continue
            }
            
            vulnerabilities = append(vulnerabilities, vuln)
        }
    }
    
    return vulnerabilities, nil
}


// createVulnerabilityFromResult creates a Vulnerability object from a SARIF result
func createVulnerabilityFromResult(result map[string]interface{}, run map[string]interface{}) (models.Vulnerability, error) {
    var vuln models.Vulnerability
    
    // Extract rule ID
    ruleID, ok := result["ruleId"].(string)
    if !ok {
        return vuln, fmt.Errorf("missing ruleId in result")
    }
    vuln.RuleID = ruleID
    
    // Extract message
    messageObj, ok := result["message"].(map[string]interface{})
    if ok {
        if text, ok := messageObj["text"].(string); ok {
            vuln.Description = text
        }
    }
    
    // Extract severity level
    if level, ok := result["level"].(string); ok {
        vuln.Severity = level
    }
    
    // Extract location information
    locationsInterface, ok := result["locations"].([]interface{})
    if ok && len(locationsInterface) > 0 {
        locationObj, ok := locationsInterface[0].(map[string]interface{})
        if ok {
            physicalLocation, ok := locationObj["physicalLocation"].(map[string]interface{})
            if ok {
                // Extract artifact location
                if artifactLocation, ok := physicalLocation["artifactLocation"].(map[string]interface{}); ok {
                    if uri, ok := artifactLocation["uri"].(string); ok {
                        vuln.Location.FilePath = uri
                    }
                }
                
                // Extract region information
                if region, ok := physicalLocation["region"].(map[string]interface{}); ok {
                    if startLine, ok := region["startLine"].(float64); ok {
                        vuln.Location.StartLine = int(startLine)
                    }
                    if endLine, ok := region["endLine"].(float64); ok {
                        vuln.Location.EndLine = int(endLine)
                    } else {
                        vuln.Location.EndLine = vuln.Location.StartLine
                    }
                    if startColumn, ok := region["startColumn"].(float64); ok {
                        vuln.Location.StartCol = int(startColumn)
                    }
                    if endColumn, ok := region["endColumn"].(float64); ok {
                        vuln.Location.EndCol = int(endColumn)
                    }
                }
            }
        }
    }

    // Extract code flows if available
    codeFlowsInterface, ok := result["codeFlows"].([]interface{})
    if ok {
        for _, cfInterface := range codeFlowsInterface {
            cf, ok := cfInterface.(map[string]interface{})
            if !ok {
                continue
            }
            
            var codeFlow models.CodeFlow
            threadFlowsInterface, ok := cf["threadFlows"].([]interface{})
            if !ok {
                continue
            }
            
            for _, tfInterface := range threadFlowsInterface {
                tf, ok := tfInterface.(map[string]interface{})
                if !ok {
                    continue
                }
                
                var threadFlow models.ThreadFlow
                locationsInterface, ok := tf["locations"].([]interface{})
                if !ok {
                    continue
                }
                
                for _, locInterface := range locationsInterface {
                    loc, ok := locInterface.(map[string]interface{})
                    if !ok {
                        continue
                    }
                    
                    var tfloc models.ThreadFlowLocation
                    if location, ok := loc["location"].(map[string]interface{}); ok {
                        if physicalLocation, ok := location["physicalLocation"].(map[string]interface{}); ok {
                            if artifactLocation, ok := physicalLocation["artifactLocation"].(map[string]interface{}); ok {
                                if uri, ok := artifactLocation["uri"].(string); ok {
                                    tfloc.FilePath = uri
                                }
                            }
                            

                    if region, ok := physicalLocation["region"].(map[string]interface{}); ok {
                        if startLine, ok := region["startLine"].(float64); ok {
                            tfloc.StartLine = int(startLine)
                        }
                        if endLine, ok := region["endLine"].(float64); ok {
                            tfloc.EndLine = int(endLine)
                        } else {
                            tfloc.EndLine = tfloc.StartLine
                        }
                        if startColumn, ok := region["startColumn"].(float64); ok {
                            tfloc.StartCol = int(startColumn)
                        }
                        if endColumn, ok := region["endColumn"].(float64); ok {
                            tfloc.EndCol = int(endColumn)
                        }
                    }
                }
            }

            if messageObj, ok := loc["message"].(map[string]interface{}); ok {
                if text, ok := messageObj["text"].(string); ok {
                    tfloc.Message = text
                }
            }

            threadFlow.Locations = append(threadFlow.Locations, tfloc)
        }

        codeFlow.ThreadFlows = append(codeFlow.ThreadFlows, threadFlow)
    }

            vuln.CodeFlows = append(vuln.CodeFlows, codeFlow)
        }
    }

    return vuln, nil
}

// // Generate a patch using an LLM
// func (s *defaultCRSService) generateLLMPatch(vuln models.Vulnerability, context, fileContent string) (string, error) {
//     // Create a prompt for the LLM
//     prompt := fmt.Sprintf(`
// You are a security expert. I need you to fix a vulnerability in the following code.

// Vulnerability: %s
// Description: %s
// Rule: %s
// Message: %s

// Here is the vulnerable code with context:
// %s


// Please provide a fix for this vulnerability. Only output the fixed code section, not the entire file.
// Explain your fix briefly in a comment.
// `, vuln.ID, vuln.Description, vuln.Rule.ID, vuln.Message, context)
    
//     return fixedCode, nil
// }


func (s *defaultCRSService) logDirectoryContents(dir string) {
    log.Printf("Contents of %s:", dir)
    err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }
        rel, err := filepath.Rel(dir, path)
        if err != nil {
            rel = path
        }
        log.Printf("  %s (%d bytes)", rel, info.Size())
        return nil
    })
    if err != nil {
        log.Printf("Error walking directory: %v", err)
    }
}

func (s *defaultCRSService) extractSources(taskDir string, is_delta bool) error {
    // Extract repo archive
    repoCmd := exec.Command("tar", "-xzf", path.Join(taskDir, "repo.tar.gz"))
    repoCmd.Dir = taskDir
    var repoOutput bytes.Buffer
    repoCmd.Stdout = &repoOutput
    repoCmd.Stderr = &repoOutput
    if err := repoCmd.Run(); err != nil {
        log.Printf("Repo extraction output:\n%s", repoOutput.String())
        return fmt.Errorf("failed to extract repo: %v", err)
    }

    // Extract fuzz-tooling archive
    toolingCmd := exec.Command("tar", "-xzf", path.Join(taskDir, "fuzz-tooling.tar.gz"))
    toolingCmd.Dir = taskDir
    var toolingOutput bytes.Buffer
    toolingCmd.Stdout = &toolingOutput
    toolingCmd.Stderr = &toolingOutput
    if err := toolingCmd.Run(); err != nil {
        log.Printf("Tooling extraction output:\n%s", toolingOutput.String())
        return fmt.Errorf("failed to extract fuzz-tooling: %v", err)
    }

    if is_delta {
        toolingCmd := exec.Command("tar", "-xzf", path.Join(taskDir, "diff.tar.gz"))
        toolingCmd.Dir = taskDir
        var toolingOutput bytes.Buffer
        toolingCmd.Stdout = &toolingOutput
        toolingCmd.Stderr = &toolingOutput
        if err := toolingCmd.Run(); err != nil {
            log.Printf("Tooling extraction output:\n%s", toolingOutput.String())
            return fmt.Errorf("failed to extract diff: %v", err)
        }
    }
    // Log directory contents for debugging
    // s.logDirectoryContents(taskDir)

    return nil
}

func (s *defaultCRSService) detectProjectName(taskDir string) (string, error) {
    // Log initial directory contents
    log.Printf("Searching for project.yaml in: %s", taskDir)
    s.logDirectoryContents(taskDir)

    // Try different patterns
    patterns := []string{
        "*/project.yaml",           // Direct subdirectory
        "*/*/project.yaml",         // Two levels deep
        "*/*/*/project.yaml",       // Three levels deep
        "example*/project.yaml",    // Example projects
        "*example*/project.yaml",   // Example projects in subdirs
    }

    for _, pattern := range patterns {
        fullPattern := path.Join(taskDir, pattern)
        log.Printf("Trying pattern: %s", fullPattern)
        
        files, err := filepath.Glob(fullPattern)
        if err != nil {
            log.Printf("Error with pattern %s: %v", pattern, err)
            continue
        }
        
        if len(files) > 0 {
            projectName := filepath.Base(filepath.Dir(files[0]))
            log.Printf("Found project.yaml at %s, project name: %s", files[0], projectName)
            return projectName, nil
        }
    }

    // Try to find any yaml files as a fallback
    yamlFiles, err := filepath.Glob(path.Join(taskDir, "**/*.yaml"))
    if err == nil && len(yamlFiles) > 0 {
        log.Printf("Found yaml files but no project.yaml:")
        for _, f := range yamlFiles {
            log.Printf("  %s", f)
        }
    }

    // If we still can't find it, let's check what files we actually have
    log.Printf("Could not find project.yaml, showing all directory contents:")
    err = filepath.Walk(taskDir, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }
        rel, err := filepath.Rel(taskDir, path)
        if err != nil {
            rel = path
        }
        if info.IsDir() {
            log.Printf("  [DIR] %s", rel)
        } else {
            log.Printf("  [FILE] %s (%d bytes)", rel, info.Size())
        }
        return nil
    })
    if err != nil {
        log.Printf("Error walking directory: %v", err)
    }

    return "", fmt.Errorf("could not find project.yaml in extracted sources")
}




func (s *defaultCRSService) verifyDirectoryAccess(dir string) error {
    log.Printf("Verifying access to directory: %s", dir)
    
    // Check if directory exists
    info, err := os.Stat(dir)
    if err != nil {
        return fmt.Errorf("failed to stat directory: %v", err)
    }
    
    // Check if it's a directory
    if !info.IsDir() {
        return fmt.Errorf("path is not a directory: %s", dir)
    }
    
    // Check permissions
    log.Printf("Directory permissions: %v", info.Mode())
    
    // Try to read directory contents
    files, err := os.ReadDir(dir)
    if err != nil {
        return fmt.Errorf("failed to read directory: %v", err)
    }
    
    log.Printf("Directory contents:")
    for _, file := range files {
        info, err := file.Info()
        if err != nil {
            log.Printf("  %s (error getting info: %v)", file.Name(), err)
            continue
        }
        log.Printf("  %s (mode: %v, size: %d)", file.Name(), info.Mode(), info.Size())
    }
    
    return nil
}

// Helper function to analyze diff
func analyzeDiff(t models.TaskDetail, diffPath string) error {
    diffContent, err := os.ReadFile(diffPath)
    if err != nil {
        return fmt.Errorf("failed to read diff file: %v", err)
    }

    //send task detail to telemetry server 
    {
        ctx := context.Background()
        ctx, span := telemetry.StartSpan(ctx, "task_detail_diff")
        defer span.End()
        for key, value := range t.Metadata {
            span.SetAttributes(attribute.String(key, value))
        }
        span.SetAttributes(
            attribute.String("diff", string(diffContent)),
            attribute.String("project_name", t.ProjectName),
            attribute.String("focus", t.Focus),
        )
    }
    return nil
}

func (s *defaultCRSService) findFuzzers(fuzzerDir string) ([]string, error) {
    entries, err := os.ReadDir(fuzzerDir)
    if err != nil {
        return nil, fmt.Errorf("failed to read fuzzer directory: %v", err)
    }

    // List of known non-fuzzer executables to skip
    skipBinaries := map[string]bool{
        "jazzer_agent_deploy.jar": true,
        "jazzer_driver": true,
        "jazzer_driver_with_sanitizer": true,
        "jazzer_junit.jar": true,
        "llvm-symbolizer": true,
        "sancov":         true,  // coverage tool
        "clang":          true,
        "clang++":        true,
    }

    // File extensions to skip
    skipExtensions := map[string]bool{
		".bin": true,  // Skip .bin files
		".log": true,  // Skip log files
        ".class": true,  // Skip Java class files
        ".jar":   true,  // Skip Java JAR files (except specific fuzzer JARs)
		".zip": true,
		".dict": true,
		".options": true,
		".bc": true,
		".json": true,
        ".o":     true,  // Skip object files
        ".a":     true,  // Skip static libraries
        ".so":    true,  // Skip shared libraries (unless they're specifically fuzzers)
        ".h":     true,  // Skip header files
        ".c":     true,  // Skip source files
        ".cpp":   true,  // Skip source files
        ".java":  true,  // Skip Java source files
    }

    var fuzzers []string
    for _, entry := range entries {
        // Skip directories and non-executable files
        if entry.IsDir() {
            continue
        }
        
        name := entry.Name()
        
        // Skip files with extensions we want to ignore
        ext := filepath.Ext(name)
        if skipExtensions[ext] {
            continue
        }
        
        // Skip known non-fuzzer binaries
        if skipBinaries[name] {
            continue
        }
        
        info, err := entry.Info()
        if err != nil {
            continue
        }
        
        // Check if file is executable
        if info.Mode()&0111 != 0 {
            fuzzers = append(fuzzers, name)
        }
    }

    if len(fuzzers) == 0 {
        return nil, fmt.Errorf("no fuzzers found in %s", fuzzerDir)
    }
    
    // log.Printf("Found %d fuzzers in %s: %v", len(fuzzers), fuzzerDir, fuzzers)
    return fuzzers, nil
}

func extractCrashTrace(output string) string {
    var crashTrace string
    
    // Check for UndefinedBehaviorSanitizer errors
    runtimeErrorRegex := regexp.MustCompile(`(.*runtime error:.*)`)
    ubsanMatch := runtimeErrorRegex.FindStringSubmatch(output)
    
    if len(ubsanMatch) > 1 {
        // Found UBSan error
        ubsanError := strings.TrimSpace(ubsanMatch[1])
        crashTrace = "UndefinedBehaviorSanitizer Error: " + ubsanError + "\n\n"
        
        // Extract stack trace - lines starting with #
        stackRegex := regexp.MustCompile(`(?m)(#\d+.*)`)
        stackMatches := stackRegex.FindAllString(output, -1)
        
        if len(stackMatches) > 0 {
            crashTrace += "Stack Trace:\n"
            for _, line := range stackMatches {
                crashTrace += line + "\n"
            }
        }
        
        // Extract summary
        summaryRegex := regexp.MustCompile(`SUMMARY: UndefinedBehaviorSanitizer: (.*)`)
        summaryMatch := summaryRegex.FindStringSubmatch(output)
        if len(summaryMatch) > 1 {
            crashTrace += "\nSummary: " + summaryMatch[1] + "\n"
        }
    } else {
        // Fall back to the original ERROR: pattern
        errorIndex := strings.Index(output, "ERROR:")
        if errorIndex != -1 {
            crashTrace = output[errorIndex:]
        }
    }
    
    // Limit the size of the crash trace if it's too large
    const maxTraceSize = 10000
    if len(crashTrace) > maxTraceSize {
        crashTrace = crashTrace[:maxTraceSize] + "... (truncated)"
    }
    
    return crashTrace
}


// POVMetadata represents the metadata for a Proof of Vulnerability
type POVMetadata struct {
    FuzzerOutput string `json:"fuzzer_output"`
    BlobFile     string `json:"blob_file"`
    FuzzerName   string `json:"fuzzer_name"`
    Sanitizer    string `json:"sanitizer"`
    ProjectName  string `json:"project_name"`
}

// savePOVMetadata saves the POV metadata to a JSON file in the POV metadata directory
func (s *defaultCRSService) savePOVMetadata(taskDir, fuzzerPath, blobPath string, output string, taskDetail models.TaskDetail) error {
    fuzzDir := filepath.Dir(fuzzerPath)

    // Create POV metadata directory if it doesn't exist
    povMetadataDir := filepath.Join(fuzzDir, s.povMetadataDir)
    if err := os.MkdirAll(povMetadataDir, 0755); err != nil {
            // If regular creation fails due to permissions, try with sudo
        if os.IsPermission(err) {
            // log.Printf("Permission denied creating directory, attempting with sudo: %s", povMetadataDir)
            cmd := exec.Command("sudo", "mkdir", "-p", povMetadataDir)
            if sudoErr := cmd.Run(); sudoErr != nil {
                return fmt.Errorf("failed to create POV metadata directory with sudo: %v", sudoErr)
            }
            
            // Set permissions after sudo creation
            chmodCmd := exec.Command("sudo", "chmod", "0777", povMetadataDir)
            if chmodErr := chmodCmd.Run(); chmodErr != nil {
                return fmt.Errorf("failed to set permissions on POV metadata directory: %v", chmodErr)
            }

            // Make sure the directory is fully accessible to all users
            chmodCmd = exec.Command("sudo", "chmod", "a+rwx", povMetadataDir)
            if chmodErr := chmodCmd.Run(); chmodErr != nil {
                log.Printf("Warning: failed to set a+rwx permissions: %v", chmodErr)
            }
        }
    }
    
    // Extract fuzzer name and sanitizer from fuzzer path
    fuzzerName := filepath.Base(fuzzerPath)
    dirParts := strings.Split(fuzzDir, "-")
    sanitizer := dirParts[len(dirParts)-1] // Last part should be the sanitizer
    
    // Generate unique identifier for this POV
    timestamp := time.Now().Format("20060102-150405")
    uniqueID := fmt.Sprintf("%s-%s", timestamp, uuid.New().String()[:8])
    
    // Save the fuzzer output to a file
    outputFileName := fmt.Sprintf("fuzzer_output_%s.txt", uniqueID)
    outputFilePath := filepath.Join(povMetadataDir, outputFileName)
    if err := os.WriteFile(outputFilePath, []byte(output), 0644); err != nil {
        // If permission denied, try using sudo
        if os.IsPermission(err) {
            log.Printf("Permission denied writing file, attempting with sudo: %s", outputFilePath)
            
            // Create a temporary file first
            tempFile := "/tmp/fuzzer_output_temp"
            if tempErr := os.WriteFile(tempFile, []byte(output), 0644); tempErr != nil {
                return fmt.Errorf("failed to write temporary file: %v", tempErr)
            }
            
            // Use sudo to move the temp file to the target location
            cmd := exec.Command("sudo", "cp", tempFile, outputFilePath)
            if cpErr := cmd.Run(); cpErr != nil {
                return fmt.Errorf("failed to copy file with sudo: %v", cpErr)
            }
            
            // Set permissions on the new file
            chmodCmd := exec.Command("sudo", "chmod", "0644", outputFilePath)
            if chmodErr := chmodCmd.Run(); chmodErr != nil {
                return fmt.Errorf("failed to set permissions on file: %v", chmodErr)
            }
            
            // Clean up temp file
            os.Remove(tempFile)
            return nil
        }
        return fmt.Errorf("failed to save fuzzer output: %v", err)
    }
    
    // Copy the blob file to the POV metadata directory
    blobFileName := fmt.Sprintf("test_blob_%s.bin", uniqueID)
    blobDestPath := filepath.Join(povMetadataDir, blobFileName)
    blobData, err := os.ReadFile(blobPath)
    if err != nil {
        return fmt.Errorf("failed to read blob file: %v", err)
    }
    if err := os.WriteFile(blobDestPath, blobData, 0644); err != nil {
        return fmt.Errorf("failed to save blob file: %v", err)
    }
    
    // Create the metadata
    metadata := POVMetadata{
        FuzzerOutput: outputFileName,
        BlobFile:     blobFileName,
        FuzzerName:   fuzzerName,
        Sanitizer:    sanitizer,
        ProjectName:  taskDetail.ProjectName,
    }
    
    // Save metadata to JSON file
    metadataFileName := fmt.Sprintf("pov_metadata_%s.json", uniqueID)
    metadataFilePath := filepath.Join(povMetadataDir, metadataFileName)
    metadataJSON, err := json.MarshalIndent(metadata, "", "  ")
    if err != nil {
        return fmt.Errorf("failed to marshal metadata to JSON: %v", err)
    }
    if err := os.WriteFile(metadataFilePath, metadataJSON, 0644); err != nil {
        return fmt.Errorf("failed to save metadata file: %v", err)
    }
    
    log.Printf("Saved POV metadata to %s", metadataFilePath)
    return nil
}

func (s *defaultCRSService) saveAllCrashesAsPOVs(crashesDir, taskDir, fuzzerPath, fuzzDir, projectDir string, output string, sanitizer string, taskDetail models.TaskDetail, fuzzerName string) string {

    // Helper function to process crash files in a directory
    processCrashFiles := func(dir string) []string {
        var allCrashFiles []string
        
        // Try libFuzzer crash files
        libFuzzerPattern := path.Join(dir, "crash-*")
        log.Printf("Looking for libFuzzer crash files in: %s", libFuzzerPattern)
        
        if files, err := filepath.Glob(libFuzzerPattern); err == nil {
            allCrashFiles = append(allCrashFiles, files...)
        } else {
            log.Printf("Error finding libFuzzer crash files in %s: %v", dir, err)
        }

        // Try libFuzzer timeout files
        if os.Getenv("DETECT_TIMEOUT_CRASH") == "1" {
            libFuzzerPattern := path.Join(dir, "timeout-*")
            log.Printf("Looking for libFuzzer timeout files in: %s", libFuzzerPattern)
            
            if files, err := filepath.Glob(libFuzzerPattern); err == nil {
                allCrashFiles = append(allCrashFiles, files...)
            } else {
                log.Printf("Error finding libFuzzer timeout files in %s: %v", dir, err)
            }
        }

        return allCrashFiles
    }

    // Search in all directories
    var allFiles []string
    searchDirs := []string{crashesDir}
    for _, dir := range searchDirs {
        allFiles = append(allFiles, processCrashFiles(dir)...)
    }

    if len(allFiles) == 0 {
        log.Printf("No crash files found in crashes directory. Saving POV metadata with fuzzer output only...")
        
        // Create a temporary blob file with the output content
        tempBlobPath := filepath.Join(fuzzDir, "temp_crash_blob.bin")
        if err := os.WriteFile(tempBlobPath, []byte(output), 0644); err != nil {
            log.Printf("Error creating temporary blob file: %v", err)
            return ""
        }
        
        if err := s.savePOVMetadata(taskDir, fuzzerPath, tempBlobPath, output, taskDetail); err != nil {
            log.Printf("Warning: Failed to save POV metadata: %v", err)
        }
        
        // Clean up the temporary file
        os.Remove(tempBlobPath)
        return ""
    }

    log.Printf("Found total of %d crash files across all directories", len(allFiles))
    crash_output := ""
    confirmedCount := 0
    maxConfirmed := 5 // Maximum number of confirmed crashes to process
    processedFiles := make([]string, 0, len(allFiles))

    // Process each crash file
    for i, crashFile := range allFiles {
        log.Printf("Processing crash file %d/%d: %s", i+1, len(allFiles), crashFile)
        //TODO: make sure crashFile will lead to crashes, if not skip it
        crashed, output, err := s.runCrashTest(crashFile, taskDetail, taskDir, projectDir, fuzzerName, sanitizer)
        if err != nil {
            log.Printf("Error running crash test for %s: %v", crashFile, err)
            continue
        }
        processedFiles = append(processedFiles, crashFile)

        // If it crashed, save the POV metadata
        if crashed {
            confirmedCount++
            log.Printf("Confirmed crash for %s with fuzzer %s", crashFile, fuzzerName)
            crash_output = output
            if err := s.savePOVMetadata(taskDir, fuzzerPath, crashFile, output, taskDetail); err != nil {
                log.Printf("Warning: Failed to save POV metadata for crash file %s: %v", crashFile, err)
            }
            // Break the loop if we've reached the maximum number of confirmed crashes
            if confirmedCount >= maxConfirmed {
                log.Printf("Reached maximum number of confirmed crashes (%d). Stopping processing.", maxConfirmed)
                break
            }
        }
    }
    log.Printf("Processed %d/%d crash files, found %d confirmed crashes", 
              len(processedFiles), len(allFiles), confirmedCount)
    // Delete all crash files after processing
    // log.Printf("Cleaning up crash files...")
    var deleteErrors int = 0
    
    // Delete all files in the crashesDir
    filesToDelete, _ := filepath.Glob(filepath.Join(crashesDir, "*"))
    for _, file := range filesToDelete {
        // Check if it's a regular file, not a directory
        fileInfo, err := os.Stat(file)
        if err != nil || fileInfo.IsDir() {
            continue
        }
        
        if err := os.Remove(file); err != nil {
            // Try with sudo if permission denied
            if os.IsPermission(err) {
                cmd := exec.Command("sudo", "rm", file)
                if err := cmd.Run(); err != nil {
                    log.Printf("Failed to delete crash file %s: %v", file, err)
                    deleteErrors++
                }
            } else {
                log.Printf("Failed to delete crash file %s: %v", file, err)
                deleteErrors++
            }
        }
    }
    
    if deleteErrors > 0 {
        log.Printf("Warning: Failed to delete %d crash files", deleteErrors)
    } else {
        // log.Printf("Successfully deleted all crash files")
    }
    
    return crash_output
}

func (s *defaultCRSService) runCrashTest(crashFile string, taskDetail models.TaskDetail, taskDir, projectDir string, fuzzerName string, sanitizer string) (bool, string, error) {
    uniqueBlobName := filepath.Base(crashFile)    
    outDir := filepath.Join(taskDir, "fuzz-tooling", "build", "out", fmt.Sprintf("%s-%s", taskDetail.ProjectName, sanitizer))
    workDir := filepath.Join(taskDir, "fuzz-tooling", "build", "work", fmt.Sprintf("%s-%s", taskDetail.ProjectName, sanitizer))

    // Prepare docker command
    dockerArgs := []string{
        "run", "--rm",
        "--platform", "linux/amd64",
        "-e", "FUZZING_ENGINE=libfuzzer",
        "-e", fmt.Sprintf("SANITIZER=%s", sanitizer),
        // "-e", "UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1",
        "-e", "ARCHITECTURE=x86_64",
        "-e", fmt.Sprintf("PROJECT_NAME=%s", taskDetail.ProjectName),
        "-v", fmt.Sprintf("%s:/src/%s", projectDir, taskDetail.ProjectName),
        "-v", fmt.Sprintf("%s:/out", outDir),
        "-v", fmt.Sprintf("%s:/work", workDir),
        fmt.Sprintf("aixcc-afc/%s", taskDetail.ProjectName),
        fmt.Sprintf("/out/%s", fuzzerName),
        "-timeout=30",
        "-timeout_exitcode=99",
        fmt.Sprintf("/out/crashes/%s", uniqueBlobName),
    }
    
    // Create command
    cmd := exec.Command("docker", dockerArgs...)
    
    // Capture output
    var outBuf bytes.Buffer
    cmd.Stdout = &outBuf
    cmd.Stderr = &outBuf
    
    // Log the command being executed
    log.Printf("Running: docker %s", strings.Join(dockerArgs, " "))
    
    // Run the command
    err := cmd.Run()
    output := outBuf.String()
    
    // Check for crash regardless of command error (libfuzzer exits with non-zero on crash)
    if err != nil && s.isCrashOutput(output) {
        log.Printf("CrashFile %s works!", crashFile)
        return true, output, nil
    }
    // If there was an error but no crash detected, it's an error
    if err != nil {
        return false, output, fmt.Errorf("error running fuzzer: %v", err)
    }
    log.Printf("CrashFile %s fails to trigger a crash!", crashFile)
    // No crash found
    return false, output, nil
}

func (s *defaultCRSService) generateCrashSignatureAndSubmit(
    crashesDir string,
    fuzzDir string, 
    taskDir string,
    projectDir string,
    sanitizer string, 
    taskDetail models.TaskDetail, 
    fuzzer string, 
    output string,
    vulnSignature string,
) error {

    // Read crash data
    crashData := s.readCrashFile(fuzzDir)
    // Skip submission if crash file is empty
    if len(crashData) == 0 {
        log.Printf("Libfuzzer skipping submission for empty crash input data")
        return nil
    }

    encodedCrashData := base64.StdEncoding.EncodeToString(crashData)

    
    // 2. Submit to either the submission service (if in worker mode) or directly to the Competition API
    if s.submissionEndpoint != "" && s.workerIndex != "" {
        // We're in worker mode, submit to the submission service
        log.Printf("Libfuzzer Worker %s submitting POV for fuzzer %s with sanitizer %s to submission service", 
                    s.workerIndex, fuzzer, sanitizer)
        
        // Extract crash trace from the output
        crashTrace := extractCrashTrace(output)
        if crashTrace != "" {
            //check crash trace contains error in application code, not purely fuzzer
            //code pattern not totally reliable
            if strings.Contains(crashTrace, taskDetail.ProjectName) || strings.Contains(crashTrace, "apache")  || strings.Contains(crashTrace, "org") {
                log.Printf("Valid Crash Trace: %s", crashTrace)
            } else {
                //TODO ask AI to check 
                log.Printf("Libfuzzer skipping submission due to invalid crash trace (TODO better check): %s", crashTrace)
                return nil
            }
        } else {
            log.Printf("Libfuzzer skipping submission due to empty crash trace!")
            return nil
        }
        // Create the submission payload
        submission := map[string]interface{}{
            "task_id": taskDetail.TaskID.String(),
            "architecture": "x86_64",
            "engine": "libfuzzer",
            "fuzzer_name": fuzzer,
            "sanitizer": sanitizer,
            "testcase": encodedCrashData,
            "signature": fuzzer+"-"+vulnSignature,
            "strategy": "libfuzzer",
            "crash_trace": crashTrace,
        }


        var submissionURL string
        if !taskDetail.HarnessesIncluded {
            submissionURL = fmt.Sprintf("%s/v1/task/%s/freeform/pov/", s.submissionEndpoint, taskDetail.TaskID.String())
            submission["strategy"] = "libfuzzer-freeform"
            if srcAny, ok := s.unharnessedFuzzerSrc.Load(taskDetail.TaskID.String()); ok {
                srcPath := srcAny.(string)
                submission["fuzzer_file"] = srcPath
                if data, err := os.ReadFile(srcPath); err == nil {
                    submission["fuzzer_source"] = string(data)
                } else {
                    log.Printf("Warning: failed to read fuzzer source %s: %v", srcPath, err)
                    submission["fuzzer_source"] = ""
                }
            } else {
                submission["fuzzer_file"]   = ""
                submission["fuzzer_source"] = ""
                log.Printf("No unharnessed fuzzer source recorded for task %s", taskDetail.TaskID)
            }

            log.Printf("Submitting to freeform endpoint: %s", submissionURL)
        } else{
            submissionURL = fmt.Sprintf("%s/v1/task/%s/pov/", s.submissionEndpoint, taskDetail.TaskID.String())
            // Log the submission endpoint for debugging
            log.Printf("Submitting to endpoint: %s",submissionURL)
        }

        // Marshal the submission
        submissionJSON, err := json.Marshal(submission)
        if err != nil {
            return fmt.Errorf("failed to marshal submission: %v", err)
        }
        
        // Create HTTP client
        client := &http.Client{
            Timeout: 60 * time.Second,
        }

        // Implement retry logic with exponential backoff
        maxRetries := 3
        var lastErr error
        var resp *http.Response
        
        for attempt := 1; attempt <= maxRetries; attempt++ {
            log.Printf("Submission attempt %d of %d for fuzzer %s with sanitizer %s", 
                        attempt, maxRetries, fuzzer, sanitizer)
                
                                
            // Create the request
            req, err := http.NewRequest("POST", submissionURL, bytes.NewBuffer(submissionJSON))
            if err != nil {
                return fmt.Errorf("failed to create submission request: %v", err)
            }
            
            // Set headers
            req.Header.Set("Content-Type", "application/json")
            
            // Get API credentials from environment
            apiKeyID := os.Getenv("COMPETITION_API_KEY_ID")
            apiToken := os.Getenv("COMPETITION_API_KEY_TOKEN")
            if apiKeyID != "" && apiToken != "" {
                req.SetBasicAuth(apiKeyID, apiToken)
            } else {
                apiKeyID = os.Getenv("CRS_KEY_ID")
                apiToken = os.Getenv("CRS_KEY_TOKEN")
                req.SetBasicAuth(apiKeyID, apiToken)
            }
            
            // Send the request
            resp, err = client.Do(req)
            // If successful, break out of the retry loop
            if err == nil {
                break
            }

            // Store the last error
            lastErr = err
            log.Printf("Attempt %d failed: %v", attempt, err)
            
            // Don't sleep after the last attempt
            if attempt < maxRetries {
                // Exponential backoff: 1s, 2s, 4s, etc.
                backoffTime := time.Duration(1<<(attempt-1)) * time.Second
                log.Printf("Retrying in %v...", backoffTime)
                time.Sleep(backoffTime)
            }
        }

        // If all attempts failed, return the last error
        if lastErr != nil {
            log.Printf("All %d submission attempts failed: %v", maxRetries, lastErr)
            return fmt.Errorf("failed to submit to submission service after %d attempts: %v", 
                                maxRetries, lastErr)
        }

        defer resp.Body.Close()
        
        // Check response
        if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
            body, _ := io.ReadAll(resp.Body)
            log.Printf("submission service returned non-OK status: %d, body: %s", 
            resp.StatusCode, string(body))
            return fmt.Errorf("submission service returned non-OK status: %d, body: %s", 
                                resp.StatusCode, string(body))
        }
        
        log.Printf("Successfully submitted POV to submission service")
    } else { 
        // 3. Submit to Competition API using the client
        log.Printf("Submitting POV for fuzzer %s with sanitizer %s", fuzzer, sanitizer)
        _, err := s.competitionClient.SubmitPOV(
            taskDetail.TaskID.String(),
            fuzzer,
            sanitizer,
            crashData,
        )
        if err != nil {
            return fmt.Errorf("failed to submit POV: %v", err)
        }
    }

    return nil
}


// generateVulnerabilitySignature creates a unique signature for a vulnerability
// to identify duplicates based on the crash output and sanitizer
func (s *defaultCRSService) generateVulnerabilitySignature0(output string, sanitizer string) string {
    // This is a simplified implementation - you may want to enhance this
    // based on your specific needs and the structure of your crash outputs
    
    // Extract key information from the crash output based on sanitizer type
    var signature string
    
    switch sanitizer {
    case "address":
        // For AddressSanitizer, look for the crash location and type
        if loc := extractASANCrashLocation(output); loc != "" {
            signature = "ASAN:" + loc
        } else {
            // Fallback to a hash of the entire output
            signature = "ASAN:generic:" + hashString(output)
        }
        
    case "undefined":
        // For UndefinedBehaviorSanitizer
        if loc := extractUBSANCrashLocation(output); loc != "" {
            signature = "UBSAN:" + loc
        } else {
            signature = "UBSAN:generic:" + hashString(output)
        }
        
    case "memory":
        // For MemorySanitizer
        if loc := extractMSANCrashLocation(output); loc != "" {
            signature = "MSAN:" + loc
        } else {
            signature = "MSAN:generic:" + hashString(output)
        }
        
    default:
        // For other sanitizers or unknown types
        signature = sanitizer + ":generic:" + hashString(output)
    }
    log.Printf("Extracted signature: %s", signature)

    return signature
}

func (s *defaultCRSService) generateCrashSignature(output string, sanitizer string) string {
    // Extract the crash location from the stack trace
    crashLocation := extractCrashLocation(output, sanitizer)
    
    // If we couldn't extract a specific location, fall back to a hash
    if crashLocation != "" {
        return crashLocation
    }

    return s.generateVulnerabilitySignature0(output,sanitizer)
}

// extractCrashLocation extracts the crash location from the output
func extractCrashLocation(output string, sanitizer string) string {
    // Look for the #0 line in the stack trace which indicates the crash point
    lines := strings.Split(output, "\n")
    
    // First try to find the #0 line which is the most reliable indicator
    for _, line := range lines {
        line = strings.TrimSpace(line)
        if strings.HasPrefix(line, "#0 ") {
            // Extract the function and location after "in"
            parts := strings.SplitN(line, " in ", 2)
            if len(parts) < 2 {
                continue
            }
            
            // Get the function name and file location
            funcInfo := parts[1]
            
            // Clean up any extra information in parentheses
            if idx := strings.Index(funcInfo, " ("); idx != -1 {
                funcInfo = funcInfo[:idx]
            }
            
            // Remove column information (e.g., ":13" in "file.c:123:13")
            if lastColonIdx := strings.LastIndex(funcInfo, ":"); lastColonIdx != -1 {
                // Check if there's another colon before this one (for the line number)
                prevColonIdx := strings.LastIndex(funcInfo[:lastColonIdx], ":")
                if prevColonIdx != -1 {
                    // This is likely a column number, remove it
                    funcInfo = funcInfo[:lastColonIdx]
                }
            }

            return funcInfo
        }
    }
    
    // If we couldn't find a #0 line, look for sanitizer-specific patterns
    switch strings.ToLower(sanitizer) {
    case "address", "asan":
        return extractASANFallbackLocation(output)
    case "undefined", "ubsan":
        return extractUBSANFallbackLocation(output)
    case "memory", "msan":
        return extractMSANFallbackLocation(output)
    }
    
    // If all else fails, look for any file path with a line number
    for _, line := range lines {
        if strings.Contains(line, "/src/") && strings.Contains(line, ".c:") {
            // This might be a file reference
            re := regexp.MustCompile(`(/src/[^:]+:\d+)`)
            matches := re.FindStringSubmatch(line)
            if len(matches) > 0 {
                return matches[1]
            }
        }
    }
    
    return ""
}

// extractASANFallbackLocation extracts location from ASAN output if #0 line isn't found
func extractASANFallbackLocation(output string) string {
    // Look for "SUMMARY: AddressSanitizer: <type> <location>"
    summaryRegex := regexp.MustCompile(`SUMMARY: AddressSanitizer: \w+ ([^(]+)`)
    matches := summaryRegex.FindStringSubmatch(output)
    if len(matches) > 1 {
        return strings.TrimSpace(matches[1])
    }
    
    return ""
}

// extractUBSANFallbackLocation extracts location from UBSAN output
func extractUBSANFallbackLocation(output string) string {
    // Look for the file and line where UBSAN detected the issue
    ubsanRegex := regexp.MustCompile(`([^:]+:\d+:\d+): runtime error:`)
    matches := ubsanRegex.FindStringSubmatch(output)
    if len(matches) > 1 {
        return matches[1]
    }
    
    return ""
}

// extractMSANFallbackLocation extracts location from MSAN output
func extractMSANFallbackLocation(output string) string {
    // Look for "WARNING: MemorySanitizer: <description> <location>"
    msanRegex := regexp.MustCompile(`MemorySanitizer:.*? at ([^:]+:\d+)`)
    matches := msanRegex.FindStringSubmatch(output)
    if len(matches) > 1 {
        return matches[1]
    }
    
    return ""
}

// Helper functions to extract crash locations from different sanitizer outputs

func extractASANCrashLocation(output string) string {
    // Look for common AddressSanitizer patterns
    // Example: "ERROR: AddressSanitizer: heap-buffer-overflow on address 0x614000000074"
    
    // This is a simplified implementation - you would want to enhance this
    // with more sophisticated regex patterns based on your actual crash outputs
    
    // Look for the crash type and function
    typeRegex := regexp.MustCompile(`AddressSanitizer: ([a-zA-Z0-9_-]+)`)
    funcRegex := regexp.MustCompile(`in ([a-zA-Z0-9_]+) .*`)
    
    var crashType, crashFunc string
    
    if matches := typeRegex.FindStringSubmatch(output); len(matches) > 1 {
        crashType = matches[1]
    }
    
    if matches := funcRegex.FindStringSubmatch(output); len(matches) > 1 {
        crashFunc = matches[1]
    }
    
    if crashType != "" && crashFunc != "" {
        return crashType + ":" + crashFunc
    } else if crashType != "" {
        return crashType
    }
    
    return ""
}

func extractUBSANCrashLocation(output string) string {
    // Similar implementation for UndefinedBehaviorSanitizer
    typeRegex := regexp.MustCompile(`runtime error: ([a-zA-Z0-9_-]+)`)
    funcRegex := regexp.MustCompile(`in ([a-zA-Z0-9_]+) .*`)
    
    var crashType, crashFunc string
    
    if matches := typeRegex.FindStringSubmatch(output); len(matches) > 1 {
        crashType = matches[1]
    }
    
    if matches := funcRegex.FindStringSubmatch(output); len(matches) > 1 {
        crashFunc = matches[1]
    }
    
    if crashType != "" && crashFunc != "" {
        return crashType + ":" + crashFunc
    } else if crashType != "" {
        return crashType
    }
    
    return ""
}

func extractMSANCrashLocation(output string) string {
    // Similar implementation for MemorySanitizer
    typeRegex := regexp.MustCompile(`MemorySanitizer: ([a-zA-Z0-9_-]+)`)
    funcRegex := regexp.MustCompile(`in ([a-zA-Z0-9_]+) .*`)
    
    var crashType, crashFunc string
    
    if matches := typeRegex.FindStringSubmatch(output); len(matches) > 1 {
        crashType = matches[1]
    }
    
    if matches := funcRegex.FindStringSubmatch(output); len(matches) > 1 {
        crashFunc = matches[1]
    }
    
    if crashType != "" && crashFunc != "" {
        return crashType + ":" + crashFunc
    } else if crashType != "" {
        return crashType
    }
    
    return ""
}

// hashString creates a hash of a string for use in signatures
func hashString(s string) string {
    h := sha256.New()
    h.Write([]byte(s))
    return fmt.Sprintf("%x", h.Sum(nil))[:16] // Use first 16 chars of hash for brevity
}

func loadProjectConfig(projectYAMLPath string) (*ProjectConfig, error) {
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


// Global map to hold a mutex for each taskDir being processed for cloning
var (
	taskDirCloningLocks     = make(map[string]*sync.Mutex)
	taskDirCloningLocksMu sync.Mutex // Mutex to protect access to the taskDirCloningLocks map
)

// Helper function to get or create a mutex for a given taskDir's cloning operations
func getCloningLockForTaskDir(taskDir string) *sync.Mutex {
	taskDirCloningLocksMu.Lock()
	defer taskDirCloningLocksMu.Unlock()

	lock, exists := taskDirCloningLocks[taskDir]
	if !exists {
		lock = &sync.Mutex{}
		taskDirCloningLocks[taskDir] = lock
	}
	return lock
}

// Helper function to execute a command and stream its output (remains the same)
func runCommandAndStreamOutput(cmd *exec.Cmd, commandDesc string) error {
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdout pipe for %s: %v", commandDesc, err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to get stderr pipe for %s: %v", commandDesc, err)
	}

	fmt.Printf("[Go INFO] Running command: %s %v\n", cmd.Path, cmd.Args)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start %s: %v", commandDesc, err)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stdoutPipe)
		for scanner.Scan() {
			fmt.Printf("[%s STDOUT]: %s\n", commandDesc, scanner.Text())
		}
	}()
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			fmt.Printf("[%s STDERR]: %s\n", commandDesc, scanner.Text())
		}
	}()

	err = cmd.Wait()
	wg.Wait() // Ensure all output is flushed
	if err != nil {
		return fmt.Errorf("%s command failed: %v", commandDesc, err)
	}
	fmt.Printf("[Go INFO] %s command completed successfully.\n", commandDesc)
	return nil
}

func generateFuzzerForUnharnessedTask(taskDir, focus, sanitizerDir, projectName, sanitizer string) (string, string, error) {

	pyScript := "/app/strategy/jeff/generate_fuzzer.py"

	args := []string{
		"--task_dir", taskDir,
		"--focus", focus,
		"--sanitizer_dir", sanitizerDir,
		"--project_name", projectName,
		"--sanitizer", sanitizer,
	}

	pyArgs := append([]string{pyScript}, args...)
	pythonInterpreter := "/tmp/crs_venv/bin/python3"

	runCmd := exec.Command(pythonInterpreter, pyArgs...)

    	// --- Print the command string for debugging ---
	var cmdStringBuilder strings.Builder
	cmdStringBuilder.WriteString(runCmd.Path) // The interpreter
	for _, arg := range runCmd.Args[1:] { // runCmd.Args[0] is the command itself (already added by runCmd.Path essentially)
		cmdStringBuilder.WriteString(" ")
		if strings.Contains(arg, " ") { // Quote arguments with spaces
			cmdStringBuilder.WriteString("\"")
			cmdStringBuilder.WriteString(arg)
			cmdStringBuilder.WriteString("\"")
		} else {
			cmdStringBuilder.WriteString(arg)
		}
	}
	fmt.Printf("[Go DEBUG] Python command to execute: %s\n", cmdStringBuilder.String())

	runCmd.Env = append(os.Environ(),
		"VIRTUAL_ENV=/tmp/crs_venv",
		"PATH=/tmp/crs_venv/bin:"+os.Getenv("PATH"),
		"PYTHONUNBUFFERED=1", // This is crucial for real-time output from Python
	)

	stdoutPipe, err := runCmd.StdoutPipe()
	if err != nil {
		return "", "", fmt.Errorf("failed to get stdout pipe: %v", err)
	}
	stderrPipe, err := runCmd.StderrPipe()
	if err != nil {
		return "", "", fmt.Errorf("failed to get stderr pipe: %v", err)
	}

	// To store all output lines and get the last one later
	var allOutputLines []string
	var outputMutex sync.Mutex // To safely append to allOutputLines

	// Start the command
	if err := runCmd.Start(); err != nil {
		return "", "", fmt.Errorf("failed to start generate_fuzzer.py: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(2) // For a goroutine for stdout and one for stderr

	// Goroutine to read and print stdout in real-time
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stdoutPipe)
		for scanner.Scan() {
			line := scanner.Text()
			fmt.Printf("[Python STDOUT %s-%s]: %s\n", projectName, sanitizer, line) // Print to Go's stdout
			outputMutex.Lock()
			allOutputLines = append(allOutputLines, line)
			outputMutex.Unlock()
		}
		if err := scanner.Err(); err != nil && err != io.EOF {
			fmt.Fprintf(os.Stderr, "[Go Error] reading python stdout: %v\n", err)
		}
	}()

	// Goroutine to read and print stderr in real-time
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			line := scanner.Text()
			fmt.Printf("[Python STDERR %s-%s]: %s\n", projectName, sanitizer, line) // Print to Go's stdout (or os.Stderr if you prefer)
			outputMutex.Lock()
			allOutputLines = append(allOutputLines, line) // Also capture stderr lines if needed for "last line" logic
			outputMutex.Unlock()
		}
		if err := scanner.Err(); err != nil && err != io.EOF {
			fmt.Fprintf(os.Stderr, "[Go Error] reading python stderr: %v\n", err)
		}
	}()

	// Wait for the command to finish
	err = runCmd.Wait()
	wg.Wait() // Wait for scanner goroutines to finish

	if err != nil {
		// Construct an error message from the collected stderr or all output if needed
		// For simplicity, we'll just use the err from runCmd.Wait() which includes exit status
		// and assume critical errors from Python were printed to its stderr (and thus to Go's stdout by the goroutine)
		return "", "", fmt.Errorf("generate_fuzzer.py failed: %v. See above logs for details", err)
	}

	outputMutex.Lock()
	defer outputMutex.Unlock()

	if len(allOutputLines) == 0 {
		return "", "", fmt.Errorf("empty output from generate_fuzzer.py!")
	}

    // collect the **last two** non-empty lines (expected order: src, bin)
    var paths []string
    for i := len(allOutputLines) - 1; i >= 0 && len(paths) < 2; i-- {
        if trimmed := strings.TrimSpace(allOutputLines[i]); trimmed != "" {
            paths = append(paths, trimmed)
        }
    }
    if len(paths) < 2 {
        return "", "", fmt.Errorf("expected two path lines from generate_fuzzer.py, got %d", len(paths))
    }
    // paths[0] = last line  → binary/output
    // paths[1] = line before → source file
    return paths[1], paths[0], nil
}

func cloneOssFuzzAndMainRepoOnce(taskDir, projectName, sanitizerDir string) error {

    // Acquire lock for this specific taskDir to synchronize cloning operations
	cloningLock := getCloningLockForTaskDir(taskDir)
	cloningLock.Lock()
	fmt.Printf("[Go INFO] Acquired cloning lock for taskDir: %s\n", taskDir)
	defer func() {
		cloningLock.Unlock()
		fmt.Printf("[Go INFO] Released cloning lock for taskDir: %s\n", taskDir)
	}()

    if _, err := os.Stat(sanitizerDir); os.IsNotExist(err) {
        fmt.Printf("[Go INFO] Sanitizer directory %s not found. Creating... (taskDir: %s)\n", sanitizerDir, taskDir)
        if errMkdir := os.MkdirAll(sanitizerDir, 0755); errMkdir != nil {
            // Release lock before returning error if MkdirAll fails, as it's not a shared resource issue
            // cloningLock.Unlock() // Consider if this specific error should bypass the main defer
            // fmt.Printf("[Go INFO] Released cloning lock for taskDir: %s due to sanitizerDir creation error\n", taskDir)
            return fmt.Errorf("failed to create sanitizer directory %s for taskDir %s: %v", sanitizerDir, taskDir, errMkdir)
        }
        fmt.Printf("[Go INFO] Successfully created sanitizer directory %s (taskDir: %s)\n", sanitizerDir, taskDir)
    } else if err != nil {
        // Release lock before returning error if Stat fails for sanitizerDir
        // cloningLock.Unlock()
        // fmt.Printf("[Go INFO] Released cloning lock for taskDir: %s due to sanitizerDir stat error\n", taskDir)
        return fmt.Errorf("failed to stat sanitizer directory %s for taskDir %s: %v", sanitizerDir, taskDir, err)
    } else {
        fmt.Printf("[Go INFO] Sanitizer directory %s already exists. (taskDir: %s)\n", sanitizerDir, taskDir)
    }

	// 1. Define paths
	ossFuzzDir := filepath.Join(taskDir, "oss-fuzz")
	mainRepoDir := filepath.Join(taskDir, "main_repo")

	// 2. Clone OSS-Fuzz if it doesn't exist
	// This block is now protected by cloningLock
	if _, err := os.Stat(ossFuzzDir); os.IsNotExist(err) {
		fmt.Printf("[Go INFO] OSS-Fuzz directory %s not found. Cloning (taskDir: %s)...\n", ossFuzzDir, taskDir)
		cmd := exec.Command("git", "clone", "--depth", "1", "https://github.com/google/oss-fuzz", ossFuzzDir)
		if errCmd := runCommandAndStreamOutput(cmd, "git-clone-oss-fuzz"); errCmd != nil {
			return fmt.Errorf("failed to clone OSS-Fuzz for taskDir %s: %v", taskDir, errCmd)
		}
	} else if err != nil {
		return fmt.Errorf("failed to stat OSS-Fuzz directory %s for taskDir %s: %v", ossFuzzDir, taskDir, err)
	} else {
		fmt.Printf("[Go INFO] OSS-Fuzz directory %s already exists. Skipping clone (taskDir: %s).\n", ossFuzzDir, taskDir)
        return nil
	}

	// 3. Read project.yaml to get main_repo URL
	// This block is also protected by cloningLock
	projectYamlPath := filepath.Join(ossFuzzDir, "projects", projectName, "project.yaml")
	var cfg ProjectConfig
	var mainRepoURL string
	maxYamlAttempts := 3
	yamlAttemptDelay := 5 * time.Second

    for attempt := 0; attempt < maxYamlAttempts; attempt++ {
		if _, err := os.Stat(projectYamlPath); err == nil {
			yamlFile, errFile := os.ReadFile(projectYamlPath)
			if errFile != nil {
				// If reading fails even if file exists (e.g. mid-clone by another process that failed partially before this lock), error out
				return fmt.Errorf("failed to read %s on attempt %d (taskDir: %s): %v", projectYamlPath, attempt+1, taskDir, errFile)
			}
			errUnmarshal := yaml.Unmarshal(yamlFile, &cfg)
			if errUnmarshal != nil {
				return fmt.Errorf("failed to unmarshal %s on attempt %d (taskDir: %s): %v", projectYamlPath, attempt+1, taskDir, errUnmarshal)
			}
			mainRepoURL = cfg.MainRepo
			if mainRepoURL == "" {
				// If main_repo is empty, it's a config error, no point retrying this specific step
				return fmt.Errorf("main_repo URL is empty in %s on attempt %d (taskDir: %s)", projectYamlPath, attempt+1, taskDir)
			}
			fmt.Printf("[Go INFO] Successfully loaded and parsed %s on attempt %d. Main repo URL: %s (taskDir: %s)\n", projectYamlPath, attempt+1, mainRepoURL, taskDir)
			break 
		} else if os.IsNotExist(err) {
			fmt.Printf("[Go INFO] Attempt %d/%d: %s not found. Waiting %s (taskDir: %s)...\n", attempt+1, maxYamlAttempts, projectYamlPath, yamlAttemptDelay, taskDir)
			if attempt < maxYamlAttempts-1 {
				time.Sleep(yamlAttemptDelay)
			} else {
				return fmt.Errorf("failed to find %s after %d attempts (taskDir: %s): %v", projectYamlPath, maxYamlAttempts, taskDir, err)
			}
		} else { 
			return fmt.Errorf("failed to stat %s on attempt %d (taskDir: %s): %v", projectYamlPath, attempt+1, taskDir, err)
		}
	}
    if mainRepoURL == "" {
        return fmt.Errorf("critical: could not determine main_repo URL from %s after all attempts (taskDir: %s)", projectYamlPath, taskDir)
    }

    	// 4. Clone Main Repo if it doesn't exist
	// This block is also protected by cloningLock
	if _, err := os.Stat(mainRepoDir); os.IsNotExist(err) {
		fmt.Printf("[Go INFO] Main project repository directory %s not found. Cloning from %s (taskDir: %s)...\n", mainRepoDir, mainRepoURL, taskDir)
		cmd := exec.Command("git", "clone", "--depth", "1", mainRepoURL, mainRepoDir)
		if errCmd := runCommandAndStreamOutput(cmd, "git-clone-main-repo"); errCmd != nil {
			return fmt.Errorf("failed to clone main project repository for taskDir %s: %v", taskDir, errCmd)
		}
	} else if err != nil {
		return fmt.Errorf("failed to stat main project repository directory %s for taskDir %s: %v", mainRepoDir, taskDir, err)
	} else {
		fmt.Printf("[Go INFO] Main project repository directory %s already exists. Skipping clone (taskDir: %s).\n", mainRepoDir, taskDir)
        return nil
	}

	// Cloning and setup part is done, lock will be released by defer.
	fmt.Printf("[Go INFO] Repository setup complete for taskDir: %s. Proceeding to call Python script.\n", taskDir)
    return nil
}

// Inside the loop: for _, sanitizer := range cfg.Sanitizers { ... }
func (s *defaultCRSService) buildFuzzersDocker(myFuzzer *string, taskDir, projectDir, sanitizerDir string, sanitizer string, language string, taskDetail models.TaskDetail) error {
    // Create a sanitizer-specific copy of the project directory
    sanitizerProjectDir := fmt.Sprintf("%s-%s", projectDir, sanitizer)

    // Create the directory if it doesn't exist
    if err := os.MkdirAll(sanitizerProjectDir, 0755); err != nil {
        return fmt.Errorf("failed to create sanitizer-specific project directory: %v", err)
    }
    
    // Copy the project files to the sanitizer-specific directory
    // Using cp command for simplicity and to handle hidden files
    cpCmd := exec.Command("cp", "-r", fmt.Sprintf("%s/.", projectDir), sanitizerProjectDir)
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
        // This handles cases where the patch needs to be in the project directory
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
    
    if *myFuzzer == UNHARNESSED && sanitizer!="coverage" {
        log.Printf("Handling unharnessed task: %s", *myFuzzer)
        //TODO git clone oss-fuzz and main repo, avoid race condition
        cloneOssFuzzAndMainRepoOnce(taskDir,taskDetail.ProjectName, sanitizerDir)

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
        //for both Java and C tasks on worker
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
                // Mount the original source directory
                "-v", fmt.Sprintf("%s:/src/%s", sanitizerProjectDir, taskDetail.ProjectName),
                // Mount your output directory (e.g., /out)
                "-v", fmt.Sprintf("%s:/out", sanitizerDir),
                // Mount a work directory
                "-v", fmt.Sprintf("%s:/work", workDir),
                "-t", fmt.Sprintf("aixcc-afc/%s", taskDetail.ProjectName),
            }
            
            // log.Printf("Running Docker command: %v", cmdArgs)
            
            buildCmd := exec.Command("docker", cmdArgs...)

            // Optional: set the buildCmd working directory if you want
            // buildCmd.Dir = projectDir

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
    // log.Printf("Build fuzzer output:\n%s", buildOutput.String())
    return nil
}

// checkSudoAvailable checks if sudo is available on the system
func checkSudoAvailable() bool {
    // Try to find sudo in PATH
    _, err := exec.LookPath("sudo")
    if err != nil {
        return false
    }
    
    // Optionally, check if we can actually use sudo
    cmd := exec.Command("sudo", "-n", "true")
    err = cmd.Run()
    return err == nil
}

func getEffectiveUserID() int {
    // This is a Unix-specific function, so we need to handle
    // cross-platform compatibility
    if runtime.GOOS == "windows" {
        // On Windows, we can't easily check if we're admin
        // Just return a non-zero value
        return 1
    }
    
    // For Unix systems, we can use the syscall package
    return syscall.Geteuid()
}

func (s *defaultCRSService) runSarifPOVStrategies(myFuzzer, taskDir, sarifFilePath string, language string, taskDetail *models.TaskDetail,    timeout int,
    phase int) bool {
    // Find all strategy files under /app/strategy/
    strategyDir := "/app/strategy"
    strategyFilePattern := "sarif_pov*.py"
    strategyFiles, err := filepath.Glob(filepath.Join(strategyDir, "**", strategyFilePattern))
    if err != nil {
        log.Printf("Failed to find strategy files: %v", err)
        return false
    }

    if len(strategyFiles) == 0 {
        log.Printf("No Sarif POV strategy files found in %s", strategyDir)
        return false
    }

    log.Printf("Found %d Sarif POV strategy files: %v", len(strategyFiles), strategyFiles)

    povSuccess := false
    var successMutex sync.Mutex
    var wg sync.WaitGroup

    for _, strategyFile := range strategyFiles {
        wg.Add(1)
        go func(strategyPath string) {
            defer wg.Done()
            strategyName := filepath.Base(strategyPath)
            log.Printf("Running Sarif POV strategy: %s", strategyPath)

            pythonInterpreter := "/tmp/crs_venv/bin/python3"
            isRoot := getEffectiveUserID() == 0
            hasSudo := checkSudoAvailable()
            maxIterations := 5

            log.Printf("Setting max iterations to %d", maxIterations)

            args := []string{
                strategyPath,
                myFuzzer,
                sarifFilePath,
                taskDetail.ProjectName,
                taskDetail.Focus,
                language,
                "--model", s.model,
                "--do-patch=false",
                "--pov-metadata-dir", s.povAdvcancedMetadataDir,
                "--check-patch-success",
                fmt.Sprintf("--fuzzing-timeout=%d", timeout),
                fmt.Sprintf("--pov-phase=%d", phase),
                fmt.Sprintf("--max-iterations=%d", maxIterations),
            }

            var runCmd *exec.Cmd
            if isRoot {
                runCmd = exec.Command(pythonInterpreter, args...)
            } else if hasSudo {
                sudoArgs := append([]string{"-E", pythonInterpreter}, args...)
                runCmd = exec.Command("sudo", sudoArgs...)
            } else {
                log.Printf("Warning: Not running as root and sudo not available. Trying direct execution.")
                runCmd = exec.Command(pythonInterpreter, args...)
            }

            log.Printf("[SARIF-POV] Executing: %s", runCmd.String())

            runCmd.Dir = taskDir
            runCmd.Env = append(os.Environ(),
                "VIRTUAL_ENV=/tmp/crs_venv",
                "PATH=/tmp/crs_venv/bin:"+os.Getenv("PATH"),
                fmt.Sprintf("SUBMISSION_ENDPOINT=%s", s.submissionEndpoint),
                fmt.Sprintf("TASK_ID=%s", taskDetail.TaskID.String()),
                fmt.Sprintf("CRS_KEY_ID=%s", os.Getenv("CRS_KEY_ID")),
                fmt.Sprintf("CRS_KEY_TOKEN=%s", os.Getenv("CRS_KEY_TOKEN")),
                fmt.Sprintf("COMPETITION_API_KEY_ID=%s", os.Getenv("COMPETITION_API_KEY_ID")),
                fmt.Sprintf("COMPETITION_API_KEY_TOKEN=%s", os.Getenv("COMPETITION_API_KEY_TOKEN")),
                fmt.Sprintf("WORKER_INDEX=%s", s.workerIndex),
                fmt.Sprintf("ANALYSIS_SERVICE_URL=%s", s.analysisServiceUrl),
                "PYTHONUNBUFFERED=1",
            )

            // If we generated an unharnessed fuzzer for this task, pass its source path.
            if srcAny, ok := s.unharnessedFuzzerSrc.Load(taskDetail.TaskID.String()); ok {
                runCmd.Env = append(runCmd.Env,
                    fmt.Sprintf("NEW_FUZZER_SRC_PATH=%s", srcAny.(string)))
            }

            // --- Streaming logs setup ---
            stdoutPipe, err := runCmd.StdoutPipe()
            if err != nil {
                log.Printf("Failed to create stdout pipe: %v", err)
                return
            }
            stderrPipe, err := runCmd.StderrPipe()
            if err != nil {
                log.Printf("Failed to create stderr pipe: %v", err)
                return
            }

            if err := runCmd.Start(); err != nil {
                log.Printf("Failed to start strategy %s: %v", strategyName, err)
                return
            }

            var outputLines []string
            var outputMutex sync.Mutex

            // Stream stdout
            go func() {
                scanner := bufio.NewScanner(stdoutPipe)
                for scanner.Scan() {
                    line := scanner.Text()
                    log.Printf("[SARIF][%s Phase-%d] %s", strategyName, phase, line)
                    outputMutex.Lock()
                    outputLines = append(outputLines, line)
                    outputMutex.Unlock()
                }
            }()
            // Stream stderr
            go func() {
                scanner := bufio.NewScanner(stderrPipe)
                for scanner.Scan() {
                    line := scanner.Text()
                    log.Printf("[SARIF ERR][%s Phase-%d] %s", strategyName, phase, line)
                    outputMutex.Lock()
                    outputLines = append(outputLines, line)
                    outputMutex.Unlock()
                }
            }()

            startTime := time.Now()
            err = runCmd.Wait()
            duration := time.Since(startTime)

            // Combine all output for POV SUCCESS detection
            outputMutex.Lock()
            combinedOutput := strings.Join(outputLines, "\n")
            outputMutex.Unlock()

            if err != nil {
                log.Printf("Sarif POV Strategy %s failed after %v: %v", strategyName, duration, err)
            } else {
                log.Printf("Sarif POV Strategy %s completed successfully in %v", strategyName, duration)
                successMutex.Lock()
                if strings.Contains(combinedOutput, "POV SUCCESS!") {
                    log.Printf("Sarif POV Strategy %s POV successful!", strategyName)
                    povSuccess = true
                } 
                successMutex.Unlock()
            }
        }(strategyFile)
    }

    wg.Wait()
    return povSuccess
}
func (s *defaultCRSService) runXPatchSarifStrategies(myFuzzer, taskDir, sarifFilePath string, language string, taskDetail models.TaskDetail,
	deadlineTime time.Time) bool {

    log.Printf("runXPatchSarifStrategies: starting patch attempt with sarif "+
    "(task type: %s)", taskDetail.Type)

    strategyDir := "/app/strategy"
    strategyFilePattern := "xpatch_sarif.py"
    strategyFiles, err := filepath.Glob(filepath.Join(strategyDir, "**", strategyFilePattern))
    if err != nil {
        log.Printf("Failed to find strategy files: %v", err)
        return false
    }

    if len(strategyFiles) == 0 {
        log.Printf("No XPATCH Sarif strategy files found in %s", strategyDir)
        return false
    }

    log.Printf("Found %d XPATCH Sarif strategy files: %v", len(strategyFiles), strategyFiles)

    patchSuccess := false
    // Calculate patching timeout based on deadline
    remainingMinutes := int(time.Until(deadlineTime).Minutes())
    // Reserve 5 minutes as safety buffer
    patchingTimeout := remainingMinutes - 5
    if patchingTimeout < 5 {
        patchingTimeout = 5
    }

    patchWorkDir := filepath.Join(taskDir, s.patchWorkDir)


    var successMutex sync.Mutex
    var wg sync.WaitGroup

    for _, strategyFile := range strategyFiles {
        wg.Add(1)
        go func(strategyPath string) {
            defer wg.Done()
            strategyName := filepath.Base(strategyPath)
            log.Printf("Running XPATCH Sarif strategy: %s", strategyPath)

            pythonInterpreter := "/tmp/crs_venv/bin/python3"
            isRoot := getEffectiveUserID() == 0
            hasSudo := checkSudoAvailable()
            maxIterations := 5

            log.Printf("Setting max iterations to %d", maxIterations)

            args := []string{
                strategyPath,
                myFuzzer,
                sarifFilePath,
                taskDetail.ProjectName,
                taskDetail.Focus,
                language,
                "--model", s.model,
                fmt.Sprintf("--patching-timeout=%d", patchingTimeout),
                "--patch-workspace-dir", patchWorkDir,
            }

            var runCmd *exec.Cmd
            if isRoot {
                runCmd = exec.Command(pythonInterpreter, args...)
            } else if hasSudo {
                sudoArgs := append([]string{"-E", pythonInterpreter}, args...)
                runCmd = exec.Command("sudo", sudoArgs...)
            } else {
                log.Printf("Warning: Not running as root and sudo not available. Trying direct execution.")
                runCmd = exec.Command(pythonInterpreter, args...)
            }

            log.Printf("[XPATCH-SARIF] Executing: %s", runCmd.String())


            runCmd.Dir = taskDir
            runCmd.Env = append(os.Environ(),
                "VIRTUAL_ENV=/tmp/crs_venv",
                "PATH=/tmp/crs_venv/bin:"+os.Getenv("PATH"),
                fmt.Sprintf("SUBMISSION_ENDPOINT=%s", s.submissionEndpoint),
                fmt.Sprintf("TASK_ID=%s", taskDetail.TaskID.String()),
                fmt.Sprintf("CRS_KEY_ID=%s", os.Getenv("CRS_KEY_ID")),
                fmt.Sprintf("CRS_KEY_TOKEN=%s", os.Getenv("CRS_KEY_TOKEN")),
                fmt.Sprintf("COMPETITION_API_KEY_ID=%s", os.Getenv("COMPETITION_API_KEY_ID")),
                fmt.Sprintf("COMPETITION_API_KEY_TOKEN=%s", os.Getenv("COMPETITION_API_KEY_TOKEN")),
                fmt.Sprintf("WORKER_INDEX=%s", s.workerIndex),
                fmt.Sprintf("ANALYSIS_SERVICE_URL=%s", s.analysisServiceUrl),
                "PYTHONUNBUFFERED=1",
            )

            // --- Streaming logs setup ---
            stdoutPipe, err := runCmd.StdoutPipe()
            if err != nil {
                log.Printf("Failed to create stdout pipe: %v", err)
                return
            }
            stderrPipe, err := runCmd.StderrPipe()
            if err != nil {
                log.Printf("Failed to create stderr pipe: %v", err)
                return
            }

            if err := runCmd.Start(); err != nil {
                log.Printf("Failed to start strategy %s: %v", strategyName, err)
                return
            }

            var outputLines []string
            var outputMutex sync.Mutex

            // Stream stdout
            go func() {
                scanner := bufio.NewScanner(stdoutPipe)
                for scanner.Scan() {
                    line := scanner.Text()
                    log.Printf("[XPATCH-SARIF][%s] %s", strategyName, line)
                    outputMutex.Lock()
                    outputLines = append(outputLines, line)
                    outputMutex.Unlock()
                }
            }()
            // Stream stderr
            go func() {
                scanner := bufio.NewScanner(stderrPipe)
                for scanner.Scan() {
                    line := scanner.Text()
                    log.Printf("[XPATCH-SARIF ERR][%s] %s", strategyName, line)
                    outputMutex.Lock()
                    outputLines = append(outputLines, line)
                    outputMutex.Unlock()
                }
            }()

            startTime := time.Now()
            err = runCmd.Wait()
            duration := time.Since(startTime)

            outputMutex.Lock()
            combinedOutput := strings.Join(outputLines, "\n")
            outputMutex.Unlock()

            if err != nil {
                log.Printf("XPATCH-Sarif Strategy %s failed after %v: %v", strategyName, duration, err)
            } else {
                log.Printf("XPATCH-Sarif Strategy %s completed successfully in %v", strategyName, duration)
                successMutex.Lock()
                if strings.Contains(combinedOutput, "PATCH SUCCESS!") {
                    log.Printf("XPATCH-Sarif Strategy %s successful!", strategyName)
                    patchSuccess = true
                } 
                successMutex.Unlock()
            }
        }(strategyFile)
    }

    wg.Wait()
    return patchSuccess
}
func (s *defaultCRSService) runAdvancedPOVStrategiesWithTimeout(
    myFuzzer, taskDir string,
    projectDir string,
    language string,
    taskDetail models.TaskDetail,
    fullTask models.Task,
	timeoutMinutes int, 
    phase int,
    roundNum int,
) bool {
    strategyDir := "/app/strategy"
    strategyFilePattern := "as*_delta.py"
    if taskDetail.Type == "full" {
        strategyFilePattern = "as*_full.py"
    }
    strategyFiles, err := filepath.Glob(filepath.Join(strategyDir, "**", strategyFilePattern))
    if err != nil {
        log.Printf("Failed to find strategy files: %v", err)
        return false
    }

    if len(strategyFiles) == 0 {
        log.Printf("No strategy files found in %s", strategyDir)
        return false
    }

    log.Printf("Found %d strategy files: %v", len(strategyFiles), strategyFiles)

    povSuccess := false
    var successMutex sync.Mutex
    var wg sync.WaitGroup

    parentCtx := context.Background()

    for _, strategyFile := range strategyFiles {
        wg.Add(1)
        go func(strategyPath string) {
            defer wg.Done()
			strategyName := filepath.Base(strategyPath)

			// --- Per-Strategy Timeout Context ---
			strategyTimeout := time.Duration(timeoutMinutes) * time.Minute
			if strategyTimeout <= 0 {
				log.Printf("[POV Round-%d Phase-%d] Invalid timeout %v for %s, skipping", roundNum, phase, strategyTimeout, strategyName)
				return
			}
			strategyCtx, strategyCancel := context.WithTimeout(parentCtx, strategyTimeout)
			defer strategyCancel() // Ensure cleanup
			// --- End Per-Strategy Timeout Context ---

			log.Printf("[POV Round-%d Phase-%d] Running advanced strategy: %s (timeout: %v)", roundNum, phase, strategyName, strategyTimeout)

            pythonInterpreter := "/tmp/crs_venv/bin/python3"
            isRoot := getEffectiveUserID() == 0
            hasSudo := checkSudoAvailable()

            // --- Calculate Max Iterations (unchanged) ---
            maxIterations := 3
            if timeoutMinutes <= 30 {
                maxIterations = 3
            } else if timeoutMinutes <= 60 {
                maxIterations = 4
            } else {
                maxIterations = 5
            }
            log.Printf("[POV Round-%d Phase-%d] Setting max iterations to %d for timeout %d minutes", roundNum, phase, maxIterations, timeoutMinutes)

            args := []string{
                strategyPath,
                myFuzzer,
                taskDetail.ProjectName,
                taskDetail.Focus,
                language,
                "--model", s.model,
                "--do-patch=false",
                "--pov-metadata-dir", s.povAdvcancedMetadataDir,
                "--check-patch-success",
                fmt.Sprintf("--fuzzing-timeout=%d", timeoutMinutes),
                fmt.Sprintf("--pov-phase=%d", phase),
                fmt.Sprintf("--max-iterations=%d", maxIterations),
            }
            if taskDetail.Type == "full" {
                args = append(args, "--full-scan", "true")
            }
            var runCmd *exec.Cmd
            if isRoot {
                runCmd = exec.CommandContext(strategyCtx,pythonInterpreter, args...)
            } else if hasSudo {
                sudoArgs := append([]string{"-E", pythonInterpreter}, args...)
                runCmd = exec.CommandContext(strategyCtx,"sudo", sudoArgs...)
            } else {
				log.Printf("[POV Round-%d Phase-%d] Warning: Not root and no sudo for %s. Trying direct.", roundNum, phase, strategyName)
                runCmd = exec.CommandContext(strategyCtx,pythonInterpreter, args...)
            }

            runCmd.Dir = taskDir
            // runCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // Kill process group on timeout

            runCmd.Env = append(os.Environ(),
                "VIRTUAL_ENV=/tmp/crs_venv",
                "PATH=/tmp/crs_venv/bin:"+os.Getenv("PATH"),
                fmt.Sprintf("SUBMISSION_ENDPOINT=%s", s.submissionEndpoint),
                fmt.Sprintf("TASK_ID=%s", taskDetail.TaskID.String()),
                fmt.Sprintf("CRS_KEY_ID=%s", os.Getenv("CRS_KEY_ID")),
                fmt.Sprintf("CRS_KEY_TOKEN=%s", os.Getenv("CRS_KEY_TOKEN")),
                fmt.Sprintf("COMPETITION_API_KEY_ID=%s", os.Getenv("COMPETITION_API_KEY_ID")),
                fmt.Sprintf("COMPETITION_API_KEY_TOKEN=%s", os.Getenv("COMPETITION_API_KEY_TOKEN")),
                fmt.Sprintf("WORKER_INDEX=%s", s.workerIndex),
                fmt.Sprintf("ANALYSIS_SERVICE_URL=%s", s.analysisServiceUrl),
                "PYTHONUNBUFFERED=1",
            )

            // If we generated an unharnessed fuzzer for this task, pass its source path.
            if srcAny, ok := s.unharnessedFuzzerSrc.Load(taskDetail.TaskID.String()); ok {
                runCmd.Env = append(runCmd.Env,
                    fmt.Sprintf("NEW_FUZZER_SRC_PATH=%s", srcAny.(string)))
            }

            // --- Streaming logs setup ---
            stdoutPipe, err := runCmd.StdoutPipe()
            if err != nil {
                log.Printf("Failed to create stdout pipe: %v", err)
                return
            }
            stderrPipe, err := runCmd.StderrPipe()
            if err != nil {
                log.Printf("Failed to create stderr pipe: %v", err)
                return
            }

            // log.Printf("Running command: %s %s", pythonInterpreter, strings.Join(args, " "))
            // log.Printf("With environment: %v", runCmd.Env)

			startTime := time.Now()
			if err := runCmd.Start(); err != nil {
				log.Printf("[POV Round-%d Phase-%d] Failed to start %s: %v", roundNum, phase, strategyName, err)
				return
			}

			var outputLines []string
			var outputMutex sync.Mutex
			var streamWg sync.WaitGroup // Wait for scanners to finish

			streamWg.Add(2)

            // Stream stdout
            go func() {
                defer streamWg.Done()

                scanner := bufio.NewScanner(stdoutPipe)
                for scanner.Scan() {
                    line := scanner.Text()
                    log.Printf("[POV Round-%d][%s Phase-%d] %s", roundNum, strategyName, phase, line)
                    outputMutex.Lock()
                    outputLines = append(outputLines, line)
                    outputMutex.Unlock()
                }
                if err := scanner.Err(); err != nil {
					// Log scanner errors, especially if caused by pipe closing on kill
                    if strategyCtx.Err() == nil { // Avoid logging errors if we intentionally killed
					    log.Printf("[POV Round-%d Phase-%d] Error scanning stdout for %s: %v", roundNum, phase, strategyName, err)
                    }
				}
            }()
            // Stream stderr
            go func() {
                defer streamWg.Done()

                scanner := bufio.NewScanner(stderrPipe)
                for scanner.Scan() {
                    line := scanner.Text()
                    log.Printf("[POV Round-%d ERR][%s Phase-%d] %s", roundNum, strategyName, phase, line)
                    outputMutex.Lock()
                    outputLines = append(outputLines, line)
                    outputMutex.Unlock()
                }
                if err := scanner.Err(); err != nil {
                    if strategyCtx.Err() == nil {
					    log.Printf("[POV Round-%d Phase-%d] Error scanning stderr for %s: %v", roundNum, phase, strategyName, err)
                    }
				}
            }()

			// --- Wait for Completion or Timeout ---
			done := make(chan error, 1)
			go func() {
				done <- runCmd.Wait()
			}()

			select {
			case err = <-done:
				// Process finished naturally (or failed)
				streamWg.Wait() // Ensure scanners finish reading before checking output
				duration := time.Since(startTime)
				outputMutex.Lock()
				combinedOutput := strings.Join(outputLines, "\n")
				outputMutex.Unlock()

				if err != nil {
					// Check if the error was due to context cancellation (already logged below)
					exitErr, ok := err.(*exec.ExitError)
                    // Don't log error again if killed due to timeout/cancel
					if !(ok && exitErr.Sys().(syscall.WaitStatus).Signal() == syscall.SIGKILL && strategyCtx.Err() != nil) {
                        log.Printf("[POV Round-%d Phase-%d] Strategy %s failed after %v: %v", roundNum, phase, strategyName, duration, err)
                    }
				} else {
					log.Printf("[POV Round-%d Phase-%d] Strategy %s completed successfully in %v", roundNum, phase, strategyName, duration)
					successMutex.Lock()
					// Check combined output only on successful exit
					if strings.Contains(combinedOutput, "POV SUCCESS!") || strings.Contains(combinedOutput, "Found successful POV") {
						if !povSuccess { // Check flag before setting
							log.Printf("[POV Round-%d Phase-%d] Strategy %s POV successful!", roundNum, phase, strategyName)
							povSuccess = true
							// Optional: cancel parentCtx here if one success is enough? Depends on logic.
						}
					}
					successMutex.Unlock()
				}
            
			case <-strategyCtx.Done():
				// Timeout or external cancellation
				streamWg.Wait() // Allow scanners to finish after kill signal
				duration := time.Since(startTime)
				if strategyCtx.Err() == context.DeadlineExceeded {
					log.Printf("[POV Round-%d Phase-%d] Strategy %s timed out after %v. Killing process group.", roundNum, phase, strategyName, duration)
				} else {
					log.Printf("[POV Round-%d Phase-%d] Strategy %s canceled after %v. Killing process group.", roundNum, phase, strategyName, duration)
				}

				// Kill the entire process group
				if runCmd.Process != nil {
					pgid, err := syscall.Getpgid(runCmd.Process.Pid)
					if err == nil {
						errKill := syscall.Kill(-pgid, syscall.SIGKILL) // Kill negative PGID
						if errKill != nil && !strings.Contains(errKill.Error(), "no such process"){ // Ignore "no such process" error
							log.Printf("[POV Round-%d Phase-%d] Error killing process group %d for %s: %v", roundNum, phase, -pgid, strategyName, errKill)
						}
					} else if !strings.Contains(err.Error(), "no such process") {
                        log.Printf("[POV Round-%d Phase-%d] Error getting PGID for %s (PID %d): %v", roundNum, phase, strategyName, runCmd.Process.Pid, err)
					}
				}
				// Wait for Wait() to return after kill
				<-done
			}
        }(strategyFile)
    }

    wg.Wait()
	// Return the final success state (thread-safe read)
	successMutex.Lock()
	finalSuccess := povSuccess
	successMutex.Unlock()
	return finalSuccess
}



// robustCopyDir copies a directory recursively with fault tolerance,
// continuing even if individual file operations fail
func robustCopyDir(src, dst string) error {
    var copyErrors []string
    
    // Get properties of source directory
    srcInfo, err := os.Lstat(src)
    if err != nil {
        log.Printf("Warning: error getting stats for source directory %s: %v", src, err)
        return fmt.Errorf("error getting stats for source directory: %w", err)
    }

    // Check if source is a symlink
    if srcInfo.Mode()&os.ModeSymlink != 0 {
        // It's a symlink, read the link target
        linkTarget, err := os.Readlink(src)
        if err != nil {
            log.Printf("Warning: error reading symlink %s: %v", src, err)
            return fmt.Errorf("error reading symlink %s: %w", src, err)
        }
        
        // Create a symlink at the destination with the same target
        if err := os.Symlink(linkTarget, dst); err != nil {
            log.Printf("Warning: error creating symlink %s -> %s: %v", dst, linkTarget, err)
            return fmt.Errorf("error creating symlink: %w", err)
        }
        return nil
    }

    // Create the destination directory with the same permissions
    if err = os.MkdirAll(dst, srcInfo.Mode()); err != nil {
        log.Printf("Warning: error creating destination directory %s: %v", dst, err)
        return fmt.Errorf("error creating destination directory: %w", err)
    }

    // Read the source directory
    entries, err := os.ReadDir(src)
    if err != nil {
        log.Printf("Warning: error reading source directory %s: %v", src, err)
        return fmt.Errorf("error reading source directory: %w", err)
    }

    // Copy each entry
    for _, entry := range entries {
        srcPath := filepath.Join(src, entry.Name())
        dstPath := filepath.Join(dst, entry.Name())

        // Use Lstat instead of Stat to detect symlinks
        entryInfo, err := os.Lstat(srcPath)
        if err != nil {
            log.Printf("Warning: skipping %s due to error: %v", srcPath, err)
            copyErrors = append(copyErrors, fmt.Sprintf("error getting stats for %s: %v", srcPath, err))
            continue // Skip this file but continue with others
        }

        // Handle different file types
        if entryInfo.Mode()&os.ModeSymlink != 0 {
            // It's a symlink, read the link target
            linkTarget, err := os.Readlink(srcPath)
            if err != nil {
                log.Printf("Warning: skipping symlink %s due to error: %v", srcPath, err)
                copyErrors = append(copyErrors, fmt.Sprintf("error reading symlink %s: %v", srcPath, err))
                continue // Skip this symlink but continue with others
            }
            
            // Create a symlink at the destination with the same target
            if err := os.Symlink(linkTarget, dstPath); err != nil {
                // log.Printf("Warning: failed to create symlink %s -> %s: %v", dstPath, linkTarget, err)
                copyErrors = append(copyErrors, fmt.Sprintf("error creating symlink %s: %v", dstPath, err))
                // Continue despite the error
            }
        } else if entryInfo.IsDir() {
            // Recursively copy the subdirectory
            if err = robustCopyDir(srcPath, dstPath); err != nil {
                log.Printf("Warning: error copying directory %s: %v", srcPath, err)
                copyErrors = append(copyErrors, fmt.Sprintf("error copying directory %s: %v", srcPath, err))
                // Continue despite the error
            }
        } else {
            // Copy the regular file
            if err = copyFile(srcPath, dstPath); err != nil {
                log.Printf("Warning: error copying file %s: %v", srcPath, err)
                copyErrors = append(copyErrors, fmt.Sprintf("error copying file %s: %v", srcPath, err))
                // Continue despite the error
            }
        }
    }

    // If we had any errors, return a summary but only after completing as much as possible
    if len(copyErrors) > 0 {
        return fmt.Errorf("completed with %d errors: %s", len(copyErrors), strings.Join(copyErrors[:min(5, len(copyErrors))], "; "))
    }

    return nil
}

// copyFile copies a single file from src to dst with fault tolerance
func copyFile(src, dst string) error {
    // Open the source file
    srcFile, err := os.Open(src)
    if err != nil {
        return fmt.Errorf("error opening source file: %w", err)
    }
    defer srcFile.Close()

    // Get source file info for permissions
    srcInfo, err := srcFile.Stat()
    if err != nil {
        return fmt.Errorf("error getting source file stats: %w", err)
    }

    // Skip if it's a directory
    if srcInfo.IsDir() {
        return nil
    }

    // Create the destination file
    dstFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, srcInfo.Mode())
    if err != nil {
        return fmt.Errorf("error creating destination file: %w", err)
    }
    defer dstFile.Close()

    // Copy the contents
    _, err = io.Copy(dstFile, srcFile)
    if err != nil {
        return fmt.Errorf("error copying file contents: %w", err)
    }

    return nil
}

var (
    safetyBufferMinutes = 1
)

func (s *defaultCRSService) runXPatchingStrategiesWithoutPOV(
	myFuzzer string,
	taskDir string,
	projectDir string,
	sanitizer string,
	language string,
	taskDetail models.TaskDetail,
	fullTask models.Task,
	deadlineTime time.Time,
) bool {
	log.Printf("runXPatchingStrategiesWithoutPOV: starting patch attempt without POVs "+
		"(task type: %s)", taskDetail.Type)
    
        if !taskDetail.HarnessesIncluded {
            log.Printf("Only do XPatch for harnessed tasks. HarnessesIncluded: %v", taskDetail.HarnessesIncluded)
            return false
        }

        patchWorkDir := filepath.Join(taskDir, s.patchWorkDir)
        os.RemoveAll(patchWorkDir) // Clean up any previous patch workspace
        if err := os.MkdirAll(patchWorkDir, 0755); err != nil {
            log.Printf("Failed to create patch workspace directory: %v", err)
            return false
        }
        
        if taskDetail.Type == "delta" {
            // 0. Copy the diff directory (diff)
            diffDir := filepath.Join(patchWorkDir, "diff")
            sourceDiffDir := filepath.Join(taskDir, "diff")
            // Check if source diff directory exists
            if _, err := os.Stat(sourceDiffDir); os.IsNotExist(err) {
                log.Printf("Source diff directory does not exist: %s", sourceDiffDir)
            } else {
                // Copy the diff directory
                if err := robustCopyDir(sourceDiffDir, diffDir); err != nil {
                    log.Printf("Failed to copy diff to patch workspace: %v", err)
                    return false
                }
                log.Printf("Copied diff folder from %s to %s", sourceDiffDir, diffDir)
            }
        }
    
        // 1. Copy the project directory (example-libpng)
        projectBaseName := filepath.Base(projectDir)
        patchProjectDir := filepath.Join(patchWorkDir, projectBaseName)
        
        // Create the destination directory first
        if err := os.MkdirAll(patchProjectDir, 0755); err != nil {
            log.Printf("Failed to create patch project directory: %v", err)
            return false
        }
        
        // Use a more robust copy function that handles directories properly
        if err := robustCopyDir(projectDir, patchProjectDir); err != nil {
            log.Printf("Failed to copy project to patch workspace: %v", err)
            return false
        }
        log.Printf("Copied project directory %s to patch workspace", projectBaseName)
        
        projectSanitizerDir := projectDir+"-"+sanitizer
        projectSanitizerBaseName := filepath.Base(projectSanitizerDir)
        patchSanitizerProjectDir := filepath.Join(patchWorkDir, projectSanitizerBaseName)
        // Create the destination directory first
        if err := os.MkdirAll(patchSanitizerProjectDir, 0755); err != nil {
            log.Printf("Failed to create patch project directory: %v", err)
            return false
        }
        if err := robustCopyDir(projectSanitizerDir, patchSanitizerProjectDir); err != nil {
            log.Printf("Failed to copy project to patch workspace: %v", err)
            return false
        }
        log.Printf("Copied project-sanitizer directory %s to patch workspace", projectSanitizerBaseName)
        
        // 2. Copy the fuzz-tooling directory if it exists
        fuzzToolingDir := filepath.Join(taskDir, "fuzz-tooling")
        if _, err := os.Stat(fuzzToolingDir); err == nil {
            patchFuzzToolingDir := filepath.Join(patchWorkDir, "fuzz-tooling")
            if err := robustCopyDir(fuzzToolingDir, patchFuzzToolingDir); err != nil {
                log.Printf("Failed to copy fuzz-tooling to patch workspace: %v", err)
                return false
            }
            log.Printf("Copied fuzz-tooling directory to patch workspace")
        } else {
            log.Printf("fuzz-tooling directory not found, skipping")
        }
            
        // Determine the fuzzer path in the patch workspace
        // First, get the relative path of the fuzzer from the task directory
        relFuzzerPath, err := filepath.Rel(taskDir, myFuzzer)
        if err != nil {
            log.Printf("Failed to get relative fuzzer path: %v", err)
            return false
        }
        
        // Then construct the new fuzzer path in the patch workspace
        patchFuzzerPath := filepath.Join(patchWorkDir, relFuzzerPath)
        
        // Make sure the fuzzer is executable in the new location
        if err := os.Chmod(patchFuzzerPath, 0755); err != nil {
            log.Printf("Warning: Failed to make fuzzer executable in patch workspace: %v", err)
            // Continue anyway, it might still work
        }
        
        log.Printf("Created separate patch workspace at %s", patchWorkDir)
        log.Printf("Original fuzzer path: %s", myFuzzer)
        log.Printf("Patch workspace fuzzer path: %s", patchFuzzerPath)
        
        // Find all strategy files under /app/strategy/
        strategyDir := "/app/strategy"
        strategyFilePattern := "xpatch*_delta.py"
        if taskDetail.Type == "full" {
            strategyFilePattern = "xpatch*_full.py"
        }
    
        strategyFiles, err := filepath.Glob(filepath.Join(strategyDir, "**", strategyFilePattern))
        if err != nil {
            log.Printf("Failed to find strategy files: %v", err)
            return false
        }
        
        if len(strategyFiles) == 0 {
            log.Printf("No strategy files found in %s", strategyDir)
            return false
        }
        
        log.Printf("Found %d strategy files: %v", len(strategyFiles), strategyFiles)
        
        patchSuccess := false

        // Calculate patching timeout based on deadline
        remainingMinutes := int(time.Until(deadlineTime).Minutes())
        // Reserve 5 minutes as safety buffer
        patchingTimeout := remainingMinutes - 5
        if patchingTimeout < 5 {
            patchingTimeout = 5
        }

        var wg sync.WaitGroup // WaitGroup per round
        for _, strategyFile := range strategyFiles {
            wg.Add(1)
            // Use a goroutine to run each strategy in parallel
            go func(strategyPath string) {
                defer wg.Done()
                
                strategyName := filepath.Base(strategyPath)
                log.Printf("[XPATCH] Running strategy: %s", strategyPath)
                
                {
                    // Create a symbolic link to the .env file in the task directory
                    envFilePath := filepath.Join("/app/strategy", ".env")
                    targetEnvPath := filepath.Join(taskDir, ".env")
                    os.Symlink(envFilePath, targetEnvPath)
                }
                
                // Use the Python interpreter from the virtual environment
                pythonInterpreter := "/tmp/crs_venv/bin/python3"
                isRoot := getEffectiveUserID() == 0
                hasSudo := checkSudoAvailable()
        
                // Prepare the arguments for the Python command
                args := []string{
                    strategyPath,
                    patchFuzzerPath,
                    taskDetail.ProjectName,
                    taskDetail.Focus,
                    language,
                    "--model", s.model,
                    fmt.Sprintf("--patching-timeout=%d", patchingTimeout),
                    "--patch-workspace-dir", patchWorkDir,
                }
                
                var runCmd *exec.Cmd
                
                patchCtx, patchCancel := context.WithTimeout(
                    context.Background(), time.Duration(patchingTimeout)*time.Minute)
                defer patchCancel()

                // Create the appropriate command based on our privileges
                if isRoot {
                    // Already running as root, no need for sudo
                    // log.Printf("Running patching as root, executing Python directly")
                    runCmd = exec.CommandContext(patchCtx, pythonInterpreter, args...)
                } else if hasSudo {
                    // Not root but sudo is available
                    // log.Printf("Running patching with sudo")
                    sudoArgs := append([]string{"-E", pythonInterpreter}, args...)
                    runCmd = exec.CommandContext(patchCtx, "sudo", sudoArgs...)
                } else {
                    // Neither root nor sudo available, try running directly
                    log.Printf("Warning: Not running as root and sudo not available. Trying direct execution for patching.")
                    runCmd = exec.CommandContext(patchCtx, pythonInterpreter, args...)
                }

                log.Printf("[XPATCH] Executing: %s", runCmd.String())

                runCmd.Dir = patchWorkDir
                runCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // NEW: own PG
 
                // Set environment variables that would be set by the virtual environment activation
                runCmd.Env = append(os.Environ(),
                    "VIRTUAL_ENV=/tmp/crs_venv",
                    "PATH=/tmp/crs_venv/bin:" + os.Getenv("PATH"),
                    fmt.Sprintf("SUBMISSION_ENDPOINT=%s", s.submissionEndpoint),
                    fmt.Sprintf("TASK_ID=%s", taskDetail.TaskID.String()),
                    // Pass through API credentials if they exist
                    fmt.Sprintf("CRS_KEY_ID=%s", os.Getenv("CRS_KEY_ID")),
                    fmt.Sprintf("CRS_KEY_TOKEN=%s", os.Getenv("CRS_KEY_TOKEN")),
                    fmt.Sprintf("COMPETITION_API_KEY_ID=%s", os.Getenv("COMPETITION_API_KEY_ID")),
                    fmt.Sprintf("COMPETITION_API_KEY_TOKEN=%s", os.Getenv("COMPETITION_API_KEY_TOKEN")),
                    // Add any other environment variables needed by the Python script
                    fmt.Sprintf("WORKER_INDEX=%s", s.workerIndex),
                    fmt.Sprintf("ANALYSIS_SERVICE_URL=%s", s.analysisServiceUrl),
                    "PYTHONUNBUFFERED=1",
                )

                // Log the command for debugging
                log.Printf("[XPATCH] Executing: %s", runCmd.String())
                // Create pipes for stdout and stderr
                stdoutPipe, err := runCmd.StdoutPipe()
                if err != nil {
                    if err != nil { log.Printf("[XPATCH] Failed stdout pipe for %s: %v", strategyName, err); return }
                }
                stderrPipe, err := runCmd.StderrPipe()
                if err != nil { log.Printf("[XPATCH] Failed stderr pipe for %s: %v", strategyName, err); return }

                // Start the command
                startTime := time.Now()
                if err := runCmd.Start(); err != nil {
                    log.Printf("[XPATCH] Failed to start %s: %v", strategyName, err)
                    return
                }
                
                // Buffer for output
                var outputBuffer bytes.Buffer
                
                // Create a channel to signal when the process is done
                done := make(chan error, 1)
                go func() {
                    done <- runCmd.Wait()
                }()
                
                // Start goroutines to collect output
                go func() {
                    scanner := bufio.NewScanner(stdoutPipe)
                    for scanner.Scan() {
                        raw := scanner.Text()
                        // Keep only what would be visible in a terminal (after the last CR)
                        text := raw
                        if i := strings.LastIndex(raw, "\r"); i >= 0 {
                            text = raw[i+1:]
                        }
                        outputBuffer.WriteString(text + "\n")
                        log.Printf("[XPATCH][%s stdout] %s", strategyName, text)
                        
                        // Check for patch success in real-time
                        if strings.Contains(text, "PATCH SUCCESS!") || 
                        strings.Contains(text, "Successfully patched") {                        
                            
                            if !patchSuccess { // Check again under lock
                                patchSuccess = true
                                // patchFoundInRound = true // Mark success for this round
                                log.Printf("[XPATCH] XPatch success detected for %s!", strategyName)
                            }
                        }
                    }
                }()

                go func() {
                    scanner := bufio.NewScanner(stderrPipe)
                    for scanner.Scan() {
                        raw := scanner.Text()
                        // Keep only what would be visible in a terminal (after the last CR)
                        text := raw
                        if i := strings.LastIndex(raw, "\r"); i >= 0 {
                            text = raw[i+1:]
                        }
                        outputBuffer.WriteString(text + "\n")
                        log.Printf("[XPATCH][%s stderr] %s", strategyName, text)
                    }
                }()
                
                // Wait for the process to complete or timeout
                select {
                case err := <-done:
                    // Process completed
                    output := outputBuffer.String()
                       // instead of io.WriteString(log.Writer(), "\r")
   io.WriteString(log.Writer(), "\r\033[K")
                    if err != nil {
                        log.Printf("[XPATCH] Strategy %s failed after %v: %v", strategyName, time.Since(startTime), err)
                        
                    } else {
                        log.Printf("[XPATCH] Strategy %s completed successfully in %v", strategyName, time.Since(startTime))
                        
                        // Check for patch success in the complete output
                        if strings.Contains(output, "PATCH SUCCESS!") || 
                        strings.Contains(output, "Successfully patched") {                        

                            if !patchSuccess {
                                patchSuccess = true
                                // patchFoundInRound = true
                                log.Printf("[XPATCH] Patch success confirmed post-run for %s.", strategyName)
                                // Don't necessarily cancel again, it might already be done.
                            }
                        } else {
                            log.Printf("[XPATCH] Strategy %s completed but did not report patch success.", strategyName)
                        }
                    }
                    
                case <-patchCtx.Done():
                    // timeout / cancel → kill whole process group
                    if runCmd.Process != nil {
                        pgid, _ := syscall.Getpgid(runCmd.Process.Pid)
                        syscall.Kill(-pgid, syscall.SIGKILL)
                    }
                    <-done // ensure Wait() returns

                       // instead of io.WriteString(log.Writer(), "\r")
   io.WriteString(log.Writer(), "\r\033[K")
                    if patchCtx.Err() == context.DeadlineExceeded {
                        log.Printf("[XPATCH] %s timed out after %v",
                             strategyName, time.Since(startTime))
                    } else {
                        log.Printf("[XPATCH] %s canceled early (%v)",
                             strategyName, patchCtx.Err())
                    }
                }
            }(strategyFile)
        }
        
        // Wait for all strategies to complete
        wg.Wait()
        log.Printf("XPatching Attempt finished patchSuccess: %v.", patchSuccess)

        return patchSuccess
}

func (s *defaultCRSService) runPatchingStrategies(myFuzzer,taskDir string, projectDir string, sanitizer, language string, povMetadataDir string, taskDetail models.TaskDetail, fullTask models.Task,deadlineTime time.Time) bool {
    // Create a separate directory for patching to avoid conflicts with ongoing POV generation
    patchWorkDir := filepath.Join(taskDir, s.patchWorkDir)
    os.RemoveAll(patchWorkDir) // Clean up any previous patch workspace
    if err := os.MkdirAll(patchWorkDir, 0755); err != nil {
        log.Printf("Failed to create patch workspace directory: %v", err)
        return false
    }
    
    if taskDetail.Type == "delta" {
        // 0. Copy the diff directory (diff)
        diffDir := filepath.Join(patchWorkDir, "diff")
        sourceDiffDir := filepath.Join(taskDir, "diff")
        // Check if source diff directory exists
        if _, err := os.Stat(sourceDiffDir); os.IsNotExist(err) {
            log.Printf("Source diff directory does not exist: %s", sourceDiffDir)
        } else {
            // Copy the diff directory
            if err := robustCopyDir(sourceDiffDir, diffDir); err != nil {
                log.Printf("Failed to copy diff to patch workspace: %v", err)
                return false
            }
            log.Printf("Copied diff folder from %s to %s", sourceDiffDir, diffDir)
        }
    }

    // 1. Copy the project directory (example-libpng)
    projectBaseName := filepath.Base(projectDir)
    patchProjectDir := filepath.Join(patchWorkDir, projectBaseName)
    
    // Create the destination directory first
    if err := os.MkdirAll(patchProjectDir, 0755); err != nil {
        log.Printf("Failed to create patch project directory: %v", err)
        return false
    }
    
    // Use a more robust copy function that handles directories properly
    if err := robustCopyDir(projectDir, patchProjectDir); err != nil {
        log.Printf("Failed to copy project to patch workspace: %v", err)
        return false
    }
    log.Printf("Copied project directory %s to patch workspace", projectBaseName)
    
    projectSanitizerDir := projectDir+"-"+sanitizer
    projectSanitizerBaseName := filepath.Base(projectSanitizerDir)
    patchSanitizerProjectDir := filepath.Join(patchWorkDir, projectSanitizerBaseName)
    // Create the destination directory first
    if err := os.MkdirAll(patchSanitizerProjectDir, 0755); err != nil {
        log.Printf("Failed to create patch project directory: %v", err)
        return false
    }
    if err := robustCopyDir(projectSanitizerDir, patchSanitizerProjectDir); err != nil {
        log.Printf("Failed to copy project to patch workspace: %v", err)
        return false
    }
    log.Printf("Copied project-sanitizer directory %s to patch workspace", projectSanitizerBaseName)
    

    if !taskDetail.HarnessesIncluded {
        //for unharnessed copy all build-*.sh 
        sourceDirForBuildScripts := taskDir // Source is the taskDir
        targetDirForBuildScripts := patchWorkDir // Target is the root of the patch workspace
        buildScripts, err := filepath.Glob(filepath.Join(sourceDirForBuildScripts, "build-*.sh"))
        if err != nil {
            log.Printf("Error finding build-*.sh files in %s: %v", sourceDirForBuildScripts, err)
            // Decide if this is a fatal error or if you can continue
            // return false // Or handle error appropriately
        }
        if len(buildScripts) == 0 {
            log.Printf("No build-*.sh files found in %s to copy.", sourceDirForBuildScripts)
        } else {
            log.Printf("Found build-*.sh files to copy: %v", buildScripts)
            for _, scriptPath := range buildScripts {
                baseName := filepath.Base(scriptPath)
                destinationPath := filepath.Join(targetDirForBuildScripts, baseName)

                // Read the source file
                input, err := os.ReadFile(scriptPath)
                if err != nil {
                    log.Printf("Failed to read build script %s: %v", scriptPath, err)
                    // return false // Or handle error
                    continue // Skip this file and try others
                }

                // Write the destination file
                err = os.WriteFile(destinationPath, input, 0755) // 0755 to keep it executable
                if err != nil {
                    log.Printf("Failed to write build script to %s: %v", destinationPath, err)
                    // return false // Or handle error
                    continue // Skip this file and try others
                }
                log.Printf("Copied build script %s to %s", baseName, destinationPath)
            }
        }
    }
    // 2. Copy the fuzz-tooling directory if it exists
    fuzzToolingDir := filepath.Join(taskDir, "fuzz-tooling")
    if _, err := os.Stat(fuzzToolingDir); err == nil {
        patchFuzzToolingDir := filepath.Join(patchWorkDir, "fuzz-tooling")
        if err := robustCopyDir(fuzzToolingDir, patchFuzzToolingDir); err != nil {
            log.Printf("Failed to copy fuzz-tooling to patch workspace: %v", err)
            return false
        }
        log.Printf("Copied fuzz-tooling directory to patch workspace")
    } else {
        log.Printf("fuzz-tooling directory not found, skipping")
    }
        
    // Determine the fuzzer path in the patch workspace
    // First, get the relative path of the fuzzer from the task directory
    relFuzzerPath, err := filepath.Rel(taskDir, myFuzzer)
    if err != nil {
        log.Printf("Failed to get relative fuzzer path: %v", err)
        return false
    }
    
    // Then construct the new fuzzer path in the patch workspace
    patchFuzzerPath := filepath.Join(patchWorkDir, relFuzzerPath)
    
    // Make sure the fuzzer is executable in the new location
    if err := os.Chmod(patchFuzzerPath, 0755); err != nil {
        log.Printf("Warning: Failed to make fuzzer executable in patch workspace: %v", err)
        // Continue anyway, it might still work
    }
    
    log.Printf("Created separate patch workspace at %s", patchWorkDir)
    log.Printf("Original fuzzer path: %s", myFuzzer)
    log.Printf("Patch workspace fuzzer path: %s", patchFuzzerPath)
    
    // Find all strategy files under /app/strategy/
    strategyDir := "/app/strategy"
    strategyFilePattern := "patch*_delta.py"
    if taskDetail.Type == "full" {
        strategyFilePattern = "patch*_full.py"
    }

    if !taskDetail.HarnessesIncluded {
        //only use patch_delta and patch_full for unharnessed tasks  
        if taskDetail.Type == "full" {
            strategyFilePattern = "patch_full.py"
        } else {
            strategyFilePattern = "patch_delta.py"
        }
    }

    strategyFiles, err := filepath.Glob(filepath.Join(strategyDir, "**", strategyFilePattern))
    if err != nil {
        log.Printf("Failed to find strategy files: %v", err)
        return false
    }
    
    if len(strategyFiles) == 0 {
        log.Printf("No strategy files found in %s", strategyDir)
        return false
    }
    
    log.Printf("Found %d strategy files: %v", len(strategyFiles), strategyFiles)
    

    
    // --- Patching Loop ---
    patchSuccess := false // Overall success flag
    var successMutex sync.Mutex // Mutex to protect patchSuccess
    // deadlineTime := time.Unix(taskDetail.Deadline/1000, 0)
    roundNum := 0

    for {
        roundNum++
        log.Printf("Starting Patching Attempt Round %d", roundNum)

        // --- Check Exit Conditions ---
        successMutex.Lock()
        currentSuccessState := patchSuccess // Read safely
        successMutex.Unlock()
        if currentSuccessState {
            log.Printf("Patch success detected before starting round %d. Exiting loop.", roundNum)
            break // Exit loop if success flag was set in a previous round
        }

        remainingTime := time.Until(deadlineTime)
        if remainingTime <= time.Duration(safetyBufferMinutes)*time.Minute {
            log.Printf("Deadline approaching before starting patching round %d. Exiting loop.", roundNum)
            break // Exit loop if deadline is too close
        }

        // Calculate timeout for this round based on remaining time
        // Use a portion of remaining time or a fixed time per round, ensuring it's > 0
        roundTimeoutDuration := remainingTime - time.Duration(safetyBufferMinutes)*time.Minute
        // Optional: Set a max timeout per round (e.g., 30 mins) if remaining time is very long
        // maxRoundDuration := 30 * time.Minute
        // if roundTimeoutDuration > maxRoundDuration {
        //     roundTimeoutDuration = maxRoundDuration
        // }
        if roundTimeoutDuration <= 0 {
             log.Printf("Insufficient time for patching round %d. Exiting loop.", roundNum)
             break
        }

        log.Printf("Patching round %d timeout: %v", roundNum, roundTimeoutDuration)

        roundCtx, cancel := context.WithTimeout(context.Background(), roundTimeoutDuration) // Context per round
        var wg sync.WaitGroup // WaitGroup per round

        // install once, right after you create roundCtx
        sigc := make(chan os.Signal, 1)
        signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
        go func() {
            <-sigc
            killAllChildren(syscall.SIGTERM)
            time.Sleep(2 * time.Second)
            killAllChildren(syscall.SIGKILL)
            cancel()           // cancel roundCtx
            fmt.Fprintln(log.Writer()) // newline so shell prompt is clean
            os.Exit(1)         // exit the Go program itself
        }()

        // patchFoundInRound := false // Track success specifically within this round
        // FIVE parallel instances for each patching strategy
        PARALLEL_PATCH_TIMES := 1
        if os.Getenv("LOCAL_TEST") != "" {
            PARALLEL_PATCH_TIMES = 1
        }
        //FOR DEBUGG
        // PARALLEL_PATCH_TIMES = 1
        var repeatedStrategyFiles []string
        for i := 0; i < PARALLEL_PATCH_TIMES; i++ {
            repeatedStrategyFiles = append(repeatedStrategyFiles, strategyFiles...)
        }

        // Run each strategy in parallel
        for _, strategyFile := range repeatedStrategyFiles {
            // Check context before launching goroutine (quick exit if round timed out/canceled early)
            if roundCtx.Err() != nil {
                log.Printf("Patching round %d context done before launching strategy %s. Skipping.", roundNum, filepath.Base(strategyFile))
                continue
            }
            wg.Add(1)
            
            // Use a goroutine to run each strategy in parallel
            go func(strategyPath string) {
                defer wg.Done()
                
                strategyName := filepath.Base(strategyPath)
                   // instead of io.WriteString(log.Writer(), "\r")
   io.WriteString(log.Writer(), "\r\033[K")
                log.Printf("[Round %d] Running patching strategy: %s", roundNum, strategyPath)
                
                {
                    // Create a symbolic link to the .env file in the task directory
                    var symlinkCreationErr error
                    envFilePath := filepath.Join("/app/strategy", ".env")
                    targetEnvPath := filepath.Join(taskDir, ".env")
                    linkFi, errLstat := os.Lstat(targetEnvPath)
                    if errLstat == nil { // Path exists
                        if linkFi.Mode()&os.ModeSymlink != 0 { // It's a symlink
                            existingLinkTarget, errReadLink := os.Readlink(targetEnvPath)
                            if errReadLink == nil && existingLinkTarget == envFilePath {
                                log.Printf("[Round %d] Symlink %s already exists and correctly points to %s. Skipping.", roundNum, targetEnvPath, envFilePath)
                                // Symlink is correct, do nothing further with os.Symlink
                            } 
                        }
                    } else if os.IsNotExist(errLstat) { // Path does not exist, create the symlink
                        log.Printf("[Round %d] Symlink %s does not exist. Creating to point to %s.", roundNum, targetEnvPath, envFilePath)
                        symlinkCreationErr = os.Symlink(envFilePath, targetEnvPath)
                    } else { // Other error during os.Lstat
                         log.Printf("[Round %d] Warning: Error during Lstat for %s: %v. Attempting to create symlink.", roundNum, targetEnvPath, errLstat)
                         symlinkCreationErr = os.Symlink(envFilePath, targetEnvPath) // Attempt to create anyway
                    }
                    if symlinkCreationErr != nil {
                        log.Printf("[Round %d] Warning: Failed to create symlink to .env file: %v", roundNum, err)
                        // Continue execution even if symlink creation fails
                    }
                }
                
                // Use the Python interpreter from the virtual environment
                pythonInterpreter := "/tmp/crs_venv/bin/python3"
                isRoot := getEffectiveUserID() == 0
                hasSudo := checkSudoAvailable()
        
                // Calculate patching timeout based on deadline
                deadlineTime := time.Unix(taskDetail.Deadline/1000, 0)
                remainingMinutes := int(time.Until(deadlineTime).Minutes())
                // Reserve 5 minutes as safety buffer
                patchingTimeout := remainingMinutes - 5
                if patchingTimeout < 5 {
                    patchingTimeout = 5
                }

                patchCtx, patchCancel := context.WithTimeout(
                    roundCtx, time.Duration(patchingTimeout)*time.Minute)
                defer patchCancel()

                // Prepare the arguments for the Python command
                args := []string{
                    strategyPath,
                    patchFuzzerPath,
                    taskDetail.ProjectName,
                    taskDetail.Focus,
                    language,
                    "--model", s.model,
                    fmt.Sprintf("--patching-timeout=%d", patchingTimeout),
                    "--pov-metadata-dir", povMetadataDir,
                    "--patch-workspace-dir", patchWorkDir,
                }
                
                var runCmd *exec.Cmd
                
                // Create the appropriate command based on our privileges
                if isRoot {
                    // Already running as root, no need for sudo
                    // log.Printf("Running patching as root, executing Python directly")
                    runCmd = exec.CommandContext(patchCtx, pythonInterpreter, args...)
                } else if hasSudo {
                    // Not root but sudo is available
                    // log.Printf("Running patching with sudo")
                    sudoArgs := append([]string{"-E", pythonInterpreter}, args...)
                    runCmd = exec.CommandContext(patchCtx, "sudo", sudoArgs...)
                } else {
                    // Neither root nor sudo available, try running directly
                    log.Printf("Warning: Not running as root and sudo not available. Trying direct execution for patching.")
                    runCmd = exec.CommandContext(patchCtx, pythonInterpreter, args...)
                }
                runCmd.Dir = patchWorkDir
                runCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // NEW: own PG
 
                // Set environment variables that would be set by the virtual environment activation
                runCmd.Env = append(os.Environ(),
                    "VIRTUAL_ENV=/tmp/crs_venv",
                    "PATH=/tmp/crs_venv/bin:" + os.Getenv("PATH"),
                    fmt.Sprintf("SUBMISSION_ENDPOINT=%s", s.submissionEndpoint),
                    fmt.Sprintf("TASK_ID=%s", taskDetail.TaskID.String()),
                    // Pass through API credentials if they exist
                    fmt.Sprintf("CRS_KEY_ID=%s", os.Getenv("CRS_KEY_ID")),
                    fmt.Sprintf("CRS_KEY_TOKEN=%s", os.Getenv("CRS_KEY_TOKEN")),
                    fmt.Sprintf("COMPETITION_API_KEY_ID=%s", os.Getenv("COMPETITION_API_KEY_ID")),
                    fmt.Sprintf("COMPETITION_API_KEY_TOKEN=%s", os.Getenv("COMPETITION_API_KEY_TOKEN")),
                    // Add any other environment variables needed by the Python script
                    fmt.Sprintf("WORKER_INDEX=%s", s.workerIndex),
                    fmt.Sprintf("ANALYSIS_SERVICE_URL=%s", s.analysisServiceUrl),
                    "PYTHONUNBUFFERED=1",
                )

                // If we generated an unharnessed fuzzer for this task, pass its source path.
                if srcAny, ok := s.unharnessedFuzzerSrc.Load(taskDetail.TaskID.String()); ok {
                    runCmd.Env = append(runCmd.Env,
                        fmt.Sprintf("NEW_FUZZER_SRC_PATH=%s", srcAny.(string)))
                }
                // Log the command for debugging
                // log.Printf("[Round %d] Executing: %s", roundNum, runCmd.String())
                // Create pipes for stdout and stderr
                stdoutPipe, err := runCmd.StdoutPipe()
                if err != nil {
                    if err != nil { log.Printf("[Round %d] Failed stdout pipe for %s: %v", roundNum, strategyName, err); return }
                }
                stderrPipe, err := runCmd.StderrPipe()
                if err != nil { log.Printf("[Round %d] Failed stderr pipe for %s: %v", roundNum, strategyName, err); return }

                
                // Start the command
                startTime := time.Now()
                if err := runCmd.Start(); err != nil {
                    log.Printf("[Round %d] Failed to start %s: %v", roundNum, strategyName, err)
                    return
                }
                
                // ─── Forward Ctrl-C (SIGINT) / SIGTERM to the child process-group ───
                if runCmd.Process != nil {
                    pgid, _ := syscall.Getpgid(runCmd.Process.Pid) // child's pgid == pid (Setpgid:true)
                    registerChildPG(pgid)
                }

                // Buffer for output
                var outputBuffer bytes.Buffer
                
                // Create a channel to signal when the process is done
                done := make(chan error, 1)
                go func() {
                    done <- runCmd.Wait()
                }()
                
                // Start goroutines to collect output
                go func() {
                    scanner := bufio.NewScanner(stdoutPipe)
                    for scanner.Scan() {
                        raw := scanner.Text()

                        // Handle in-line carriage returns from progress bars, etc.
                        for _, part := range strings.Split(raw, "\r") {
                            part = sanitizeTerminalString(part)
                            if part == "" {
                                continue
                            }
                               // instead of io.WriteString(log.Writer(), "\r")
   io.WriteString(log.Writer(), "\r\033[K")
                            outputBuffer.WriteString(part + "\n")
                            log.Printf("[Round %d][basic %s stdout] %s", roundNum, strategyName, part)

                            // Check for patch success in real-time
                            if strings.Contains(part, "PATCH SUCCESS!") ||
                                strings.Contains(part, "Successfully patched") {

                                successMutex.Lock()
                                if !patchSuccess {
                                    patchSuccess = true
                                       // instead of io.WriteString(log.Writer(), "\r")
   io.WriteString(log.Writer(), "\r\033[K")
                                    log.Printf("[Round %d] Patch success detected for %s! Cancelling other strategies in this round.",
                                        roundNum, strategyName)
                                    cancel()
                                }
                                successMutex.Unlock()
                            }
                        }
                    }
                }()

                go func() {
                    scanner := bufio.NewScanner(stderrPipe)
                    for scanner.Scan() {
                        raw := scanner.Text()

                        for _, part := range strings.Split(raw, "\r") {
                            part = sanitizeTerminalString(part)
                            if part == "" {
                                continue
                            }
                               // instead of io.WriteString(log.Writer(), "\r")
   io.WriteString(log.Writer(), "\r\033[K")
                            outputBuffer.WriteString(part + "\n")
                            log.Printf("[Round %d][basic %s stderr] %s", roundNum, strategyName, part)
                        }
                    }
                }()
                
                // Wait for the process to complete or timeout
                select {
                case err := <-done:
                    // Process completed
                    output := outputBuffer.String()

                       // instead of io.WriteString(log.Writer(), "\r")
   io.WriteString(log.Writer(), "\r\033[K")

                    if err != nil {
                        log.Printf("[Round %d] Strategy %s failed after %v: %v", roundNum, strategyName, time.Since(startTime), err)
                        
                    } else {
                        log.Printf("[Round %d] Strategy %s completed successfully in %v", roundNum, strategyName, time.Since(startTime))
                        
                        // Check for patch success in the complete output
                        if strings.Contains(output, "PATCH SUCCESS!") || 
                        strings.Contains(output, "Successfully patched") {                        
                            // Safely update the success flag
                            successMutex.Lock()
                            if !patchSuccess {
                                patchSuccess = true
                                // patchFoundInRound = true
                                   // instead of io.WriteString(log.Writer(), "\r")
   io.WriteString(log.Writer(), "\r\033[K")
                                log.Printf("[Round %d] Patch success confirmed post-run for %s. (Cancellation might have already occurred).", roundNum, strategyName)
                                // Don't necessarily cancel again, it might already be done.
                            }
                            successMutex.Unlock()
                        } else {
                            log.Printf("[Round %d] Strategy %s completed but did not report patch success.", roundNum, strategyName)
                        }
                    }
                    
                case <-patchCtx.Done():
                    // timeout / cancel → kill whole process group
                    if runCmd.Process != nil {
                        pgid, _ := syscall.Getpgid(runCmd.Process.Pid)
                        syscall.Kill(-pgid, syscall.SIGKILL)
                    }
                    <-done // ensure Wait() returns

                       // instead of io.WriteString(log.Writer(), "\r")
   io.WriteString(log.Writer(), "\r\033[K")

                    if patchCtx.Err() == context.DeadlineExceeded {
                        log.Printf("[Round %d] %s timed out after %v",
                            roundNum, strategyName, time.Since(startTime))
                    } else {
                        log.Printf("[Round %d] %s canceled early (%v)",
                            roundNum, strategyName, patchCtx.Err())
                    }
                }
            }(strategyFile)
        }
        
        // Wait for all strategies to complete
        wg.Wait()
           // instead of io.WriteString(log.Writer(), "\r")
   io.WriteString(log.Writer(), "\r\033[K")
        log.Printf("Patching Attempt Round %d finished.", roundNum)
        // After the round finishes, check the global success flag again
        successMutex.Lock()
        finalRoundSuccessCheck := patchSuccess
        successMutex.Unlock()

        if finalRoundSuccessCheck {
               // instead of io.WriteString(log.Writer(), "\r")
   io.WriteString(log.Writer(), "\r\033[K")
            log.Printf("Patch success confirmed after round %d. Exiting loop.", roundNum)
            break // Exit the main loop if patch was found in this round
        }

        // Optional: Add a delay between rounds if desired
        // time.Sleep(10 * time.Second)

    } // --- End Patching Loop ---

       // instead of io.WriteString(log.Writer(), "\r")
   io.WriteString(log.Writer(), "\r\033[K")
    log.Printf("Exiting patching strategies function.")
    // Return the final state of patchSuccess
    successMutex.Lock()
    finalResult := patchSuccess
    successMutex.Unlock()

    fmt.Fprintln(log.Writer())   // ensure prompt starts on a fresh line

    return finalResult
}

func (s *defaultCRSService) runStrategies(myFuzzer, taskDir, projectDir, fuzzDir, language string, taskDetail models.TaskDetail, fullTask models.Task) bool {
    // Find all strategy files under /app/strategy/
    strategyDir := "/app/strategy"

    strategyFilePattern := "xs*_delta.py"
    if taskDetail.Type == "full" {
        switch strings.ToLower(language) {
        case "c", "cpp", "c++":
            // Use C/C++-specific full-run strategies
            strategyFilePattern = "xs*_c_full.py"
        case "java", "jvm":
            // Use Java-specific full-run strategies
            strategyFilePattern = "xs*_java_full.py"
        default:
            // Fallback to any generic full-run strategy
        strategyFilePattern = "xs*_full.py"
        }
    }

    strategyFiles, err := filepath.Glob(filepath.Join(strategyDir, "**", strategyFilePattern))
    if err != nil {
        log.Printf("Failed to find strategy files: %v", err)
        return false
    }
    
    if len(strategyFiles) == 0 {
        log.Printf("No strategy files found in %s", strategyDir)
        return false
    }
    
    log.Printf("Found %d strategy files: %v", len(strategyFiles), strategyFiles)
    
    // Create a channel to signal when a POV is found
    povFoundChan := make(chan bool, 1)
    
    // Create a wait group to wait for all strategies to complete
    var wg sync.WaitGroup
    
    // Create a context that can be used to cancel all strategies
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel() // Ensure we cancel the context when this function returns
    
    // Run each strategy in parallel
    for _, strategyFile := range strategyFiles {
        wg.Add(1)
        
        // Use a goroutine to run each strategy in parallel
        go func(strategyPath string) {
            defer wg.Done()
            
            strategyName := filepath.Base(strategyPath)
            log.Printf("Running strategy: %s", strategyPath)
            
            {
                // Create a symbolic link to the .env file in the task directory
                envFilePath := filepath.Join("/app/strategy", ".env")
                targetEnvPath := filepath.Join(taskDir, ".env")
                
                // Remove existing symlink if it exists
                _ = os.Remove(targetEnvPath)
                
                // Create the symbolic link
                err = os.Symlink(envFilePath, targetEnvPath)
                if err != nil {
                    log.Printf("Warning: Failed to create symlink to .env file: %v", err)
                    // Continue execution even if symlink creation fails
                }
            }


            const strategyTimeout = 45 * time.Minute
            strategyCtx, strategyCancel := context.WithTimeout(ctx, strategyTimeout)
            defer strategyCancel()

            // Use the Python interpreter from the virtual environment
            pythonInterpreter := "/tmp/crs_venv/bin/python3"
            
            // Check if we're running as root or if sudo is available
            isRoot := getEffectiveUserID() == 0
            hasSudo := checkSudoAvailable()
            
            // Prepare the arguments for the Python command
            args := []string{
                strategyPath,
                myFuzzer,
                taskDetail.ProjectName,
                taskDetail.Focus,
                language,
                "--model", s.model,
                "--pov-metadata-dir", s.povMetadataDir0,
                "--check-patch-success",
            }
            
            if taskDetail.Type == "full" {
                args = append(args, "--full-scan", "true")
            }
            var runCmd *exec.Cmd
            
            // Create the appropriate command based on our privileges
            if isRoot {
                // Already running as root, no need for sudo
                // log.Printf("Running as root, executing Python directly")
                runCmd = exec.CommandContext(strategyCtx,pythonInterpreter, args...)
            } else if hasSudo {
                // Not root but sudo is available
                sudoArgs := append([]string{"-E", pythonInterpreter}, args...)
                runCmd = exec.CommandContext(strategyCtx,"sudo", sudoArgs...)
            } else {
                // Neither root nor sudo available, try running directly
                log.Printf("Warning: Not running as root and sudo not available. Trying direct execution.")
                runCmd = exec.CommandContext(strategyCtx,pythonInterpreter, args...)
            }
            // Log the command for debugging
            // log.Printf("Executing command: %s", runCmd.String())
            runCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
            runCmd.Dir = taskDir
            // Set environment variables that would be set by the virtual environment activation
            runCmd.Env = append(os.Environ(),
                "VIRTUAL_ENV=/tmp/crs_venv",
                "PATH=/tmp/crs_venv/bin:" + os.Getenv("PATH"),
                fmt.Sprintf("SUBMISSION_ENDPOINT=%s", s.submissionEndpoint),
                fmt.Sprintf("TASK_ID=%s", taskDetail.TaskID.String()),
                // Pass through API credentials if they exist
                fmt.Sprintf("CRS_KEY_ID=%s", os.Getenv("CRS_KEY_ID")),
                fmt.Sprintf("CRS_KEY_TOKEN=%s", os.Getenv("CRS_KEY_TOKEN")),
                fmt.Sprintf("COMPETITION_API_KEY_ID=%s", os.Getenv("COMPETITION_API_KEY_ID")),
                fmt.Sprintf("COMPETITION_API_KEY_TOKEN=%s", os.Getenv("COMPETITION_API_KEY_TOKEN")),
                // Add any other environment variables needed by the Python script
                fmt.Sprintf("WORKER_INDEX=%s", s.workerIndex),
                fmt.Sprintf("ANALYSIS_SERVICE_URL=%s", s.analysisServiceUrl),
                "PYTHONUNBUFFERED=1",
            )

            // If we generated an unharnessed fuzzer for this task, pass its source path.
            if srcAny, ok := s.unharnessedFuzzerSrc.Load(taskDetail.TaskID.String()); ok {
                runCmd.Env = append(runCmd.Env,
                    fmt.Sprintf("NEW_FUZZER_SRC_PATH=%s", srcAny.(string)))
            }

            // Create pipes for stdout and stderr
            stdoutPipe, err := runCmd.StdoutPipe()
            if err != nil {
                log.Printf("Failed to create stdout pipe: %v", err)
                return
            }
            stderrPipe, err := runCmd.StderrPipe()
            if err != nil {
                log.Printf("Failed to create stderr pipe: %v", err)
                return
            }
            
            // Start the command
            startTime := time.Now()
            if err := runCmd.Start(); err != nil {
                log.Printf("Failed to start strategy %s: %v", strategyName, err)
                return
            }
            // Create a channel to signal when the process is done
            done := make(chan error, 1)
            go func() {
                done <- runCmd.Wait()
            }()
            
            // Create a ticker to check for POVs periodically
            ticker := time.NewTicker(5 * time.Second)
            defer ticker.Stop()
            
            // Buffer for output
            var outputBuffer bytes.Buffer
            
            // Start goroutines to collect output
            go func() {
                scanner := bufio.NewScanner(stdoutPipe)
                for scanner.Scan() {
                    raw := scanner.Text()
                        // Keep only what would be visible in a terminal (after the last CR)
                        text := raw
                        if i := strings.LastIndex(raw, "\r"); i >= 0 {
                            text = raw[i+1:]
                        }
                    outputBuffer.WriteString(text + "\n")
                    log.Printf("[basic %s stdout] %s", strategyName, text)
                }
            }()

            go func() {
                scanner := bufio.NewScanner(stderrPipe)
                for scanner.Scan() {
                    raw := scanner.Text()
                        // Keep only what would be visible in a terminal (after the last CR)
                        text := raw
                        if i := strings.LastIndex(raw, "\r"); i >= 0 {
                            text = raw[i+1:]
                        }
                    outputBuffer.WriteString(text + "\n")
                    log.Printf("[basic %s stderr] %s", strategyName, text)
                }
            }()

            // Monitor for POVs and process completion
            povFound := false
            
            for {
                select {
                case <-ticker.C:
                    // Check for successful POVs if we haven't already signaled
                    if !povFound {
                        povDir := filepath.Join(fuzzDir, s.povMetadataDir)
                        if _, err := os.Stat(povDir); err == nil {
                            // Directory exists, check for files
                            files, err := os.ReadDir(povDir)
                            if err == nil && len(files) > 0 {
                                log.Printf("Strategy %s: Found POV files in %s directory", strategyName, povDir)                                
                                // Signal that a POV was found (only once)
                                select {
                                case povFoundChan <- true:
                                    log.Printf("Strategy %s: Signaled POV found", strategyName)
                                    povFound = true
                                default:
                                    // Channel already has a value, no need to send again
                                    povFound = true
                                }
                                
                                // Continue running to generate more POVs
                                log.Printf("Strategy %s: Continuing to run for more POVs", strategyName)
                            }
                        }
                    }
                    
                case err := <-done:
                    // Process completed
                    output := outputBuffer.String()
                    if err != nil {
                        log.Printf("Strategy %s failed after %v: %v",
                            strategyName, time.Since(startTime), err)
                    } else {
                        log.Printf("Strategy %s completed successfully in %v",
                            strategyName, time.Since(startTime))
                        
                        // Check output for POV SUCCESS! message as a backup
                        if !povFound && strings.Contains(output, "POV SUCCESS!") {
                            log.Printf("Strategy %s POV successful!", strategyName)
                            
                            // Signal that a POV was found
                            select {
                            case povFoundChan <- true:
                                log.Printf("Strategy %s: Signaled POV found", strategyName)
                            default:
                                // Channel already has a value, no need to send again
                            }
                        }
                    }
                    return
                    
                case <-strategyCtx.Done():
                    // Timeout reached or context canceled
                    if strategyCtx.Err() == context.DeadlineExceeded {
                        log.Printf("Strategy %s timed out (≥%v). Killing process tree.",
                            strategyName, strategyTimeout)
                    } else {
                        log.Printf("Strategy %s canceled after %v.", strategyName, time.Since(startTime))
                    }
                    if runCmd.Process != nil {
                        // Kill entire group: negative PGID
                        pgid, _ := syscall.Getpgid(runCmd.Process.Pid)
                        syscall.Kill(-pgid, syscall.SIGKILL)
                        }
                        <-done // ensure Wait() returns
                    return
                }
            }
        }(strategyFile)
    }
    
    // Use a single goroutine to handle the result
    resultChan := make(chan bool, 1)
    go func() {
        // Two possible outcomes:
        // 1. A POV is found by one of the strategies
        // 2. All strategies complete without finding a POV
        
        // Create a channel to signal when all strategies are done
        allDone := make(chan struct{})
        go func() {
            wg.Wait()
            close(allDone)
        }()
        
        // Wait for either a POV to be found or all strategies to complete
        select {
        case <-allDone:
            // All strategies completed without finding a POV
            // log.Printf("All strategies have completed execution without finding a POV")
            resultChan <- false
            
        case result := <-povFoundChan:
            // A POV was found
            log.Printf("A POV was found, returning result")
            resultChan <- result
            
            // Cancel all other running strategies
            cancel()
        }
        
        // Close the result channel when done
        close(resultChan)
    }()
    
    // Return the result
    return <-resultChan
}

func filterInstrumentedLines(output string) string {
    lines := strings.Split(output, "\n")
    var filteredLines []string
    
    for _, line := range lines {
        // Skip info logs and VM warnings
        if strings.HasPrefix(line, "INFO:") || 
           strings.Contains(line, "Server VM warning:") {
            continue
        }
        
        // Keep all other lines
        filteredLines = append(filteredLines, line)
    }
    
    return strings.Join(filteredLines, "\n")
}

func (s *defaultCRSService) extractCrashOutput(output string) string {
    // Maximum size to return (4KB)
    const maxSize = 4096
    
    // Helper function to limit output size
    limitSize := func(start int) string {
        if len(output)-start > maxSize {
            return output[start : start+maxSize]
        }
        return output[start:]
    }
    
    // Look for AddressSanitizer error
    asanIndex := strings.Index(output, "ERROR: AddressSanitizer")
    if asanIndex != -1 {
        return limitSize(asanIndex)
    }
    
    // Look for other sanitizer errors
    ubsanIndex := strings.Index(output, "ERROR: UndefinedBehaviorSanitizer")
    if ubsanIndex != -1 {
        return limitSize(ubsanIndex)
    }
    
    msanIndex := strings.Index(output, "ERROR: MemorySanitizer")
    if msanIndex != -1 {
        return limitSize(msanIndex)
    }
    {
        msanIndex := strings.Index(output, "WARNING: MemorySanitizer")
        if msanIndex != -1 {
            return limitSize(msanIndex)
        }
    }
    
    
    // Look for libFuzzer crash indicator
    libfuzzerIndex := strings.Index(output, "==ERROR: libFuzzer")
    if libfuzzerIndex != -1 {
        return limitSize(libfuzzerIndex)
    }
    
    // Look for SEGV indicator
    segvIndex := strings.Index(output, "SUMMARY: AddressSanitizer: SEGV")
    if segvIndex != -1 {
        // Try to find the start of the error report
        errorStart := strings.LastIndex(output[:segvIndex], "==")
        if errorStart != -1 {
            return limitSize(errorStart)
        }
        return limitSize(segvIndex)
    }
    
    // If no specific error marker found, return the last 4KB of output
    if len(output) > maxSize {
        return output[len(output)-maxSize:]
    }
    
    return output
}
func loadTaskDetailFromJson(myFuzzer, fuzzDir, taskDir string) *models.TaskDetail {
	// First try the original path in fuzzDir
	jsonFilePath := filepath.Join(fuzzDir, "task_detail.json")
	
	// Check if file exists
	if _, err := os.Stat(jsonFilePath); os.IsNotExist(err) {
		// Original file not found, try using the hash-based filename in taskDir
		fuzzerHash := hashString(myFuzzer)
		jsonFilePath = filepath.Join(taskDir, fmt.Sprintf("task_detail_%s.json", fuzzerHash))
		
		// Check if hash-based file exists
		if _, err := os.Stat(jsonFilePath); os.IsNotExist(err) {
			log.Printf("Warning: Task detail file not found at both %s and %s", 
				filepath.Join(fuzzDir, "task_detail.json"), 
				jsonFilePath)
			return &models.TaskDetail{} // Return empty struct instead of nil to avoid nil pointer dereference
		}
		
		log.Printf("Using hash-based task detail file: %s", jsonFilePath)
	} else {
		log.Printf("Using original task detail file: %s", jsonFilePath)
	}
	
	// Read file content
	fileContent, err := os.ReadFile(jsonFilePath)
	if err != nil {
		log.Printf("Error reading task detail file: %v", err)
		return &models.TaskDetail{}
	}
	
	// Unmarshal JSON
	var taskDetail models.TaskDetail
	err = json.Unmarshal(fileContent, &taskDetail)
	if err != nil {
		log.Printf("Error unmarshaling task detail: %v", err)
		return &models.TaskDetail{}
	}
	
	return &taskDetail
}

func (s *defaultCRSService) HandleSarifBroadcastWorker(broadcastWorker models.SARIFBroadcastDetailWorker) error {

        myFuzzer:= broadcastWorker.Fuzzer
        broadcast := broadcastWorker.Broadcast
        taskID := broadcast.TaskID.String()
        //TODO worker handle broadcast
        log.Printf("[SARIF] worker fuzzer %s handle SARIF broadcast for task: %s", myFuzzer, taskID)
        // Probably we already have a fuzzer running either a delta-scan or a full-scan task 
        // Regardless of that, let's try to generate POV based on the broadcast info 
    
        //extract the source code file and location (region line numbers)
        
        // 1. Extract and validate the SARIF report
        sarifData, err := extractSarifData(broadcast.SARIF)
        if err != nil {
            return fmt.Errorf("failed to extract SARIF data: %w", err)
        }
    
        // 2. Analyze the SARIF report to identify vulnerabilities
        vulnerabilities, err := analyzeSarifVulnerabilities(sarifData)
        if err != nil {
            return fmt.Errorf("failed to analyze vulnerabilities: %w", err)
        }
        
        if len(vulnerabilities) == 0 {
            log.Printf("SOMETHING MUST BE WRONG!!! No vulnerabilities found in SARIF report for task %s", taskID)
            return nil
        }
    
        log.Printf("Worker found %d vulnerabilities in SARIF report for task %s", len(vulnerabilities), taskID)
    
        showVulnerabilityDetail(taskID, vulnerabilities)


        if waitForFile(myFuzzer, 2*60) {
            // File exists, proceed with processing
    
        } else {
            // File doesn't exist after timeout, handle this case
            log.Printf("SOMETHING IS WRONG! Fuzzer file %s: has NOT been created yet. Too slow!", myFuzzer)
        }

        go func() {
            
            //save to sarifFilePath and then invoke Python
            sarifFilePath, err:= saveSarifBroadcast(s.workDir,taskID,broadcast)
            if err!=nil || sarifFilePath == "" {
                log.Printf("[SARIF] failed to persist SARIF broadcast: %v", err)
                return
            }
            //let's try to get taskDetail by loading fuzzerDir
            {

                // Find the index of "fuzz-tooling/build/out" in the fuzzer path
                fuzzToolingIndex := strings.Index(myFuzzer, "fuzz-tooling/")
                if fuzzToolingIndex != -1 {
                    // Extract the base directory (everything before fuzz-tooling/build/out)
                    taskDir := myFuzzer[:fuzzToolingIndex]
                    // Remove trailing slash if present
                    taskDir = strings.TrimRight(taskDir, "/")
                    
                    fuzzDir := filepath.Dir(myFuzzer)
                    jsonFilePath := filepath.Join(fuzzDir, "task_detail.json")
                    if waitForFile(jsonFilePath, 2*60) {
                        // File exists, proceed with processing
                    } else {
                        // File doesn't exist after timeout, handle this case
                        log.Printf("SOMETHING IS WRONG! taskDetail json file %s: has NOT been created yet. Too slow!", jsonFilePath)
                    }
                    taskDetail := loadTaskDetailFromJson(myFuzzer, fuzzDir,taskDir)

                    
                    dockerfilePath := path.Join(taskDir, "fuzz-tooling/projects",taskDetail.ProjectName)
                    projectYAMLPath := filepath.Join(dockerfilePath, "project.yaml")
                    cfg, cfgErr := loadProjectConfig(projectYAMLPath)

                    if cfgErr !=nil || cfg == nil {
                        log.Printf("[SARIF] failed to load project.yaml: %v", err)
                        return
                    }
                    
                    {
                        // Calculate time budget based on deadline
                        deadlineTime := time.Unix(taskDetail.Deadline/1000, 0)
                        totalBudgetMinutes := int(time.Until(deadlineTime).Minutes())
                        if totalBudgetMinutes <= 0 {
                            log.Printf("WARNING: Task deadline is too close or already passed!")
                            totalBudgetMinutes = 60 // Minimum working time
                            deadlineTime = time.Now().Add(60 * time.Minute) // New line to reset the deadline
                        }

                        workingBudgetMinutes := totalBudgetMinutes - safetyBufferMinutes
                        povBudgetMinutes := int(float64(workingBudgetMinutes) * 0.8)

                        phaseRatios := []float64{0.1, 0.2, 0.2, 0.5}
                        timeouts := make([]int, len(phaseRatios))
                        
                        for i, ratio := range phaseRatios {
                            timeouts[i] = int(float64(povBudgetMinutes) * ratio)
                            log.Printf("Phase %d POV budget: %d minutes", i+1, timeouts[i])
                        }

                        ctx := context.Background()
                        var (
                            wg          sync.WaitGroup
                            patchOnce   sync.Once
                            povFound    uint32 // 0 = false, 1 = true
                            patch_success bool  // written only via patchOnce
                        )

                        for phase, timeout := range timeouts {
                            wg.Add(1)
                            go func(phase, timeout int) {
                                defer wg.Done()

                                timeout = povBudgetMinutes
                                if timeout <=0 {
                                    timeout = 5
                                } else if timeout > 45 {
                                    //limit to 45mins max
                                    timeout = 45
                                }
                                log.Printf("Starting Sarif POV phase %d with timeout %d minutes", phase, timeout)

                                // --- tracing span ----------------------------------------------------
                                _, span := telemetry.StartSpan(ctx, fmt.Sprintf("sarif_pov_phase_%d", phase))
                                span.SetAttributes(
                                    attribute.String("crs.action.category", "sarif_pov_generation"),
                                    attribute.String("crs.action.name", fmt.Sprintf("runPOVPhase%d", phase)),
                                    attribute.Int("crs.phase.number", phase),
                                    attribute.Int("crs.phase.timeout_minutes", timeout),
                                )
                                for k, v := range taskDetail.Metadata {
                                    span.SetAttributes(attribute.String(k, v))
                                }

                                ok := s.runSarifPOVStrategies(myFuzzer, taskDir, sarifFilePath,
                                    cfg.Language, taskDetail, timeout, phase)
                                span.SetAttributes(attribute.Bool("crs.phase.pov_success", ok))
                                span.End()

                                if ok {
                                    atomic.StoreUint32(&povFound, 1)
                                    patchOnce.Do(func() {
                                        log.Printf("[SARIF] Phase %d produced a POV – kicking-off patch generation", phase)

                                        fuzzDir := filepath.Dir(myFuzzer)
                                        parts   := strings.Split(filepath.Base(fuzzDir), "-")
                                        sanitizer := parts[len(parts)-1]

                                        if projectDir, err := s.findProjectDir(taskDetail.TaskID.String()); err == nil {
                                            patch_success = s.runPatchingStrategies(
                                                myFuzzer, taskDir, projectDir, sanitizer, cfg.Language,
                                                s.povAdvcancedMetadataDir, *taskDetail, models.Task{}, deadlineTime,
                                            )
                                        }
                                    })
                                } else {
                                    log.Printf("No Sarif POV found in phase %d", phase)
                                }
                            }(phase, timeout)
                        }

                        // wait for all phases to finish
                        wg.Wait()

                        // ---------- XPatch-Sarif fallback (only if no POV) --------------------------
                        if atomic.LoadUint32(&povFound) == 0 && taskDetail.HarnessesIncluded {
                            patchOnce.Do(func() {
                                povCnt, patchCnt, err := s.getPOVStatsFromSubmissionService(taskDetail.TaskID.String())
                                if err != nil {
                                    log.Printf("Error getPOVStatsFromSubmissionService: %v", err)
                                    return
                                }
                                if povCnt > 0 && patchCnt > 0 {
                                    return // already have submissions – nothing to do
                                }

                                log.Printf("[SARIF] no valid POVs – trying XPatch-Sarif fallback")
                                sarifDir     := path.Join(taskDir, "sarif_broadcasts")
                                fuzzerName   := filepath.Base(myFuzzer)
                                sentinelFile := path.Join(taskDir, "xpatch-"+fuzzerName)

                                if dirExists(sarifDir) && fileExists(sentinelFile) {
                                    files, _ := filepath.Glob(filepath.Join(sarifDir, "*.json"))
                                    for _, sarifPath := range files {
                                        if s.runXPatchSarifStrategies(myFuzzer, taskDir, sarifPath,
                                            cfg.Language, *taskDetail, deadlineTime) {
                                            patch_success = true
                                            break
                                        }
                                    }
                                }
                            })
                        }

                        log.Printf("[SARIF] pov_success: %v patch_success: %v",
                            atomic.LoadUint32(&povFound) == 1, patch_success)
                    }
                }
            }
        }()

    return nil
}

// waitForFile waits until the specified file exists
// Returns true if the file exists, false if timeout is reached
func waitForFile(filePath string, timeoutSeconds int) bool {
	// Set timeout
	timeout := time.After(time.Duration(timeoutSeconds) * time.Second)
	// Check every second
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	
	log.Printf("Waiting for file to exist: %s (timeout: %d seconds)...", filePath, timeoutSeconds)
	
	// Keep checking until timeout
	for {
		select {
		case <-timeout:
			log.Printf("Timeout reached while waiting for file: %s", filePath)
			return false
		case <-ticker.C:
			// Check if file exists
			if _, err := os.Stat(filePath); err == nil {
				log.Printf("File found: %s", filePath)
				return true
			}
		}
	}
}

func (s *defaultCRSService) runLibFuzzer(myFuzzer,taskDir string, projectDir string, language string, taskDetail models.TaskDetail, fullTask models.Task) error {
    if true {
        log.Printf("Skipped [runLibFuzzer] for local testing: %s]", myFuzzer)
        return nil
    }
    // Create a span for fuzzer execution
    ctx := context.Background()
    _, fuzzerSpan := telemetry.StartSpan(ctx, "libfuzzer_execution")
    fuzzerSpan.SetAttributes(attribute.String("crs.action.category", "fuzzing"))
    fuzzerSpan.SetAttributes(attribute.String("crs.action.name", "runLibFuzzer"))   
    for key, value := range taskDetail.Metadata {
        fuzzerSpan.SetAttributes(attribute.String(key, value))
    }    
    defer fuzzerSpan.End()

   
    fuzzerPath := myFuzzer
    log.Printf("[Fuzzer worker fuzzerPath: %s]", fuzzerPath)

    fuzzerName := filepath.Base(fuzzerPath)
    fuzzDir := filepath.Dir(fuzzerPath)
    baseName := filepath.Base(fuzzDir) // e.g. "bind9-address"
    parts := strings.Split(baseName, "-")
    sanitizer := parts[len(parts)-1] // "address" in this example
    
    log.Printf("[Fuzzer %s] Starting with sanitizer=%s...", fuzzerName, sanitizer)

    // Create directory "crashes" under fuzzDir if it does not exist
    crashesDir := filepath.Join(fuzzDir, "crashes")
    if _, err := os.Stat(crashesDir); os.IsNotExist(err) {
        if err := os.MkdirAll(crashesDir, 0755); err != nil {
            // If regular creation fails, try with sudo
            // log.Printf("Regular directory creation failed: %v, attempting with sudo", err)
            cmd := exec.Command("sudo", "mkdir", "-p", crashesDir)
            cmd.Stdout = os.Stdout
            cmd.Stderr = os.Stderr
            if sudoErr := cmd.Run(); sudoErr != nil {
                log.Printf("failed to create libfuzzer crashes directory with sudo: %v", sudoErr)
            } else {
                // Set permissions after sudo creation to allow anyone to write
                chmodCmd := exec.Command("sudo", "chmod", "0777", crashesDir)
                if chmodErr := chmodCmd.Run(); chmodErr != nil {
                    log.Printf("failed to set permissions on crashes directory: %v", chmodErr)
                }
            }
        }
    }

    var successfulPoVs int = 0
    LIMIT_POV_NUM := 3
    // Track successful patches
    var successfulPatches int = 0
    
    // Map to track unique crash signatures we've already processed
    processedCrashes := make(map[string]bool)
    
    // Set up fuzzing until deadline
    deadlineTime := time.Unix(taskDetail.Deadline/1000, 0)
    totalLibfuzzingTime := time.Until(deadlineTime) / 2
    
    // Check if deadline is in the past or very close, and if so, set it to 15 mins from now
    if time.Until(deadlineTime) <= 0 || time.Until(deadlineTime).Minutes() < float64(safetyBufferMinutes) {
        log.Printf("Deadline is in the past or too close. Setting temporary deadline of 30 minutes from now for testing.")
        deadlineTime = time.Now().Add(30 * time.Minute)
    }

    deadlineCtx, cancelDeadline := context.WithDeadline(
        context.Background(),
        deadlineTime.Add(-time.Duration(safetyBufferMinutes)*time.Minute),
    )
    defer cancelDeadline()

    libFuzzerStartTime := time.Now() // Record start time for this round

FUZZ_LOOP:
    // Main fuzzing loop - continue until deadline
    for {
        // Quick abort if global deadline fired.
        select {
        case <-deadlineCtx.Done():
            log.Printf("Stopping fuzzing: %v", deadlineCtx.Err())
            break FUZZ_LOOP // Exit the outer loop
        default:
        }

        //Check if POV already produced by LLM, if yes, break
        {
            // Check if any successful POV files or directories exist under fuzzDir
            matches, err := filepath.Glob(filepath.Join(fuzzDir, "successful_povs*"))
            if err != nil {
                log.Printf("Error checking for successful POV files/directories: %v", err)
            } else {
                for _, match := range matches {
                    if info, err := os.Stat(match); err == nil {
                        if info.Mode().IsRegular() || info.IsDir() {
                            log.Printf("Found successful POV (%s). Stopping fuzzing w/ libfuzzer.", match)
                            return nil
                        }
                    } else {
                        log.Printf("Error stating file/directory %s: %v", match, err)
                    }
                }
            }
        }
        
        // Compute per-run timeout.
        runTimeout := 10 * time.Minute
        timeLeft := time.Until(deadlineTime.Add(-time.Duration(safetyBufferMinutes) * time.Minute))
        if timeLeft < runTimeout {
            runTimeout = timeLeft
        }
        log.Printf("[DEBUG] Computed runTimeout: %v, time left until deadline: %v", runTimeout, timeLeft)
        if runTimeout <= 0 {
            log.Printf("No time left for another fuzz iteration.")
            break FUZZ_LOOP // Exit the outer loop
        }

        runCtx, runCancel := context.WithTimeout(deadlineCtx, runTimeout)
        defer runCancel()    

        // name container so we can stop it
        containerName := fmt.Sprintf("libfuzz_%s_%d", fuzzerName, time.Now().UnixNano())
        // Get fuzzer arguments - potentially modifying for continuous fuzzing
        cmdArgs := getFuzzerArgs(containerName, fuzzDir, fuzzerName, language, sanitizer, taskDir)
        
        // Prepare command with timeout
        runCmd := exec.CommandContext(runCtx, "docker", cmdArgs...)
        runCmd.Dir = fuzzDir

        // Goroutine to stop the container when the context is done
        containerStopWg := sync.WaitGroup{}
        containerStopWg.Add(1)
        go func() {
            defer containerStopWg.Done()
            <-runCtx.Done() // Wait for cancellation or timeout
            stopCmd := exec.Command("docker", "stop", "-t", "0", containerName)
            log.Printf("Context done (%v), attempting to stop container: %s", runCtx.Err(), stopCmd.String())
            if err := stopCmd.Run(); err != nil {
                    // Log differently if context was canceled vs deadline exceeded?
                    // Don't log error if container already stopped/removed
                    if !strings.Contains(err.Error(), "No such container") {
                        log.Printf("Error stopping container %s: %v", containerName, err)
                    }
            } else {
                    log.Printf("Successfully stopped container %s", containerName)
            }
            // Docker should remove the container due to --rm
                // Give Docker a moment to clean up
            time.Sleep(1 * time.Second)
        }()

        log.Printf("[DEBUG] Running libfuzzing iteration with: docker %s", strings.Join(cmdArgs, " "))
        
        var runOutput bytes.Buffer
        runCmd.Stdout = &runOutput
        runCmd.Stderr = &runOutput
        
        // Run the fuzzer
        err := runCmd.Run()
        // runCancel() // Always cancel context to avoid leaks
        containerStopWg.Wait() // Wait for the container stop attempt to finish

        output := runOutput.String()
        
        // --- Crash Processing ---
        if runCtx.Err() == context.DeadlineExceeded {
            log.Printf("[Fuzzer %s] Run timed out after %v", fuzzerName, runTimeout)
            // Continue to next iteration or break based on global deadline check at top
        } else if runCtx.Err() == context.Canceled {
                log.Printf("[Fuzzer %s] Run canceled", fuzzerName)
                // If canceled due to global deadline, loop will break. If other reason, log it.
        } else if err != nil && s.isCrashOutput(output) {
            log.Printf("[Fuzzer %s] Found potential crash!", fuzzerName)
            
            // Extract relevant crash info and generate signature
            relevantOutput := s.extractCrashOutput(output)
            relevantOutput = filterInstrumentedLines(relevantOutput)
            crashSignature := s.generateCrashSignature(relevantOutput, sanitizer)
            // Check if we've already seen this crash
            if processed, exists := processedCrashes[crashSignature]; exists && processed {
                log.Printf("Skipping duplicate crash with signature: %s", crashSignature)
            } else {
                successfulPoVs++
                if successfulPoVs > LIMIT_POV_NUM {
                    log.Printf("Reached POV limit (%d). Stopping fuzzing.", LIMIT_POV_NUM)
                    break FUZZ_LOOP
                }
                log.Printf("Processing a new crash #%d with signature: %s", successfulPoVs, crashSignature)
                s.povMetadataDir = fmt.Sprintf("%s_%d", s.povMetadataDir, successfulPoVs)

                log.Printf("Saving POV metadata for crash files...")
                
                // Mark this crash as processed
                processedCrashes[crashSignature] = true
                
                // Save all crashes as POVs
                crash_output := s.saveAllCrashesAsPOVs(crashesDir, taskDir, fuzzerPath, fuzzDir, 
                                               projectDir, relevantOutput, sanitizer,
                                               taskDetail, fuzzerName)
                
                // Generate crash signature and submit
                s.generateCrashSignatureAndSubmit(crashesDir, fuzzDir, taskDir, projectDir, 
                                                sanitizer, taskDetail, fuzzerName, crash_output,crashSignature)
                
                // Try patching
                patch_success := s.runPatchingStrategies(myFuzzer,taskDir, projectDir, sanitizer, language, s.povMetadataDir,
                                                       taskDetail, fullTask,deadlineTime)
                if patch_success {
                    successfulPatches++
                    log.Printf("Successfully patched vulnerability #%d!", successfulPatches)
                    if taskDetail.Type == "delta" {
                        // for delta-scan, patch only one vulnerability
                        break
                    }
                    // Continue fuzzing to find more vulnerabilities
                    log.Printf("Continuing to fuzz for more vulnerabilities...")
                } else {
                    // If patch was not successful, try a few more times for this crash
                    log.Printf("Initial patch attempt unsuccessful, trying again...")
                    
                    maxRetries := 300
                    for retry := 0; retry < maxRetries; retry++ {
                        // Check global deadline context before each retry
                        select {
                        case <-deadlineCtx.Done():
                            log.Printf("Global deadline reached during patch retry %d. Stopping retries for crash %s.", retry+1, crashSignature)
                            // Break inner retry loop; outer loop will check deadline again and exit.
                            goto EndRetryLoop // Use goto to break out of nested select/loop cleanly
                        default:
                            // Continue if deadline not reached
                        }
                        
                        log.Printf("Retry patching attempt %d/%d for crash %s", 
                                  retry+1, maxRetries, crashSignature)
                        
                        patch_success = s.runPatchingStrategies(myFuzzer,taskDir, projectDir,sanitizer, language, s.povMetadataDir,
                                                             taskDetail, fullTask, deadlineTime)
                        if patch_success {
                            successfulPatches++
                            log.Printf("Patch succeeded on retry %d! Total successful patches: %d", 
                                      retry+1, successfulPatches)
                            break FUZZ_LOOP // Exit outer fuzz loop as well
                        }
                        goto EndRetryLoop // Exit retry loop, continue fuzzing outer loop
                        
                        // Short wait between retries
                        // time.Sleep(5 * time.Second)
                    }
                EndRetryLoop: // Label to break out of retry loop cleanly   
                    if !patch_success {
                        log.Printf("Failed to patch after %d attempts. Moving on to find more crashes.", 
                                  maxRetries)
                    }
                }
            }
        } else if err != nil {
            // Non-crash error
            log.Printf("[Fuzzer %s] Run ended with error (might be normal): %v", fuzzerName, err)
            
            // Only log a snippet of potentially large output
            if len(output) > 10000 {
                log.Printf("Output snippet (last 10000 chars): %s", output[len(output)-10000:])
            } else {
                log.Printf("Output: %s", output)
            }
        } else {
            // No crash, no error - normal completion
            log.Printf("[Fuzzer %s] Fuzzing iteration completed without crashes.", fuzzerName)
        }
        

        {
            libFuzzerDuration := time.Since(libFuzzerStartTime)
            pov_count, patch_count, err := s.getPOVStatsFromSubmissionService(taskDetail.TaskID.String())
            if err != nil {
                log.Printf("Error getPOVStatsFromSubmissionService: %v", err)
            } else if pov_count > 0 && (libFuzzerDuration > totalLibfuzzingTime || (libFuzzerDuration > totalLibfuzzingTime/2 && s.status.Processing > 1)) {
                // Enough POVs already exist and this fuzzer has been running >1 h – stop to save resources
                log.Printf("POV already found in other fuzzers. libfuzzer Duration %v. Stop libfuzzer. pov_count: %d patch_count: %d",
                    libFuzzerDuration, pov_count, patch_count)
                break
            } else if libFuzzerDuration > totalLibfuzzingTime && s.status.Processing > 1 {
                log.Printf("libfuzzer Duration %v and multiple worker fuzzers: %d. Stop libfuzzer. pov_count: %d patch_count: %d",
                libFuzzerDuration, s.status.Processing, pov_count, patch_count)
                break
            } else if pov_count > 0 {
                // POVs exist but we haven’t hit the 1 h mark yet – keep fuzzing a bit longer
                log.Printf("POVs found by other fuzzers, but libfuzzer only Duration %v. Continuing. pov_count: %d patch_count: %d",
                    libFuzzerDuration, pov_count, patch_count)
            } else {
                log.Printf("No POVs found so far, libfuzzer Duration: %v, continue to next round", libFuzzerDuration)
            }
        }

        // Short pause only if not approaching deadline
        if time.Until(deadlineTime.Add(-time.Duration(safetyBufferMinutes)*time.Minute)) > 5*time.Second {
            time.Sleep(2 * time.Second)
        }
    }
    
    // Final report
    log.Printf("Libfuzzer Fuzzing completed for %s. Found and patched %d unique vulnerabilities.", 
              fuzzerName, successfulPatches)
    
    return nil
}


// monitorVulnerabilityFile watches the suspected_vulns.json file for changes
// and logs updates as they occur
func monitorVulnerabilityFile(filePath string) {
    lastSize := int64(0)
    lastCount := 0
    
    for {
        // Sleep to avoid excessive CPU usage
        time.Sleep(30 * time.Second)
        
        // Check if file exists
        info, err := os.Stat(filePath)
        if err != nil {
            if !os.IsNotExist(err) {
                log.Printf("Error checking vulnerability file: %v", err)
            }
            continue
        }
        
        // Check if file size has changed
        currentSize := info.Size()
        if currentSize != lastSize {
            lastSize = currentSize
            
            // Read the file to get current vulnerability count
            data, err := os.ReadFile(filePath)
            if err != nil {
                log.Printf("Error reading vulnerability file: %v", err)
                continue
            }
            
            var vulns []interface{}
            if err := json.Unmarshal(data, &vulns); err != nil {
                log.Printf("Error parsing vulnerability file: %v", err)
                continue
            }
            
            currentCount := len(vulns)
            if currentCount != lastCount {
                if lastCount > 0 {
                    log.Printf("Vulnerability file updated: found %d new potential vulnerabilities (total: %d)", 
                              currentCount - lastCount, currentCount)
                } else {
                    log.Printf("Vulnerability file updated: now contains %d potential vulnerabilities", currentCount)
                }
                lastCount = currentCount
                
                // If we have a significant number of vulnerabilities, log more details
                if currentCount >= 5 && currentCount % 5 == 0 {
                    // Get file types and counts
                    fileTypes := make(map[string]int)
                    for _, v := range vulns {
                        if vuln, ok := v.(map[string]interface{}); ok {
                            if filePath, ok := vuln["filePath"].(string); ok {
                                ext := filepath.Ext(filePath)
                                fileTypes[ext]++
                            }
                        }
                    }
                    
                    // Log file type distribution
                    log.Printf("Vulnerability distribution by file type:")
                    for ext, count := range fileTypes {
                        log.Printf("  %s: %d vulnerabilities", ext, count)
                    }
                }
            }
        }
    }
}

func saveTaskDetailToJson(taskDetail models.TaskDetail, myFuzzer string, fuzzDir string) error {

            // Create a hash from the fuzzer name
            fuzzerHash := hashString(myFuzzer)

    filePath := filepath.Join(fuzzDir, "task_detail.json")

    if !strings.Contains(fuzzDir, "fuzz-tooling/build/out") {
        // Create the file path with hash
        filePath = filepath.Join(fuzzDir, fmt.Sprintf("task_detail_%s.json", fuzzerHash))
    }

    // Marshal the taskDetail struct to JSON with indentation for readability
    jsonData, err := json.MarshalIndent(taskDetail, "", "  ")
    if err != nil {
        return fmt.Errorf("failed to marshal task detail: %v", err)
    }
    
    // Write the JSON data to the file
    err = os.WriteFile(filePath, jsonData, 0644)
    if err != nil {
        // Try with sudo if regular write fails
        if os.IsPermission(err) {
            tempFileName := fmt.Sprintf("/tmp/task_detail_%s.json", fuzzerHash)
            if tempErr := os.WriteFile(tempFileName, jsonData, 0644); tempErr != nil {
                return fmt.Errorf("failed to write temporary file: %v", tempErr)
            }
            
            cmd := exec.Command("sudo", "cp", tempFileName, filePath)
            if cpErr := cmd.Run(); cpErr != nil {
                return fmt.Errorf("failed to copy file with sudo: %v", cpErr)
            }
            
            chmodCmd := exec.Command("sudo", "chmod", "0644", filePath)
            if chmodErr := chmodCmd.Run(); chmodErr != nil {
                log.Printf("Warning: failed to set file permissions: %v", chmodErr)
            }
            
            os.Remove(tempFileName)
        } else {
            return fmt.Errorf("failed to write task detail to file: %v", err)
        }
    }
    
    log.Printf("Successfully saved task detail to %s", filePath)
    return nil
}


func (s *defaultCRSService) distributeFuzzers(allFuzzers []string, taskDetail models.TaskDetail, fullTask models.Task) {
    maxRetries := 1000
    retryInterval := 2 * time.Minute
    
    // Create a slice of fuzzer status to preserve order
    type fuzzerStatus struct {
        name     string
        attempts int
        pending  bool
    }
    
    // Initialize status for all fuzzers
    fuzzerStatuses := make([]fuzzerStatus, len(allFuzzers))
    for i, fuzzer := range allFuzzers {
        fuzzerStatuses[i] = fuzzerStatus{
            name:     fuzzer,
            attempts: 0,
            pending:  true,
        }
    }
    
    // First attempt for all fuzzers - in original order
    for i := range fuzzerStatuses {
        if !fuzzerStatuses[i].pending {
            continue
        }
        
        fuzzer := fuzzerStatuses[i].name
        if err := s.sendFuzzerToWorker(fuzzer, taskDetail, fullTask); err != nil {
            log.Printf("Failed to distribute fuzzer %s to any worker, will retry later: %v", fuzzer, err)
        } else {
            fuzzerStatuses[i].pending = false
        }
    }
    
    // Count pending fuzzers
    pendingCount := 0
    for i := range fuzzerStatuses {
        if fuzzerStatuses[i].pending {
            pendingCount++
        }
    }
    
    // If we still have pending fuzzers, start retry loop
    for pendingCount > 0 {
        log.Printf("Waiting %v before retrying %d pending fuzzers...", retryInterval, pendingCount)
        time.Sleep(retryInterval)
        
        // Try each pending fuzzer again - in original order
        for i := range fuzzerStatuses {
            if !fuzzerStatuses[i].pending {
                continue
            }
            
            fuzzer := fuzzerStatuses[i].name
            attempts := fuzzerStatuses[i].attempts
            
            // Check if we've exceeded max retries
            if attempts >= maxRetries {
                log.Printf("Exceeded maximum retries (%d) for fuzzer %s", maxRetries, fuzzer)
                fuzzerStatuses[i].pending = false
                pendingCount--
                //TODO Run locally as a last resort
                continue
            }
            
            if err := s.sendFuzzerToWorker(fuzzer, taskDetail, fullTask); err != nil {
                // Increment retry count
                fuzzerStatuses[i].attempts++
                log.Printf("All workers are still busy... still could not find a worker for fuzzer %s (attempt %d/%d)", 
                          fuzzer, attempts+1, maxRetries)
            } else {
                fuzzerStatuses[i].pending = false
                pendingCount--
            }
        }
        
        // If no more pending fuzzers, exit the loop
        if pendingCount == 0 {
            break
        }
    }
    
    // Report on any fuzzers that couldn't be distributed
    if pendingCount > 0 {
        // Collect names of pending fuzzers for the log
        pendingFuzzers := make([]string, 0, pendingCount)
        for _, status := range fuzzerStatuses {
            if status.pending {
                pendingFuzzers = append(pendingFuzzers, status.name)
            }
        }
        log.Printf("Could not distribute %d fuzzers after maximum retries: %v", 
                  pendingCount, pendingFuzzers)
    }
}

// copyFuzzDirForParallelStrategies creates multiple copies of the fuzzing directory
// for parallel fuzzing strategies. It creates copies in subdirectories ap0-ap3 and xp0.
func copyFuzzDirForParallelStrategies(myFuzzer,fuzzDir string) error {
    // Define target directories
    targetDirs := []string{"ap0", "ap1", "ap2", "ap3", "xp0", "sarif0"}
    fuzzerName := filepath.Base(myFuzzer)                         // e.g. html
    // Detect the sanitizer suffix in the parent directory name and strip it.
    sanitizerSuffixes := []string{
        "-address", "-undefined", "-memory", "-thread", "-ubsan",
        "-asan", "-msan", "-tsan",
    }
    coverageDir := fuzzDir                                        // default
    for _, suf := range sanitizerSuffixes {
        if strings.Contains(fuzzDir, suf) {
            coverageDir = strings.Replace(fuzzDir, suf, "", 1)    // e.g. libxml2-address → libxml2
            break
        }
    }

    coverageFuzzerPath := filepath.Join(coverageDir, fuzzerName)  // sibling binary    
    // Ensure the source directory exists
    info, err := os.Stat(fuzzDir)
    if err != nil {
        return fmt.Errorf("error accessing source directory %s: %w", fuzzDir, err)
    }
    
    if !info.IsDir() {
        return fmt.Errorf("%s is not a directory", fuzzDir)
    }
    
    isRoot := getEffectiveUserID() == 0
    if !isRoot {
        // Fix permissions using sudo
        // log.Printf("Current permissions on %s: %v", fuzzDir, info.Mode().Perm())
        // log.Printf("Attempting to fix permissions using sudo...")
    
        // Use sudo to change ownership and permissions
        chownCmd := exec.Command("sudo", "chown", "-R", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), fuzzDir)
        if err := chownCmd.Run(); err != nil {
            log.Printf("Warning: Failed to change ownership with sudo: %v", err)
        } else {
            // log.Printf("Successfully changed ownership of %s", fuzzDir)
        }
    
        // Change permissions
        chmodCmd := exec.Command("sudo", "chmod", "-R", "755", fuzzDir)
        if err := chmodCmd.Run(); err != nil {
            log.Printf("Warning: Failed to change permissions with sudo: %v", err)
        } else {
            // log.Printf("Successfully changed permissions of %s", fuzzDir)
        }
    
        // List contents of source directory for debugging
        // files, err := os.ReadDir(fuzzDir)
        // if err != nil {
        //     log.Printf("Error reading source directory contents: %v", err)
        //     return fmt.Errorf("error reading source directory contents: %w", err)
        // }
    
        // log.Printf("Source directory contains %d items:", len(files))
        // for _, file := range files {
        //     log.Printf("  - %s (isDir: %v)", file.Name(), file.IsDir())
        // }
    }

    for _, targetDir := range targetDirs {
        destPath := filepath.Join(fuzzDir, targetDir)
        
        // Create the target directory
        if err := os.MkdirAll(destPath, 0755); err != nil {
            return fmt.Errorf("failed to create directory %s: %w", destPath, err)
        }
        
        // Walk through the source directory and copy files
        err = filepath.Walk(fuzzDir, func(path string, info os.FileInfo, err error) error {
            if err != nil {
                return err
            }
            
            // Skip if the current path is one of our target directories
            for _, td := range targetDirs {
                if strings.Contains(path, filepath.Join(fuzzDir, td)) {
                    return nil
                }
            }
            
            // Get the path relative to the source directory
            relPath, err := filepath.Rel(fuzzDir, path)
            if err != nil {
                return err
            }
            
            // Skip the root directory
            if relPath == "." {
                return nil
            }
            
            // Create the destination path
            dest := filepath.Join(destPath, relPath)
            
            if info.IsDir() {
                // Create the directory
                return os.MkdirAll(dest, info.Mode())
            } else {
                // Copy the file
                return copyFile(path, dest)
            }
        })
        
        if err != nil {
            return fmt.Errorf("error copying to %s: %w", destPath, err)
        }

        // ------------------------------------
        // 2) Copy the *coverage* fuzzer binary
        // ------------------------------------
        if _, err := os.Stat(coverageFuzzerPath); err == nil {
            destCoverage := filepath.Join(destPath, fuzzerName+"-coverage")
            if copyErr := copyFile(coverageFuzzerPath, destCoverage); copyErr != nil {
                log.Printf("Failed to copy coverage fuzzer to %s: %v", destCoverage, copyErr)
            } else {
                log.Printf("Added coverage fuzzer: %s", destCoverage)
            }
        } else {
            log.Printf("Coverage fuzzer not found (skipped): %s", coverageFuzzerPath)
        }

        log.Printf("Created parallel strategy directory: %s", destPath)
    }
    
    return nil
}

func (s *defaultCRSService) runFuzzing(myFuzzer,taskDir string, taskDetail models.TaskDetail, fullTask models.Task, cfg *ProjectConfig, allFuzzers []string) error {

    if os.Getenv("LOCAL_TEST") != "" {
        s.workerIndex = "0"
        s.submissionEndpoint = "http://localhost:7081"
        myFuzzer = allFuzzers[0]
        for _, f := range allFuzzers {
            if strings.HasSuffix(f, "libxml2-address/xml") ||  strings.HasSuffix(f, "tika-address/HtmlParserFuzzer")  ||  strings.HasSuffix(f, "zookeeper-address/MessageTrackerPeekReceivedFuzzer") ||  strings.HasSuffix(f, "apache-commons-compress-address/CompressZipFuzzer")  ||  strings.HasSuffix(f, "sqlite3-address/customfuzz3")  {
                myFuzzer = f
                break
            }
        }
    }

    log.Printf("=========================================== Current Fuzzer ===========================================")
    log.Printf("myFuzzer: %s", myFuzzer)
    log.Printf("=========================================== Current Fuzzer ===========================================")

    // for crs-worker: send each fuzzer to a worker node
    // for a worker node, run the fuzzer w/ all resources
    if s.workerIndex == ""  {
        // For crs-webapp: send each fuzzer to a dedicated worker node
        s.distributeFuzzers(allFuzzers,taskDetail,fullTask)
    } else {

        //for testing only 
        //    if !strings.HasSuffix(myFuzzer, "apache-commons-compress-address/CompressZipFuzzer"){
        //     return nil
        // }
        
        // for crs-worker, let's develop a baseline strategy S0 for delta challenge
        // 1. ask LLM to generate Python code for test harness to trigger vulnerablity
        // - provide commit, fuzzer source code
        // - run Python code, test, ask again if failed and provide error message in another iteration
        // - limit timeout 30min and number of iterations 100
        // - ask multiple different models

        // note: 48h total time competition
        // 2. if timeout still all fail, save the seed corpus, ask LLM to generate dictionary, and do fuzzing
        // - for fuzzing, every 30mins, collect runtime data -print_final_stats=1, and ask LLM to regenerate seed inputs/dict based on runtime data and existing seeds
        // - let it run for six hours?? try focus-function in the commit

        // 3. if still fails, i don't know what to do.... [go ahead to work on patching ??] ....

        // Strategy S1
        // - write a static analysis to find all possible call stack from fuzzer to target functions in the commit
        // - provide the call stacks/corresponding source code to the LLM for generating inputs [HOW LONG IT TAKES FOR LARGE CODE??]


        // Strategy S2
        // - Analyze fuzzer to Generate grammar for fuzzing inputs
        // - Generate customized input generator based on the grammar (Python code)
        // - Run many parallel fuzzing inputs for a few hours

        // Strategy S3
        // - rebuild fuzzer with -fsanitize-coverage=func to track what functions are executed at runtime
        // - the runtime traces are provided to the LLM for generating new inputs [HOW MUCH SLOW DOWN??]
      
        // TRY DIFFERENT PROMPT TEMPLATES
        // - ask for generating inputs to trigger common vulnerablities specific CWE... 
        // - FOR JAVA/C, different prompts?

        // SETUP a local LLM service in case running out of credits
        // - ollama qwq?

        // Get absolute paths
        absTaskDir, err := filepath.Abs(taskDir)
        if err != nil {
            return fmt.Errorf("failed to get absolute task dir path: %v", err)
        }
        
        projectDir := path.Join(absTaskDir, taskDetail.Focus)
        // Run fuzzer
        if myFuzzer != ""  {

            fuzzDir := filepath.Dir(myFuzzer)
            saveTaskDetailToJson(taskDetail,myFuzzer,fuzzDir)

            //for workers, due to parallel running races, create a copy of fuzzDir for each thread
           err := copyFuzzDirForParallelStrategies(myFuzzer,fuzzDir)
           if err != nil {
            log.Printf("Failed to copy fuzzDir %s for parallel strategies. Error: %v", fuzzDir, err)
           } else {
            log.Printf("Running worker fuzzer: %v", myFuzzer)
           }

           baseName := filepath.Base(fuzzDir) // e.g. "bind9-address"
           parts := strings.Split(baseName, "-")
           sanitizer := parts[len(parts)-1] // "address" in this example

            // DO ALL STRATEGIES IN PARALLEL
            // JEFF-S0: python3 /app/jeff/xs0.py fuzzerPath
            // JEFF-S1: python3 jeff/xs1.py fuzzerPath
            // ZE-S0: python3 ze/xs0.py fuzzerPath
            // HQ-S0: python3 heqing/xs0.py fuzzerPath
            // ...

            llmFuzzingStartTime := time.Now() // llm fuzzing start time for this round

            patch_success := false
            pov_success := false

            // run strategies in parallel
            var povFound sync.Once
            type signal struct{}
            povChan := make(chan signal)
                        
            ctx := context.Background()

            //libfuzzer
            libFuzzerStarted := false
            //for C project, start write away
            lang := strings.ToLower(cfg.Language)
            if lang == "c" || lang == "c++" {
                libFuzzerStarted = true
                go func()  {
                    s.runLibFuzzer(myFuzzer, taskDir, projectDir, cfg.Language, taskDetail, fullTask)
                } ()
            }
            
            // go func() {
                log.Printf("BASIC PHASE started...")
                // 30 mins
                _, basicPhasesSpan := telemetry.StartSpan(ctx, "llm_basic_phase")
                basicPhasesSpan.SetAttributes(attribute.String("crs.action.category", "fuzzing"))
                basicPhasesSpan.SetAttributes(attribute.String("crs.action.name", "runLLMStrategies"))
                for key, value := range taskDetail.Metadata {
                    basicPhasesSpan.SetAttributes(attribute.String(key, value))
                }
                defer basicPhasesSpan.End()

                if os.Getenv("FUZZER_TEST") == "" {
                     pov_success = s.runStrategies(myFuzzer,taskDir, projectDir, fuzzDir, cfg.Language, taskDetail, fullTask)
                } else {    
                     // for testing and then exit
                     s.runLibFuzzer(myFuzzer,taskDir, projectDir, cfg.Language, taskDetail, fullTask)
                     os.Exit(0)
                }
                
                if pov_success {
                    povFound.Do(func() { close(povChan) })
                } else {
                    //if libFuzzer not started, e.g., for Java
                    if !libFuzzerStarted {
                        go func()  {
                            s.runLibFuzzer(myFuzzer, taskDir, projectDir, cfg.Language, taskDetail, fullTask)
                        } ()
                    }
                }
            // }()

             // Calculate time budget based on deadline
             deadlineTime := time.Unix(taskDetail.Deadline/1000, 0)
             totalBudgetMinutes := int(time.Until(deadlineTime).Minutes())
             if totalBudgetMinutes <= 0 {
                 log.Printf("(FOR TESTING): Task deadline passed! Setting it to one hour from now.")
                 totalBudgetMinutes = 60 // Minimum working time
                 deadlineTime = time.Now().Add(60 * time.Minute) // New line to reset the deadline
             }
 
             totalLibfuzzingTime := time.Until(deadlineTime) / 2
             log.Printf("totalLibfuzzingTime: %v", totalLibfuzzingTime)
             halfTimeToDeadline := time.Now().Add(totalLibfuzzingTime)
             log.Printf("halfTimeToDeadline: %v", halfTimeToDeadline)

             // if taskDetail.Type == "delta" {
             //     //should be ~6h for final
             // } else {
             //     //should be ~12h for final
             // }           
            workingBudgetMinutes := totalBudgetMinutes - safetyBufferMinutes
            sequentialTestRun := false          
            go func()  {
                // if pov failed, run continous fuzzing w/ load seeds every 10mins
                log.Printf("ADVANCED PHASES started...")

                //do libfuzzer after basic phase - seeds generated by LLM
                // go func() {
                //     s.runLibFuzzer(myFuzzer, taskDir, projectDir, cfg.Language, taskDetail, fullTask)
                // }()

                ctx, advancedPhasesSpan := telemetry.StartSpan(ctx, "llm_advanced_phases")
                advancedPhasesSpan.SetAttributes(attribute.String("crs.action.category", "fuzzing"))
                advancedPhasesSpan.SetAttributes(attribute.String("crs.action.name", "RunAdvancedLLMPhases"))
                for key, value := range taskDetail.Metadata {
                    advancedPhasesSpan.SetAttributes(attribute.String(key, value))
                }
                defer advancedPhasesSpan.End()
                
                log.Printf("Time budget: %.2f hours total, %.2f hours for work", 
                    float64(totalBudgetMinutes)/60.0, 
                    float64(workingBudgetMinutes)/60.0)


                advancedPhasesSpan.SetAttributes(attribute.Float64("crs.budget.total_hours", float64(totalBudgetMinutes)/60.0))
                advancedPhasesSpan.SetAttributes(attribute.Float64("crs.budget.working_hours", float64(workingBudgetMinutes)/60.0))

                // Initial POV budget calculated (e.g., 80% of working time)
                initialPovBudgetMinutes := int(float64(workingBudgetMinutes) * 0.8)
                if initialPovBudgetMinutes < 1 {
                    initialPovBudgetMinutes = 1 
                }
                log.Printf("Initial calculated POV budget: %d minutes", initialPovBudgetMinutes)
                initialPovBudgetDuration := time.Duration(initialPovBudgetMinutes) * time.Minute


                // Using 4 phases as an example based on the original phaseRatios len
                numPhases := 4 

                roundNum := 0 // Counter for logging/telemetry

                var totalPovTimeSpent time.Duration // Accumulator for time spent in POV rounds
                // Loop until POV is found or deadline approaches
                for {
                    roundNum++
                    log.Printf("Starting Advanced Phases Round %d", roundNum)

                    // --- Check for exit conditions before starting a new round ---
                    // 1. Check if POV was found in a previous round or by the basic phase
                    select {
                    case <-povChan:
                        log.Printf("POV signal received before starting round %d, exiting advanced loop.", roundNum)
                        return // Exit the advanced phases goroutine
                    default:
                        // No POV signal yet, continue
                    }

                    // 2. Check deadline - leave buffer time
                    currentTime := time.Now()
                    if currentTime.After(deadlineTime.Add(-time.Duration(safetyBufferMinutes) * time.Minute)) {
                         log.Printf("Absolute deadline approaching before starting round %d, exiting advanced loop.", roundNum)
                         return // Exit the advanced phases goroutine
                    }

                    // 3. Check remaining POV budget based on time spent in previous rounds
                    remainingPovBudgetDuration := initialPovBudgetDuration - totalPovTimeSpent
                    if remainingPovBudgetDuration <= 0 {
                         log.Printf("Calculated POV budget exhausted before starting round %d (spent: %v), exiting advanced loop.", roundNum, totalPovTimeSpent)
                         return // Exit the advanced phases goroutine
                    }

                    // Determine the actual timeout for this round: minimum of remaining overall deadline and remaining calculated POV budget
                    absoluteRemainingTime := deadlineTime.Sub(currentTime)
                    effectiveRemainingTime := absoluteRemainingTime - time.Duration(safetyBufferMinutes)*time.Minute
                    
                    roundTimeoutDuration := remainingPovBudgetDuration // Start with remaining calculated budget
                    if effectiveRemainingTime < roundTimeoutDuration {
                        log.Printf("Round %d timeout capped by absolute deadline proximity. Using %v instead of %v.", roundNum, effectiveRemainingTime, roundTimeoutDuration)
                        roundTimeoutDuration = effectiveRemainingTime // Cap by actual time left
                    }

                    if roundTimeoutDuration <= 0 {
                        log.Printf("Insufficient time budget calculated for round %d (%v). Exiting advanced loop.", roundNum, roundTimeoutDuration)
                        return // No time left for this round
                    }
                    
                    roundTimeoutMinutes := int(roundTimeoutDuration.Minutes())
                    if roundTimeoutMinutes < 1 { roundTimeoutMinutes = 1} // Ensure at least 1 minute timeout value
                    if roundTimeoutMinutes > 60 { roundTimeoutMinutes = 60} // Ensure at most 60 minutes per round

                    log.Printf("Starting Advanced Phases Round %d with timeout budget: %d minutes", roundNum, roundTimeoutMinutes)
                    // --- End Exit Condition Checks ---

                    roundStartTime := time.Now() // Record start time for this round


                    var roundWG sync.WaitGroup // WaitGroup for the current round
                    povFoundInRound := false   // Track if POV found specifically in this round

                    if sequentialTestRun {

                        log.Printf("Running sequential phases for round %d...", roundNum)
                        // Calculate timeouts based on *remaining* budget? Or fixed per round?
                        // Example: Fixed timeouts per round based on original ratios
                        phaseRatios := []float64{0.1, 0.2, 0.2, 0.5}
                        phaseTimeouts := make([]int, len(phaseRatios))
                        for i, ratio := range phaseRatios {
                            phaseTimeouts[i] = int(float64(roundTimeoutMinutes) * ratio)
                            if phaseTimeouts[i] < 1 { phaseTimeouts[i] = 1 } // Min 1 min per phase
                        }

                        // Run in multiple phases with increasing timeouts
                        for phase, timeout := range phaseTimeouts {
                            // Check deadline before starting phase
                            if time.Now().After(deadlineTime.Add(-time.Duration(safetyBufferMinutes) * time.Minute)) {
                                log.Printf("Deadline approaching during sequential phase %d of round %d.", phase+1, roundNum)
                                povFoundInRound = false // Ensure we exit outer loop if deadline hit here
                                break // Break inner phase loop
                            }
                            log.Printf("Starting phase %d (timeout %d min) for round %d", phase+1, timeout, roundNum)
                        // Create a span for each phase
                            _, phaseSpan := telemetry.StartSpan(ctx, fmt.Sprintf("pov_round%d_phase%d", roundNum, phase+1))
                            phaseSpan.SetAttributes(attribute.String("crs.action.category", "input_generation"))
                            phaseSpan.SetAttributes(attribute.String("crs.action.name", fmt.Sprintf("runPOVPhase%d", phase)))
                            phaseSpan.SetAttributes(attribute.Int("crs.phase.number", phase))
                            phaseSpan.SetAttributes(attribute.Int("crs.round.number", roundNum))
                            phaseSpan.SetAttributes(attribute.Int("crs.phase.timeout_minutes", timeout))
                            for key, value := range taskDetail.Metadata {
                                phaseSpan.SetAttributes(attribute.String(key, value))
                            }
                            // FOR PHASE 1: five each call + coverage
                            // FOR PHASE 2: + category
                            // FOR PHASE 3: + full source code
                            pov_success = s.runAdvancedPOVStrategiesWithTimeout(myFuzzer,taskDir, projectDir,cfg.Language, taskDetail, fullTask, timeout,phase,roundNum)
                        
                            phaseSpan.SetAttributes(attribute.Bool("crs.phase.pov_success", pov_success))
                            phaseSpan.End()

                            if pov_success {
                                log.Printf("POV found in sequential phase %d of round %d.", phase+1, roundNum)
                                povFoundInRound = true
                                povFound.Do(func() { close(povChan) })
                                break
                            }
                            log.Printf("No POV found in sequential phase %d of round %d.", phase+1, roundNum)
                        }
                        if povFoundInRound {
                            break // Exit the outer round loop
                        }

                    } else {

                        log.Printf("Running parallel phases for round %d (timeout per phase: %d min)...", roundNum, roundTimeoutMinutes) // Log the calculated round timeout

                        for phase := 0; phase < numPhases; phase++ {
                            roundWG.Add(1) // Increment counter before launching goroutine
                            go func(phase int) {
                                defer roundWG.Done() // Decrement counter when goroutine finishes
                                // Check deadline *inside* goroutine before starting work? Optional but good practice.
                                if time.Now().After(deadlineTime.Add(-time.Duration(safetyBufferMinutes) * time.Minute)) {
                                    log.Printf("Deadline approaching, skipping parallel phase %d of round %d.", phase+1, roundNum)
                                    return 
                                }
                                log.Printf("Starting parallel phase %d (using round timeout %d min) for round %d", phase+1, roundTimeoutMinutes, roundNum) 
                                // Create a span for each phase
                                _, phaseSpan := telemetry.StartSpan(ctx, fmt.Sprintf("pov_round%d_phase%d", roundNum, phase+1))
                                phaseSpan.SetAttributes(attribute.String("crs.action.category", "input_generation"))
                                phaseSpan.SetAttributes(attribute.String("crs.action.name", fmt.Sprintf("runPOVPhase%d", phase)))
                                phaseSpan.SetAttributes(attribute.Int("crs.phase.number", phase))
                                phaseSpan.SetAttributes(attribute.Int("crs.round.number", roundNum))
                                phaseSpan.SetAttributes(attribute.Int("crs.phase.timeout_minutes", roundTimeoutMinutes)) 
                                for key, value := range taskDetail.Metadata {
                                    phaseSpan.SetAttributes(attribute.String(key, value))
                                }
                                pov_success = s.runAdvancedPOVStrategiesWithTimeout(myFuzzer,taskDir, projectDir,cfg.Language, taskDetail, fullTask, roundTimeoutMinutes,phase,roundNum)
                            
                                phaseSpan.SetAttributes(attribute.Bool("crs.phase.pov_success", pov_success))
                                phaseSpan.End()
                                if pov_success {
                                    log.Printf("POV found in parallel phase %d of round %d.", phase+1, roundNum)
                                    povFound.Do(func() { close(povChan) })
                                } else {
                                    log.Printf("No POV found in parallel phase %d of round %d.", phase+1, roundNum)
                                }
                            }(phase)

                        }
                        // Wait for all goroutines *in this round* to complete
                        roundWG.Wait()
                         // Calculate time spent *in this round*
                         roundDuration := time.Since(roundStartTime)
                         log.Printf("All parallel phases for round %d completed in %v.", roundNum, roundDuration)
                         // Add this round's duration to the total spent time
                         totalPovTimeSpent += roundDuration 
                         log.Printf("Total POV time spent across rounds: %v", totalPovTimeSpent)

                        // After waiting, check if the POV signal was sent during this round
                        select {
                        case <-povChan:
                            log.Printf("POV signal received after round %d completed.", roundNum)
                            povFoundInRound = true // Set flag to break outer loop
                        default:
                            // No POV signal from this round, loop will continue after checking deadline
                        }

                    } // End parallel execution logic
                    // If POV was found in this round (either sequential or parallel), break the outer loop
                    if povFoundInRound {
                        break
                    }

                    // Optional: Add a small delay between rounds?
                    // time.Sleep(10 * time.Second) 
                    //check if other fuzzers have found POVs, if yes and runnnig long enough, break
                    {
                        llmFuzzingDuration := time.Since(llmFuzzingStartTime)
                        pov_count, patch_count, err := s.getPOVStatsFromSubmissionService(taskDetail.TaskID.String())
                        if err != nil {
                            log.Printf("Error getPOVStatsFromSubmissionService: %v", err)
                        } else if pov_count > 0 && llmFuzzingDuration > 45 * time.Minute {
                            // Enough POVs already exist and this fuzzer has been running >1 h – stop to save resources
                            log.Printf("POV already found in other fuzzers. llmFuzzingDuration %v (>45min). Stop LLM Fuzzer %s. pov_count: %d patch_count: %d",
                            llmFuzzingDuration, myFuzzer, pov_count, patch_count)
                            break
                        } else if llmFuzzingDuration > totalLibfuzzingTime || llmFuzzingDuration > 60 * time.Minute {
                            // half time of challenge time 
                            log.Printf("Halftime or 1h passed. llmFuzzingDuration %v. Stop LLM Fuzzer %s. pov_count: %d patch_count: %d",
                            llmFuzzingDuration, myFuzzer, pov_count, patch_count)
                            break
                        } else if pov_count > 0 {
                            // POVs exist but we haven’t hit the 1 h mark yet – keep fuzzing a bit longer
                            log.Printf("POVs found by other fuzzers but llmFuzzingDuration only %v (<1h). Continuing. pov_count: %d patch_count: %d",
                            llmFuzzingDuration, pov_count, patch_count)
                        } else {
                            log.Printf("No POVs found so far, llmFuzzingDuration: %v, continue to next round", llmFuzzingDuration)
                        }
                    }
                } // End of the main advanced phases loop

                log.Printf("Exiting advanced phases goroutine.")
                // Advanced phases finished (either by finding POV or hitting deadline in loop check)
                // The outer select statement will handle the next steps (patching or deadline error)
                
            }()

            // Wait for POV found or deadline
            select {
            case <-povChan:
                log.Println("POV found, proceeding to patching.")
                // Proceed to patching

                // Create a span for patching
                _, patchSpan := telemetry.StartSpan(ctx, "patching")
                patchSpan.SetAttributes(attribute.String("crs.action.category", "patch_generation"))
                patchSpan.SetAttributes(attribute.String("crs.action.name", "runPatchingStrategies"))
                for key, value := range taskDetail.Metadata {
                    patchSpan.SetAttributes(attribute.String(key, value))
                }
                advancedMetadataPath := filepath.Join(fuzzDir, s.povAdvcancedMetadataDir)
                if _, err := os.Stat(advancedMetadataPath); err == nil {
                    // Advanced metadata directory exists, use it for patching
                    log.Printf("Using advanced POV metadata for patching: %s", s.povAdvcancedMetadataDir)
                    patch_success = s.runPatchingStrategies(myFuzzer, taskDir, projectDir, sanitizer, cfg.Language, 
                                                            s.povAdvcancedMetadataDir, taskDetail, fullTask,deadlineTime)
                } else {
                    // Advanced metadata not found, fallback to basic metadata
                    log.Printf("Using basic POV metadata for patching: %s", s.povMetadataDir0)
                    patch_success = s.runPatchingStrategies(myFuzzer, taskDir, projectDir, sanitizer, cfg.Language, 
                                                            s.povMetadataDir0, taskDetail, fullTask,deadlineTime)
                }
                patchSpan.SetAttributes(attribute.Bool("crs.patch.success", patch_success))
                patchSpan.End()

            case <- time.After(time.Until(halfTimeToDeadline)):
                //use the first worker of a challenge to do xpatch
                if myFuzzer != UNHARNESSED {
                    pov_count, patch_count, err := s.getPOVStatsFromSubmissionService(taskDetail.TaskID.String())
                    if err != nil {
                        log.Printf("Error getPOVStatsFromSubmissionService: %v", err)
                    } else if pov_count ==0 || patch_count == 0 {
                        log.Printf("Halftime has passed but NO PATCH found (pov_count: %d patch_count %d), let's try xpatch...", pov_count, patch_count)
                        patch_success = s.runXPatchingStrategiesWithoutPOV(myFuzzer, taskDir, projectDir, sanitizer, cfg.Language, 
                            taskDetail, fullTask,deadlineTime)

                        if !patch_success && taskDetail.HarnessesIncluded {
                            //last try: to use sarif if available 
                            sarifDir := path.Join(taskDir, "sarif_broadcasts")
                            if dirExists(sarifDir) {
                                log.Printf("[XPATCH-SARIF] try patching with SARIF info if available...")
                                // Load all SARIF JSON files under taskDir/sarif_broadcasts and
                                // attempt XPATCH for each of them.
                                sarifFiles, err := filepath.Glob(filepath.Join(sarifDir, "*.json"))
                                if err != nil {
                                    log.Printf("Error while globbing SARIF files: %v", err)
                                }
                                for _, sarifPath := range sarifFiles {
                                    if s.runXPatchSarifStrategies(myFuzzer, taskDir, sarifPath, cfg.Language, taskDetail, deadlineTime) {
                                        patch_success = true
                                        break
                                    }
                                }
                            }
                        }

                        log.Printf("[XPATCH Completed] patch_success: %v", patch_success)

                        // create (or overwrite) a sentinel file so other processes can detect
                        // that XPATCH has finished running for this fuzzer.
                        fuzzerName := filepath.Base(myFuzzer)
                        sentinelFile := path.Join(taskDir, "xpatch-"+fuzzerName)
                        if err := os.WriteFile(sentinelFile, []byte(fmt.Sprintf("success=%v\n", patch_success)), 0644); err != nil {
                            log.Printf("failed to create sentinel file %s: %v", sentinelFile, err)
                        } else {
                            log.Printf("[XPATCH Completed] created sentinel file: %s", sentinelFile)
                        }
                    }
                }

            case <-time.After(time.Until(deadlineTime)):
                log.Println("Deadline reached without finding POV.")
                return errors.New("Failed to find POV within deadline")
            }

               // instead of io.WriteString(log.Writer(), "\r")
   io.WriteString(log.Writer(), "\r\033[K")
            if patch_success {
                log.Printf("JOB DONE! %s", myFuzzer)
                return nil
            } else {
                log.Printf("Failed to find patch within deadline.")
                return errors.New("Failed to find patch within deadline")
            }

        } 
    }
    return nil
}

func getFuzzerArgs(containerName, fuzzDir, fuzzerName, language, sanitizer, taskDir string) []string {
    // Get available CPU cores
    numCPU := runtime.NumCPU()
    
    // Determine the seed corpus path
    seedCorpusName := fmt.Sprintf("%s_seed_corpus", fuzzerName)
    seedCorpusPath := filepath.Join(taskDir, seedCorpusName)
    
    // Docker run arguments
    dockerArgs := []string{
        "run",
        "--privileged",
        "--platform", "linux/amd64",
        "--rm",
        "--name="+containerName,
    }
    
    numOfJobs := numCPU
    if numCPU >= 180 {
        numOfJobs = numCPU-12
    } else if numCPU >= 32 {
        numOfJobs = numCPU-4
    } else {
        numOfJobs = numCPU-2
    }

    // Resource arguments based on VM size
    var resourceArgs []string
    if numCPU >= 180 { // Likely M192is_v2 or similar high-end VM
        resourceArgs = []string{
            "--shm-size=512g",
            "--memory=3072g",
            fmt.Sprintf("--cpus=%d", numCPU-12), // Reserve some CPUs for system
        }
    } else if numCPU >= 32 { // Medium-sized VM
        resourceArgs = []string{
            "--shm-size=16g",
            "--memory=96g",
            fmt.Sprintf("--cpus=%d", numCPU-4),
        }
    } else { // Smaller VM like D5_v2
        resourceArgs = []string{
            "--shm-size=8g",
            "--memory=42g",
            fmt.Sprintf("--cpus=%d", numCPU-2),
        }
    }

    if strings.HasPrefix(language, "j") {
        //FOR JAVA, use only 1/4 of the resources for fuzzing
        if numOfJobs > numCPU/4 {
            numOfJobs = numCPU/4
        }
        // max 16
        if numOfJobs > 16 {
            numOfJobs = 16
        }

        resourceArgs = []string{
            "--shm-size=16g",
            "--memory=40g",
            fmt.Sprintf("--cpus=%d", 16),
        }
    }

    numOfWorkers := numOfJobs
    
    // Environment variables
    envArgs := []string{
        "-e", "FUZZING_ENGINE=libfuzzer",
        "-e", fmt.Sprintf("SANITIZER=%s", sanitizer),
        "-e", "RUN_FUZZER_MODE=interactive",
        // "-e", "UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1",
        "-e", "HELPER=True",
    }
    
    // Volume mounts
    volumeArgs := []string{
        "-v", fmt.Sprintf("%s:/out", fuzzDir),
    }
    
    // Add dynamic seed corpus volume mount if the directory exists
    if _, err := os.Stat(seedCorpusPath); err == nil {
        volumeArgs = append(volumeArgs, "-v", fmt.Sprintf("%s:/additional_corpus", seedCorpusPath))
    }
    
    //TODO LLM to generate fuzz dict and save to {fuzzerName}_custom.dict
    customDictPath := filepath.Join(taskDir, fmt.Sprintf("%s_custom.dict", fuzzerName))
    hasDictionary := false
    if _, err := os.Stat(customDictPath); err == nil {
        hasDictionary = true
        volumeArgs = append(volumeArgs, "-v", fmt.Sprintf("%s:/additional_dict", customDictPath))
    }
    
    // Create a persistent corpus directory
    hasCorpus := true
    corpusDir := filepath.Join(taskDir, fmt.Sprintf("%s_corpus", fuzzerName))
    if _, err := os.Stat(corpusDir); os.IsNotExist(err) {
        if err := os.MkdirAll(corpusDir, 0755); err != nil {
            hasCorpus = false
            log.Printf("failed to create corpus directory: %v", err)
        }
    }

    volumeArgs = append(volumeArgs, "-v", fmt.Sprintf("%s:/corpus", corpusDir))
        
    // Container and command
    containerArgs := []string{
        "ghcr.io/aixcc-finals/base-runner:v1.3.0",
        "run_fuzzer",
        fuzzerName,
    }    
    // Common fuzzer options
    commonFuzzerOpts := []string{
        "-verbosity=0",
        "-entropic=1",
        "-entropic_scale_per_exec_time=1", // optimize generation strategy for higher coverage and higher speed; weak for mutating detail values.
        "-cross_over_uniform_dist=1",
        "-prefer_small=1",
        "-use_value_profile=1",
        "-fork=1",
        "-shrink=1",
        "-reduce_inputs=1",
        "-use_counters=1",
        "-artifact_prefix=/out/crashes/",
    }
    
    if hasDictionary {
        commonFuzzerOpts = append(commonFuzzerOpts, "-dict=/additional_dict")
    }
    if hasCorpus {
        commonFuzzerOpts = append(commonFuzzerOpts, "/corpus")
    }

    // Specific fuzzer options based on VM size
    var fuzzerOpts []string
    if numCPU >= 180 { // Likely M192is_v2 or similar high-end VM
        fuzzerOpts = []string{
            "-max_total_time=7200",
            fmt.Sprintf("-jobs=%d", numOfJobs),
            fmt.Sprintf("-workers=%d", numOfWorkers),
            "-print_final_stats=1",
            "-reload=300",
            // "-timeout=30",
            "-timeout_exitcode=99",
            "-rss_limit_mb=262144",
            "-malloc_limit_mb=131072",
            "-max_len=168276",
            "-detect_leaks=0",
        }
    } else if numCPU >= 32 { // Medium-sized VM
        fuzzerOpts = []string{
            "-max_total_time=7200",
            fmt.Sprintf("-jobs=%d", numOfJobs),
            fmt.Sprintf("-workers=%d", numOfWorkers),
            "-print_final_stats=1",
            "-reload=300",
            // "-timeout=15",
            "-timeout_exitcode=99",
            "-rss_limit_mb=32768",
            "-malloc_limit_mb=16384",
            "-max_len=168276",
        }
    } else { // Smaller VM like D5_v2
        fuzzerOpts = []string{
            "-max_total_time=7200",
            fmt.Sprintf("-jobs=%d", numOfJobs),
            fmt.Sprintf("-workers=%d", numOfWorkers),
            "-print_final_stats=1",
            "-reload=300",
            // "-timeout=10",
            "-timeout_exitcode=99",
            "-rss_limit_mb=16384",
            "-malloc_limit_mb=8192",
            "-max_len=168276",
        }
    }
    
    // Add dynamic seed corpus directory as an argument if it exists
    var corpusArgs []string
    if _, err := os.Stat(seedCorpusPath); err == nil {
        corpusArgs = append(corpusArgs, "/additional_corpus")
    }
    
    // Combine all arguments in the correct order
    var cmdArgs []string
    cmdArgs = append(cmdArgs, dockerArgs...)
    cmdArgs = append(cmdArgs, resourceArgs...)
    cmdArgs = append(cmdArgs, envArgs...)
    cmdArgs = append(cmdArgs, volumeArgs...)
    cmdArgs = append(cmdArgs, containerArgs...)
    cmdArgs = append(cmdArgs, commonFuzzerOpts...)
    cmdArgs = append(cmdArgs, fuzzerOpts...)
    cmdArgs = append(cmdArgs, corpusArgs...)
    
    return cmdArgs
}

// WorkerStatus tracks the status of each worker
type WorkerStatus struct {
    LastAssignedTime time.Time
    FailureCount     int
    BlacklistedUntil time.Time
    AssignedTasks    int
}

func (s *defaultCRSService) sendFuzzerToWorker(fuzzer string, taskDetail models.TaskDetail, fullTask models.Task) error {
    // Lock to ensure consistent task distribution across concurrent requests
    s.distributionMutex.Lock()
    defer s.distributionMutex.Unlock()

    // Create a worker-specific task request with just this task and fuzzer
    workerRequest := models.WorkerTask{
        MessageID:   fullTask.MessageID,
        MessageTime: fullTask.MessageTime,
        Tasks:       []models.TaskDetail{taskDetail},
        Fuzzer:      fuzzer,
    }
    
    // Marshal the request
    taskJSON, err := json.Marshal(workerRequest)
    if err != nil {
        return fmt.Errorf("error marshaling task: %v", err)
    }
    
    // Get API credentials from environment
    apiKeyID := os.Getenv("CRS_KEY_ID")
    apiToken := os.Getenv("CRS_KEY_TOKEN")
    
    // Lock to safely access and update worker status
    s.workerStatusMux.Lock()
    defer s.workerStatusMux.Unlock()
    
    // Check if this fuzzer has been assigned before
    if existingWorker, exists := s.fuzzerToWorkerMap[fuzzer]; exists {
        log.Printf("Found existing assignment for fuzzer %s -> worker %d", fuzzer, existingWorker)
        
        // Check if the worker is not blacklisted
        workerStatus := s.workerStatus[existingWorker]
        if time.Now().After(workerStatus.BlacklistedUntil) {
            // Try to send to the existing worker first
            if s.tryWorker(existingWorker, taskJSON, apiKeyID, apiToken, fuzzer, taskDetail.TaskID.String()) {
                return nil
            }
            // If failed, continue with normal worker selection
        }
    }
    
    // Find the best worker to assign the task to
    selectedWorker := s.selectBestWorker()
    
    // If all workers are busy, reset their assigned task counts
    if selectedWorker == -1 {
        log.Printf("All workers are busy, resetting assignment counts")
        for i := range s.workerStatus {
            s.workerStatus[i].AssignedTasks = 0
        }
        selectedWorker = s.selectBestWorker()
    }
    
    // Try the selected worker
    if selectedWorker != -1 && s.tryWorker(selectedWorker, taskJSON, apiKeyID, apiToken, fuzzer, taskDetail.TaskID.String()) {
        return nil
    }
    
    // If the selected worker failed, try all non-blacklisted workers
    log.Printf("Selected worker %d failed, trying all available workers", selectedWorker)
    for j := 1; j < s.workerNodes; j++ {
        i := (selectedWorker + j) % s.workerNodes
        if i == selectedWorker {
            continue // Skip the already tried worker
        }
        // Skip blacklisted workers
        if !time.Now().After(s.workerStatus[i].BlacklistedUntil) {
            log.Printf("Worker %d is blacklisted until %v, skipping", i, s.workerStatus[i].BlacklistedUntil)
            continue
        }
        
        if s.tryWorker(i, taskJSON, apiKeyID, apiToken, fuzzer, taskDetail.TaskID.String()) {
            return nil
        }
    }
    
    // If we get here, we've tried all workers and none worked
    return fmt.Errorf("all available workers failed to accept the task")
}

// selectBestWorker finds the best worker to assign a task to
func (s *defaultCRSService) selectBestWorker() int {
    now := time.Now()
    var bestWorker int = -1
    var minAssignedTasks int = math.MaxInt32
    
    // First, look for non-blacklisted workers with the fewest assigned tasks
    for i := 0; i < s.workerNodes; i++ {
        status := s.workerStatus[i]
        
        // Skip blacklisted workers
        if !now.After(status.BlacklistedUntil) {
            continue
        }
        
        // Find the worker with the fewest assigned tasks
        if status.AssignedTasks < minAssignedTasks {
            minAssignedTasks = status.AssignedTasks
            bestWorker = i
        }
    }
    
    return bestWorker
}

// tryWorker attempts to send a task to a specific worker
func (s *defaultCRSService) tryWorker(workerIndex int, taskJSON []byte, apiKeyID, apiToken, fuzzer, taskID string) bool {
    // Construct the worker URL
    workerURL := fmt.Sprintf("http://crs-worker-%d.crs-worker.crs-webservice.svc.cluster.local:%d/v1/task/", 
                            workerIndex, s.workerBasePort)
    
    if os.Getenv("LOCAL_TEST") != "" {
        workerURL = "http://localhost:9081/v1/task/"                      
    }
    
    // log.Printf("Attempting to send fuzzer %s to worker %d", fuzzer, workerIndex)
    
    // Send the task to the worker
    client := &http.Client{
        Timeout: 10 * time.Second,
    }
    
    req, err := http.NewRequest("POST", workerURL, bytes.NewBuffer(taskJSON))
    if err != nil {
        log.Printf("Error creating request for worker %d: %v", workerIndex, err)
        s.recordWorkerFailure(workerIndex)
        return false
    }
    
    req.Header.Set("Content-Type", "application/json")
    if apiKeyID != "" && apiToken != "" {
        req.SetBasicAuth(apiKeyID, apiToken)
    }
    
    resp, err := client.Do(req)
    if err != nil {
        log.Printf("Error sending task to worker %d: %v", workerIndex, err)
        s.recordWorkerFailure(workerIndex)
        return false
    }
    
    // Check response status
    if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
        body, _ := io.ReadAll(resp.Body)
        log.Printf("Worker %d returned non-OK status: %d, body: %s", 
                workerIndex, resp.StatusCode, string(body))
        resp.Body.Close()
        s.recordWorkerFailure(workerIndex)
        return false
    }
    
    // Success!
    resp.Body.Close()
    
    // Update the worker status
    s.workerStatus[workerIndex].LastAssignedTime = time.Now()
    s.workerStatus[workerIndex].FailureCount = 0
    s.workerStatus[workerIndex].AssignedTasks++
    
    // Update the fuzzer-to-worker map with the successful worker
    s.fuzzerToWorkerMap[fuzzer] = workerIndex
    s.taskToWorkersMap[taskID] = append(s.taskToWorkersMap[taskID], WorkerFuzzerPair{
        Worker: workerIndex,
        Fuzzer:  fuzzer,
    })
    // Increment the counter only on successful distribution
    s.totalTasksDistributed++
    
    log.Printf("Successfully assigned fuzzer %s to worker %d for task %s", 
            fuzzer, workerIndex, taskID)
    
    return true
}

// recordWorkerFailure records a failure for a worker and blacklists it if necessary
func (s *defaultCRSService) recordWorkerFailure(workerIndex int) {
    status := s.workerStatus[workerIndex]
    status.FailureCount++
    
    // If the worker has failed too many times, blacklist it for 5 minutes
    if status.FailureCount >= 3 {
        status.BlacklistedUntil = time.Now().Add(5 * time.Minute)
        log.Printf("Worker %d has failed %d times, blacklisted until %v", 
                workerIndex, status.FailureCount, status.BlacklistedUntil)
    }
}

func (s *defaultCRSService) isSASTokenExpired(urlStr string) bool {
    u, err := url.Parse(urlStr)
    if err != nil {
        return true
    }
    
    // Get expiry time from SAS token
    se := u.Query().Get("se")
    if se == "" {
        return false  // No expiry time found
    }
    
    // Parse the expiry time
    expiry, err := time.Parse(time.RFC3339, se)
    if err != nil {
        log.Printf("Failed to parse SAS token expiry time: %v", err)
        return true
    }
    
    // Add some buffer time (e.g., 5 minutes)
    bufferTime := 5 * time.Minute
    if time.Until(expiry) < bufferTime {
        log.Printf("SAS token will expire soon or has expired. Expiry: %v", expiry)
        return true
    }
    
    return false
}

func (s *defaultCRSService) downloadAndVerifySource(taskDir string, source models.SourceDetail) error {
    // Check SAS token expiration first
    if s.isSASTokenExpired(source.URL) {
        return fmt.Errorf("SAS token for %s has expired or will expire soon", source.Type)
    }
    
    outPath := path.Join(taskDir, fmt.Sprintf("%s.tar.gz", source.Type))
    
    maxRetries := 3
    for attempt := 1; attempt <= maxRetries; attempt++ {
        log.Printf("Downloading %s (attempt %d/%d): %s", source.Type, attempt, maxRetries, source.URL)
        
        // Create HTTP client with timeout
        client := &http.Client{
            Timeout: 5 * time.Minute,
        }

        // Make request
        resp, err := client.Get(source.URL)
        if err != nil {
            log.Printf("Download error: %v", err)
            if attempt == maxRetries {
                return fmt.Errorf("failed to download source after %d attempts: %v", maxRetries, err)
            }
            continue
        }
        defer resp.Body.Close()

        // Check response status
        if resp.StatusCode != http.StatusOK {
            log.Printf("Download failed with status %d", resp.StatusCode)
            if attempt == maxRetries {
                return fmt.Errorf("download failed with status %d after %d attempts", resp.StatusCode, maxRetries)
            }
            continue
        }

        // Check Content-Length
        expectedSize := resp.ContentLength
        // if expectedSize > 0 {
        //     log.Printf("Expected file size: %d bytes", expectedSize)
        //     // For repo.tar.gz, expect around 1.6MB
        //     if source.Type == models.SourceTypeRepo && expectedSize < 1_000_000 {
        //         log.Printf("Warning: repo.tar.gz seems too small (%d bytes)", expectedSize)
        //         if attempt == maxRetries {
        //             return fmt.Errorf("repo.tar.gz too small: %d bytes", expectedSize)
        //         }
        //         continue
        //     }
        // }

        // Create output file
        out, err := os.Create(outPath)
        if err != nil {
            return fmt.Errorf("failed to create output file: %v", err)
        }
        defer out.Close()

        // Calculate SHA256 while copying
        h := sha256.New()
        written, err := io.Copy(io.MultiWriter(out, h), resp.Body)
        if err != nil {
            log.Printf("Download incomplete: %v", err)
            os.Remove(outPath) // Clean up partial file
            if attempt == maxRetries {
                return fmt.Errorf("failed to save file after %d attempts: %v", maxRetries, err)
            }
            continue
        }

        // Verify downloaded size matches Content-Length
        if expectedSize > 0 && written != expectedSize {
            log.Printf("Size mismatch. Expected: %d, Got: %d", expectedSize, written)
            os.Remove(outPath) // Clean up incomplete file
            if attempt == maxRetries {
                return fmt.Errorf("incomplete download after %d attempts. Expected: %d, Got: %d", 
                    maxRetries, expectedSize, written)
            }
            continue
        }

        // Verify minimum size for repo.tar.gz
        // if source.Type == models.SourceTypeRepo && written < 1_000_000 {
        //     log.Printf("repo.tar.gz too small: %d bytes", written)
        //     os.Remove(outPath) // Clean up suspicious file
        //     if attempt == maxRetries {
        //         return fmt.Errorf("repo.tar.gz too small after %d attempts: %d bytes", maxRetries, written)
        //     }
        //     continue
        // }

        // Verify SHA256
        downloadedHash := hex.EncodeToString(h.Sum(nil))
        if downloadedHash != source.SHA256 {
            log.Printf("SHA256 mismatch for %s\nExpected: %s\nGot:      %s", 
                source.Type, source.SHA256, downloadedHash)
            os.Remove(outPath) // Clean up invalid file
            if attempt == maxRetries {
                return fmt.Errorf("SHA256 mismatch for %s after %d attempts", source.Type, maxRetries)
            }
            continue
        }

        // Verify the file on disk
        if stat, err := os.Stat(outPath); err != nil {
            log.Printf("Failed to stat downloaded file: %v", err)
            if attempt == maxRetries {
                return fmt.Errorf("failed to verify file after download: %v", err)
            }
            continue
        } else {
            log.Printf("Successfully downloaded %s: %s (%d bytes)", 
                source.Type, outPath, stat.Size())
        }

        return nil
    }

    return fmt.Errorf("failed to download and verify %s after %d attempts", source.Type, maxRetries)
}

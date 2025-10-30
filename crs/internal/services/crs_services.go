package services

import (
    "io/fs"
    "math/rand"
    "runtime"
    "time"
    "bytes"
    "path/filepath"
    "fmt"
    "os"
    "path"
    "os/exec"
    "encoding/json"
    "encoding/base64"
    "bufio"
    "net"
    "net/http"
    "io"
    "log"
    "unicode"
    "strings"
    "crypto/sha256"
    "crs/internal/models"
    "crs/internal/competition"
    "crs/internal/executor"
    "github.com/google/uuid"
    "regexp"
    "sync"
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

// ProjectConfig is an alias to executor.ProjectConfig for backward compatibility
type ProjectConfig = executor.ProjectConfig

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

// Add VulnerabilitySubmission model
type VulnerabilitySubmission struct {
    ChallengeID  string `json:"challenge_id"`
    TestHarness  string `json:"harness_name"`
    Sanitizer    string `json:"sanitizer"`
    Architecture string `json:"architecture"`
    CrashData    []byte `json:"data_file"`
}

func NewCRSService(workerNodes int, workerBasePort int, model string) *defaultCRSService {
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

func (s *defaultCRSService) IsWorkerBusy() (bool, []string) {
    workerTaskMutex.Lock()
    defer workerTaskMutex.Unlock()

    var activeIDs []string
    for taskID := range activeWorkerTasks {
        activeIDs = append(activeIDs, taskID)
    }
    return len(activeWorkerTasks) > 0, activeIDs
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
    crashData := executor.ReadCrashFile(fuzzDir, s.povMetadataDir)
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
    return executor.LoadProjectConfig(projectYAMLPath)
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

// selectBestWorker finds the best worker to assign a task to
// tryWorker attempts to send a task to a specific worker
// recordWorkerFailure records a failure for a worker and blacklists it if necessary

package services

import (
    "io/fs"
    "runtime"
    "time"
    "path/filepath"
    "fmt"
    "os"
    "path"
    "os/exec"
    "encoding/json"
    "bufio"
    "io"
    "log"
    "unicode"
    "strings"
    "crypto/sha256"
    "crs/internal/models"
    "crs/internal/competition"
    "crs/internal/executor"
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


var (
    childGroups   = make(map[int]struct{})
    childGroupsMu sync.Mutex
)



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




// PullAFCDockerImage runs the helper.py script to build and pull Docker images for the project

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



// Find POVs with timeout and send broadcasts to assigned workers

// Helper method to send broadcast to a specific worker

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


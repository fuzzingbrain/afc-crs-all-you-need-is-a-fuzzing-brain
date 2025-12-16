package executor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"crs/internal/models"
	"crs/internal/utils/helpers"
)

// runPatchingStrategies executes patching strategies in multiple rounds with parallel execution
func runPatchingStrategies(
	myFuzzer, taskDir, projectDir, sanitizer, language, povMetadataDir string,
	taskDetail models.TaskDetail,
	fullTask models.Task,
	deadlineTime time.Time,
	patchWorkDir string,
	model string,
	submissionEndpoint string,
	workerIndex string,
	analysisServiceUrl string,
	unharnessedFuzzerSrcPath string,
) bool {
	// Create a separate directory for patching to avoid conflicts with ongoing POV generation
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
			if err := helpers.RobustCopyDir(sourceDiffDir, diffDir); err != nil {
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
	if err := helpers.RobustCopyDir(projectDir, patchProjectDir); err != nil {
		log.Printf("Failed to copy project to patch workspace: %v", err)
		return false
	}
	log.Printf("Copied project directory %s to patch workspace", projectBaseName)

	projectSanitizerDir := projectDir + "-" + sanitizer
	projectSanitizerBaseName := filepath.Base(projectSanitizerDir)
	patchSanitizerProjectDir := filepath.Join(patchWorkDir, projectSanitizerBaseName)
	// Create the destination directory first
	if err := os.MkdirAll(patchSanitizerProjectDir, 0755); err != nil {
		log.Printf("Failed to create patch project directory: %v", err)
		return false
	}
	if err := helpers.RobustCopyDir(projectSanitizerDir, patchSanitizerProjectDir); err != nil {
		log.Printf("Failed to copy project to patch workspace: %v", err)
		return false
	}
	log.Printf("Copied project-sanitizer directory %s to patch workspace", projectSanitizerBaseName)

	if !taskDetail.HarnessesIncluded {
		//for unharnessed copy all build-*.sh
		sourceDirForBuildScripts := taskDir           // Source is the taskDir
		targetDirForBuildScripts := patchWorkDir      // Target is the root of the patch workspace
		buildScripts, err := filepath.Glob(filepath.Join(sourceDirForBuildScripts, "build-*.sh"))
		if err != nil {
			log.Printf("Error finding build-*.sh files in %s: %v", sourceDirForBuildScripts, err)
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
					continue // Skip this file and try others
				}

				// Write the destination file
				err = os.WriteFile(destinationPath, input, 0755) // 0755 to keep it executable
				if err != nil {
					log.Printf("Failed to write build script to %s: %v", destinationPath, err)
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
		if err := helpers.RobustCopyDir(fuzzToolingDir, patchFuzzToolingDir); err != nil {
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

	// Find all strategy files under strategy/jeff/
	strategyBaseDir := os.Getenv("STRATEGY_BASE_DIR")
	if strategyBaseDir == "" {
		strategyBaseDir = "/app/strategy"
	}
	strategyDir := filepath.Join(strategyBaseDir, "jeff")
	strategyFilePattern := "patch0_delta.py"
	if taskDetail.Type == "full" {
		strategyFilePattern = "patch0_full.py"
	}

	if !taskDetail.HarnessesIncluded {
		//only use patch_delta and patch_full for unharnessed tasks
		if taskDetail.Type == "full" {
			strategyFilePattern = "patch_full.py"
		} else {
			strategyFilePattern = "patch_delta.py"
		}
	}

	strategyFiles, err := filepath.Glob(filepath.Join(strategyDir, strategyFilePattern))
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
	patchSuccess := false          // Overall success flag
	var successMutex sync.Mutex    // Mutex to protect patchSuccess
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
		if remainingTime <= time.Duration(SafetyBufferMinutes)*time.Minute {
			log.Printf("Deadline approaching before starting patching round %d. Exiting loop.", roundNum)
			break // Exit loop if deadline is too close
		}

		// Calculate timeout for this round based on remaining time
		roundTimeoutDuration := remainingTime - time.Duration(SafetyBufferMinutes)*time.Minute
		if roundTimeoutDuration <= 0 {
			log.Printf("Insufficient time for patching round %d. Exiting loop.", roundNum)
			break
		}

		log.Printf("Patching round %d timeout: %v", roundNum, roundTimeoutDuration)

		roundCtx, cancel := context.WithTimeout(context.Background(), roundTimeoutDuration) // Context per round
		var wg sync.WaitGroup                                                                // WaitGroup per round

		// install once, right after you create roundCtx
		sigc := make(chan os.Signal, 1)
		signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-sigc
			helpers.KillAllChildren(syscall.SIGTERM)
			time.Sleep(2 * time.Second)
			helpers.KillAllChildren(syscall.SIGKILL)
			cancel() // cancel roundCtx
			fmt.Fprintln(log.Writer()) // newline so shell prompt is clean
			os.Exit(1)                 // exit the Go program itself
		}()

		// FIVE parallel instances for each patching strategy
		PARALLEL_PATCH_TIMES := 1
		if os.Getenv("LOCAL_TEST") != "" {
			PARALLEL_PATCH_TIMES = 1
		}
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
				isRoot := helpers.GetEffectiveUserID() == 0
				hasSudo := helpers.CheckSudoAvailable()

				// Calculate patching timeout based on deadline
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
					"--model", model,
					fmt.Sprintf("--patching-timeout=%d", patchingTimeout),
					"--pov-metadata-dir", povMetadataDir,
					"--patch-workspace-dir", patchWorkDir,
				}

				var runCmd *exec.Cmd

				// Create the appropriate command based on our privileges
				if isRoot {
					runCmd = exec.CommandContext(patchCtx, pythonInterpreter, args...)
				} else if hasSudo {
					sudoArgs := append([]string{"-E", pythonInterpreter}, args...)
					runCmd = exec.CommandContext(patchCtx, "sudo", sudoArgs...)
				} else {
					log.Printf("Warning: Not running as root and sudo not available. Trying direct execution for patching.")
					runCmd = exec.CommandContext(patchCtx, pythonInterpreter, args...)
				}
				runCmd.Dir = patchWorkDir
				runCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // NEW: own PG

				// Set environment variables that would be set by the virtual environment activation
				runCmd.Env = append(os.Environ(),
					"VIRTUAL_ENV=/tmp/crs_venv",
					"PATH=/tmp/crs_venv/bin:"+os.Getenv("PATH"),
					fmt.Sprintf("SUBMISSION_ENDPOINT=%s", submissionEndpoint),
					fmt.Sprintf("TASK_ID=%s", taskDetail.TaskID.String()),
					// Pass through API credentials if they exist
					fmt.Sprintf("CRS_KEY_ID=%s", os.Getenv("CRS_KEY_ID")),
					fmt.Sprintf("CRS_KEY_TOKEN=%s", os.Getenv("CRS_KEY_TOKEN")),
					fmt.Sprintf("COMPETITION_API_KEY_ID=%s", os.Getenv("COMPETITION_API_KEY_ID")),
					fmt.Sprintf("COMPETITION_API_KEY_TOKEN=%s", os.Getenv("COMPETITION_API_KEY_TOKEN")),
					// Add any other environment variables needed by the Python script
					fmt.Sprintf("WORKER_INDEX=%s", workerIndex),
					fmt.Sprintf("ANALYSIS_SERVICE_URL=%s", analysisServiceUrl),
					"PYTHONUNBUFFERED=1",
				)

				// If we generated an unharnessed fuzzer for this task, pass its source path.
				if unharnessedFuzzerSrcPath != "" {
					runCmd.Env = append(runCmd.Env,
						fmt.Sprintf("NEW_FUZZER_SRC_PATH=%s", unharnessedFuzzerSrcPath))
				}

				// Create pipes for stdout and stderr
				stdoutPipe, err := runCmd.StdoutPipe()
				if err != nil {
					if err != nil {
						log.Printf("[Round %d] Failed stdout pipe for %s: %v", roundNum, strategyName, err)
						return
					}
				}
				stderrPipe, err := runCmd.StderrPipe()
				if err != nil {
					log.Printf("[Round %d] Failed stderr pipe for %s: %v", roundNum, strategyName, err)
					return
				}

				// Start the command
				startTime := time.Now()
				if err := runCmd.Start(); err != nil {
					log.Printf("[Round %d] Failed to start %s: %v", roundNum, strategyName, err)
					return
				}

				// ─── Forward Ctrl-C (SIGINT) / SIGTERM to the child process-group ───
				if runCmd.Process != nil {
					pgid, _ := syscall.Getpgid(runCmd.Process.Pid) // child's pgid == pid (Setpgid:true)
					helpers.RegisterChildPG(pgid)
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
							part = helpers.SanitizeTerminalString(part)
							if part == "" {
								continue
							}
							io.WriteString(log.Writer(), "\r\033[K")
							outputBuffer.WriteString(part + "\n")
							log.Printf("[Round %d][basic %s stdout] %s", roundNum, strategyName, part)

							// Check for patch success in real-time
							if strings.Contains(part, "PATCH SUCCESS!") ||
								strings.Contains(part, "Successfully patched") {

								successMutex.Lock()
								if !patchSuccess {
									patchSuccess = true
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
							part = helpers.SanitizeTerminalString(part)
							if part == "" {
								continue
							}
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
								io.WriteString(log.Writer(), "\r\033[K")
								log.Printf("[Round %d] Patch success confirmed post-run for %s. (Cancellation might have already occurred).", roundNum, strategyName)
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
		io.WriteString(log.Writer(), "\r\033[K")
		log.Printf("Patching Attempt Round %d finished.", roundNum)
		// After the round finishes, check the global success flag again
		successMutex.Lock()
		finalRoundSuccessCheck := patchSuccess
		successMutex.Unlock()

		if finalRoundSuccessCheck {
			io.WriteString(log.Writer(), "\r\033[K")
			log.Printf("Patch success confirmed after round %d. Exiting loop.", roundNum)
			break // Exit the main loop if patch was found in this round
		}

	} // --- End Patching Loop ---

	io.WriteString(log.Writer(), "\r\033[K")
	log.Printf("Exiting patching strategies function.")
	// Return the final state of patchSuccess
	successMutex.Lock()
	finalResult := patchSuccess
	successMutex.Unlock()

	fmt.Fprintln(log.Writer()) // ensure prompt starts on a fresh line

	return finalResult
}

func runXPatchingStrategiesWithoutPOV(
	myFuzzer, taskDir, projectDir, sanitizer, language string,
	taskDetail models.TaskDetail,
	fullTask models.Task,
	deadlineTime time.Time,
	patchWorkDir string,
	model string,
	submissionEndpoint string,
	workerIndex string,
	analysisServiceUrl string,
) bool {
	log.Printf("runXPatchingStrategiesWithoutPOV: starting patch attempt without POVs "+
		"(task type: %s)", taskDetail.Type)

	if !taskDetail.HarnessesIncluded {
		log.Printf("Only do XPatch for harnessed tasks. HarnessesIncluded: %v", taskDetail.HarnessesIncluded)
		return false
	}

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
			if err := helpers.RobustCopyDir(sourceDiffDir, diffDir); err != nil {
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
	if err := helpers.RobustCopyDir(projectDir, patchProjectDir); err != nil {
		log.Printf("Failed to copy project to patch workspace: %v", err)
		return false
	}
	log.Printf("Copied project directory %s to patch workspace", projectBaseName)

	projectSanitizerDir := projectDir + "-" + sanitizer
	projectSanitizerBaseName := filepath.Base(projectSanitizerDir)
	patchSanitizerProjectDir := filepath.Join(patchWorkDir, projectSanitizerBaseName)
	// Create the destination directory first
	if err := os.MkdirAll(patchSanitizerProjectDir, 0755); err != nil {
		log.Printf("Failed to create patch project directory: %v", err)
		return false
	}
	if err := helpers.RobustCopyDir(projectSanitizerDir, patchSanitizerProjectDir); err != nil {
		log.Printf("Failed to copy project to patch workspace: %v", err)
		return false
	}
	log.Printf("Copied project-sanitizer directory %s to patch workspace", projectSanitizerBaseName)

	// 2. Copy the fuzz-tooling directory if it exists
	fuzzToolingDir := filepath.Join(taskDir, "fuzz-tooling")
	if _, err := os.Stat(fuzzToolingDir); err == nil {
		patchFuzzToolingDir := filepath.Join(patchWorkDir, "fuzz-tooling")
		if err := helpers.RobustCopyDir(fuzzToolingDir, patchFuzzToolingDir); err != nil {
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

	// Find all strategy files under strategy/jeff/
	strategyBaseDir := os.Getenv("STRATEGY_BASE_DIR")
	if strategyBaseDir == "" {
		strategyBaseDir = "/app/strategy"
	}
	strategyDir := filepath.Join(strategyBaseDir, "jeff")
	strategyFilePattern := "xpatch_delta.py"
	if taskDetail.Type == "full" {
		strategyFilePattern = "xpatch_full.py"
	}

	strategyFiles, err := filepath.Glob(filepath.Join(strategyDir, strategyFilePattern))
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
			isRoot := helpers.GetEffectiveUserID() == 0
			hasSudo := helpers.CheckSudoAvailable()

			// Prepare the arguments for the Python command
			args := []string{
				strategyPath,
				patchFuzzerPath,
				taskDetail.ProjectName,
				taskDetail.Focus,
				language,
				"--model", model,
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
				runCmd = exec.CommandContext(patchCtx, pythonInterpreter, args...)
			} else if hasSudo {
				// Not root but sudo is available
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
				"PATH=/tmp/crs_venv/bin:"+os.Getenv("PATH"),
				fmt.Sprintf("SUBMISSION_ENDPOINT=%s", submissionEndpoint),
				fmt.Sprintf("TASK_ID=%s", taskDetail.TaskID.String()),
				// Pass through API credentials if they exist
				fmt.Sprintf("CRS_KEY_ID=%s", os.Getenv("CRS_KEY_ID")),
				fmt.Sprintf("CRS_KEY_TOKEN=%s", os.Getenv("CRS_KEY_TOKEN")),
				fmt.Sprintf("COMPETITION_API_KEY_ID=%s", os.Getenv("COMPETITION_API_KEY_ID")),
				fmt.Sprintf("COMPETITION_API_KEY_TOKEN=%s", os.Getenv("COMPETITION_API_KEY_TOKEN")),
				// Add any other environment variables needed by the Python script
				fmt.Sprintf("WORKER_INDEX=%s", workerIndex),
				fmt.Sprintf("ANALYSIS_SERVICE_URL=%s", analysisServiceUrl),
				"PYTHONUNBUFFERED=1",
			)

			// Log the command for debugging
			log.Printf("[XPATCH] Executing: %s", runCmd.String())
			// Create pipes for stdout and stderr
			stdoutPipe, err := runCmd.StdoutPipe()
			if err != nil {
				if err != nil {
					log.Printf("[XPATCH] Failed stdout pipe for %s: %v", strategyName, err)
					return
				}
			}
			stderrPipe, err := runCmd.StderrPipe()
			if err != nil {
				log.Printf("[XPATCH] Failed stderr pipe for %s: %v", strategyName, err)
				return
			}

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

func runXPatchSarifStrategies(
	myFuzzer, taskDir, sarifFilePath, language string,
	taskDetail models.TaskDetail,
	deadlineTime time.Time,
	patchWorkDir string,
	model string,
	submissionEndpoint string,
	workerIndex string,
	analysisServiceUrl string,
) bool {

	log.Printf("runXPatchSarifStrategies: starting patch attempt with sarif "+
		"(task type: %s)", taskDetail.Type)

	strategyBaseDir := os.Getenv("STRATEGY_BASE_DIR")
	if strategyBaseDir == "" {
		strategyBaseDir = "/app/strategy"
	}
	strategyDir := filepath.Join(strategyBaseDir, "jeff")
	strategyFilePattern := "xpatch_sarif.py"
	strategyFiles, err := filepath.Glob(filepath.Join(strategyDir, strategyFilePattern))
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

	var successMutex sync.Mutex
	var wg sync.WaitGroup

	for _, strategyFile := range strategyFiles {
		wg.Add(1)
		go func(strategyPath string) {
			defer wg.Done()
			strategyName := filepath.Base(strategyPath)
			log.Printf("Running XPATCH Sarif strategy: %s", strategyPath)

			pythonInterpreter := "/tmp/crs_venv/bin/python3"
			isRoot := helpers.GetEffectiveUserID() == 0
			hasSudo := helpers.CheckSudoAvailable()
			maxIterations := 5

			log.Printf("Setting max iterations to %d", maxIterations)

			args := []string{
				strategyPath,
				myFuzzer,
				sarifFilePath,
				taskDetail.ProjectName,
				taskDetail.Focus,
				language,
				"--model", model,
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
				fmt.Sprintf("SUBMISSION_ENDPOINT=%s", submissionEndpoint),
				fmt.Sprintf("TASK_ID=%s", taskDetail.TaskID.String()),
				fmt.Sprintf("CRS_KEY_ID=%s", os.Getenv("CRS_KEY_ID")),
				fmt.Sprintf("CRS_KEY_TOKEN=%s", os.Getenv("CRS_KEY_TOKEN")),
				fmt.Sprintf("COMPETITION_API_KEY_ID=%s", os.Getenv("COMPETITION_API_KEY_ID")),
				fmt.Sprintf("COMPETITION_API_KEY_TOKEN=%s", os.Getenv("COMPETITION_API_KEY_TOKEN")),
				fmt.Sprintf("WORKER_INDEX=%s", workerIndex),
				fmt.Sprintf("ANALYSIS_SERVICE_URL=%s", analysisServiceUrl),
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

func getPOVStatsFromSubmissionService(taskID, submissionEndpoint string) (int, int, error) {
	url := fmt.Sprintf("%s/v1/task/%s/pov_stats/", submissionEndpoint, taskID)

	// Create the HTTP request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("Error creating getPOVStats request for taskID %s: %v", taskID, err)
		return 0, 0, err
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")

	// Get API credentials from environment
	apiKeyID := os.Getenv("COMPETITION_API_KEY_ID")
	apiToken := os.Getenv("COMPETITION_API_KEY_TOKEN")
	if apiKeyID != "" && apiToken != "" {
		req.SetBasicAuth(apiKeyID, apiToken)
	}

	// Set context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	// Create a client with custom timeout settings
	client := &http.Client{
		Timeout: 180 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
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
		log.Printf("Error getting POV statistics from submission service: %v", err)
		if ctx.Err() == context.DeadlineExceeded {
			log.Printf("Request timed out, may need to increase timeout or check server load")
		}
		return 0, 0, err
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Submission service returned non-200 status: %d, body: %s", resp.StatusCode, string(body))
		return 0, 0, fmt.Errorf("submission service returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var response models.POVStatsResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		log.Printf("Error decoding POV stats response: %v", err)
		return 0, 0, err
	}

	return response.Count, response.PatchCount, nil
}

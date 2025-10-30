package executor

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unicode"

	"crs/internal/models"
)

// saveTaskDetailToJson saves task detail to a JSON file in the fuzzer directory
func saveTaskDetailToJson(taskDetail models.TaskDetail, fuzzer, fuzzDir string) {
	// Create a hash from the fuzzer name
	fuzzerHash := hashString(fuzzer)

	filePath := filepath.Join(fuzzDir, "task_detail.json")

	if !strings.Contains(fuzzDir, "fuzz-tooling/build/out") {
		// Create the file path with hash
		filePath = filepath.Join(fuzzDir, fmt.Sprintf("task_detail_%s.json", fuzzerHash))
	}

	// Marshal the taskDetail struct to JSON with indentation for readability
	jsonData, err := json.MarshalIndent(taskDetail, "", "  ")
	if err != nil {
		log.Printf("Failed to marshal task detail: %v", err)
		return
	}

	// Write the JSON data to the file
	err = os.WriteFile(filePath, jsonData, 0644)
	if err != nil {
		// Try with sudo if regular write fails
		if os.IsPermission(err) {
			tempFileName := fmt.Sprintf("/tmp/task_detail_%s.json", fuzzerHash)
			if tempErr := os.WriteFile(tempFileName, jsonData, 0644); tempErr != nil {
				log.Printf("Failed to write temporary file: %v", tempErr)
				return
			}

			cmd := exec.Command("sudo", "cp", tempFileName, filePath)
			if cpErr := cmd.Run(); cpErr != nil {
				log.Printf("Failed to copy file with sudo: %v", cpErr)
				return
			}

			chmodCmd := exec.Command("sudo", "chmod", "0644", filePath)
			if chmodErr := chmodCmd.Run(); chmodErr != nil {
				log.Printf("Warning: failed to set file permissions: %v", chmodErr)
			}

			os.Remove(tempFileName)
		} else {
			log.Printf("Failed to write task detail to file: %v", err)
			return
		}
	}

	log.Printf("Successfully saved task detail to %s", filePath)
}

// copyFuzzDirForParallelStrategies creates copies of fuzzDir for parallel strategy execution
func copyFuzzDirForParallelStrategies(fuzzer, fuzzDir string) error {
	// Define target directories for parallel strategies
	targetDirs := []string{"ap0", "ap1", "ap2", "ap3", "xp0", "sarif0"}
	fuzzerName := filepath.Base(fuzzer) // e.g. html

	// Detect the sanitizer suffix in the parent directory name and strip it
	sanitizerSuffixes := []string{
		"-address", "-undefined", "-memory", "-thread", "-ubsan",
		"-asan", "-msan", "-tsan",
	}
	coverageDir := fuzzDir // default
	for _, suf := range sanitizerSuffixes {
		if strings.Contains(fuzzDir, suf) {
			coverageDir = strings.Replace(fuzzDir, suf, "", 1) // e.g. libxml2-address → libxml2
			break
		}
	}

	coverageFuzzerPath := filepath.Join(coverageDir, fuzzerName) // sibling binary

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
		chownCmd := exec.Command("sudo", "chown", "-R", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), fuzzDir)
		if err := chownCmd.Run(); err != nil {
			log.Printf("Warning: Failed to change ownership with sudo: %v", err)
		}

		chmodCmd := exec.Command("sudo", "chmod", "-R", "755", fuzzDir)
		if err := chmodCmd.Run(); err != nil {
			log.Printf("Warning: Failed to change permissions with sudo: %v", err)
		}
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

		// Copy the *coverage* fuzzer binary
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

// hashString generates a SHA256 hash of a string and returns the first 16 characters
func hashString(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	return fmt.Sprintf("%x", h.Sum(nil))[:16] // Use first 16 chars of hash for brevity
}

// copyFile copies a file from src to dst
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

// getEffectiveUserID returns the effective user ID, handling cross-platform compatibility
func getEffectiveUserID() int {
	// This is a Unix-specific function
	if runtime.GOOS == "windows" {
		// On Windows, we can't easily check if we're admin
		// Just return a non-zero value
		return 1
	}

	// For Unix systems, use the syscall package
	return syscall.Geteuid()
}

// checkSudoAvailable checks if sudo is available and can be used
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

// robustCopyDir copies a directory from src to dst with fault tolerance
// Handles symlinks, preserves permissions, and continues on errors
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
		maxErrors := 5
		if len(copyErrors) < maxErrors {
			maxErrors = len(copyErrors)
		}
		return fmt.Errorf("completed with %d errors: %s", len(copyErrors), strings.Join(copyErrors[:maxErrors], "; "))
	}

	return nil
}

// ─── Process Group Management ───────────────────────────────────────────────

var (
	childGroups   = make(map[int]struct{})
	childGroupsMu sync.Mutex
)

// registerChildPG registers a process group ID for tracking
func registerChildPG(pgid int) {
	childGroupsMu.Lock()
	childGroups[pgid] = struct{}{}
	childGroupsMu.Unlock()
}

// killAllChildren sends a signal to all registered child process groups
func killAllChildren(sig syscall.Signal) {
	childGroupsMu.Lock()
	for pgid := range childGroups {
		syscall.Kill(-pgid, sig)
	}
	childGroupsMu.Unlock()
}

// ─── Terminal Output Sanitization ───────────────────────────────────────────

var ansiRegexp = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

// sanitizeTerminalString removes ANSI codes and control characters from strings
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

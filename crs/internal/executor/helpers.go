package executor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
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

// ─── POV/Crash File Operations ─────────────────────────────────────────────

// ReadCrashFile reads the newest crash blob file from the POV metadata directory
func ReadCrashFile(fuzzDir, povMetadataDir string) []byte {
	// Define the povMetadataDir path
	povMetadataDirPath := filepath.Join(fuzzDir, povMetadataDir)

	// Search specifically for test_blob_*.bin files
	blobPattern := filepath.Join(povMetadataDirPath, "test_blob_*.bin")
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

// ─── Directory/File Utilities ───────────────────────────────────────────────

// LogDirectoryContents logs all files in a directory recursively (for debugging)
func LogDirectoryContents(dir string) {
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

// SortFuzzersByGroup sorts fuzzers by sanitizer type (address, undefined, memory)
// Currently disabled (returns input as-is) but kept for potential future use
func SortFuzzersByGroup(allFuzzers []string) []string {
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

	// Note: rand.Seed/Shuffle would need math/rand and time imports
	// Keeping the structure for reference but currently returns unsorted

	// Concatenate in the desired order
	return append(append(address, undefined...), memory...)
}

// VerifyDirectoryAccess verifies that a directory exists and is accessible
func VerifyDirectoryAccess(dir string) error {
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

// ─── Source Extraction and Project Detection ────────────────────────────────

// ExtractSources extracts repo and fuzz-tooling archives from a task directory
func ExtractSources(taskDir string, isDelta bool) error {
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

	if isDelta {
		diffCmd := exec.Command("tar", "-xzf", path.Join(taskDir, "diff.tar.gz"))
		diffCmd.Dir = taskDir
		var diffOutput bytes.Buffer
		diffCmd.Stdout = &diffOutput
		diffCmd.Stderr = &diffOutput
		if err := diffCmd.Run(); err != nil {
			log.Printf("Diff extraction output:\n%s", diffOutput.String())
			return fmt.Errorf("failed to extract diff: %v", err)
		}
	}

	return nil
}

// DetectProjectName searches for project.yaml and returns the project name
func DetectProjectName(taskDir string) (string, error) {
	// Log initial directory contents
	log.Printf("Searching for project.yaml in: %s", taskDir)
	LogDirectoryContents(taskDir)

	// Try different patterns
	patterns := []string{
		"*/project.yaml",         // Direct subdirectory
		"*/*/project.yaml",       // Two levels deep
		"*/*/*/project.yaml",     // Three levels deep
		"example*/project.yaml",  // Example projects
		"*example*/project.yaml", // Example projects in subdirs
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

// IsSASTokenExpired checks if the SAS token in the URL is expired or will expire soon
func IsSASTokenExpired(urlStr string) bool {
	u, err := url.Parse(urlStr)
	if err != nil {
		return true
	}

	// Get expiry time from SAS token
	se := u.Query().Get("se")
	if se == "" {
		return false // No expiry time found
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

// DownloadAndVerifySource downloads a source archive from the given URL and verifies its SHA256
func DownloadAndVerifySource(taskDir string, source models.SourceDetail) error {
	// Check SAS token expiration first
	if IsSASTokenExpired(source.URL) {
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

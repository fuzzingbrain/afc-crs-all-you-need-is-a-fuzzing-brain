package build

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"crs/internal/utils/helpers"
)

// BuildAFCFuzzers builds fuzzers for a given project with proper isolation per sanitizer.
// It creates unique out/work directories for each sanitizer build to avoid conflicts.
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

// BuildAFCFuzzers0 is an older version of BuildAFCFuzzers that copies the output
// to a sanitizer directory after building.
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
	if err := helpers.RobustCopyDir(outDir, sanitizerDir); err != nil {
		log.Printf("[BuildAFCFuzzers] failed to copy fuzzer files: outDir %s %v", outDir, err)
	} else {
		log.Printf("[BuildAFCFuzzers] fuzzer files copied to %s", sanitizerDir)
	}

	return cmdOutput.String(), nil
}

// PullAFCDockerImage pulls the OSS-Fuzz Docker image for a project and tags it
// with the aixcc-afc prefix for local use.
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


// SPDX-License-Identifier: Apache-2.0
package c

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv" 
	"strings"

		
	"github.com/antlr4-go/antlr/v4" 
	// c_parser "static-analysis/internal/parser/c/grammar"
)
// PreprocessFile runs the C preprocessor on a file and returns the preprocessed content
// and a map of line numbers from preprocessed to original source
func PreprocessFile(filePath string, includeDirs []string) (string, map[int]LineInfo, error) {
	// Create a temporary file for the preprocessed output
	tmpFile, err := os.CreateTemp("", "preprocessed_*.c")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	// Create a temporary file for the custom header
	headerFile, err := os.CreateTemp("", "custom_header_*.h")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create header file: %v", err)
	}
	defer os.Remove(headerFile.Name())

	// Write a custom header that disables the ZLIB version check
	headerContent := `
#define PNG_ZLIB_VERNUM_NOCHECK
#define ZLIB_VERNUM 0x12b0
#define PNG_ZLIB_VERNUM 0x12b0
`
	if _, err := headerFile.WriteString(headerContent); err != nil {
		return "", nil, fmt.Errorf("failed to write header file: %v", err)
	}
	headerFile.Close()

	// Build the cpp command with line markers
	args := []string{"-E", "-P", "-C"} // -E=preprocess only, -P=no line markers, -C=keep comments
	
	// Include our custom header first
	args = append(args, "-include", headerFile.Name())
	
	// Add include directories
	for _, dir := range includeDirs {
		args = append(args, "-I"+dir)
	}
	
	// Add the input file
	args = append(args, filePath)
	
	// Add the output file
	args = append(args, "-o", tmpFile.Name())
	
	// Run the preprocessor
	cmd := exec.Command("gcc", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", nil, fmt.Errorf("preprocessor failed: %v\nOutput: %s", err, output)
	}
	
	// Read the preprocessed content
	preprocessed, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		return "", nil, fmt.Errorf("failed to read preprocessed file: %v", err)
	}
	
	// Create a line map
	lineMap, err := createLineMap(string(preprocessed), filePath)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create line map: %v", err)
	}
	
	return string(preprocessed), lineMap, nil
}

// createLineMap creates a map from preprocessed line numbers to original file and line
func createLineMap(preprocessed string, originalFile string) (map[int]LineInfo, error) {
	lines := strings.Split(preprocessed, "\n")
	lineMap := make(map[int]LineInfo)
	
	// By default, map all lines to the original file
	for i := range lines {
		lineMap[i+1] = LineInfo{
			File: originalFile,
			Line: i+1,
		}
	}
	
	return lineMap, nil
}
// LineInfo represents information about a line in the original source
type LineInfo struct {
	File string
	Line int
}

// buildLineMap builds a mapping from preprocessed line numbers to original source
func buildLineMap(preprocessedFile string) (map[int]LineInfo, error) {
	content, err := ioutil.ReadFile(preprocessedFile)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")
	lineMap := make(map[int]LineInfo)
	
	currentFile := ""
	currentLine := 0
	
	for i, line := range lines {
		// Look for line markers: # linenum "filename" flags
		if strings.HasPrefix(line, "# ") {
			parts := strings.Split(line, " ")
			if len(parts) >= 3 {
				lineNum, err := strconv.Atoi(parts[1])
				if err == nil {
					filename := strings.Trim(parts[2], "\"")
					currentFile = filename
					currentLine = lineNum - 1 // -1 because we're about to increment
				}
			}
		}
		
		// Map this preprocessed line to the current original source line
		currentLine++
		lineMap[i+1] = LineInfo{
			File: currentFile,
			Line: currentLine,
		}
	}
	
	return lineMap, nil
}

// Fix ParseFile to use the correct return type from PreprocessFile
func ParseFile(filePath string, includeDirs []string) (antlr.Tree, error) {
	// Preprocess the file
	preprocessed, _, err := PreprocessFile(filePath, includeDirs)
	if err != nil {
		return nil, fmt.Errorf("preprocessing failed: %v", err)
	}
	
	// Parse the preprocessed content
	return Parse(preprocessed)
}
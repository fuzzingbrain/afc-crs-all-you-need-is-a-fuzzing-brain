package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"path/filepath"
	"static-analysis/internal/engine"
	"static-analysis/internal/engine/models"
	"strings"
	"time"

	"github.com/google/uuid"
)

func main() {
	flag.Parse()
	// Check if task path is provided
	if len(flag.Args()) < 1 {
		log.Fatal("Task path is required as an argument")
	}
	taskPath := flag.Arg(0)

	// Get absolute paths
	absTaskPath, err := filepath.Abs(taskPath)
	if err != nil {
		log.Fatalf("Failed to get absolute task dir path: %v", err)
	}

	//----------------------------------------------------------
	// Locate and load task_detail*.json (if present)
	//----------------------------------------------------------
	var (
		taskDetail models.TaskDetail
		jsonFound  bool
	)

	taskDir := absTaskPath
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

	// Run analysis (for both JSON-loaded and fallback)
	results, err := engine.EngineMainAnalysisCore(taskDetail, absTaskPath)
	if err != nil {
		log.Fatalf("Analysis failed: %v", err)
	}
	// log.Printf("Analysis complete: %+v", results)

	// helper: write JSON file
	writeJSON := func(path string, v any) error {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(path, b, 0o644)
	}

	// helper: safe file suffix from entryPoint
	sanitizeEntryPoint := func(ep string) string {
		s := strings.ReplaceAll(ep, string(os.PathSeparator), "_")
		s = strings.ReplaceAll(s, ":", "_")
		s = strings.ReplaceAll(s, ".", "_")
		s = strings.ReplaceAll(s, " ", "_")
		if len(s) > 120 {
			s = s[len(s)-120:]
		}
		return s
	}

	// helper: map[entryPoint][]name + results.Functions -> []FunctionDefinition
	makeDefsForEntry := func(res *models.AnalysisResults, entryPoint string) []models.FunctionDefinition {
		var names []string
		if res.ReachableFunctions != nil {
			names = res.ReachableFunctions[entryPoint]
		}
		seen := make(map[string]struct{}, len(names))
		out := make([]models.FunctionDefinition, 0, len(names))

		for _, name := range names {
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}

			if def, ok := res.Functions[name]; ok && def != nil {
				out = append(out, *def)
				continue
			}

			simple := name
			if idx := strings.LastIndex(simple, "."); idx != -1 {
				simple = simple[idx+1:]
			}
			found := false
			for fn, def := range res.Functions {
				if def != nil && strings.HasSuffix(fn, "."+simple) {
					out = append(out, *def)
					found = true
					break
				}
			}
			if !found {
				out = append(out, models.FunctionDefinition{Name: name})
			}
		}
		return out
	}

	// Output directory：<task>/static_analysis
	outDir := filepath.Join(absTaskPath, "static_analysis")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		log.Printf("failed to create json output dir: %v", err)
		return
	}

	// entryPoints
	entryPoints := make([]string, 0, len(results.ReachableFunctions))
	for ep := range results.ReachableFunctions {
		entryPoints = append(entryPoints, ep)
	}

	if len(entryPoints) == 0 {
		log.Printf("No reachable sets in results; nothing to export.")
		return
	}

	index := make(map[string]string, len(entryPoints)) // entryPoint -> filename

	for _, ep := range entryPoints {
		resp := struct {
			Status             string                      `json:"status"`
			ReachableFunctions []models.FunctionDefinition `json:"reachable"`
		}{
			Status:             "success",
			ReachableFunctions: makeDefsForEntry(&results, ep),
		}

		safe := sanitizeEntryPoint(ep)
		filename := "analysis_response_" + safe + ".json"
		outFile := filepath.Join(outDir, filename)

		if err := writeJSON(outFile, resp); err != nil {
			log.Printf("failed to write %s: %v", outFile, err)
			continue
		}
		index[ep] = filename
		log.Printf("wrote %s (entry: %s)", outFile, ep)
	}

	// <task>/static_analysis/index.json
	idxFile := filepath.Join(outDir, "index.json")
	if err := writeJSON(idxFile, index); err != nil {
		log.Printf("failed to write index %s: %v", idxFile, err)
	} else {
		log.Printf("wrote %s (entryPoint -> response file)", idxFile)
	}
}

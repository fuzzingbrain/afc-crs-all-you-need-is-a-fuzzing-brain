// SPDX-License-Identifier: Apache-2.0
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"static-analysis/internal/analysis/callgraph"
	"static-analysis/internal/analysis/visitor"
	"static-analysis/internal/parser/c"
	"static-analysis/internal/parser/java"
)

func main() {
	// Parse command line arguments
	inputPath := flag.String("input", "", "Path to file or directory to analyze")
	outputPath := flag.String("output", "callgraph.dot", "Path to output DOT file")
	flag.Parse()

	if *inputPath == "" {
		fmt.Println("Please provide an input path with -input")
		os.Exit(1)
	}

	// Check if input is a file or directory
	fileInfo, err := os.Stat(*inputPath)
	if err != nil {
		fmt.Printf("Error accessing input path: %v\n", err)
		os.Exit(1)
	}

	var filesToAnalyze []string

	if fileInfo.IsDir() {
		// Walk directory to find C and Java files
		err = filepath.Walk(*inputPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() {
				ext := strings.ToLower(filepath.Ext(path))
				if ext == ".c" || ext == ".h" || ext == ".java" {
					filesToAnalyze = append(filesToAnalyze, path)
				}
			}
			return nil
		})
		if err != nil {
			fmt.Printf("Error walking directory: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Single file
		filesToAnalyze = append(filesToAnalyze, *inputPath)
	}

	// Collect call graphs from all files
	var graphs []*callgraph.CallGraph

	// Process each file
	for _, filePath := range filesToAnalyze {
		fmt.Printf("Analyzing %s...\n", filePath)
		
		// Read file content
		content, err := ioutil.ReadFile(filePath)
		if err != nil {
			fmt.Printf("Error reading file %s: %v\n", filePath, err)
			continue
		}

		ext := strings.ToLower(filepath.Ext(filePath))
		
		if ext == ".c" || ext == ".h" {
			// Parse C file
			tree, err := c.Parse(string(content))
			if err != nil {
				fmt.Printf("Error parsing C file %s: %v\n", filePath, err)
				continue
			}
			
			// Visit parse tree to build call graph
			v := visitor.NewCCallGraphVisitor(filePath)
			tree.Accept(v)
			
			// Add to collection of graphs
			graphs = append(graphs, v.CallGraph)
			fmt.Printf("Found %d functions in %s\n", len(v.CallGraph.Functions), filePath)
			
		} else if ext == ".java" {
			// Parse Java file
			tree, err := java.Parse(string(content))
			if err != nil {
				fmt.Printf("Error parsing Java file %s: %v\n", filePath, err)
				continue
			}
			
			// Visit parse tree to build call graph
			v := visitor.NewJavaCallGraphVisitor(filePath)
			tree.Accept(v)
			
			// Add to collection of graphs
			graphs = append(graphs, v.CallGraph)
			fmt.Printf("Found %d methods in %s\n", len(v.CallGraph.Functions), filePath)
		}
	}

	// Merge all call graphs
	mergedGraph := callgraph.MergeCallGraphs(graphs...)
	
	// Generate DOT file
	err = mergedGraph.GenerateDOTFile(*outputPath)
	if err != nil {
		fmt.Printf("Error generating DOT file: %v\n", err)
		os.Exit(1)
	}
	
	fmt.Printf("Call graph visualization written to %s\n", *outputPath)
	fmt.Printf("To visualize the graph, run: dot -Tpng %s -o callgraph.png\n", *outputPath)
	
	fmt.Println("Analysis complete!")
}
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"competition-api/internal/testmodels"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"net/http"
	"time"
)

func main() {
	// Example SARIF data for a libpng vulnerability
	sarifData := map[string]interface{}{
		"version": "2.1.0",
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":    "libFuzzer",
						"version": "1.0",
					},
				},
				"results": []map[string]interface{}{
					{
						"ruleId": "BUFFER_OVERFLOW",
						"message": map[string]interface{}{
							"text": "heap-buffer-overflow in png_handle_iCCP",
						},
						"locations": []map[string]interface{}{
							{
								"physicalLocation": map[string]interface{}{
									"artifactLocation": map[string]interface{}{
										"uri": "pngrutil.c",
									},
									"region": map[string]interface{}{
										"startLine": 1447,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// Create vulnerability broadcast
	vuln := testmodels.VulnBroadcast{
		MessageID:   uuid.New(),
		MessageTime: time.Now().Unix(),
		Vulns: []testmodels.VulnDetail{
			{
				TaskID: uuid.MustParse("7645d65b-aa72-4d32-92b8-240d1544eb22"), // Replace with actual task ID
				VulnID: uuid.New(),
				SARIF:  sarifData,
			},
		},
	}

	// Convert to JSON
	jsonData, err := json.Marshal(vuln)
	if err != nil {
		panic(err)
	}

	// Send to CRS
	req, err := http.NewRequest("POST", "http://localhost:8080/v1/sarif/", bytes.NewBuffer(jsonData))
	if err != nil {
		panic(err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("username", "password")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	fmt.Printf("Vulnerability submitted with status: %d\n", resp.StatusCode)
	fmt.Printf("Vuln ID: %s\n", vuln.Vulns[0].VulnID)
}

package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aristonllc/stigkube/pkg/models"
)

// PrintSummary outputs a human-readable summary of scan results to stdout
func PrintSummary(result *models.ScanResult) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("STIG COMPLIANCE SCAN RESULTS")
	fmt.Println(strings.Repeat("=", 60))

	fmt.Printf("\nCluster: %s\n", result.ClusterName)
	fmt.Printf("Kubernetes Version: %s\n", result.KubernetesVersion)
	fmt.Printf("Deployment Method: %s\n", result.DeploymentMethod)
	fmt.Printf("Nodes: %d\n", result.NodeCount)
	fmt.Printf("Scan Time: %s\n", result.ScanTimestamp.Format(time.RFC3339))

	fmt.Println("\n" + strings.Repeat("-", 60))
	fmt.Println("SUMMARY")
	fmt.Println(strings.Repeat("-", 60))

	fmt.Printf("\nTotal Checks: %d\n", result.Summary.Total)
	fmt.Printf("  Passed:       %d\n", result.Summary.Pass)
	fmt.Printf("  Failed:       %d\n", result.Summary.Fail)
	fmt.Printf("  Not Reviewed: %d\n", result.Summary.NotReviewed)
	fmt.Printf("  Not Applicable: %d\n", result.Summary.NotApplicable)
	fmt.Printf("  Errors:       %d\n", result.Summary.Error)

	fmt.Println("\nBy Severity:")
	fmt.Printf("  CAT I (High) Failures:   %d\n", result.Summary.HighFail)
	fmt.Printf("  CAT II (Medium) Failures: %d\n", result.Summary.MediumFail)
	fmt.Printf("  CAT III (Low) Failures:  %d\n", result.Summary.LowFail)

	// Print failed findings
	if result.Summary.Fail > 0 {
		fmt.Println("\n" + strings.Repeat("-", 60))
		fmt.Println("FAILED CHECKS")
		fmt.Println(strings.Repeat("-", 60))

		for _, finding := range result.Findings {
			if finding.Status == models.StatusFail {
				printFinding(finding)
			}
		}
	}

	// Print not reviewed findings
	if result.Summary.NotReviewed > 0 {
		fmt.Println("\n" + strings.Repeat("-", 60))
		fmt.Println("NOT REVIEWED (Requires Node Access)")
		fmt.Println(strings.Repeat("-", 60))

		for _, finding := range result.Findings {
			if finding.Status == models.StatusNotReviewed {
				fmt.Printf("\n[%s] %s\n", finding.Control.ID, finding.Control.Title)
				fmt.Printf("  Severity: CAT %s (%s)\n", finding.Control.CAT, finding.Control.Severity)
				fmt.Printf("  Reason: %s\n", finding.Details)
			}
		}
	}

	fmt.Println("\n" + strings.Repeat("=", 60))
}

func printFinding(finding models.Finding) {
	fmt.Printf("\n[%s] %s\n", finding.Control.ID, finding.Control.Title)
	fmt.Printf("  STIG ID: %s\n", finding.Control.STIGID)
	fmt.Printf("  Severity: CAT %s (%s)\n", finding.Control.CAT, finding.Control.Severity)
	fmt.Printf("  Status: FAIL\n")
	if finding.Details != "" {
		fmt.Printf("  Details: %s\n", finding.Details)
	}
	if finding.ExpectedValue != "" {
		fmt.Printf("  Expected: %s\n", finding.ExpectedValue)
	}
	if finding.ActualValue != "" {
		fmt.Printf("  Actual: %s\n", finding.ActualValue)
	}
	if finding.NodeName != "" {
		fmt.Printf("  Node: %s\n", finding.NodeName)
	}
}

// WriteJSON writes scan results to a JSON file
func WriteJSON(result *models.ScanResult, outputDir string) error {
	// Ensure output directory exists (0750 per STIG file permission requirements)
	if err := os.MkdirAll(outputDir, 0750); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Generate filename with timestamp
	filename := fmt.Sprintf("scan-results-%s.json", result.ScanTimestamp.Format("2006-01-02-150405"))
	filepath := filepath.Join(outputDir, filename)

	// Marshal to JSON
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal results: %w", err)
	}

	// Write file (0600 per STIG file permission requirements)
	if err := os.WriteFile(filepath, data, 0600); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	fmt.Printf("Results written to: %s\n", filepath)
	return nil
}

// strings helper to avoid importing strings for one function
var strings = struct {
	Repeat func(string, int) string
}{
	Repeat: func(s string, count int) string {
		result := ""
		for i := 0; i < count; i++ {
			result += s
		}
		return result
	},
}

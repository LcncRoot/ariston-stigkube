package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aristonllc/stigkube/pkg/models"
	"github.com/aristonllc/stigkube/pkg/remediator"
	"github.com/aristonllc/stigkube/pkg/stig"
)

var (
	scanResultFile string
)

var remediateCmd = &cobra.Command{
	Use:   "remediate",
	Short: "Generate Ansible remediation playbook from scan results",
	Long: `Remediate reads scan results and generates an Ansible role tailored
to the detected deployment method.

Examples:
  # Generate remediation from most recent scan results
  stigkube remediate

  # Generate remediation from specific scan results file
  stigkube remediate --from ./stigkube-output/scan-results-2024-01-15-103045.json

  # Generate remediation to specific directory
  stigkube remediate --output ./my-roles/`,
	RunE: runRemediate,
}

func init() {
	remediateCmd.Flags().StringVar(&scanResultFile, "from", "", "Path to scan results JSON file (defaults to most recent in output directory)")
}

func runRemediate(cmd *cobra.Command, args []string) error {
	// Load STIG controls (needed for control data)
	if err := stig.Load(); err != nil {
		return fmt.Errorf("failed to load STIG controls: %w", err)
	}

	// Find scan results file
	resultsPath := scanResultFile
	if resultsPath == "" {
		var err error
		resultsPath, err = findMostRecentScanResults(output)
		if err != nil {
			return fmt.Errorf("failed to find scan results: %w\n\nRun 'stigkube scan' first, or specify --from with path to scan results JSON", err)
		}
	}

	fmt.Printf("Loading scan results from: %s\n", resultsPath)

	// Load scan results
	result, err := loadScanResults(resultsPath)
	if err != nil {
		return fmt.Errorf("failed to load scan results: %w", err)
	}

	fmt.Printf("Loaded %d findings for cluster: %s (deployment: %s)\n",
		len(result.Findings), result.ClusterName, result.DeploymentMethod)

	// Count failed findings
	failedCount := 0
	for _, f := range result.Findings {
		if f.Status == models.StatusFail {
			failedCount++
		}
	}

	if failedCount == 0 {
		fmt.Println("No failed findings to remediate - cluster is compliant!")
		return nil
	}

	fmt.Printf("Found %d failed controls requiring remediation\n", failedCount)

	// Generate remediation
	remediationDir := filepath.Join(output, "remediation")
	rem := remediator.New(result.DeploymentMethod, remediationDir)
	if err := rem.Generate(result); err != nil {
		return fmt.Errorf("remediation generation failed: %w", err)
	}

	fmt.Printf("\nRemediation generated successfully!\n")
	fmt.Printf("Output directory: %s\n", remediationDir)
	fmt.Println("\nNext steps:")
	fmt.Println("  1. Review the generated playbook: site.yml")
	fmt.Println("  2. Update the inventory file with your node details")
	fmt.Println("  3. Test with: ansible-playbook -i inventory site.yml --check")
	fmt.Println("  4. Apply with: ansible-playbook -i inventory site.yml")

	return nil
}

// findMostRecentScanResults finds the most recent scan results JSON file in the output directory
func findMostRecentScanResults(outputDir string) (string, error) {
	pattern := filepath.Join(outputDir, "scan-results-*.json")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return "", fmt.Errorf("failed to search for scan results: %w", err)
	}

	if len(matches) == 0 {
		return "", fmt.Errorf("no scan results found in %s", outputDir)
	}

	// Sort by filename (which includes timestamp) to get most recent
	sort.Sort(sort.Reverse(sort.StringSlice(matches)))

	return matches[0], nil
}

// loadScanResults loads scan results from a JSON file
func loadScanResults(path string) (*models.ScanResult, error) {
	// #nosec G304 - path is user-provided CLI input or discovered from known output directory
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var result models.ScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Enrich findings with full control data from STIG database
	for i := range result.Findings {
		if result.Findings[i].Control.ID != "" {
			control := stig.GetControl(result.Findings[i].Control.ID)
			if control != nil {
				result.Findings[i].Control = *control
			}
		}
	}

	// Set default deployment method if not present
	if result.DeploymentMethod == "" {
		result.DeploymentMethod = "unknown"
	}

	// Clean up deployment method if it has extra info
	if strings.Contains(result.DeploymentMethod, " ") {
		result.DeploymentMethod = strings.Split(result.DeploymentMethod, " ")[0]
	}

	return &result, nil
}

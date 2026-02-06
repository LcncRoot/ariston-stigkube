package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/aristonllc/stigkube/pkg/reporter"
	"github.com/aristonllc/stigkube/pkg/stig"
)

var (
	reportFormat     string
	reportFromFile   string
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate reports from scan results",
	Long: `Report reads scan results and generates human-readable or
machine-readable reports in various formats.

Examples:
  # Generate text summary from most recent scan
  stigkube report

  # Generate text summary from specific scan file
  stigkube report --from ./stigkube-output/scan-results-2024-01-15.json

  # Generate XCCDF for STIG Viewer import
  stigkube report --format xccdf

  # Generate JSON (copy to different location)
  stigkube report --format json -o ./reports/`,
	RunE: runReport,
}

func init() {
	reportCmd.Flags().StringVar(&reportFormat, "format", "text", "Report format: text, json, xccdf")
	reportCmd.Flags().StringVar(&reportFromFile, "from", "", "Path to scan results JSON file (defaults to most recent)")
}

func runReport(cmd *cobra.Command, args []string) error {
	// Load STIG controls (needed for enriching findings)
	if err := stig.Load(); err != nil {
		return fmt.Errorf("failed to load STIG controls: %w", err)
	}

	// Find scan results file
	resultsPath := reportFromFile
	if resultsPath == "" {
		var err error
		resultsPath, err = findMostRecentScanResults(output)
		if err != nil {
			return fmt.Errorf("failed to find scan results: %w\n\nRun 'stigkube scan --json' first, or specify --from with path to scan results JSON", err)
		}
	}

	fmt.Printf("Loading scan results from: %s\n", resultsPath)

	// Load scan results (reuse function from remediate.go)
	result, err := loadScanResults(resultsPath)
	if err != nil {
		return fmt.Errorf("failed to load scan results: %w", err)
	}

	// Ensure summary is calculated
	result.CalculateSummary()

	// Generate report in requested format
	switch reportFormat {
	case "text":
		reporter.PrintSummary(result)

	case "json":
		if err := reporter.WriteJSON(result, output); err != nil {
			return fmt.Errorf("failed to write JSON report: %w", err)
		}

	case "xccdf":
		if err := reporter.WriteXCCDF(result, output); err != nil {
			return fmt.Errorf("failed to write XCCDF report: %w", err)
		}

	default:
		return fmt.Errorf("unknown report format: %s (supported: text, json, xccdf)", reportFormat)
	}

	return nil
}

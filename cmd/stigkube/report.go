package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	reportFormat string
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate reports from scan results",
	Long: `Report reads scan results and generates human-readable or
machine-readable reports.

Examples:
  # Generate text report
  stigkube report

  # Generate JSON report
  stigkube report --format json`,
	RunE: runReport,
}

func init() {
	reportCmd.Flags().StringVar(&reportFormat, "format", "text", "Report format: text, json, xccdf")
}

func runReport(cmd *cobra.Command, args []string) error {
	// TODO: Implement report generation from saved results
	fmt.Printf("Generating %s report from: %s\n", reportFormat, output)
	fmt.Println("TODO: Report generation not yet implemented")

	return nil
}

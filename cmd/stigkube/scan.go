package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/aristonllc/stigkube/pkg/detector"
	"github.com/aristonllc/stigkube/pkg/remediator"
	"github.com/aristonllc/stigkube/pkg/reporter"
	"github.com/aristonllc/stigkube/pkg/scanner"
	"github.com/aristonllc/stigkube/pkg/stig"
)

var (
	remediate   bool
	jsonOutput  bool
	xccdfOutput bool
	verboseMode bool
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a Kubernetes cluster against the DISA STIG",
	Long: `Scan deploys a scanner into the target cluster, runs STIG compliance
checks against all components, and reports findings.

Examples:
  # Scan using default kubeconfig
  stigkube scan

  # Scan with explicit kubeconfig
  stigkube scan --kubeconfig /path/to/config

  # Scan and generate remediation
  stigkube scan --remediate --output ./stigkube-output/`,
	RunE: runScan,
}

func init() {
	scanCmd.Flags().BoolVar(&remediate, "remediate", false, "Generate remediation playbook after scan")
	scanCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results as JSON")
	scanCmd.Flags().BoolVar(&xccdfOutput, "xccdf", false, "Output results as XCCDF for STIG Viewer import")
	scanCmd.Flags().BoolVarP(&verboseMode, "verbose", "v", false, "Verbose output")
}

func runScan(cmd *cobra.Command, args []string) error {
	// Load STIG controls
	if err := stig.Load(); err != nil {
		return fmt.Errorf("failed to load STIG controls: %w", err)
	}
	fmt.Printf("Loaded %d STIG controls\n", stig.GetControlCount())

	// Resolve kubeconfig path
	kubeconfigPath := kubeconfig
	if kubeconfigPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		kubeconfigPath = filepath.Join(home, ".kube", "config")
	}

	// Create scanner
	s, err := scanner.New(kubeconfigPath)
	if err != nil {
		return fmt.Errorf("failed to create scanner: %w", err)
	}

	// Detect deployment method
	fmt.Println("Detecting deployment method...")
	deployMethod, err := detector.Detect(s.Client())
	if err != nil {
		fmt.Printf("Warning: failed to detect deployment method: %v\n", err)
		deployMethod = "unknown"
	}
	fmt.Printf("Detected deployment method: %s\n", deployMethod)

	// Run scan
	fmt.Println("Running STIG compliance scan...")
	result, err := s.Scan()
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	result.DeploymentMethod = deployMethod
	result.CalculateSummary()

	// Output results
	if jsonOutput {
		if err := reporter.WriteJSON(result, output); err != nil {
			return fmt.Errorf("failed to write JSON report: %w", err)
		}
	} else {
		reporter.PrintSummary(result)
	}

	// Generate XCCDF output for STIG Viewer
	if xccdfOutput {
		if err := reporter.WriteXCCDF(result, output); err != nil {
			return fmt.Errorf("failed to write XCCDF report: %w", err)
		}
	}

	// Generate remediation if requested
	if remediate {
		fmt.Println("\nGenerating remediation playbook...")
		remediationDir := filepath.Join(output, "remediation")
		rem := remediator.New(deployMethod, remediationDir)
		if err := rem.Generate(result); err != nil {
			return fmt.Errorf("remediation generation failed: %w", err)
		}
	}

	// Return error if there are CAT I failures
	if result.Summary.HighFail > 0 {
		return fmt.Errorf("scan completed with %d CAT I (high severity) failures", result.Summary.HighFail)
	}

	return nil
}

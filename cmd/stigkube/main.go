package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	version    = "dev"
	kubeconfig string
	output     string
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "stigkube",
	Short: "Kubernetes STIG compliance scanner and remediation generator",
	Long: `StigKube scans Kubernetes clusters against the DISA Kubernetes STIG,
reports compliance gaps, and generates Ansible remediation playbooks
tailored to the cluster's deployment method.`,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("stigkube version %s\n", version)
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file (defaults to ~/.kube/config)")
	rootCmd.PersistentFlags().StringVarP(&output, "output", "o", "./stigkube-output", "Output directory for reports and remediation")

	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(remediateCmd)
	rootCmd.AddCommand(reportCmd)
}

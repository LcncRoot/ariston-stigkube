package scanner

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/aristonllc/stigkube/pkg/models"
	"github.com/aristonllc/stigkube/pkg/scanner/apiserver"
	"github.com/aristonllc/stigkube/pkg/scanner/general"
	"github.com/aristonllc/stigkube/pkg/stig"
)

// Scanner performs STIG compliance checks against a Kubernetes cluster
type Scanner struct {
	client     *kubernetes.Clientset
	kubeconfig string
}

// New creates a new Scanner with the given kubeconfig
func New(kubeconfig string) (*Scanner, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to build kubeconfig: %w", err)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	return &Scanner{
		client:     client,
		kubeconfig: kubeconfig,
	}, nil
}

// Client returns the kubernetes client
func (s *Scanner) Client() *kubernetes.Clientset {
	return s.client
}

// Scan performs all STIG compliance checks
func (s *Scanner) Scan() (*models.ScanResult, error) {
	ctx := context.Background()

	result := &models.ScanResult{
		ScanTimestamp: time.Now(),
		Findings:      []models.Finding{},
	}

	// Get cluster info
	version, err := s.client.Discovery().ServerVersion()
	if err != nil {
		return nil, fmt.Errorf("failed to get cluster version: %w", err)
	}
	result.KubernetesVersion = version.GitVersion

	// Get node count
	nodes, err := s.client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}
	result.NodeCount = len(nodes.Items)

	// Get cluster name from kubeconfig context (if available)
	result.ClusterName = "unknown"

	fmt.Printf("Scanning cluster: %s (Kubernetes %s, %d nodes)\n",
		result.ClusterName, result.KubernetesVersion, result.NodeCount)

	// Run API server checks
	fmt.Println("  Checking API server configuration...")
	apiFindings, err := apiserver.Check(ctx, s.client)
	if err != nil {
		fmt.Printf("  Warning: API server checks failed: %v\n", err)
	} else {
		result.Findings = append(result.Findings, apiFindings...)
	}

	// Run general/cluster-level checks
	fmt.Println("  Checking cluster-level controls...")
	generalFindings, err := general.Check(ctx, s.client)
	if err != nil {
		fmt.Printf("  Warning: General checks failed: %v\n", err)
	} else {
		result.Findings = append(result.Findings, generalFindings...)
	}

	// TODO: Add more check categories
	// - kubelet checks (requires node access)
	// - etcd checks (requires node access)
	// - scheduler checks
	// - controller manager checks
	// - proxy checks
	// - node permission checks

	fmt.Printf("  Completed %d checks\n", len(result.Findings))

	return result, nil
}

// getControlsForComponent returns STIG controls for a specific component
func getControlsForComponent(component string) []models.Control {
	var controls []models.Control
	for _, c := range stig.Controls {
		// Simple matching based on title/description keywords
		switch component {
		case "apiserver":
			if containsAny(c.Title, "API Server", "API server") {
				controls = append(controls, c)
			}
		case "kubelet":
			if containsAny(c.Title, "Kubelet", "kubelet") {
				controls = append(controls, c)
			}
		case "etcd":
			if containsAny(c.Title, "etcd", "Etcd") {
				controls = append(controls, c)
			}
		case "scheduler":
			if containsAny(c.Title, "Scheduler", "scheduler") {
				controls = append(controls, c)
			}
		case "controller":
			if containsAny(c.Title, "Controller Manager", "controller manager") {
				controls = append(controls, c)
			}
		}
	}
	return controls
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

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
	"github.com/aristonllc/stigkube/pkg/scanner/node"
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

	// Run node-level checks (requires privileged pod deployment)
	fmt.Println("  Checking node-level controls (deploying scanner pods)...")
	nodeScanner := node.New(s.client)
	nodeFindings, err := nodeScanner.ScanAllNodes(ctx)
	if err != nil {
		fmt.Printf("  Warning: Node-level checks failed: %v\n", err)
	} else {
		result.Findings = append(result.Findings, nodeFindings...)
	}

	// Deduplicate findings - prefer node-level over API-level, prefer pass/fail over not_reviewed
	result.Findings = deduplicateFindings(result.Findings)

	fmt.Printf("  Completed %d checks\n", len(result.Findings))

	return result, nil
}

// deduplicateFindings removes duplicate findings for the same control,
// preferring node-level findings and pass/fail over not_reviewed
func deduplicateFindings(findings []models.Finding) []models.Finding {
	// Map to track best finding per control ID (and node if applicable)
	bestFindings := make(map[string]models.Finding)

	for _, f := range findings {
		// Create key based on control ID and node
		key := f.Control.ID
		if f.NodeName != "" {
			key = f.Control.ID + ":" + f.NodeName
		}

		existing, exists := bestFindings[key]
		if !exists {
			bestFindings[key] = f
			continue
		}

		// Prefer findings in this order:
		// 1. Pass/Fail over NotReviewed/Error
		// 2. Node-level (has NodeName) over API-level
		// 3. More specific details
		if shouldReplace(existing, f) {
			bestFindings[key] = f
		}
	}

	// Convert map back to slice
	result := make([]models.Finding, 0, len(bestFindings))
	for _, f := range bestFindings {
		result = append(result, f)
	}

	return result
}

// shouldReplace returns true if newFinding should replace existing
func shouldReplace(existing, newFinding models.Finding) bool {
	// Priority order for status
	statusPriority := map[string]int{
		models.StatusPass:          4,
		models.StatusFail:          3,
		models.StatusNotApplicable: 2,
		models.StatusNotReviewed:   1,
		models.StatusError:         0,
	}

	existingPriority := statusPriority[existing.Status]
	newPriority := statusPriority[newFinding.Status]

	// Higher priority status wins
	if newPriority > existingPriority {
		return true
	}
	if newPriority < existingPriority {
		return false
	}

	// Same priority - prefer node-level findings
	if newFinding.NodeName != "" && existing.NodeName == "" {
		return true
	}

	// Prefer findings with actual values
	if newFinding.ActualValue != "" && existing.ActualValue == "" {
		return true
	}

	return false
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

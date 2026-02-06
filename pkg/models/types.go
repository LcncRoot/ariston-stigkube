package models

import "time"

// Control represents a single DISA STIG control
type Control struct {
	ID          string   `json:"id"`           // e.g., "V-242381"
	STIGID      string   `json:"stig_id"`      // e.g., "CNTR-K8-000220"
	SRG         string   `json:"srg"`          // e.g., "SRG-APP-000023-CTR-000055"
	CAT         string   `json:"cat"`          // "I", "II", "III"
	Severity    string   `json:"severity"`     // "high", "medium", "low"
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Fix         string   `json:"fix"`
	Check       string   `json:"check"`
	CCI         []string `json:"cci,omitempty"`
}

// Severity returns normalized severity
func (c Control) GetSeverity() string {
	switch c.CAT {
	case "I":
		return "high"
	case "II":
		return "medium"
	case "III":
		return "low"
	default:
		return c.Severity
	}
}

// Finding represents the result of checking one control
type Finding struct {
	Control       Control `json:"control"`
	Status        string  `json:"status"` // "pass", "fail", "not_applicable", "not_reviewed", "error"
	Details       string  `json:"details"`
	ActualValue   string  `json:"actual_value"`
	ExpectedValue string  `json:"expected_value"`
	NodeName      string  `json:"node_name,omitempty"` // empty for cluster-level
	Remediation   string  `json:"remediation"`
}

// Status constants
const (
	StatusPass          = "pass"
	StatusFail          = "fail"
	StatusNotApplicable = "not_applicable"
	StatusNotReviewed   = "not_reviewed"
	StatusManualReview  = "manual_review"
	StatusError         = "error"
)

// ScanResult is the complete output of a scan
type ScanResult struct {
	ClusterName       string      `json:"cluster_name"`
	KubernetesVersion string      `json:"kubernetes_version"`
	DeploymentMethod  string      `json:"deployment_method"`
	ScanTimestamp     time.Time   `json:"scan_timestamp"`
	NodeCount         int         `json:"node_count"`
	Findings          []Finding   `json:"findings"`
	Summary           ScanSummary `json:"summary"`
}

// ScanSummary provides counts
type ScanSummary struct {
	Total         int `json:"total"`
	Pass          int `json:"pass"`
	Fail          int `json:"fail"`
	NotApplicable int `json:"not_applicable"`
	NotReviewed   int `json:"not_reviewed"`
	Error         int `json:"error"`
	HighFail      int `json:"high_fail"`   // CAT I failures
	MediumFail    int `json:"medium_fail"` // CAT II failures
	LowFail       int `json:"low_fail"`    // CAT III failures
}

// CalculateSummary computes summary from findings
func (r *ScanResult) CalculateSummary() {
	r.Summary = ScanSummary{}
	for _, f := range r.Findings {
		r.Summary.Total++
		switch f.Status {
		case StatusPass:
			r.Summary.Pass++
		case StatusFail:
			r.Summary.Fail++
			switch f.Control.CAT {
			case "I":
				r.Summary.HighFail++
			case "II":
				r.Summary.MediumFail++
			case "III":
				r.Summary.LowFail++
			}
		case StatusNotApplicable:
			r.Summary.NotApplicable++
		case StatusNotReviewed:
			r.Summary.NotReviewed++
		case StatusError:
			r.Summary.Error++
		}
	}
}

// DeploymentMethod constants
const (
	DeployKubeadm   = "kubeadm"
	DeployKubespray = "kubespray"
	DeployRKE2      = "rke2"
	DeployK3s       = "k3s"
	DeployOpenShift = "openshift"
	DeployManual    = "manual"
	DeployUnknown   = "unknown"
)

// NodeInfo contains information about a cluster node
type NodeInfo struct {
	Name              string            `json:"name"`
	Role              string            `json:"role"` // "control-plane", "worker"
	KubeletVersion    string            `json:"kubelet_version"`
	ContainerRuntime  string            `json:"container_runtime"`
	OS                string            `json:"os"`
	KernelVersion     string            `json:"kernel_version"`
	Labels            map[string]string `json:"labels"`
}
